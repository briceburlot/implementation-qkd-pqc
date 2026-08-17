"""
KME (Key Management Entity) — ETSI GS QKD 014 REST API server.
API gestionnaire des clés.
Elle pourra par la suite appeler le programme permettant la PQC

Elle expose les trois endpoints standard necessaire a la SAE :
  GET  /api/v1/keys/{slave_SAE_ID}/status
  POST /api/v1/keys/{slave_SAE_ID}/enc_keys   (master SAE -> get key + key_ID)
  POST /api/v1/keys/{master_SAE_ID}/dec_keys  (slave  SAE -> get key by key_ID)

Principes :
Les 2 KME (A et B) partage la meme clé quantique distribuée.
Ici les informations de cette clée partagée est simulé par un store commun
pour que cette requete de clé par le SAE A (key + key_ID) puisse etre récupérer par
le SAE B en utilisant uniquement le key_ID comme affiché par la démo cf. sae_API.
"""

import base64
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json


# --- Shared quantum key store (simulates the QKD link between KME-A / KME-B) ---
class SharedKeyStore:
    """In-memory store standing in for the QKD-distributed key material.

    In a real deployment each KME holds its own copy synchronised over the
    quantum channel. For a single-process demo both KMEs point to the same
    instance.
    """

    def __init__(self):
        self._keys = {}  # key_ID -> base64 key
        self._lock = threading.Lock()

    def new_key(self, size_bits=256):
        key_bytes = os.urandom(size_bits // 8)
        key_b64 = base64.b64encode(key_bytes).decode("ascii")
        key_id = str(uuid.uuid4())
        with self._lock:
            self._keys[key_id] = key_b64
        return key_id, key_b64

    def get_key(self, key_id):
        with self._lock:
            return self._keys.get(key_id)


class KMEHandler(BaseHTTPRequestHandler):
    store = None # injected before serving
    default_size = 256 # taille attendue de l'information

    # -- helpers ------------------------------------------------------------
    def _send_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def log_message(self, *args):
        pass  # silence default logging

    # -- routing ------------------------------------------------------------
    def do_GET(self):
        parts = self.path.strip("/").split("/")
        # api/v1/keys/{SAE_ID}/status
        if len(parts) == 5 and parts[:3] == ["api", "v1", "keys"] and parts[4] == "status":
            slave_sae_id = parts[3]
            self._send_json(200, {
                "source_KME_ID": "KME_A",
                "target_KME_ID": "KME_B",
                "master_SAE_ID": "SAE_A",
                "slave_SAE_ID": slave_sae_id,
                "key_size": self.default_size,
                "stored_key_count": 25000,
                "max_key_count": 100000,
                "max_key_per_request": 128,
                "max_key_size": 1024,
                "min_key_size": 64,
            })
        else:
            self._send_json(404, {"message": "Not found"})

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        body = self._read_body()

        # api/v1/keys/{slave_SAE_ID}/enc_keys  -> master SAE gets key + key_ID
        if len(parts) == 5 and parts[:3] == ["api", "v1", "keys"] and parts[4] == "enc_keys":
            number = int(body.get("number", 1))
            size = int(body.get("size", self.default_size))
            keys = []
            for _ in range(number):
                key_id, key_b64 = self.store.new_key(size)
                keys.append({"key_ID": key_id, "key": key_b64})
            self._send_json(200, {"keys": keys})

        # api/v1/keys/{master_SAE_ID}/dec_keys -> slave SAE gets key by key_ID
        elif len(parts) == 5 and parts[:3] == ["api", "v1", "keys"] and parts[4] == "dec_keys":
            key_ids = body.get("key_IDs", [])
            if not key_ids and "key_ID" in body:
                key_ids = [{"key_ID": body["key_ID"]}]
            keys = []
            for item in key_ids:
                kid = item["key_ID"] if isinstance(item, dict) else item
                key_b64 = self.store.get_key(kid)
                if key_b64 is None:
                    self._send_json(400, {"message": f"key_ID {kid} not found"})
                    return
                keys.append({"key_ID": kid, "key": key_b64})
            self._send_json(200, {"keys": keys})
        else:
            self._send_json(404, {"message": "Not found"})


def make_server(host, port, store):
    handler = type("BoundKMEHandler", (KMEHandler,), {"store": store})
    return ThreadingHTTPServer((host, port), handler)


if __name__ == "__main__":
    host = os.environ.get("KME_HOST", "0.0.0.0")
    port = int(os.environ.get("KME_PORT", "8000"))
    shared = SharedKeyStore()
    srv = make_server(host, port, shared)
    print(f"KME serving on http://{host}:{port}")
    srv.serve_forever()
