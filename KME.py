"""
KME (Key Management Entity) — ETSI GS QKD 014 REST API server.
API gestionnaire des clés.
Elle pourra par la suite appeler le programme permettant la PQC

Elle expose les trois endpoints standard necessaire a la SAE (Figure 2 / 5.1-5.4) :
  GET  /api/v1/keys/{slave_SAE_ID}/status
  POST /api/v1/keys/{slave_SAE_ID}/enc_keys   (master SAE -> get key + key_ID)
  POST /api/v1/keys/{master_SAE_ID}/dec_keys  (slave  SAE -> get key by key_ID)

Topologie multi-site (Figure 1) :
Chaque site (Trusted Node) a son propre process KME, independant, avec son
propre store de clés. Pour simuler le "QKD Link" qui synchronise deux KME
distants, ce KME expose un endpoint interne :
  POST /internal/sync_keys
Quand un SAE maître demande des clés (enc_keys) pour un slave_SAE_ID qui vit
sur un autre site, le KME local pousse ces clés vers le KME pair via ce
endpoint, en s'appuyant sur une table de routage KME_PEERS
(slave_SAE_ID -> URL du KME qui héberge ce SAE). Le SAE esclave peut ensuite
les récupérer localement (dec_keys) exactement comme le prévoit le protocole.
"""

import base64
import json
import os
import threading
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class SharedKeyStore:
    """In-memory store standing in for the QKD-distributed key material held
    by a single KME."""

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

    def put_key(self, key_id, key_b64):
        """Store key material received from a peer KME (QKD link sync)."""
        with self._lock:
            self._keys[key_id] = key_b64

    def get_key(self, key_id):
        with self._lock:
            return self._keys.get(key_id)


class KMEHandler(BaseHTTPRequestHandler):
    store = None  # injected before serving
    kme_id = "KME"  # injected before serving
    peers = None  # injected before serving: {slave_SAE_ID: peer_KME_base_url}
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
                "source_KME_ID": self.kme_id,
                "target_KME_ID": self.peers.get(slave_sae_id, self.kme_id),
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

    def _sync_to_peer(self, peer_url, keys):
        """Push freshly generated key material to the peer KME hosting the
        slave SAE, simulating the QKD link between the two Trusted Nodes."""
        data = json.dumps({"keys": keys}).encode("utf-8")
        req = urllib.request.Request(
            peer_url.rstrip("/") + "/internal/sync_keys", data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        body = self._read_body()

        # internal/sync_keys -> peer KME pushing key material over the simulated QKD link
        if len(parts) == 2 and parts == ["internal", "sync_keys"]:
            for item in body.get("keys", []):
                self.store.put_key(item["key_ID"], item["key"])
            self._send_json(200, {"status": "ok"})

        # api/v1/keys/{slave_SAE_ID}/enc_keys  -> master SAE gets key + key_ID
        elif len(parts) == 5 and parts[:3] == ["api", "v1", "keys"] and parts[4] == "enc_keys":
            slave_sae_id = parts[3]
            number = int(body.get("number", 1))
            size = int(body.get("size", self.default_size))
            keys = []
            for _ in range(number):
                key_id, key_b64 = self.store.new_key(size)
                keys.append({"key_ID": key_id, "key": key_b64})

            peer_url = self.peers.get(slave_sae_id)
            if peer_url:
                try:
                    self._sync_to_peer(peer_url, keys)
                except (urllib.error.URLError, TimeoutError, OSError) as exc:
                    self._send_json(503, {"message": f"failed to reach peer KME for {slave_sae_id}: {exc}"})
                    return

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


def make_server(host, port, store, kme_id="KME", peers=None):
    handler = type("BoundKMEHandler", (KMEHandler,), {
        "store": store, "kme_id": kme_id, "peers": peers or {},
    })
    return ThreadingHTTPServer((host, port), handler)


if __name__ == "__main__":
    host = os.environ.get("KME_HOST", "0.0.0.0")
    port = int(os.environ.get("KME_PORT", "8000"))
    kme_id = os.environ.get("KME_ID", "KME")
    peers = json.loads(os.environ.get("KME_PEERS", "{}"))  # {slave_SAE_ID: peer_KME_base_url}
    shared = SharedKeyStore()
    srv = make_server(host, port, shared, kme_id, peers)
    print(f"KME {kme_id} serving on http://{host}:{port} (peers: {peers})")
    srv.serve_forever()
