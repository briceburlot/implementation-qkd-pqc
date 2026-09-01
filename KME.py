"""
This module models a QKD Node inside a security perimeter (Trusted Node):

    ┌─────────────── Security perimeter (Trusted Node) ───────────────┐
    │  APPs (SAE)                                                     │
    │     ▲                                                           │
    │     │ ETSI GS QKD 014 REST API                                  │
    │     ▼                                                           │
    │  KeyManagement  ◄──────────────►  QKDControl                    │
    │     │  ▲                              │  ▲                      │
    │     ▼  │                              ▼  │                      │
    │  ┌───────────────── QKD Key Store Peers ─────────────────┐      │
    │  │ QKDKeyStorePeer(peerA)  QKDKeyStorePeer(peerB) ...     │     │
    │  └───────────────────────────────────────────────────────┘      │
    │                          ▲                                      │
    │                          │                                      │
    │                    ForwardingModule  ──(QKD link)──► other Node │
    └─────────────────────────────────────────────────────────────────┘

Correspondence with the diagram:
  - APPs                -> the client SAEs (external, via the REST API)
  - Key Management      -> class KeyManagement: serves the ETSI 014 API to
                           SAEs, picks the right Key Store Peer, allocates/
                           retrieves keys
  - QKD Control         -> class QKDControl: drives the Key Store Peers and
                           the Forwarding Module (the "QKD network" side),
                           not exposed to SAEs
  - QKD Key Store Peer  -> class QKDKeyStorePeer: ONE store per peer KME
                           (instead of a single global store as before)
  - Forwarding Module   -> class ForwardingModule: relays key material to
                           the peer KME over the simulated QKD link

Exposed endpoints:
  GET  /api/v1/keys/{slave_SAE_ID}/status
  POST /api/v1/keys/{slave_SAE_ID}/enc_keys    (master SAE -> key + key_ID)
  POST /api/v1/keys/{master_SAE_ID}/dec_keys   (slave  SAE -> key by key_ID)
Internal endpoint (QKD link, out of the ETSI API scope):
  POST /internal/sync_keys                      (peer's Forwarding Module)

NB: the hybrid cryptographic layer (PQC ⊕ QKD, WireGuard) lives on the SAE
side (crypto_hybrid.py + wireguard.py). As required by ETSI, the KME remains
a pure supplier of identical symmetric keys on both sides — and therefore
NEVER has a PQC dependency.

Authentication (two separate servers, one single process):
  - external port (KME_PORT, default 8000), facing the SAEs: **classic
    mTLS** (TLS_SERVER_CERT/KEY + TLS_CA_CERT), SAE client certificate
    required (CERT_REQUIRED). Serves only /api/v1/keys/...
  - internal port (KME_INTERNAL_PORT, default 8001), facing peer KMEs:
    plain HTTP, UNCHANGED — KME<->KME replication remains out of scope for
    this authentication request. Serves only /internal/sync_keys.
"""

import base64
import json
import os
import ssl
import threading
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# =========================================================================== #
# QKD Key Store Peer  —  one key store per peer KME (scheme_site)              #
# =========================================================================== #
class QKDKeyStorePeer:
    """In-memory store of the key material shared with ONE given peer KME.

    In the diagram, the QKD Node holds several stacked "QKD Key Store Peer"
    instances: one per QKD link / per peer. Each store holds the QKD keys
    reconciled with that specific peer. Here quantum generation /
    reconciliation / privacy amplification are out of scope (ETSI clause 1):
    we model the result, namely a key_ID -> key dictionary.
    """

    def __init__(self, peer_kme_id):
        self.peer_kme_id = peer_kme_id
        self._keys = {}          # key_ID -> base64 key
        self._lock = threading.Lock()

    def new_key(self, size_bits=256):
        """Allocates a new key (generated locally, to be replicated to the peer)."""
        key_bytes = os.urandom(size_bits // 8)
        key_b64 = base64.b64encode(key_bytes).decode("ascii")
        key_id = str(uuid.uuid4())
        with self._lock:
            self._keys[key_id] = key_b64
        return key_id, key_b64

    def put_key(self, key_id, key_b64):
        """Stores a key received from the peer (replication over the QKD link)."""
        with self._lock:
            self._keys[key_id] = key_b64

    def get_key(self, key_id):
        with self._lock:
            return self._keys.get(key_id)

    def has_key(self, key_id):
        with self._lock:
            return key_id in self._keys

    def count(self):
        with self._lock:
            return len(self._keys)


# --------------------------------------------------------------------------- #
# Backward compatibility: SharedKeyStore                                       #
# --------------------------------------------------------------------------- #
class SharedKeyStore(QKDKeyStorePeer):
    """Historical alias kept for sae_API.demo() (a single shared store).

    Behaves like a QKDKeyStorePeer with no particular peer.
    """

    def __init__(self, peer_kme_id="PEER"):
        super().__init__(peer_kme_id)


# =========================================================================== #
# Forwarding Module  —  relays key material over the QKD link (scheme_site)    #
# =========================================================================== #
class ForwardingModule:
    """Pushes key material to the peer KME hosting the slave SAE.

    Models the "Forwarding Module" from the diagram: it is the one that
    talks to the QKD network (here, the peer KME's internal
    /internal/sync_keys endpoint). The slave_SAE_ID -> peer KME URL routing
    comes from the KME_PEERS table.
    """

    def __init__(self, peers):
        # peers: {slave_SAE_ID: peer_KME_base_url}
        self.peers = peers or {}

    def peer_url_for(self, sae_id):
        return self.peers.get(sae_id)

    def forward_keys(self, peer_url, keys):
        """Replicates `keys` (list of {key_ID, key}) to the peer KME."""
        data = json.dumps({"keys": keys}).encode("utf-8")
        req = urllib.request.Request(
            peer_url.rstrip("/") + "/internal/sync_keys",
            data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()


# =========================================================================== #
# QKD Control  —  drives the Key Store Peers and the Forwarding Module         #
# =========================================================================== #
class QKDControl:
    """"QKD network" side of the Node (blue in the diagram).

    Manages the set of QKDKeyStorePeer instances (created on the fly per
    peer) and delegates relaying to the ForwardingModule. Is NOT exposed
    directly to the SAEs.
    """

    def __init__(self, peers):
        self.forwarding = ForwardingModule(peers)
        self._stores = {}                 # peer_KME_id -> QKDKeyStorePeer
        self._lock = threading.Lock()

    def store_for_peer(self, peer_kme_id):
        """Returns (creating it if needed) a peer's Key Store Peer."""
        with self._lock:
            store = self._stores.get(peer_kme_id)
            if store is None:
                store = QKDKeyStorePeer(peer_kme_id)
                self._stores[peer_kme_id] = store
            return store

    def peer_kme_id_for_sae(self, sae_id):
        """Derives a peer identifier from the routing URL.

        (The fine-grained SAE->KME_ID mapping is out of ETSI scope; we
        derive a stable id from the peer's URL to index the right store.)
        """
        url = self.forwarding.peer_url_for(sae_id)
        return url  # the URL acts as the peer key, unique per remote KME

    def find_key_anywhere(self, key_id):
        """Looks up a key by key_ID across all Key Store Peers.

        Used by dec_keys: the slave SAE requests a key by its key_ID without
        knowing which peer-store it landed in.
        """
        with self._lock:
            stores = list(self._stores.values())
        for store in stores:
            k = store.get_key(key_id)
            if k is not None:
                return k
        return None

    def ingest_from_peer(self, keys):
        """Stores keys received from a peer (via the remote Forwarding Module).

        We don't necessarily know the sending peer here; we place them in a
        dedicated "inbound" store so they can be found by key_ID.
        """
        store = self.store_for_peer("__inbound__")
        for item in keys:
            store.put_key(item["key_ID"], item["key"])

    def total_stored(self):
        with self._lock:
            return sum(s.count() for s in self._stores.values())


# =========================================================================== #
# Key Management  —  "applications/SAE" side, serves the ETSI 014 API (scheme_site) #
# =========================================================================== #
class KeyManagement:
    """"APPs" side of the Node (green in the diagram).

    Implements the logic of the three ETSI 014 methods, relying on
    QKDControl (Key Store Peers + Forwarding Module). This is the only
    component the HTTP handler depends on.
    """

    def __init__(self, kme_id, qkd_control, default_size=256):
        self.kme_id = kme_id
        self.qkd = qkd_control
        self.default_size = default_size

    # -- clause 5.2: Get status ---------------------------------------------- #
    def status(self, slave_sae_id):
        peer_url = self.qkd.forwarding.peer_url_for(slave_sae_id)
        return {
            "source_KME_ID": self.kme_id,
            "target_KME_ID": peer_url or self.kme_id,
            "master_SAE_ID": "SAE_A",
            "slave_SAE_ID": slave_sae_id,
            "key_size": self.default_size,
            "stored_key_count": 25000,
            "max_key_count": 100000,
            "max_key_per_request": 128,
            "max_key_size": 1024,
            "min_key_size": 64,
            "max_SAE_ID_count": 0,
        }

    # -- clause 5.3: Get key (master SAE) ------------------------------------ #
    def get_enc_keys(self, slave_sae_id, number, size):
        """Allocates `number` keys in the right peer's Key Store Peer, then
        relays them to the remote KME via the Forwarding Module. Returns the
        list of {key_ID, key} for the local master SAE."""
        peer_key = self.qkd.peer_kme_id_for_sae(slave_sae_id)  # url or None
        store = self.qkd.store_for_peer(peer_key or "__local__")

        keys = []
        for _ in range(number):
            key_id, key_b64 = store.new_key(size)
            keys.append({"key_ID": key_id, "key": key_b64})

        peer_url = self.qkd.forwarding.peer_url_for(slave_sae_id)
        if peer_url:
            # relay to the peer: may raise URLError/OSError/TimeoutError
            self.qkd.forwarding.forward_keys(peer_url, keys)
        return keys

    # -- clause 5.4: Get key with key IDs (slave SAE) ------------------------ #
    def get_dec_keys(self, key_ids):
        """Looks up keys by key_ID in any Key Store Peer.
        Raises KeyError(key_id) if a key cannot be found (=> 400 ETSI)."""
        keys = []
        for item in key_ids:
            kid = item["key_ID"] if isinstance(item, dict) else item
            key_b64 = self.qkd.find_key_anywhere(kid)
            if key_b64 is None:
                raise KeyError(kid)
            keys.append({"key_ID": kid, "key": key_b64})
        return keys

    # -- incoming QKD link ---------------------------------------------------- #
    def ingest_from_peer(self, keys):
        self.qkd.ingest_from_peer(keys)


# =========================================================================== #
# HTTP Handlers  —  translate the REST API to the Key Management layer         #
# =========================================================================== #
class _JSONHandlerMixin:
    """Common JSON serialization helpers, shared by both handlers."""

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
        pass  # silence


class ExternalKMEHandler(_JSONHandlerMixin, BaseHTTPRequestHandler):
    """SAE side (external port, mTLS): only the ETSI 014 API (clauses 5.1-5.4)."""

    key_management = None  # injected before serving (KeyManagement instance)

    def do_GET(self):
        parts = self.path.strip("/").split("/")
        km = self.key_management
        if (len(parts) == 5 and parts[:3] == ["api", "v1", "keys"]
                and parts[4] == "status"):
            self._send_json(200, km.status(parts[3]))
        else:
            self._send_json(404, {"message": "Not found"})

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        km = self.key_management
        body = self._read_body()

        if not (len(parts) == 5 and parts[:3] == ["api", "v1", "keys"]):
            self._send_json(404, {"message": "Not found"})
            return

        sae_id = parts[3]

        # clause 5.3: Get key (master SAE)
        if parts[4] == "enc_keys":
            number = int(body.get("number", 1))
            size = int(body.get("size", km.default_size))
            try:
                keys = km.get_enc_keys(sae_id, number, size)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                self._send_json(503, {
                    "message": f"failed to reach peer KME for {sae_id}: {exc}"})
                return
            self._send_json(200, {"keys": keys})

        # clause 5.4: Get key with key IDs (slave SAE)
        elif parts[4] == "dec_keys":
            key_ids = body.get("key_IDs", [])
            if not key_ids and "key_ID" in body:
                key_ids = [{"key_ID": body["key_ID"]}]
            try:
                keys = km.get_dec_keys(key_ids)
            except KeyError as missing:
                self._send_json(400, {
                    "message": f"key_ID {missing.args[0]} not found"})
                return
            self._send_json(200, {"keys": keys})
        else:
            self._send_json(404, {"message": "Not found"})


class InternalKMEHandler(_JSONHandlerMixin, BaseHTTPRequestHandler):
    """Peer KME side (internal port, plain HTTP): only the internal QKD
    link. Deliberately unauthenticated — out of scope for this request,
    behavior unchanged."""

    key_management = None  # injected before serving (KeyManagement instance)

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        km = self.key_management
        body = self._read_body()

        if len(parts) == 2 and parts == ["internal", "sync_keys"]:
            km.ingest_from_peer(body.get("keys", []))
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"message": "Not found"})


# backward compatibility: old name, used nowhere else but kept in case some
# external code imports KMEHandler directly.
KMEHandler = ExternalKMEHandler


# =========================================================================== #
# Assembling the QKD Node + server(s)                                        #
# =========================================================================== #
def _build_tls_context(tls):
    """Builds the mTLS server SSLContext from a dict
    {cert, key, ca_cert} of file paths. `verify_mode` = CERT_REQUIRED:
    the client (SAE) MUST present a certificate signed by the same CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=tls["cert"], keyfile=tls["key"])
    ctx.load_verify_locations(cafile=tls["ca_cert"])
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def make_server(host, port, store=None, kme_id="KME", peers=None,
                key_management=None, tls=None):
    """Builds the QKD Node's external HTTP server (SAE side).

    Two calling modes:
      - modern: pass `key_management` (a KeyManagement instance);
      - legacy: pass `store` (SharedKeyStore) — used by sae_API.demo().
        In that case the store is wrapped in a minimal QKD Node.

    `tls`: optional dict {cert, key, ca_cert}. If provided, the server
    requires mTLS (CERT_REQUIRED); if None (in-memory demo outside Docker),
    the server stays plain HTTP, as before.
    """
    if key_management is None:
        qkd = QKDControl(peers or {})
        if store is not None:
            # reuse the given store as the sole Key Store Peer
            qkd._stores["__local__"] = store
        key_management = KeyManagement(kme_id, qkd)

    handler = type("BoundExternalKMEHandler", (ExternalKMEHandler,), {
        "key_management": key_management,
    })
    srv = ThreadingHTTPServer((host, port), handler)
    if tls:
        srv.socket = _build_tls_context(tls).wrap_socket(srv.socket, server_side=True)
    return srv


def make_internal_server(host, port, key_management):
    """Builds the internal HTTP server (facing peer KMEs): plain HTTP,
    unchanged, out of scope for this authentication request."""
    handler = type("BoundInternalKMEHandler", (InternalKMEHandler,), {
        "key_management": key_management,
    })
    return ThreadingHTTPServer((host, port), handler)


if __name__ == "__main__":
    host = os.environ.get("KME_HOST", "0.0.0.0")
    port = int(os.environ.get("KME_PORT", "8000"))
    internal_port = int(os.environ.get("KME_INTERNAL_PORT", "8001"))
    kme_id = os.environ.get("KME_ID", "KME")
    peers = json.loads(os.environ.get("KME_PEERS", "{}"))

    tls = None
    if os.environ.get("TLS_SERVER_CERT"):
        tls = {
            "cert": os.environ["TLS_SERVER_CERT"],
            "key": os.environ["TLS_SERVER_KEY"],
            "ca_cert": os.environ["TLS_CA_CERT"],
        }

    qkd_control = QKDControl(peers)
    key_mgmt = KeyManagement(kme_id, qkd_control)

    external_srv = make_server(host, port, kme_id=kme_id, key_management=key_mgmt, tls=tls)
    internal_srv = make_internal_server(host, internal_port, key_mgmt)

    scheme = "https (mTLS)" if tls else "http"
    print(f"QKD Node {kme_id}: {scheme}://{host}:{port} (SAE, ETSI 014) "
          f"+ http://{host}:{internal_port} (KME peers: {peers})")

    threading.Thread(target=internal_srv.serve_forever, daemon=True).start()
    external_srv.serve_forever()
