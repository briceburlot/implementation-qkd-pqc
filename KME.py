"""
KME.py — QKD Node conforme à ETSI GS QKD 014 + structure "scheme_site".

Ce module modélise une QKD Node telle que dessinée dans "scheme_site.png",
à l'intérieur d'un périmètre de sécurité (Trusted Node) :

    ┌─────────────── Security perimeter (Trusted Node) ───────────────┐
    │  APPs (SAE)                                                      │
    │     ▲                                                            │
    │     │ ETSI GS QKD 014 REST API                                  │
    │     ▼                                                            │
    │  KeyManagement  ◄──────────────►  QKDControl                    │
    │     │  ▲                              │  ▲                       │
    │     ▼  │                              ▼  │                       │
    │  ┌───────────────── QKD Key Store Peers ─────────────────┐      │
    │  │ QKDKeyStorePeer(peerA)  QKDKeyStorePeer(peerB) ...     │      │
    │  └───────────────────────────────────────────────────────┘      │
    │                          ▲                                       │
    │                          │                                       │
    │                    ForwardingModule  ──(QKD link)──► autre Node  │
    └─────────────────────────────────────────────────────────────────┘

Correspondance avec le schéma :
  - APPs                -> les SAE clients (externes, via l'API REST)
  - Key Management      -> classe KeyManagement : sert l'API ETSI 014 aux SAE,
                           choisit le bon Key Store Peer, alloue/retrouve les clés
  - QKD Control         -> classe QKDControl : pilote les Key Store Peers et le
                           Forwarding Module (côté "réseau QKD"), pas exposé aux SAE
  - QKD Key Store Peer  -> classe QKDKeyStorePeer : UN store par KME pair
                           (au lieu d'un unique store global comme avant)
  - Forwarding Module   -> classe ForwardingModule : relaie le matériel de clé
                           vers le KME pair sur le lien QKD simulé

Endpoints exposés (inchangés côté SAE — Figure 2 / clauses 5.1-5.4) :
  GET  /api/v1/keys/{slave_SAE_ID}/status
  POST /api/v1/keys/{slave_SAE_ID}/enc_keys    (master SAE -> key + key_ID)
  POST /api/v1/keys/{master_SAE_ID}/dec_keys   (slave  SAE -> key by key_ID)
Endpoint interne (lien QKD, hors API ETSI) :
  POST /internal/sync_keys                      (Forwarding Module du pair)

NB : la couche cryptographique hybride (PQC ⊕ QKD, WireGuard) vit côté SAE
(crypto_hybrid.py + wireguard.py). Le KME reste, comme le veut l'ETSI, un pur
fournisseur de clés symétriques identiques de part et d'autre.
"""

import base64
import json
import os
import threading
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# =========================================================================== #
# QKD Key Store Peer  —  un store de clés par KME pair (scheme_site)           #
# =========================================================================== #
class QKDKeyStorePeer:
    """Store en mémoire du matériel de clé partagé avec UN KME pair donné.

    Sur le schéma, la QKD Node possède plusieurs "QKD Key Store Peer" empilés :
    un par lien QKD / par pair. Chaque store détient les clés QKD réconciliées
    avec ce pair précis. Ici la génération quantique / réconciliation / privacy
    amplification est hors périmètre (ETSI clause 1) : on modélise le résultat,
    à savoir un dictionnaire key_ID -> clé.
    """

    def __init__(self, peer_kme_id):
        self.peer_kme_id = peer_kme_id
        self._keys = {}          # key_ID -> base64 key
        self._lock = threading.Lock()

    def new_key(self, size_bits=256):
        """Alloue une nouvelle clé (générée localement, à répliquer au pair)."""
        key_bytes = os.urandom(size_bits // 8)
        key_b64 = base64.b64encode(key_bytes).decode("ascii")
        key_id = str(uuid.uuid4())
        with self._lock:
            self._keys[key_id] = key_b64
        return key_id, key_b64

    def put_key(self, key_id, key_b64):
        """Enregistre une clé reçue du pair (réplication via lien QKD)."""
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
# Rétro-compatibilité : SharedKeyStore                                         #
# --------------------------------------------------------------------------- #
class SharedKeyStore(QKDKeyStorePeer):
    """Alias historique conservé pour sae_API.demo() (un seul store partagé).

    Se comporte comme un QKDKeyStorePeer sans pair particulier.
    """

    def __init__(self, peer_kme_id="PEER"):
        super().__init__(peer_kme_id)


# =========================================================================== #
# Forwarding Module  —  relais du matériel de clé sur le lien QKD (scheme_site)#
# =========================================================================== #
class ForwardingModule:
    """Pousse le matériel de clé vers le KME pair hébergeant le SAE esclave.

    Modélise le "Forwarding Module" du schéma : c'est lui qui parle au réseau
    QKD (ici, l'endpoint interne /internal/sync_keys du KME pair). Le routage
    slave_SAE_ID -> URL du KME pair vient de la table KME_PEERS.
    """

    def __init__(self, peers):
        # peers : {slave_SAE_ID: peer_KME_base_url}
        self.peers = peers or {}

    def peer_url_for(self, sae_id):
        return self.peers.get(sae_id)

    def forward_keys(self, peer_url, keys):
        """Réplique `keys` (liste de {key_ID, key}) vers le KME pair."""
        data = json.dumps({"keys": keys}).encode("utf-8")
        req = urllib.request.Request(
            peer_url.rstrip("/") + "/internal/sync_keys",
            data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()


# =========================================================================== #
# QKD Control  —  pilote les Key Store Peers et le Forwarding Module           #
# =========================================================================== #
class QKDControl:
    """Face "réseau QKD" de la Node (bleu sur le schéma).

    Gère l'ensemble des QKDKeyStorePeer (création à la volée par pair) et
    délègue le relais au ForwardingModule. N'est PAS exposé directement aux SAE.
    """

    def __init__(self, peers):
        self.forwarding = ForwardingModule(peers)
        self._stores = {}                 # peer_KME_id -> QKDKeyStorePeer
        self._lock = threading.Lock()

    def store_for_peer(self, peer_kme_id):
        """Retourne (en le créant au besoin) le Key Store Peer d'un pair."""
        with self._lock:
            store = self._stores.get(peer_kme_id)
            if store is None:
                store = QKDKeyStorePeer(peer_kme_id)
                self._stores[peer_kme_id] = store
            return store

    def peer_kme_id_for_sae(self, sae_id):
        """Déduit un identifiant de pair à partir de l'URL de routage.

        (Le mapping fin SAE->KME_ID est hors périmètre ETSI ; on dérive un id
        stable depuis l'URL du pair pour indexer le bon store.)
        """
        url = self.forwarding.peer_url_for(sae_id)
        return url  # l'URL fait office de clé de pair, unique par KME distant

    def find_key_anywhere(self, key_id):
        """Cherche une clé par key_ID dans tous les Key Store Peers.

        Utilisé par dec_keys : le SAE esclave demande une clé par son key_ID
        sans savoir dans quel store-pair elle a atterri.
        """
        with self._lock:
            stores = list(self._stores.values())
        for store in stores:
            k = store.get_key(key_id)
            if k is not None:
                return k
        return None

    def ingest_from_peer(self, keys):
        """Range des clés reçues d'un pair (via Forwarding Module distant).

        On ne connaît pas forcément le pair émetteur ici ; on les place dans un
        store dédié "inbound" pour qu'elles soient retrouvables par key_ID.
        """
        store = self.store_for_peer("__inbound__")
        for item in keys:
            store.put_key(item["key_ID"], item["key"])

    def total_stored(self):
        with self._lock:
            return sum(s.count() for s in self._stores.values())


# =========================================================================== #
# Key Management  —  face "applications/SAE", sert l'API ETSI 014 (scheme_site)#
# =========================================================================== #
class KeyManagement:
    """Face "APPs" de la Node (vert sur le schéma).

    Implémente la logique des trois méthodes ETSI 014 en s'appuyant sur le
    QKDControl (Key Store Peers + Forwarding Module). C'est le seul composant
    dont dépend le handler HTTP.
    """

    def __init__(self, kme_id, qkd_control, default_size=256):
        self.kme_id = kme_id
        self.qkd = qkd_control
        self.default_size = default_size

    # -- clause 5.2 : Get status -------------------------------------------- #
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

    # -- clause 5.3 : Get key (master SAE) ---------------------------------- #
    def get_enc_keys(self, slave_sae_id, number, size):
        """Alloue `number` clés dans le Key Store Peer du bon pair, puis les
        relaie au KME distant via le Forwarding Module. Retourne la liste
        de {key_ID, key} pour le SAE maître local."""
        peer_key = self.qkd.peer_kme_id_for_sae(slave_sae_id)  # url ou None
        store = self.qkd.store_for_peer(peer_key or "__local__")

        keys = []
        for _ in range(number):
            key_id, key_b64 = store.new_key(size)
            keys.append({"key_ID": key_id, "key": key_b64})

        peer_url = self.qkd.forwarding.peer_url_for(slave_sae_id)
        if peer_url:
            # relais vers le pair : peut lever URLError/OSError/TimeoutError
            self.qkd.forwarding.forward_keys(peer_url, keys)
        return keys

    # -- clause 5.4 : Get key with key IDs (slave SAE) ---------------------- #
    def get_dec_keys(self, key_ids):
        """Retrouve les clés par key_ID dans n'importe quel Key Store Peer.
        Lève KeyError(key_id) si une clé est introuvable (=> 400 ETSI)."""
        keys = []
        for item in key_ids:
            kid = item["key_ID"] if isinstance(item, dict) else item
            key_b64 = self.qkd.find_key_anywhere(kid)
            if key_b64 is None:
                raise KeyError(kid)
            keys.append({"key_ID": kid, "key": key_b64})
        return keys

    # -- lien QKD entrant --------------------------------------------------- #
    def ingest_from_peer(self, keys):
        self.qkd.ingest_from_peer(keys)


# =========================================================================== #
# Handler HTTP  —  traduit l'API REST vers le Key Management                   #
# =========================================================================== #
class KMEHandler(BaseHTTPRequestHandler):
    key_management = None  # injecté avant de servir (instance KeyManagement)

    # -- helpers ------------------------------------------------------------ #
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

    # -- routing ------------------------------------------------------------ #
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

        # lien QKD entrant : le Forwarding Module d'un pair pousse des clés
        if len(parts) == 2 and parts == ["internal", "sync_keys"]:
            km.ingest_from_peer(body.get("keys", []))
            self._send_json(200, {"status": "ok"})
            return

        if not (len(parts) == 5 and parts[:3] == ["api", "v1", "keys"]):
            self._send_json(404, {"message": "Not found"})
            return

        sae_id = parts[3]

        # clause 5.3 : Get key (master SAE)
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

        # clause 5.4 : Get key with key IDs (slave SAE)
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


# =========================================================================== #
# Assemblage de la QKD Node + serveur                                          #
# =========================================================================== #
def make_server(host, port, store=None, kme_id="KME", peers=None,
                key_management=None):
    """Construit le serveur HTTP de la QKD Node.

    Deux modes d'appel :
      - moderne : passer `key_management` (instance KeyManagement) ;
      - hérité  : passer `store` (SharedKeyStore) — utilisé par sae_API.demo().
        Dans ce cas on enveloppe le store dans une QKD Node minimale.
    """
    if key_management is None:
        qkd = QKDControl(peers or {})
        if store is not None:
            # réutilise le store fourni comme unique Key Store Peer
            qkd._stores["__local__"] = store
        key_management = KeyManagement(kme_id, qkd)

    handler = type("BoundKMEHandler", (KMEHandler,), {
        "key_management": key_management,
    })
    return ThreadingHTTPServer((host, port), handler)


if __name__ == "__main__":
    host = os.environ.get("KME_HOST", "0.0.0.0")
    port = int(os.environ.get("KME_PORT", "8000"))
    kme_id = os.environ.get("KME_ID", "KME")
    peers = json.loads(os.environ.get("KME_PEERS", "{}"))

    qkd_control = QKDControl(peers)
    key_mgmt = KeyManagement(kme_id, qkd_control)
    srv = make_server(host, port, kme_id=kme_id, key_management=key_mgmt)
    print(f"QKD Node {kme_id} serving on http://{host}:{port} (peers: {peers})")
    srv.serve_forever()
