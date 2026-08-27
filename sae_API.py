"""
sae_API.py — SAE (Secure Application Entity), ETSI GS QKD 014 + hybride QKD/PQC.

Client SAE qui orchestre les 4 points du schéma "img_scheme" :

  1) SAE_A demande une clé QKD au KME  (API ETSI 014 : enc_keys / dec_keys)
  2) SAE_A ↔ SAE_B : établissement d'un secret PQC (ML-KEM-768, liboqs) et
     notification du key_ID sur le canal classique
  3) clé_finale = clé_PQC ⊕ clé_QKD              (crypto_hybrid.combine_keys)
  4) tunnel WireGuard entre SAE_A et SAE_B, clé_finale injectée comme
     PresharedKey ; le trafic est chiffré en ChaCha20-Poly1305 (wireguard.py)

Deux niveaux d'utilisation :
  - SAEClient           : appels ETSI 014 bruts (get_status / enc / dec).
  - orchestrate_master  : déroule les 4 points côté maître.
  - orchestrate_slave   : déroule les 4 points côté esclave.

Le rendez-vous entre les deux SAE (échange clé publique PQC, ciphertext,
clés publiques WireGuard, key_ID) passe par un petit canal "classique" — hors
périmètre au sens ETSI. En Docker on le matérialise par un volume partagé
(fichiers JSON) : simple, sans dépendance, et fidèle au "Step 2 (out-of-scope)"
du protocole. Le PSK, lui, n'est JAMAIS écrit : il est recalculé des deux côtés.

Authentification :
  - SAE<->KME : mTLS classique (EC P-256, `TLS_CLIENT_CERT/KEY` + `TLS_CA_CERT`).
    Aucune dépendance PQC de ce côté (voir `KME.py`).
  - SAE<->SAE (canal classique) : chaque message est signé ML-DSA-65 par
    l'émetteur et vérifié par le destinataire contre son certificat d'identité
    (voir `pqc_cert.py` et `AuthenticatedChannel` ci-dessous) — empêche un
    tiers ayant accès au volume partagé de substituer une clé publique PQC ou
    un ciphertext (MITM).
"""

import json
import os
import ssl
import time
import urllib.request


# =========================================================================== #
# Client ETSI GS QKD 014 — mTLS classique (aucune dépendance PQC)              #
# =========================================================================== #
class SAEClient:
    def __init__(self, sae_id, kme_base_url, ssl_context=None):
        self.sae_id = sae_id
        self.base = kme_base_url.rstrip("/")
        self._opener = None
        if ssl_context is not None:
            self._opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl_context)
            )

    def _urlopen(self, req):
        if self._opener is not None:
            return self._opener.open(req)
        return urllib.request.urlopen(req)

    def _get(self, path):
        req = urllib.request.Request(self.base + path, method="GET")
        with self._urlopen(req) as resp:
            return json.loads(resp.read())

    def _post(self, path, payload):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base + path, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self._urlopen(req) as resp:
            return json.loads(resp.read())


    def get_status(self, slave_sae_id):
        return self._get(f"/api/v1/keys/{slave_sae_id}/status")

    def get_enc_key(self, slave_sae_id, number=1, size=256):
        """Master SAE : demande des clés fraîches. Retourne [{key_ID, key}]."""
        body = {"number": number, "size": size}
        return self._post(f"/api/v1/keys/{slave_sae_id}/enc_keys", body)["keys"]

    def get_dec_key(self, master_sae_id, key_ids):
        """Slave SAE : récupère des clés par key_ID."""
        body = {"key_IDs": [{"key_ID": k} for k in key_ids]}
        return self._post(f"/api/v1/keys/{master_sae_id}/dec_keys", body)["keys"]


def build_client_tls_context(client_cert, client_key, ca_cert):
    """SSLContext mTLS côté SAE : présente son certificat client (identité)
    et vérifie le certificat serveur du KME contre la CA classique."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=ca_cert)
    ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
    return ctx


# =========================================================================== #
# Canal classique "hors périmètre" (rendez-vous via volume partagé)           #
# =========================================================================== #
class ClassicChannel:
    """Boîte aux lettres fichier pour l'échange non secret entre SAE.

    Transporte : key_ID, clé publique PQC, ciphertext PQC, clés publiques
    WireGuard, endpoints. RIEN de tout cela n'est secret : la sécurité repose
    sur le PSK hybride, jamais transmis.
    """

    def __init__(self, directory):
        self.dir = directory
        os.makedirs(self.dir, exist_ok=True)

    def put(self, name, obj):
        path = os.path.join(self.dir, name + ".json")
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f)
        os.replace(tmp, path)  # écriture atomique

    def get(self, name, timeout=30.0, poll=0.2):
        path = os.path.join(self.dir, name + ".json")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(path):
                with open(path) as f:
                    return json.load(f)
            time.sleep(poll)
        raise TimeoutError(f"canal classique : '{name}' non reçu à temps")


# =========================================================================== #
# Canal classique authentifié — signature ML-DSA-65 (CRYSTALS-Dilithium)      #
# =========================================================================== #
class AuthenticatedChannel:
    """Enrobe `ClassicChannel` : signe chaque message envoyé, vérifie chaque
    message reçu contre le certificat ML-DSA de l'émetteur attendu.

    Ferme la seule faille du canal classique (le volume partagé n'offre
    aucune garantie d'intégrité) : sans ça, un tiers ayant accès au volume
    pourrait substituer sa propre clé publique PQC ou son propre ciphertext,
    et faire croire à chaque SAE qu'il a négocié le secret hybride avec son
    pair légitime alors qu'il l'a négocié avec l'attaquant.
    """

    def __init__(self, channel, sae_id, *, private_key, certificate,
                 cert_dir, ca_public_key):
        self.channel = channel
        self.sae_id = sae_id
        self._private_key = private_key
        self._certificate = certificate
        self._cert_dir = cert_dir
        self._ca_public_key = ca_public_key

        import pqc_cert as pc
        self._pc = pc
        # sanity : notre propre certificat doit être valide vis-à-vis de la CA
        if not pc.verify_certificate(certificate, ca_public_key):
            raise ValueError(f"certificat ML-DSA local ({sae_id}) invalide "
                              f"vis-à-vis de la CA")

    def _peer_certificate(self, peer_sae_id):
        cert_path = os.path.join(self._cert_dir, f"{peer_sae_id.lower()}.cert.json")
        cert = self._pc.load_json(cert_path)
        if cert.get("sae_id") != peer_sae_id:
            raise ValueError(f"certificat {cert_path} : sae_id inattendu")
        if not self._pc.verify_certificate(cert, self._ca_public_key):
            raise ValueError(f"certificat {peer_sae_id} invalide (signature CA)")
        return cert

    def put_signed(self, name, obj):
        """Signe `obj` avec notre clé privée ML-DSA et publie l'enveloppe."""
        signature = self._pc.sign(self._private_key, self._pc.canonical_bytes(obj))
        envelope = {
            "sae_id": self.sae_id,
            "payload": obj,
            "signature": self._pc.b64_encode(signature),
        }
        self.channel.put(name, envelope)

    def get_verified(self, name, expected_sae_id, timeout=30.0):
        """Récupère un message, vérifie sa signature contre le certificat
        (certifié par la CA) de `expected_sae_id`. Lève ValueError si la
        signature est invalide ou si l'émetteur n'est pas celui attendu."""
        envelope = self.channel.get(name, timeout=timeout)
        if envelope.get("sae_id") != expected_sae_id:
            raise ValueError(
                f"canal classique '{name}' : émetteur {envelope.get('sae_id')} "
                f"!= attendu {expected_sae_id}")

        peer_cert = self._peer_certificate(expected_sae_id)
        peer_public_key = self._pc.certificate_public_key(peer_cert)
        signature = self._pc.b64_decode(envelope["signature"])
        message = self._pc.canonical_bytes(envelope["payload"])
        if not self._pc.verify(peer_public_key, message, signature):
            raise ValueError(
                f"canal classique '{name}' : signature ML-DSA invalide "
                f"(émetteur prétendu {expected_sae_id})")
        return envelope["payload"]


# =========================================================================== #
# Orchestration des 4 points — côté MAÎTRE (SAE_A)                             #
# =========================================================================== #
def orchestrate_master(client, peer_sae_id, channel, *,
                       size_bits=256, wg=None):
    """Déroule points 1→4 côté maître. Retourne la clé finale (bytes).

    `channel` doit être un `AuthenticatedChannel` : chaque message échangé
    avec le pair est signé ML-DSA à l'envoi et vérifié à la réception contre
    le certificat de `peer_sae_id`."""
    import crypto_hybrid as ch
    import pqc_cert

    # --- Point 1 : clé QKD via le KME (master -> enc_keys) -------------------
    enc = client.get_enc_key(peer_sae_id, number=1, size=size_bits)[0]
    key_id, qkd_key_b64 = enc["key_ID"], enc["key"]
    print(f"[1] clé QKD obtenue  key_ID={key_id}")

    # --- Point 2a : notifier le key_ID au pair (canal classique, signé) -----
    channel.put_signed("key_id", {"key_ID": key_id, "master_SAE_ID": client.sae_id})

    # --- Point 2b : établissement PQC ML-KEM-768 ----------------------------
    #   le maître est l'initiateur : il attend la clé publique de l'esclave,
    #   encapsule, et renvoie le ciphertext. Chaque message est authentifié
    #   ML-DSA : impossible pour un tiers de substituer sa propre clé.
    peer_msg = channel.get_verified("pqc_pub", peer_sae_id)
    peer_pub = pqc_cert.b64_decode(peer_msg["public_key"])
    ciphertext, pqc_secret = ch.pqc_initiator_encapsulate(peer_pub)
    channel.put_signed("pqc_ct", {"ciphertext": pqc_cert.b64_encode(ciphertext)})
    print(f"[2] secret PQC établi ({len(pqc_secret)} octets, {ch.PQC_KEM_ALG}) "
          f"- clé publique du pair authentifiée ML-DSA")

    # --- Point 3 : clé finale = HKDF(PQC ⊕ QKD) -----------------------------
    final_key = ch.combine_keys_from_b64(qkd_key_b64, pqc_secret)
    print(f"[3] clé hybride PQC⊕QKD dérivée -> PSK {ch.to_wireguard_psk(final_key)}")

    # --- Point 4 : tunnel WireGuard, PSK = clé finale -----------------------
    if wg:
        _bring_up_tunnel(final_key, channel, peer_sae_id, role="master", **wg)
    return final_key


# =========================================================================== #
# Orchestration des 4 points — côté ESCLAVE (SAE_B)                            #
# =========================================================================== #
def orchestrate_slave(client, master_sae_id, channel, *, wg=None):
    """Déroule points 1→4 côté esclave. Retourne la clé finale (bytes).

    `channel` doit être un `AuthenticatedChannel` (voir orchestrate_master)."""
    import crypto_hybrid as ch
    import pqc_cert

    # --- Point 2 (responder d'abord) : publier la clé publique PQC ----------
    responder = ch.PqcResponder()
    channel.put_signed("pqc_pub", {"public_key": pqc_cert.b64_encode(responder.public_key())})

    # --- Point 1 : récupérer le key_ID puis la clé QKD (slave -> dec_keys) --
    key_msg = channel.get_verified("key_id", master_sae_id)
    key_id = key_msg["key_ID"]
    qkd_key_b64 = client.get_dec_key(master_sae_id, [key_id])[0]["key"]
    print(f"[1] clé QKD récupérée key_ID={key_id} (notification key_ID "
          f"authentifiée ML-DSA)")

    # --- Point 2 (suite) : décapsuler le ciphertext du maître ---------------
    ct_msg = channel.get_verified("pqc_ct", master_sae_id)
    ciphertext = pqc_cert.b64_decode(ct_msg["ciphertext"])
    pqc_secret = responder.decapsulate(ciphertext)
    responder.close()
    print(f"[2] secret PQC établi ({len(pqc_secret)} octets, {ch.PQC_KEM_ALG})")

    # --- Point 3 : même clé finale que le maître ----------------------------
    final_key = ch.combine_keys_from_b64(qkd_key_b64, pqc_secret)
    print(f"[3] clé hybride PQC⊕QKD dérivée -> PSK {ch.to_wireguard_psk(final_key)}")

    # --- Point 4 : tunnel WireGuard, PSK = clé finale -----------------------
    if wg:
        _bring_up_tunnel(final_key, channel, master_sae_id, role="slave", **wg)
    return final_key


# --------------------------------------------------------------------------- #
# Point 4 (détail) : montage du tunnel WireGuard avec le PSK hybride           #
# --------------------------------------------------------------------------- #
def _bring_up_tunnel(final_key, channel, peer_sae_id, *, role,
                     local_ip, listen_port, peer_endpoint, peer_allowed_ips,
                     iface="wg0"):
    """Génère les clés WG locales, échange les clés publiques via le canal
    classique authentifié, puis monte l'interface avec le PSK = clé hybride."""
    import crypto_hybrid as ch
    import wireguard as wgmod

    if not wgmod.wg_tools_available():
        print("[4] wireguard-tools absents ici : tunnel non monté "
              "(OK hors Docker). PSK prêt à l'emploi.")
        return

    priv, pub = wgmod.generate_keypair()
    channel.put_signed(f"wg_pub_{role}", {"public_key": pub})
    other = "slave" if role == "master" else "master"
    peer_pub = channel.get_verified(f"wg_pub_{other}", peer_sae_id)["public_key"]

    psk = ch.to_wireguard_psk(final_key)
    wgmod.bring_up(
        iface=iface,
        private_key=priv,
        local_ip=local_ip,
        listen_port=listen_port,
        peer_public_key=peer_pub,
        peer_psk=psk,
        peer_endpoint=peer_endpoint,
        peer_allowed_ips=peer_allowed_ips,
    )
    print(f"[4] tunnel WireGuard '{iface}' actif (ChaCha20-Poly1305, "
          f"PSK hybride QKD+PQC)")
    print(wgmod.show(iface))


# =========================================================================== #
# Démo locale (un seul process, un KME en mémoire) — points 1→3               #
# =========================================================================== #
def demo():
    import threading
    from KME import SharedKeyStore, make_server

    shared = SharedKeyStore()
    server = make_server("127.0.0.1", 8000, shared)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)

    kme_url = "http://127.0.0.1:8000"
    sae_a = SAEClient("SAE_A", kme_url)   # maître
    sae_b = SAEClient("SAE_B", kme_url)   # esclave

    print("== Status ==")
    print(sae_a.get_status("SAE_B"))

    print("\n== SAE_A demande une clé de chiffrement ==")
    enc = sae_a.get_enc_key("SAE_B", number=1, size=256)[0]
    key_id, key_a = enc["key_ID"], enc["key"]
    print("key_ID :", key_id)

    print("\n== SAE_B récupère la clé via le key_ID ==")
    key_b = sae_b.get_dec_key("SAE_A", [key_id])[0]["key"]
    print("clés QKD identiques :", key_a == key_b)

    # points 2+3 en mémoire si liboqs présent
    import crypto_hybrid as ch
    if ch.pqc_available():
        resp = ch.PqcResponder()
        pub = resp.public_key()
        ct, ss_a = ch.pqc_initiator_encapsulate(pub)
        ss_b = resp.decapsulate(ct); resp.close()
        fa = ch.combine_keys_from_b64(key_a, ss_a)
        fb = ch.combine_keys_from_b64(key_b, ss_b)
        print("clé hybride identique :", fa == fb, "| PSK =", ch.to_wireguard_psk(fa))
    else:
        print("(liboqs absent : points 2+3 sautés — dispo dans l'image Docker)")

    server.shutdown()


# =========================================================================== #
# Mode conteneur                                                               #
# =========================================================================== #
def main():
    """Mode conteneur : parle au KME de KME_URL, joue le rôle SAE_ROLE.

    Variables d'environnement :
      KME_URL, SAE_ID, PEER_SAE_ID, SAE_ROLE (master|slave)
      CHANNEL_DIR          répertoire du canal classique (volume partagé)
      HYBRID=1             active points 2→4 (PQC + WireGuard) ; sinon ETSI seul
      WG_LOCAL_IP, WG_LISTEN_PORT, WG_PEER_ENDPOINT, WG_PEER_ALLOWED_IPS
      KEY_ID / KEY_ID_FILE rétro-compat (mode ETSI simple)

      Authentification SAE<->KME (mTLS classique, requis dès que présent) :
      TLS_CLIENT_CERT, TLS_CLIENT_KEY, TLS_CA_CERT

      Authentification SAE<->SAE (ML-DSA-65, mode hybride uniquement) :
      PQC_PRIV_KEY, PQC_CERT, PQC_CERT_DIR, PQC_CA_PUB
    """
    kme_url = os.environ["KME_URL"]
    sae_id = os.environ.get("SAE_ID", "SAE_A")
    peer_sae_id = os.environ.get("PEER_SAE_ID", "SAE_B")
    role = os.environ.get("SAE_ROLE", "master")
    hybrid = os.environ.get("HYBRID", "0") == "1"

    ssl_context = None
    if os.environ.get("TLS_CLIENT_CERT"):
        ssl_context = build_client_tls_context(
            os.environ["TLS_CLIENT_CERT"],
            os.environ["TLS_CLIENT_KEY"],
            os.environ["TLS_CA_CERT"],
        )
        if kme_url.startswith("http://"):
            kme_url = "https://" + kme_url[len("http://"):]

    client = SAEClient(sae_id, kme_url, ssl_context=ssl_context)
    print(f"== {sae_id} ({role}) status vs {peer_sae_id} ==")
    print(client.get_status(peer_sae_id))

    # ---- Mode hybride complet (4 points) -----------------------------------
    if hybrid:
        import pqc_cert

        raw_channel = ClassicChannel(os.environ.get("CHANNEL_DIR", "/shared/chan"))
        channel = AuthenticatedChannel(
            raw_channel, sae_id,
            private_key=pqc_cert.load_bytes(os.environ["PQC_PRIV_KEY"]),
            certificate=pqc_cert.load_json(os.environ["PQC_CERT"]),
            cert_dir=os.environ["PQC_CERT_DIR"],
            ca_public_key=pqc_cert.load_bytes(os.environ["PQC_CA_PUB"]),
        )
        wg = None
        if os.environ.get("WG_LOCAL_IP"):
            wg = {
                "local_ip": os.environ["WG_LOCAL_IP"],
                "listen_port": int(os.environ.get("WG_LISTEN_PORT", "51820")),
                "peer_endpoint": os.environ.get("WG_PEER_ENDPOINT") or None,
                "peer_allowed_ips": os.environ["WG_PEER_ALLOWED_IPS"],
            }
        if role == "master":
            orchestrate_master(client, peer_sae_id, channel, wg=wg)
        else:
            orchestrate_slave(client, peer_sae_id, channel, wg=wg)
        if wg:
            # garder le process vivant pour maintenir le tunnel
            print("tunnel maintenu ; Ctrl-C pour arrêter.")
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                pass
        return

    # ---- Mode ETSI simple (rétro-compatible) -------------------------------
    key_id_file = os.environ.get("KEY_ID_FILE")
    if role == "master":
        enc = client.get_enc_key(peer_sae_id, number=1, size=256)[0]
        print("key_ID :", enc["key_ID"])
        print("key    :", enc["key"])
        if key_id_file:
            with open(key_id_file, "w") as f:
                f.write(enc["key_ID"])
    else:
        key_id = os.environ.get("KEY_ID")
        if not key_id and key_id_file:
            with open(key_id_file) as f:
                key_id = f.read().strip()
        key = client.get_dec_key(peer_sae_id, [key_id])[0]["key"]
        print("key_ID :", key_id)
        print("key    :", key)


if __name__ == "__main__":
    if "KME_URL" in os.environ:
        main()
    else:
        demo()
