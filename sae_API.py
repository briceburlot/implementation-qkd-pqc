"""
sae_API.py — SAE (Secure Application Entity), ETSI GS QKD 014 + hybrid QKD/PQC.

  1) SAE_A requests a QKD key from the KME  (ETSI 014 API: enc_keys / dec_keys)
  2) SAE_A <-> SAE_B: establishing a PQC secret (ML-KEM-768, liboqs) and
     notifying the key_ID over the classic channel
  3) final_key = PQC_key ⊕ QKD_key              (crypto_hybrid.combine_keys)
  4) WireGuard tunnel between SAE_A and SAE_B, final_key injected as the
     PresharedKey; traffic is encrypted with ChaCha20-Poly1305 (wireguard.py)

Two levels of use:
  - SAEClient           : raw ETSI 014 calls (get_status / enc / dec).
  - orchestrate_master  : runs the 4 points on the master side.
  - orchestrate_slave   : runs the 4 points on the slave side.

The rendezvous between the two SAEs (PQC public key exchange, ciphertext,
WireGuard public keys, key_ID) goes through a small "classic" channel — out
of scope in the ETSI sense. In Docker it is materialized by a shared volume
(JSON files): simple, dependency-free, and faithful to the protocol's
"Step 2 (out-of-scope)". The PSK itself is NEVER written down: it is
recomputed on both sides.

Authentication:
  - SAE<->KME: classic mTLS (EC P-256, `TLS_CLIENT_CERT/KEY` + `TLS_CA_CERT`).
    No PQC dependency on this side (see `KME.py`).
  - SAE<->SAE (classic channel): every message is signed with ML-DSA-65 by
    the sender and verified by the recipient against its identity
    certificate (see `pqc_cert.py` and `AuthenticatedChannel` below) —
    prevents a third party with access to the shared volume from
    substituting a PQC public key or a ciphertext (MITM).
"""

import json
import os
import ssl
import time
import urllib.request


# =========================================================================== #
# ETSI GS QKD 014 client — classic mTLS (no PQC dependency)                    #
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
        """Master SAE: requests fresh keys. Returns [{key_ID, key}]."""
        body = {"number": number, "size": size}
        return self._post(f"/api/v1/keys/{slave_sae_id}/enc_keys", body)["keys"]

    def get_dec_key(self, master_sae_id, key_ids):
        """Slave SAE: retrieves keys by key_ID."""
        body = {"key_IDs": [{"key_ID": k} for k in key_ids]}
        return self._post(f"/api/v1/keys/{master_sae_id}/dec_keys", body)["keys"]


def build_client_tls_context(client_cert, client_key, ca_cert):
    """mTLS SSLContext on the SAE side: presents its own client certificate
    (identity) and verifies the KME's server certificate against the
    classical CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=ca_cert)
    ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
    return ctx


# =========================================================================== #
# "Out of scope" classic channel (rendezvous via a shared volume)             #
# =========================================================================== #
class ClassicChannel:
    """File-based mailbox for non-secret exchange between SAEs.

    Carries: key_ID, PQC public key, PQC ciphertext, WireGuard public keys,
    endpoints. NONE of this is secret: security relies on the hybrid PSK,
    which is never transmitted.
    """

    def __init__(self, directory):
        self.dir = directory
        os.makedirs(self.dir, exist_ok=True)

    def put(self, name, obj):
        path = os.path.join(self.dir, name + ".json")
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f)
        os.replace(tmp, path)  # atomic write

    def get(self, name, timeout=30.0, poll=0.2):
        path = os.path.join(self.dir, name + ".json")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(path):
                with open(path) as f:
                    return json.load(f)
            time.sleep(poll)
        raise TimeoutError(f"classic channel: '{name}' not received in time")


# =========================================================================== #
# Authenticated classic channel — ML-DSA-65 signature (CRYSTALS-Dilithium)     #
# =========================================================================== #
class AuthenticatedChannel:
    """Wraps `ClassicChannel`: signs each message sent, verifies each
    message received against the expected sender's ML-DSA certificate.

    Closes the classic channel's only weakness (the shared volume offers no
    integrity guarantee): without this, a third party with access to the
    volume could substitute its own PQC public key or its own ciphertext,
    and make each SAE believe it had negotiated the hybrid secret with its
    legitimate peer when it had actually negotiated it with the attacker.
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
        # sanity check: our own certificate must be valid against the CA
        if not pc.verify_certificate(certificate, ca_public_key):
            raise ValueError(f"local ML-DSA certificate ({sae_id}) is invalid "
                              f"against the CA")

    def _peer_certificate(self, peer_sae_id):
        cert_path = os.path.join(self._cert_dir, f"{peer_sae_id.lower()}.cert.json")
        cert = self._pc.load_json(cert_path)
        if cert.get("sae_id") != peer_sae_id:
            raise ValueError(f"certificate {cert_path}: unexpected sae_id")
        if not self._pc.verify_certificate(cert, self._ca_public_key):
            raise ValueError(f"certificate {peer_sae_id} is invalid (CA signature)")
        return cert

    def put_signed(self, name, obj):
        """Signs `obj` with our ML-DSA private key and publishes the envelope."""
        signature = self._pc.sign(self._private_key, self._pc.canonical_bytes(obj))
        envelope = {
            "sae_id": self.sae_id,
            "payload": obj,
            "signature": self._pc.b64_encode(signature),
        }
        self.channel.put(name, envelope)

    def get_verified(self, name, expected_sae_id, timeout=30.0):
        """Retrieves a message, verifies its signature against the
        (CA-certified) certificate of `expected_sae_id`. Raises ValueError
        if the signature is invalid or if the sender is not the expected
        one."""
        envelope = self.channel.get(name, timeout=timeout)
        if envelope.get("sae_id") != expected_sae_id:
            raise ValueError(
                f"classic channel '{name}': sender {envelope.get('sae_id')} "
                f"!= expected {expected_sae_id}")

        peer_cert = self._peer_certificate(expected_sae_id)
        peer_public_key = self._pc.certificate_public_key(peer_cert)
        signature = self._pc.b64_decode(envelope["signature"])
        message = self._pc.canonical_bytes(envelope["payload"])
        if not self._pc.verify(peer_public_key, message, signature):
            raise ValueError(
                f"classic channel '{name}': invalid ML-DSA signature "
                f"(claimed sender {expected_sae_id})")
        return envelope["payload"]


# =========================================================================== #
# Orchestration of the 4 points — MASTER side (SAE_A)                          #
# =========================================================================== #
def orchestrate_master(client, peer_sae_id, channel, *,
                       size_bits=256, wg=None):
    """Runs points 1->4 on the master side. Returns the final key (bytes).

    `channel` must be an `AuthenticatedChannel`: every message exchanged
    with the peer is signed with ML-DSA on send and verified on receipt
    against the certificate of `peer_sae_id`."""
    import crypto_hybrid as ch
    import pqc_cert

    # --- Point 1: QKD key via the KME (master -> enc_keys) --------------------
    enc = client.get_enc_key(peer_sae_id, number=1, size=size_bits)[0]
    key_id, qkd_key_b64 = enc["key_ID"], enc["key"]
    print(f"[1] QKD key obtained  key_ID={key_id}")

    # --- Point 2a: notify the peer of the key_ID (classic channel, signed) ---
    channel.put_signed("key_id", {"key_ID": key_id, "master_SAE_ID": client.sae_id})

    # --- Point 2b: PQC ML-KEM-768 establishment -------------------------------
    #   the master is the initiator: it waits for the slave's public key,
    #   encapsulates, and sends back the ciphertext. Each message is
    #   authenticated with ML-DSA: no third party can substitute its own key.
    peer_msg = channel.get_verified("pqc_pub", peer_sae_id)
    peer_pub = pqc_cert.b64_decode(peer_msg["public_key"])
    ciphertext, pqc_secret = ch.pqc_initiator_encapsulate(peer_pub)
    channel.put_signed("pqc_ct", {"ciphertext": pqc_cert.b64_encode(ciphertext)})
    print(f"[2] PQC secret established ({len(pqc_secret)} bytes, {ch.PQC_KEM_ALG}) "
          f"- peer's public key authenticated with ML-DSA")

    # --- Point 3: final key = HKDF(PQC ⊕ QKD) ---------------------------------
    final_key = ch.combine_keys_from_b64(qkd_key_b64, pqc_secret)
    print(f"[3] hybrid PQC⊕QKD key derived -> PSK {ch.to_wireguard_psk(final_key)}")

    # --- Point 4: WireGuard tunnel, PSK = final key ---------------------------
    if wg:
        _bring_up_tunnel(final_key, channel, peer_sae_id, role="master", **wg)
    return final_key


# =========================================================================== #
# Orchestration of the 4 points — SLAVE side (SAE_B)                           #
# =========================================================================== #
def orchestrate_slave(client, master_sae_id, channel, *, wg=None):
    """Runs points 1->4 on the slave side. Returns the final key (bytes).

    `channel` must be an `AuthenticatedChannel` (see orchestrate_master)."""
    import crypto_hybrid as ch
    import pqc_cert

    # --- Point 2 (responder first): publish the PQC public key ---------------
    responder = ch.PqcResponder()
    channel.put_signed("pqc_pub", {"public_key": pqc_cert.b64_encode(responder.public_key())})

    # --- Point 1: retrieve the key_ID then the QKD key (slave -> dec_keys) ---
    key_msg = channel.get_verified("key_id", master_sae_id)
    key_id = key_msg["key_ID"]
    qkd_key_b64 = client.get_dec_key(master_sae_id, [key_id])[0]["key"]
    print(f"[1] QKD key retrieved key_ID={key_id} (key_ID notification "
          f"authenticated with ML-DSA)")

    # --- Point 2 (continued): decapsulate the master's ciphertext ------------
    ct_msg = channel.get_verified("pqc_ct", master_sae_id)
    ciphertext = pqc_cert.b64_decode(ct_msg["ciphertext"])
    pqc_secret = responder.decapsulate(ciphertext)
    responder.close()
    print(f"[2] PQC secret established ({len(pqc_secret)} bytes, {ch.PQC_KEM_ALG})")

    # --- Point 3: same final key as the master --------------------------------
    final_key = ch.combine_keys_from_b64(qkd_key_b64, pqc_secret)
    print(f"[3] hybrid PQC⊕QKD key derived -> PSK {ch.to_wireguard_psk(final_key)}")

    # --- Point 4: WireGuard tunnel, PSK = final key ---------------------------
    if wg:
        _bring_up_tunnel(final_key, channel, master_sae_id, role="slave", **wg)
    return final_key


# --------------------------------------------------------------------------- #
# Point 4 (detail): bringing up the WireGuard tunnel with the hybrid PSK       #
# --------------------------------------------------------------------------- #
def _bring_up_tunnel(final_key, channel, peer_sae_id, *, role,
                     local_ip, listen_port, peer_endpoint, peer_allowed_ips,
                     iface="wg0"):
    """Generates the local WG keys, exchanges the public keys over the
    authenticated classic channel, then brings up the interface with
    PSK = hybrid key."""
    import crypto_hybrid as ch
    import wireguard as wgmod

    if not wgmod.wg_tools_available():
        print("[4] wireguard-tools not found here: tunnel not brought up "
              "(OK outside Docker). PSK ready to use.")
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
    print(f"[4] WireGuard tunnel '{iface}' up (ChaCha20-Poly1305, "
          f"hybrid QKD+PQC PSK)")
    print(wgmod.show(iface))


# =========================================================================== #
# Local demo (single process, in-memory KME) — points 1->3                    #
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
    sae_a = SAEClient("SAE_A", kme_url)   # master
    sae_b = SAEClient("SAE_B", kme_url)   # slave

    print("== Status ==")
    print(sae_a.get_status("SAE_B"))

    print("\n== SAE_A requests an encryption key ==")
    enc = sae_a.get_enc_key("SAE_B", number=1, size=256)[0]
    key_id, key_a = enc["key_ID"], enc["key"]
    print("key_ID :", key_id)

    print("\n== SAE_B retrieves the key via the key_ID ==")
    key_b = sae_b.get_dec_key("SAE_A", [key_id])[0]["key"]
    print("identical QKD keys:", key_a == key_b)

    # points 2+3 in memory if liboqs is present
    import crypto_hybrid as ch
    if ch.pqc_available():
        resp = ch.PqcResponder()
        pub = resp.public_key()
        ct, ss_a = ch.pqc_initiator_encapsulate(pub)
        ss_b = resp.decapsulate(ct); resp.close()
        fa = ch.combine_keys_from_b64(key_a, ss_a)
        fb = ch.combine_keys_from_b64(key_b, ss_b)
        print("identical hybrid key:", fa == fb, "| PSK =", ch.to_wireguard_psk(fa))
    else:
        print("(liboqs absent: points 2+3 skipped — available in the Docker image)")

    server.shutdown()


# =========================================================================== #
# Container mode                                                               #
# =========================================================================== #
def main():
    """Container mode: talks to the KME at KME_URL, plays the SAE_ROLE role.

    Environment variables:
      KME_URL, SAE_ID, PEER_SAE_ID, SAE_ROLE (master|slave)
      CHANNEL_DIR          classic channel directory (shared volume)
      HYBRID=1             enables points 2->4 (PQC + WireGuard); otherwise ETSI only
      WG_LOCAL_IP, WG_LISTEN_PORT, WG_PEER_ENDPOINT, WG_PEER_ALLOWED_IPS
      KEY_ID / KEY_ID_FILE backward compatibility (plain ETSI mode)

      SAE<->KME authentication (classic mTLS, required as soon as present):
      TLS_CLIENT_CERT, TLS_CLIENT_KEY, TLS_CA_CERT

      SAE<->SAE authentication (ML-DSA-65, hybrid mode only):
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

    # ---- Full hybrid mode (4 points) ---------------------------------------
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
            # keep the process alive to maintain the tunnel
            print("tunnel maintained; Ctrl-C to stop.")
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                pass
        return

    # ---- Plain ETSI mode (backward-compatible) -----------------------------
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
