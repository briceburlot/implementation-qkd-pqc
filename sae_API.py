"""
SAE (Secure Application Entity) client — ETSI GS QKD 014.
Programme client a mettre en conteneur

Peut demander des clés au KME et les transmettre a un autre SAE

Fonctions principales de la SAE :
    - get_status
    - get_key : master SAE  -> (key_ID, key)
    - get_key_by_id : slave  SAE  -> key   (given a key_ID)

Ce programme ajoute un systeme de suivi pour demo :
    SAE_A --REST/get--> KME  ==(key_ID travels over classic channel)==>  SAE_B
    SAE_A obtains (key, key_ID); SAE_B retrieves the SAME key using key_ID.
"""

import json
import urllib.request


class SAEClient:
    def __init__(self, sae_id, kme_base_url):
        self.sae_id = sae_id
        self.base = kme_base_url.rstrip("/")

    # -- low-level HTTP -----------------------------------------------------
    def _get(self, path):
        req = urllib.request.Request(self.base + path, method="GET")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    def _post(self, path, payload):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base + path, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    # -- ETSI 014 operations ------------------------------------------------
    def get_status(self, slave_sae_id):
        return self._get(f"/api/v1/keys/{slave_sae_id}/status")

    def get_enc_key(self, slave_sae_id, number=1, size=256):
        """Master SAE: request fresh key(s). Returns list of {key_ID, key}."""
        body = {"number": number, "size": size}
        return self._post(f"/api/v1/keys/{slave_sae_id}/enc_keys", body)["keys"]

    def get_dec_key(self, master_sae_id, key_ids):
        """Slave SAE: retrieve key(s) by key_ID(s)."""
        body = {"key_IDs": [{"key_ID": k} for k in key_ids]}
        return self._post(f"/api/v1/keys/{master_sae_id}/dec_keys", body)["keys"]


def demo():
    import threading
    import time
    from kme_server import SharedKeyStore, make_server

    # Single shared key store => simulates the QKD-linked pair KME_A / KME_B
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
    print("key(A) :", key_a)

    # --- key_ID is transmitted A -> B over the ordinary (classic) channel ---
    print("\n== SAE_B retrieves the key using only the key_ID ==")
    key_b = sae_b.get_dec_key("SAE_A", [key_id])[0]["key"]
    print("key(B) :", key_b)

    print("\n== Keys match:", key_a == key_b, "==")
    server.shutdown()


if __name__ == "__main__":
    demo()
