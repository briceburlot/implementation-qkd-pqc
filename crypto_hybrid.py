"""
crypto_hybrid.py — Couche cryptographique hybride QKD + PQC.

Implémente les points 2 et 3 du schéma "img_scheme" :

  Point 2 : établissement d'un secret partagé par cryptographie post-quantique
            (PQC) entre SAE_A et SAE_B, via la librairie Open Quantum Safe
            (liboqs) avec le KEM standard NIST ML-KEM-768 (ex-Kyber768).

  Point 3 : combinaison XOR des deux secrets ->  clé_finale = clé_PQC ⊕ clé_QKD

Modèle de sécurité (schéma hybride) :
    Le secret combiné reste sûr tant qu'AU MOINS un des deux canaux tient.
    - la clé QKD protège contre un adversaire qui casserait ML-KEM ;
    - la clé PQC protège si le lien QKD (ou son store) est compromis.
    C'est le principe recommandé pour marier QKD et PQC.

Le secret combiné n'est PAS utilisé directement comme clé de chiffrement : il
sert de PresharedKey (PSK) WireGuard (voir wireguard.py, point 4). On le passe
donc par un HKDF pour obtenir exactement 32 octets, quelle que soit la taille
de la clé QKD demandée au KME.

Ce module n'a aucune dépendance réseau : il est volontairement "pur" et testable
indépendamment du transport HTTP (KME) et du tunnel (WireGuard).
"""

import base64
import hashlib
import hmac

# Nom du mécanisme KEM tel qu'exposé par liboqs (oqs.get_enabled_kem_mechanisms()).
PQC_KEM_ALG = "ML-KEM-768"

# Taille de la clé finale (octets) : 32 = clé ChaCha20 / PresharedKey WireGuard.
FINAL_KEY_LEN = 32


# --------------------------------------------------------------------------- #
# Import liboqs (Open Quantum Safe)                                            #
# --------------------------------------------------------------------------- #
def _import_oqs():
    """Importe le wrapper Python de liboqs, avec un message d'erreur explicite.

    Le paquet PyPI est `liboqs-python` mais s'importe sous le nom `oqs`.
    """
    try:
        import oqs  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "La librairie Open Quantum Safe (module 'oqs', paquet "
            "'liboqs-python') est introuvable. Elle est installée dans les "
            "images Docker de ce projet ; hors Docker : voir "
            "https://github.com/open-quantum-safe/liboqs-python"
        ) from exc
    return oqs


def pqc_available():
    """True si liboqs est importable et expose bien ML-KEM-768."""
    try:
        oqs = _import_oqs()
        return PQC_KEM_ALG in oqs.get_enabled_kem_mechanisms()
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Point 2 — établissement de clé PQC (ML-KEM-768)                              #
# --------------------------------------------------------------------------- #
#
# Le KEM ML-KEM se déroule en trois temps (rôles Diffie-Hellman-like) :
#
#   Responder (ici SAE_B / slave) :   (public_key, secret_key) = keygen()
#                                      -- envoie public_key -->
#   Initiator (ici SAE_A / master) :  (ciphertext, ss) = encaps(public_key)
#                                      <-- envoie ciphertext --
#   Responder :                        ss = decaps(ciphertext)
#
# Les deux parties obtiennent le MÊME secret `ss` (32 octets pour ML-KEM-768)
# sans jamais le transmettre en clair : c'est la sécurité MLWE de ML-KEM.


class PqcResponder:
    """Côté qui génère la paire de clés et déchiffre (décapsule).

    Dans notre orchestration c'est le SAE esclave (SAE_B) : il publie sa clé
    publique, reçoit le ciphertext du maître, et récupère le secret partagé.

    L'objet conserve la clé secrète en interne (état de liboqs) entre keygen()
    et decapsulate() : il faut donc garder la même instance vivante.
    """

    def __init__(self, alg=PQC_KEM_ALG):
        oqs = _import_oqs()
        self._kem = oqs.KeyEncapsulation(alg)

    def public_key(self):
        """Génère la paire et retourne la clé publique (bytes) à publier."""
        return self._kem.generate_keypair()

    def decapsulate(self, ciphertext):
        """Récupère le secret partagé PQC à partir du ciphertext reçu."""
        return bytes(self._kem.decap_secret(ciphertext))

    def close(self):
        # liboqs libère le matériel secret ; supporte le context manager.
        try:
            self._kem.free()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def pqc_initiator_encapsulate(peer_public_key, alg=PQC_KEM_ALG):
    """Côté initiateur (SAE maître) : encapsule sous la clé publique du pair.

    Retourne (ciphertext, shared_secret). Le ciphertext est envoyé au
    responder ; shared_secret est identique de part et d'autre.
    """
    oqs = _import_oqs()
    with oqs.KeyEncapsulation(alg) as kem:
        ciphertext, shared_secret = kem.encap_secret(peer_public_key)
    return bytes(ciphertext), bytes(shared_secret)


# --------------------------------------------------------------------------- #
# Point 3 — combinaison XOR + dérivation vers la clé finale                    #
# --------------------------------------------------------------------------- #
def xor_bytes(a, b):
    """XOR octet-à-octet. Les deux entrées doivent avoir la même longueur."""
    if len(a) != len(b):
        raise ValueError(
            f"XOR : longueurs différentes ({len(a)} vs {len(b)} octets)"
        )
    return bytes(x ^ y for x, y in zip(a, b))


def _hkdf_sha256(ikm, length, salt=b"", info=b""):
    """HKDF (RFC 5869) sur SHA-256 — sans dépendance externe.

    Sert à ramener le secret combiné à exactement `length` octets, en le
    mélangeant de façon irréversible (extract + expand).
    """
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()  # extract
    okm, t, counter = b"", b"", 1  # expand
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def combine_keys(qkd_key, pqc_key, length=FINAL_KEY_LEN):
    """Point 3 du schéma : clé_finale = HKDF( clé_PQC ⊕ clé_QKD ).

    `qkd_key` et `pqc_key` sont des bytes. Ils doivent avoir la même longueur
    (on demande donc au KME une clé QKD de 256 bits = 32 octets, comme le
    secret ML-KEM-768). Le XOR est mélangé par HKDF pour produire une clé de
    `length` octets utilisable telle quelle comme PSK WireGuard.
    """
    xored = xor_bytes(qkd_key, pqc_key)
    return _hkdf_sha256(
        xored,
        length,
        salt=b"ETSI-QKD-014-hybrid",
        info=b"QKD+PQC->WireGuard-PSK",
    )


def combine_keys_from_b64(qkd_key_b64, pqc_key_bytes, length=FINAL_KEY_LEN):
    """Variante pratique : la clé QKD arrive en base64 (format ETSI 6.3)."""
    qkd_key = base64.b64decode(qkd_key_b64)
    return combine_keys(qkd_key, pqc_key_bytes, length)


def to_wireguard_psk(final_key):
    """Encode la clé finale (32 octets) au format PresharedKey WireGuard.

    WireGuard attend une clé de 32 octets encodée en base64 standard.
    """
    if len(final_key) != 32:
        raise ValueError("Une PresharedKey WireGuard fait exactement 32 octets")
    return base64.b64encode(final_key).decode("ascii")


# --------------------------------------------------------------------------- #
# Démonstration autonome (sans réseau ni Docker)                              #
# --------------------------------------------------------------------------- #
def _self_demo():
    """Rejoue points 2 + 3 en mémoire pour vérifier que les deux côtés
    aboutissent à la même clé finale."""
    import os

    # --- Point 1 (simulé) : les deux SAE partagent DÉJÀ la même clé QKD ------
    # (dans le vrai flux elle vient du KME via l'API ETSI 014, même key_ID)
    qkd_key = os.urandom(32)

    # --- Point 2 : établissement PQC ML-KEM-768 ------------------------------
    if not pqc_available():
        print("liboqs indisponible ici : démo PQC sautée (OK en Docker).")
        return

    responder = PqcResponder()             # SAE_B
    pub = responder.public_key()           # SAE_B -> SAE_A : clé publique
    ct, ss_a = pqc_initiator_encapsulate(pub)   # SAE_A encapsule
    ss_b = responder.decapsulate(ct)       # SAE_B décapsule
    responder.close()
    assert ss_a == ss_b, "les secrets PQC diffèrent !"
    print(f"secret PQC partagé : {ss_a.hex()[:32]}... ({len(ss_a)} octets)")

    # --- Point 3 : XOR + dérivation -----------------------------------------
    final_a = combine_keys(qkd_key, ss_a)
    final_b = combine_keys(qkd_key, ss_b)
    assert final_a == final_b, "les clés combinées diffèrent !"
    print(f"clé finale (PSK)   : {final_a.hex()}")
    print(f"PSK WireGuard b64  : {to_wireguard_psk(final_a)}")
    print("OK : les deux côtés obtiennent une clé identique.")


if __name__ == "__main__":
    _self_demo()
