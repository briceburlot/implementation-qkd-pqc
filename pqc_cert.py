"""
pqc_cert.py — Identité et authentification PQC des SAE (signatures ML-DSA).

Authentifie le canal classique SAE<->SAE (`sae_API.ClassicChannel`) : ce
canal transporte la clé publique PQC, le ciphertext ML-KEM et les clés
publiques WireGuard entre les deux SAE. Rien de tout cela n'est secret, mais
rien n'était non plus authentifié : un tiers ayant accès au volume partagé
pouvait substituer sa propre clé publique (MITM). Ce module ajoute une
signature **ML-DSA-65** (CRYSTALS-Dilithium, standardisé FIPS 204, niveau de
sécurité NIST 3 — cohérent avec ML-KEM-768 déjà utilisé pour l'échange de
clé) sur chaque message, vérifiée contre un certificat d'identité par SAE,
lui-même signé par une CA ML-DSA locale au réseau simulé.

Le certificat est un simple JSON (pas de X.509 : la partie classique du
projet — mTLS SAE<->KME — utilise déjà `cryptography`/X.509 pour la CA
classique ; ici on reste volontairement minimal, liboqs ne parlant que des
clés brutes) :

    {"sae_id": "SAE_A", "algorithm": "ML-DSA-65",
     "public_key": "<b64>", "signature": "<b64 de la CA>"}

Ce module n'a aucune dépendance réseau ; il est utilisé à la fois par
`pki_setup.py` (génération de la CA et des certificats) et par `sae_API.py`
(signature/vérification des messages du canal classique à l'exécution).
"""

import base64
import json

# Mécanisme de signature liboqs (oqs.get_enabled_sig_mechanisms()).
PQC_SIG_ALG = "ML-DSA-65"


def _import_oqs():
    try:
        import oqs  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "La librairie Open Quantum Safe (module 'oqs', paquet "
            "'liboqs-python') est introuvable. Elle est installée dans "
            "l'image Docker SAE ; hors Docker : voir "
            "https://github.com/open-quantum-safe/liboqs-python"
        ) from exc
    return oqs


def pqc_sig_available():
    """True si liboqs est importable et expose bien ML-DSA-65."""
    try:
        oqs = _import_oqs()
        return PQC_SIG_ALG in oqs.get_enabled_sig_mechanisms()
    except Exception:
        return False


def b64_encode(b):
    return base64.b64encode(b).decode("ascii")


def b64_decode(s):
    return base64.b64decode(s)


# alias internes historiques (utilisés dans ce module)
_b64e = b64_encode
_b64d = b64_decode


# --------------------------------------------------------------------------- #
# Clés ML-DSA-65 — génération, signature, vérification                        #
# --------------------------------------------------------------------------- #
def generate_keypair(alg=PQC_SIG_ALG):
    """Génère une paire de clés ML-DSA. Retourne (secret_key, public_key) en bytes."""
    oqs = _import_oqs()
    with oqs.Signature(alg) as signer:
        public_key = signer.generate_keypair()
        # liboqs-python expose la clé secrète soit via export_secret_key(),
        # soit via l'attribut `secret_key` selon la version du wrapper.
        if hasattr(signer, "export_secret_key"):
            secret_key = signer.export_secret_key()
        else:  # pragma: no cover
            secret_key = signer.secret_key
    return bytes(secret_key), bytes(public_key)


def sign(secret_key, message, alg=PQC_SIG_ALG):
    """Signe `message` (bytes) avec la clé secrète ML-DSA fournie."""
    oqs = _import_oqs()
    with oqs.Signature(alg, secret_key=secret_key) as signer:
        return bytes(signer.sign(message))


def verify(public_key, message, signature, alg=PQC_SIG_ALG):
    """Vérifie une signature ML-DSA. Retourne True/False (jamais d'exception)."""
    oqs = _import_oqs()
    try:
        with oqs.Signature(alg) as verifier:
            return bool(verifier.verify(message, signature, public_key))
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Certificats d'identité SAE (JSON signé par la CA ML-DSA)                     #
# --------------------------------------------------------------------------- #
def canonical_bytes(obj):
    """Encodage canonique (clés triées, séparateurs compacts) pour signer/vérifier
    un objet JSON de façon reproductible des deux côtés."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# alias interne historique
_canonical_bytes = canonical_bytes


def make_certificate(sae_id, public_key, ca_secret_key, alg=PQC_SIG_ALG):
    """Construit et signe (par la CA) le certificat d'identité ML-DSA d'un SAE."""
    body = {"sae_id": sae_id, "algorithm": alg, "public_key": _b64e(public_key)}
    signature = sign(ca_secret_key, _canonical_bytes(body), alg=alg)
    return {**body, "signature": _b64e(signature)}


def verify_certificate(cert, ca_public_key):
    """Vérifie qu'un certificat SAE a bien été signé par la CA ML-DSA."""
    body = {k: v for k, v in cert.items() if k != "signature"}
    try:
        signature = _b64d(cert["signature"])
    except (KeyError, ValueError, TypeError):
        return False
    return verify(ca_public_key, _canonical_bytes(body), signature,
                  alg=cert.get("algorithm", PQC_SIG_ALG))


def certificate_public_key(cert):
    """Extrait la clé publique ML-DSA (bytes) d'un certificat déjà vérifié."""
    return _b64d(cert["public_key"])


# --------------------------------------------------------------------------- #
# Petits helpers fichiers (utilisés par pki_setup.py et sae_API.py)            #
# --------------------------------------------------------------------------- #
def load_json(path):
    with open(path) as f:
        return json.load(f)


def save_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f)


def load_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def save_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)
