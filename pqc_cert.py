"""
pqc_cert.py — PQC identity and authentication of SAEs (ML-DSA signatures).

Authenticates the classic SAE<->SAE channel (`sae_API.ClassicChannel`): this
channel carries the PQC public key, the ML-KEM ciphertext, and the
WireGuard public keys between the two SAEs. None of this is secret, but
none of it was authenticated either: a third party with access to the
shared volume could substitute their own public key (MITM). This module
adds an **ML-DSA-65** signature (CRYSTALS-Dilithium, standardized as FIPS
204, NIST security level 3 — consistent with ML-KEM-768 already used for
key exchange) on each message, verified against a per-SAE identity
certificate, itself signed by an ML-DSA CA local to the simulated network.

The certificate is a plain JSON object (not X.509: the classical part of
the project — SAE<->KME mTLS — already uses `cryptography`/X.509 for the
classical CA; here we deliberately keep it minimal, since liboqs only deals
with raw keys):

    {"sae_id": "SAE_A", "algorithm": "ML-DSA-65",
     "public_key": "<b64>", "signature": "<b64 from the CA>"}

This module has no network dependency; it is used both by `pki_setup.py`
(CA and certificate generation) and by `sae_API.py` (signing/verifying the
classic channel's messages at runtime).
"""

import base64
import json

# liboqs signature mechanism (oqs.get_enabled_sig_mechanisms()).
PQC_SIG_ALG = "ML-DSA-65"


def _import_oqs():
    try:
        import oqs  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "The Open Quantum Safe library (module 'oqs', package "
            "'liboqs-python') was not found. It is installed in the "
            "SAE Docker image; outside Docker, see "
            "https://github.com/open-quantum-safe/liboqs-python"
        ) from exc
    return oqs


def pqc_sig_available():
    """True if liboqs is importable and does expose ML-DSA-65."""
    try:
        oqs = _import_oqs()
        return PQC_SIG_ALG in oqs.get_enabled_sig_mechanisms()
    except Exception:
        return False


def b64_encode(b):
    return base64.b64encode(b).decode("ascii")


def b64_decode(s):
    return base64.b64decode(s)


# historical internal aliases (used within this module)
_b64e = b64_encode
_b64d = b64_decode


# --------------------------------------------------------------------------- #
# ML-DSA-65 keys — generation, signing, verification                          #
# --------------------------------------------------------------------------- #
def generate_keypair(alg=PQC_SIG_ALG):
    """Generates an ML-DSA key pair. Returns (secret_key, public_key) as bytes."""
    oqs = _import_oqs()
    with oqs.Signature(alg) as signer:
        public_key = signer.generate_keypair()
        # liboqs-python exposes the secret key either via export_secret_key(),
        # or via the `secret_key` attribute depending on the wrapper version.
        if hasattr(signer, "export_secret_key"):
            secret_key = signer.export_secret_key()
        else:  # pragma: no cover
            secret_key = signer.secret_key
    return bytes(secret_key), bytes(public_key)


def sign(secret_key, message, alg=PQC_SIG_ALG):
    """Signs `message` (bytes) with the given ML-DSA secret key."""
    oqs = _import_oqs()
    with oqs.Signature(alg, secret_key=secret_key) as signer:
        return bytes(signer.sign(message))


def verify(public_key, message, signature, alg=PQC_SIG_ALG):
    """Verifies an ML-DSA signature. Returns True/False (never raises)."""
    oqs = _import_oqs()
    try:
        with oqs.Signature(alg) as verifier:
            return bool(verifier.verify(message, signature, public_key))
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# SAE identity certificates (JSON signed by the ML-DSA CA)                     #
# --------------------------------------------------------------------------- #
def canonical_bytes(obj):
    """Canonical encoding (sorted keys, compact separators) to sign/verify a
    JSON object reproducibly on both sides."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# historical internal alias
_canonical_bytes = canonical_bytes


def make_certificate(sae_id, public_key, ca_secret_key, alg=PQC_SIG_ALG):
    """Builds and signs (with the CA) an SAE's ML-DSA identity certificate."""
    body = {"sae_id": sae_id, "algorithm": alg, "public_key": _b64e(public_key)}
    signature = sign(ca_secret_key, _canonical_bytes(body), alg=alg)
    return {**body, "signature": _b64e(signature)}


def verify_certificate(cert, ca_public_key):
    """Verifies that an SAE certificate was indeed signed by the ML-DSA CA."""
    body = {k: v for k, v in cert.items() if k != "signature"}
    try:
        signature = _b64d(cert["signature"])
    except (KeyError, ValueError, TypeError):
        return False
    return verify(ca_public_key, _canonical_bytes(body), signature,
                  alg=cert.get("algorithm", PQC_SIG_ALG))


def certificate_public_key(cert):
    """Extracts the ML-DSA public key (bytes) from an already-verified certificate."""
    return _b64d(cert["public_key"])


# --------------------------------------------------------------------------- #
# Small file helpers (used by pki_setup.py and sae_API.py)                     #
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
