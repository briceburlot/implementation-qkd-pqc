"""
crypto_hybrid.py — Hybrid QKD + PQC cryptographic layer.

Implements points 2 and 3 of the "img_scheme" diagram:

  Point 2: establishing a shared secret via post-quantum cryptography
            (PQC) between SAE_A and SAE_B, via the Open Quantum Safe
            library (liboqs) with the NIST standard KEM ML-KEM-768 (ex-Kyber768).

  Point 3: XOR combination of the two secrets -> final_key = PQC_key ⊕ QKD_key

Security model (hybrid scheme):
    The combined secret remains secure as long as AT LEAST one of the two
    channels holds.
    - the QKD key protects against an adversary who would break ML-KEM;
    - the PQC key protects if the QKD link (or its store) is compromised.
    This is the recommended principle for combining QKD and PQC.

The combined secret is NOT used directly as an encryption key: it serves as
the WireGuard PresharedKey (PSK) (see wireguard.py, point 4). It is
therefore passed through an HKDF to obtain exactly 32 bytes, whatever the
size of the QKD key requested from the KME.

This module has no network dependency: it is deliberately "pure" and
testable independently of the transport (HTTP for the KME) and the tunnel
(WireGuard).
"""

import base64
import hashlib
import hmac

# Name of the KEM mechanism as exposed by liboqs (oqs.get_enabled_kem_mechanisms()).
PQC_KEM_ALG = "ML-KEM-768"

# Size of the final key (bytes): 32 = ChaCha20 key / WireGuard PresharedKey.
FINAL_KEY_LEN = 32


# --------------------------------------------------------------------------- #
# Import liboqs (Open Quantum Safe)                                            #
# --------------------------------------------------------------------------- #
def _import_oqs():
    """Imports the Python wrapper for liboqs, with an explicit error message.

    The PyPI package is `liboqs-python` but is imported under the name `oqs`.
    """
    try:
        import oqs  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "The Open Quantum Safe library (module 'oqs', package "
            "'liboqs-python') was not found. It is installed in this "
            "project's Docker images; outside Docker, see "
            "https://github.com/open-quantum-safe/liboqs-python"
        ) from exc
    return oqs


def pqc_available():
    """True if liboqs is importable and does expose ML-KEM-768."""
    try:
        oqs = _import_oqs()
        return PQC_KEM_ALG in oqs.get_enabled_kem_mechanisms()
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Point 2 — PQC key establishment (ML-KEM-768)                                 #
# --------------------------------------------------------------------------- #
#
# The ML-KEM KEM proceeds in three steps (Diffie-Hellman-like roles):
#
#   Responder (here SAE_B / slave):   (public_key, secret_key) = keygen()
#                                      -- sends public_key -->
#   Initiator (here SAE_A / master):  (ciphertext, ss) = encaps(public_key)
#                                      <-- sends ciphertext --
#   Responder:                        ss = decaps(ciphertext)
#
# Both parties obtain the SAME secret `ss` (32 bytes for ML-KEM-768) without
# ever transmitting it in the clear: this is the MLWE security of ML-KEM.


class PqcResponder:
    """Side that generates the key pair and decrypts (decapsulates).

    In our orchestration this is the slave SAE (SAE_B): it publishes its
    public key, receives the ciphertext from the master, and recovers the
    shared secret.

    The object keeps the secret key internally (liboqs state) between
    keygen() and decapsulate(): the same instance must therefore be kept
    alive.
    """

    def __init__(self, alg=PQC_KEM_ALG):
        oqs = _import_oqs()
        self._kem = oqs.KeyEncapsulation(alg)

    def public_key(self):
        """Generates the pair and returns the public key (bytes) to publish."""
        return self._kem.generate_keypair()

    def decapsulate(self, ciphertext):
        """Recovers the PQC shared secret from the received ciphertext."""
        return bytes(self._kem.decap_secret(ciphertext))

    def close(self):
        # liboqs frees the secret material; supports the context manager.
        try:
            self._kem.free()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def pqc_initiator_encapsulate(peer_public_key, alg=PQC_KEM_ALG):
    """Initiator side (master SAE): encapsulates under the peer's public key.

    Returns (ciphertext, shared_secret). The ciphertext is sent to the
    responder; shared_secret is identical on both sides.
    """
    oqs = _import_oqs()
    with oqs.KeyEncapsulation(alg) as kem:
        ciphertext, shared_secret = kem.encap_secret(peer_public_key)
    return bytes(ciphertext), bytes(shared_secret)


# --------------------------------------------------------------------------- #
# Point 3 — XOR combination + derivation to the final key                     #
# --------------------------------------------------------------------------- #
def xor_bytes(a, b):
    """Byte-by-byte XOR. Both inputs must have the same length."""
    if len(a) != len(b):
        raise ValueError(
            f"XOR: different lengths ({len(a)} vs {len(b)} bytes)"
        )
    return bytes(x ^ y for x, y in zip(a, b))


def _hkdf_sha256(ikm, length, salt=b"", info=b""):
    """HKDF (RFC 5869) over SHA-256 — no external dependency.

    Used to bring the combined secret down to exactly `length` bytes, mixing
    it irreversibly (extract + expand).
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
    """Point 3 of the scheme: final_key = HKDF( PQC_key ⊕ QKD_key ).

    `qkd_key` and `pqc_key` are bytes. They must have the same length (we
    therefore request a 256-bit = 32-byte QKD key from the KME, matching the
    ML-KEM-768 secret). The XOR is mixed via HKDF to produce a `length`-byte
    key usable as-is as a WireGuard PSK.
    """
    xored = xor_bytes(qkd_key, pqc_key)
    return _hkdf_sha256(
        xored,
        length,
        salt=b"ETSI-QKD-014-hybrid",
        info=b"QKD+PQC->WireGuard-PSK",
    )


def combine_keys_from_b64(qkd_key_b64, pqc_key_bytes, length=FINAL_KEY_LEN):
    """Convenience variant: the QKD key arrives in base64 (ETSI 6.3 format)."""
    qkd_key = base64.b64decode(qkd_key_b64)
    return combine_keys(qkd_key, pqc_key_bytes, length)


def to_wireguard_psk(final_key):
    """Encodes the final key (32 bytes) in WireGuard PresharedKey format.

    WireGuard expects a 32-byte key encoded in standard base64.
    """
    if len(final_key) != 32:
        raise ValueError("A WireGuard PresharedKey must be exactly 32 bytes")
    return base64.b64encode(final_key).decode("ascii")


# --------------------------------------------------------------------------- #
# Standalone demo (no network, no Docker)                                     #
# --------------------------------------------------------------------------- #
def _self_demo():
    """Replays points 2 + 3 in memory to check that both sides end up with
    the same final key."""
    import os

    # --- Point 1 (simulated): both SAEs ALREADY share the same QKD key ------
    # (in the real flow it comes from the KME via the ETSI 014 API, same key_ID)
    qkd_key = os.urandom(32)

    # --- Point 2: PQC ML-KEM-768 establishment -------------------------------
    if not pqc_available():
        print("liboqs unavailable here: PQC demo skipped (OK in Docker).")
        return

    responder = PqcResponder()             # SAE_B
    pub = responder.public_key()           # SAE_B -> SAE_A: public key
    ct, ss_a = pqc_initiator_encapsulate(pub)   # SAE_A encapsulates
    ss_b = responder.decapsulate(ct)       # SAE_B decapsulates
    responder.close()
    assert ss_a == ss_b, "PQC secrets differ!"
    print(f"shared PQC secret : {ss_a.hex()[:32]}... ({len(ss_a)} bytes)")

    # --- Point 3: XOR + derivation -----------------------------------------
    final_a = combine_keys(qkd_key, ss_a)
    final_b = combine_keys(qkd_key, ss_b)
    assert final_a == final_b, "combined keys differ!"
    print(f"final key (PSK)   : {final_a.hex()}")
    print(f"WireGuard PSK b64 : {to_wireguard_psk(final_a)}")
    print("OK: both sides obtain an identical key.")


if __name__ == "__main__":
    _self_demo()
