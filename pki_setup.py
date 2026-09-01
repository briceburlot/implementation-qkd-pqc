#!/usr/bin/env python3
"""
pki_setup.py — Provisions the two PKIs of the simulated network, for a given
list of sites (same labels as `generate-network.py`):

  1) Classical PKI (EC P-256, via `cryptography`) for SAE<->KME mTLS:
     one CA, one server certificate per KME, one client certificate per SAE.
     Deliberately 100% classical: this is the link that must NOT depend on
     PQC.

  2) ML-DSA-65 PKI (via liboqs, `pqc_cert.py`) to authenticate the classic
     SAE<->SAE channel: one CA, one identity certificate per SAE.

Run once via the `pki-init` compose service (SAE image, which already has
liboqs + cryptography), writes to /certs (mounted from ./certs on the host).
Idempotent: never regenerates a CA or certificate that already exists, which
allows adding a site to an existing network without invalidating the others.

Usage:
    python3 pki_setup.py A B C            # sites -> /certs/...
"""

import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import pqc_cert

CERTS_ROOT = os.environ.get("CERTS_ROOT", "/certs")
TLS_DIR = os.path.join(CERTS_ROOT, "tls")
PQC_DIR = os.path.join(CERTS_ROOT, "pqc")
PQC_PUBLIC_DIR = os.path.join(PQC_DIR, "public")
PQC_PRIVATE_DIR = os.path.join(PQC_DIR, "private")

VALID_DAYS = 3650  # 10 years: simulation PKI, no rotation to manage


# =========================================================================== #
# Classical PKI (EC P-256) — SAE<->KME mTLS                                   #
# =========================================================================== #
def _write_pem_key(path, key):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def _write_pem_cert(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _load_ca():
    with open(os.path.join(TLS_DIR, "ca.key"), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(os.path.join(TLS_DIR, "ca.crt"), "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def ensure_classical_ca():
    ca_key_path = os.path.join(TLS_DIR, "ca.key")
    ca_crt_path = os.path.join(TLS_DIR, "ca.crt")
    if os.path.exists(ca_key_path) and os.path.exists(ca_crt_path):
        print("[tls] classical CA already present, kept")
        return

    os.makedirs(TLS_DIR, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "QKD-Sim Root CA (classical)"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    _write_pem_key(ca_key_path, key)
    _write_pem_cert(ca_crt_path, cert)
    print("[tls] classical CA generated (EC P-256)")


def ensure_leaf_cert(common_name, filename_stem, *, san_dns=None, is_server):
    """Generates (if missing) a leaf certificate signed by the classical CA."""
    crt_path = os.path.join(TLS_DIR, f"{filename_stem}.crt")
    key_path = os.path.join(TLS_DIR, f"{filename_stem}.key")
    if os.path.exists(crt_path) and os.path.exists(key_path):
        print(f"[tls] certificate {filename_stem} already present, kept")
        return

    ca_key, ca_cert = _load_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH if is_server
                else x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False,
        )
    )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns]),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())

    _write_pem_key(key_path, key)
    _write_pem_cert(crt_path, cert)
    print(f"[tls] certificate {filename_stem} generated (CN={common_name})")


# =========================================================================== #
# ML-DSA-65 PKI — authentication of the classic SAE<->SAE channel             #
# =========================================================================== #
def ensure_pqc_ca():
    priv_path = os.path.join(PQC_DIR, "ca_priv.key")
    pub_path = os.path.join(PQC_DIR, "ca_pub.key")
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        print("[pqc] ML-DSA CA already present, kept")
        return

    os.makedirs(PQC_DIR, exist_ok=True)
    secret_key, public_key = pqc_cert.generate_keypair()
    pqc_cert.save_bytes(priv_path, secret_key)
    pqc_cert.save_bytes(pub_path, public_key)
    print(f"[pqc] ML-DSA CA generated ({pqc_cert.PQC_SIG_ALG})")


def ensure_sae_pqc_identity(sae_id, filename_stem):
    priv_path = os.path.join(PQC_PRIVATE_DIR, f"{filename_stem}.key")
    cert_path = os.path.join(PQC_PUBLIC_DIR, f"{filename_stem}.cert.json")
    if os.path.exists(priv_path) and os.path.exists(cert_path):
        print(f"[pqc] identity {sae_id} already present, kept")
        return

    os.makedirs(PQC_PRIVATE_DIR, exist_ok=True)
    os.makedirs(PQC_PUBLIC_DIR, exist_ok=True)
    ca_secret_key = pqc_cert.load_bytes(os.path.join(PQC_DIR, "ca_priv.key"))

    secret_key, public_key = pqc_cert.generate_keypair()
    cert = pqc_cert.make_certificate(sae_id, public_key, ca_secret_key)

    pqc_cert.save_bytes(priv_path, secret_key)
    pqc_cert.save_json(cert_path, cert)
    print(f"[pqc] identity {sae_id} generated and certified")


# =========================================================================== #
# Orchestration                                                                #
# =========================================================================== #
def main():
    sites = [s.upper() for s in sys.argv[1:]]
    if not sites:
        print("usage: pki_setup.py SITE [SITE ...]", file=sys.stderr)
        sys.exit(1)

    ensure_classical_ca()
    ensure_pqc_ca()

    for label in sites:
        site = label.lower()
        ensure_leaf_cert(f"KME_{label}", f"kme_{site}", san_dns=[f"kme-{site}", "localhost"],
                          is_server=True)
        ensure_leaf_cert(f"SAE_{label}", f"sae_{site}", is_server=False)
        ensure_sae_pqc_identity(f"SAE_{label}", f"sae_{site}")

    print(f"PKI ready for {len(sites)} site(s): {', '.join(sites)}")


if __name__ == "__main__":
    main()
