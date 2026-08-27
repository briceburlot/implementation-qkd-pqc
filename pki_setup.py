#!/usr/bin/env python3
"""
pki_setup.py — Provisionne les deux PKI du réseau simulé, pour une liste de
sites donnée (mêmes labels que `generate-network.py`) :

  1) PKI classique (EC P-256, via `cryptography`) pour le mTLS SAE<->KME :
     une CA, un certificat serveur par KME, un certificat client par SAE.
     Volontairement 100% classique : c'est le lien qui ne doit PAS dépendre
     de PQC.

  2) PKI ML-DSA-65 (via liboqs, `pqc_cert.py`) pour authentifier le canal
     classique SAE<->SAE : une CA, un certificat d'identité par SAE.

Exécuté une fois via le service compose `pki-init` (image SAE, qui a déjà
liboqs + cryptography), écrit dans /certs (monté depuis ./certs sur l'hôte).
Idempotent : ne régénère jamais une CA ou un certificat déjà présent, ce qui
permet d'ajouter un site à un réseau existant sans invalider les autres.

Usage :
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

VALID_DAYS = 3650  # 10 ans : PKI de simulation, pas de rotation à gérer


# =========================================================================== #
# PKI classique (EC P-256) — mTLS SAE<->KME                                   #
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
        print("[tls] CA classique déjà présente, conservée")
        return

    os.makedirs(TLS_DIR, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "QKD-Sim Root CA (classique)"),
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
    print("[tls] CA classique générée (EC P-256)")


def ensure_leaf_cert(common_name, filename_stem, *, san_dns=None, is_server):
    """Génère (si absent) un certificat de feuille signé par la CA classique."""
    crt_path = os.path.join(TLS_DIR, f"{filename_stem}.crt")
    key_path = os.path.join(TLS_DIR, f"{filename_stem}.key")
    if os.path.exists(crt_path) and os.path.exists(key_path):
        print(f"[tls] certificat {filename_stem} déjà présent, conservé")
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
    print(f"[tls] certificat {filename_stem} généré (CN={common_name})")


# =========================================================================== #
# PKI ML-DSA-65 — authentification du canal classique SAE<->SAE               #
# =========================================================================== #
def ensure_pqc_ca():
    priv_path = os.path.join(PQC_DIR, "ca_priv.key")
    pub_path = os.path.join(PQC_DIR, "ca_pub.key")
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        print("[pqc] CA ML-DSA déjà présente, conservée")
        return

    os.makedirs(PQC_DIR, exist_ok=True)
    secret_key, public_key = pqc_cert.generate_keypair()
    pqc_cert.save_bytes(priv_path, secret_key)
    pqc_cert.save_bytes(pub_path, public_key)
    print(f"[pqc] CA ML-DSA générée ({pqc_cert.PQC_SIG_ALG})")


def ensure_sae_pqc_identity(sae_id, filename_stem):
    priv_path = os.path.join(PQC_PRIVATE_DIR, f"{filename_stem}.key")
    cert_path = os.path.join(PQC_PUBLIC_DIR, f"{filename_stem}.cert.json")
    if os.path.exists(priv_path) and os.path.exists(cert_path):
        print(f"[pqc] identité {sae_id} déjà présente, conservée")
        return

    os.makedirs(PQC_PRIVATE_DIR, exist_ok=True)
    os.makedirs(PQC_PUBLIC_DIR, exist_ok=True)
    ca_secret_key = pqc_cert.load_bytes(os.path.join(PQC_DIR, "ca_priv.key"))

    secret_key, public_key = pqc_cert.generate_keypair()
    cert = pqc_cert.make_certificate(sae_id, public_key, ca_secret_key)

    pqc_cert.save_bytes(priv_path, secret_key)
    pqc_cert.save_json(cert_path, cert)
    print(f"[pqc] identité {sae_id} générée et certifiée")


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

    print(f"PKI prête pour {len(sites)} site(s) : {', '.join(sites)}")


if __name__ == "__main__":
    main()
