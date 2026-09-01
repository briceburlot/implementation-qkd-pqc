#!/usr/bin/env python3
"""
Generates a docker-compose.yml replicating N sites (Figure 1 of ETSI GS QKD 014):
each site = an independent SAE + KME pair, with all KMEs connected in
"full mesh" (each one directly knows the others) to simulate the inter-site
QKD links.

Usage:
    python3 generate-network.py A B C            # 3 sites -> docker-compose.yml
    python3 generate-network.py A B C D E -o net5.yml

The generated SAEs stay "idle" (sleep infinity): an operation is launched
with docker compose exec, picking the role and target site on the fly, e.g.:

    docker compose exec -e SAE_ROLE=master -e PEER_SAE_ID=SAE_C sae-a python sae_API.py
    docker compose exec -e SAE_ROLE=slave -e PEER_SAE_ID=SAE_A -e KEY_ID=<...> sae-c python sae_API.py
"""

import argparse
import json
import sys

# The KME exposes two ports: external (mTLS, facing SAEs, ETSI 014) and
# internal (plain HTTP, facing peer KMEs, replication — out of scope for auth).
KME_EXTERNAL_PORT = 8000
KME_INTERNAL_PORT = 8001

# The original HTTP check would fail the TLS handshake (it presents no
# client certificate): we just check that the external port accepts
# connections.
HEALTHCHECK_TEMPLATE = (
    "import socket; "
    "socket.create_connection(('localhost', {port}), timeout=2)"
)


def build_compose(sites):
    labels = [s.upper() for s in sites]
    if len(labels) < 2:
        raise ValueError("at least 2 sites are needed for them to communicate")
    if len(set(labels)) != len(labels):
        raise ValueError("site names must be unique")

    lines = ["services:"]

    # --- pki-init: generates the classical PKI (mTLS) + ML-DSA (SAE<->SAE) --
    # once for the whole network, in ./certs (mounted on the host).
    lines += [
        "  pki-init:",
        "    build:",
        "      context: .",
        "      dockerfile: Dockerfile.sae",
        "    entrypoint: [\"python\", \"pki_setup.py\"]",
        f"    command: [{', '.join(json.dumps(l) for l in labels)}]",
        "    volumes:",
        "      - ./certs:/certs",
        "",
    ]

    for i, label in enumerate(labels):
        site = label.lower()
        kme_service = f"kme-{site}"
        peers = {
            f"SAE_{other}": f"http://kme-{other.lower()}:{KME_INTERNAL_PORT}"
            for other in labels if other != label
        }
        host_port = 8001 + i

        lines += [
            f"  {kme_service}:",
            "    build:",
            "      context: .",
            "      dockerfile: Dockerfile.kme",
            "    ports:",
            f'      - "{host_port}:{KME_EXTERNAL_PORT}"',
            "    depends_on:",
            "      pki-init:",
            "        condition: service_completed_successfully",
            "    environment:",
            f"      KME_ID: KME_{label}",
            f"      KME_PEERS: '{json.dumps(peers)}'",
            f"      KME_INTERNAL_PORT: \"{KME_INTERNAL_PORT}\"",
            "      TLS_SERVER_CERT: /certs/server.crt",
            "      TLS_SERVER_KEY: /certs/server.key",
            "      TLS_CA_CERT: /certs/ca.crt",
            "    volumes:",
            f"      - ./certs/tls/kme_{site}.crt:/certs/server.crt:ro",
            f"      - ./certs/tls/kme_{site}.key:/certs/server.key:ro",
            "      - ./certs/tls/ca.crt:/certs/ca.crt:ro",
            "    healthcheck:",
            f'      test: ["CMD", "python", "-c", "{HEALTHCHECK_TEMPLATE.format(port=KME_EXTERNAL_PORT)}"]',
            "      interval: 3s",
            "      timeout: 2s",
            "      retries: 10",
            "",
        ]

    for label in labels:
        site = label.lower()
        sae_id = f"SAE_{label}"
        lines += [
            f"  sae-{site}:",
            "    build:",
            "      context: .",
            "      dockerfile: Dockerfile.sae",
            # NET_ADMIN: required to bring up the WireGuard interface (point 4).
            "    cap_add:",
            "      - NET_ADMIN",
            "    depends_on:",
            "      pki-init:",
            "        condition: service_completed_successfully",
            f"      kme-{site}:",
            "        condition: service_healthy",
            "    environment:",
            f"      KME_URL: https://kme-{site}:{KME_EXTERNAL_PORT}",
            f"      SAE_ID: {sae_id}",
            # shared classic channel (key_ID, PQC/WG public keys, ciphertext)
            "      CHANNEL_DIR: /shared/chan",
            # SAE<->KME mTLS (classical, no PQC dependency)
            "      TLS_CLIENT_CERT: /certs/client.crt",
            "      TLS_CLIENT_KEY: /certs/client.key",
            "      TLS_CA_CERT: /certs/ca.crt",
            # ML-DSA-65 SAE<->SAE (authenticates the classic channel)
            "      PQC_CA_PUB: /certs/pqc_ca.pub",
            "      PQC_CERT_DIR: /certs/pqc_public",
            f"      PQC_CERT: /certs/pqc_public/sae_{site}.cert.json",
            "      PQC_PRIV_KEY: /certs/pqc_priv.key",
            "    volumes:",
            "      - shared-data:/shared",
            f"      - ./certs/tls/sae_{site}.crt:/certs/client.crt:ro",
            f"      - ./certs/tls/sae_{site}.key:/certs/client.key:ro",
            "      - ./certs/tls/ca.crt:/certs/ca.crt:ro",
            "      - ./certs/pqc/ca_pub.key:/certs/pqc_ca.pub:ro",
            "      - ./certs/pqc/public:/certs/pqc_public:ro",
            f"      - ./certs/pqc/private/sae_{site}.key:/certs/pqc_priv.key:ro",
            "    command: [\"sleep\", \"infinity\"]",
            "",
        ]

    lines += ["volumes:", "  shared-data:", ""]
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sites", nargs="+", help="names of the sites to replicate (e.g. A B C D)")
    parser.add_argument("-o", "--out", default="docker-compose.yml", help="output file (default: docker-compose.yml)")
    args = parser.parse_args()

    try:
        compose = build_compose(args.sites)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    with open(args.out, "w") as f:
        f.write(compose)

    print(f"{args.out} generated for {len(args.sites)} sites: {', '.join(s.upper() for s in args.sites)}")


if __name__ == "__main__":
    main()
