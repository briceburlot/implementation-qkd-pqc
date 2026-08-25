#!/usr/bin/env python3
"""
Génère un docker-compose.yml répliquant N sites (Figure 1 de l'ETSI GS QKD 014) :
chaque site = un couple SAE + KME indépendant, tous les KME étant reliés en
"full mesh" (chacun connaît directement les autres) pour simuler les liens QKD
inter-sites.

Usage :
    python3 generate-network.py A B C            # 3 sites -> docker-compose.yml
    python3 generate-network.py A B C D E -o net5.yml

Les SAE générés restent "idle" (sleep infinity) : on lance une opération avec
docker compose exec, en choisissant à la volée le rôle et le site cible, par ex :

    docker compose exec -e SAE_ROLE=master -e PEER_SAE_ID=SAE_C sae-a python sae_API.py
    docker compose exec -e SAE_ROLE=slave -e PEER_SAE_ID=SAE_A -e KEY_ID=<...> sae-c python sae_API.py
"""

import argparse
import json
import sys

HEALTHCHECK_TEMPLATE = (
    "import urllib.request; "
    "urllib.request.urlopen('http://localhost:8000/api/v1/keys/{sae_id}/status', timeout=2)"
)


def build_compose(sites):
    labels = [s.upper() for s in sites]
    if len(labels) < 2:
        raise ValueError("il faut au moins 2 sites pour qu'ils puissent communiquer")
    if len(set(labels)) != len(labels):
        raise ValueError("les noms de site doivent être uniques")

    lines = ["services:"]

    for i, label in enumerate(labels):
        site = label.lower()
        kme_service = f"kme-{site}"
        sae_id = f"SAE_{label}"
        peers = {
            f"SAE_{other}": f"http://kme-{other.lower()}:8000"
            for other in labels if other != label
        }
        host_port = 8001 + i

        lines += [
            f"  {kme_service}:",
            "    build:",
            "      context: .",
            "      dockerfile: Dockerfile.kme",
            "    ports:",
            f'      - "{host_port}:8000"',
            "    environment:",
            f"      KME_ID: KME_{label}",
            f"      KME_PEERS: '{json.dumps(peers)}'",
            "    healthcheck:",
            f'      test: ["CMD", "python", "-c", "{HEALTHCHECK_TEMPLATE.format(sae_id=sae_id)}"]',
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
            # NET_ADMIN : requis pour monter l'interface WireGuard (point 4).
            "    cap_add:",
            "      - NET_ADMIN",
            "    depends_on:",
            f"      kme-{site}:",
            "        condition: service_healthy",
            "    environment:",
            f"      KME_URL: http://kme-{site}:8000",
            f"      SAE_ID: {sae_id}",
            # canal classique partagé (key_ID, clés publiques PQC/WG, ciphertext)
            "      CHANNEL_DIR: /shared/chan",
            "    volumes:",
            "      - shared-data:/shared",
            "    command: [\"sleep\", \"infinity\"]",
            "",
        ]

    lines += ["volumes:", "  shared-data:", ""]
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sites", nargs="+", help="noms des sites à répliquer (ex: A B C D)")
    parser.add_argument("-o", "--out", default="docker-compose.yml", help="fichier de sortie (défaut: docker-compose.yml)")
    args = parser.parse_args()

    try:
        compose = build_compose(args.sites)
    except ValueError as exc:
        print(f"erreur: {exc}", file=sys.stderr)
        sys.exit(1)

    with open(args.out, "w") as f:
        f.write(compose)

    print(f"{args.out} généré pour {len(args.sites)} sites : {', '.join(s.upper() for s in args.sites)}")


if __name__ == "__main__":
    main()
