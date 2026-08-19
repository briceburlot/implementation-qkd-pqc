# Lancement du projet

Le projet simule un réseau QKD multi-sites (cf. Figure 1 de l'ETSI GS QKD 014) :
chaque site est un couple **SAE + KME** conteneurisé et indépendant. Les KME se
synchronisent entre eux via un endpoint interne (`/internal/sync_keys`) qui
simule le lien QKD entre Trusted Nodes.

## Option A — Démo automatique à 2 sites (Figure 2 du PDF)

Lance 2 sites (A et B), `sae-a` demande une clé pour `SAE_B`, `sae-b` la
récupère automatiquement via le `key_ID` (transmis par un volume partagé qui
simule le canal classique "hors périmètre" du protocole).

```bash
docker compose -f docker-compose.demo.yml up --build
docker compose -f docker-compose.demo.yml logs sae-a sae-b   # vérifier que les 2 clés sont identiques
docker compose -f docker-compose.demo.yml down -v
```

## Option B — Réseau interactif à N sites (Figure 1 du PDF)

Le fichier `docker-compose.yml` par défaut réplique 3 sites (A, B, C), tous les
KME étant reliés en full mesh (chacun connaît directement les autres).

### Générer/régénérer le réseau

```bash
python3 generate-network.py A B C           # -> docker-compose.yml (3 sites)
python3 generate-network.py A B C D E       # autant de sites que voulu
```

### Lancer le réseau

```bash
docker compose up --build -d
```

Les conteneurs SAE restent inactifs (`sleep infinity`) : on choisit à la volée
le rôle et le site cible avec `docker compose exec`.

### Exemple : échanger une clé entre le site A et le site C

```bash
# SAE_A (maître) demande une clé pour SAE_C -> le KME A la réplique vers le KME C
docker compose exec -e SAE_ROLE=master -e PEER_SAE_ID=SAE_C sae-a python sae_API.py
# -> note le key_ID affiché

# SAE_C (esclave) récupère la même clé localement, via son propre KME
docker compose exec -e SAE_ROLE=slave -e PEER_SAE_ID=SAE_A -e KEY_ID=<key_ID> sae-c python sae_API.py
```

Un site non impliqué (ex. `sae-b`) qui tenterait de récupérer cette clé avec
le même `key_ID` obtient une erreur 400 : chaque KME ne connaît que les clés
qui lui ont été explicitement destinées.

### Arrêter et nettoyer

```bash
docker compose down -v
```

## Alternative — Sans docker compose (2 sites, commandes manuelles)

```bash
docker build -f Dockerfile.kme -t qkd-kme .
docker build -f Dockerfile.sae -t qkd-sae .
docker network create qkd-net

docker run -d --name kme-a --network qkd-net -p 8001:8000 \
  -e KME_ID=KME_A -e KME_PEERS='{"SAE_B": "http://kme-b:8000"}' qkd-kme
docker run -d --name kme-b --network qkd-net -p 8002:8000 \
  -e KME_ID=KME_B -e KME_PEERS='{"SAE_A": "http://kme-a:8000"}' qkd-kme

docker run --rm --network qkd-net \
  -e KME_URL=http://kme-a:8000 -e SAE_ID=SAE_A -e PEER_SAE_ID=SAE_B -e SAE_ROLE=master \
  qkd-sae
# IMPORTANT : récupérer le key_ID affiché

docker run --rm --network qkd-net \
  -e KME_URL=http://kme-b:8000 -e SAE_ID=SAE_B -e PEER_SAE_ID=SAE_A -e SAE_ROLE=slave \
  -e KEY_ID=<key_ID_obtenu_précédemment> \
  qkd-sae

docker stop kme-a kme-b && docker rm kme-a kme-b
docker network rm qkd-net
```
