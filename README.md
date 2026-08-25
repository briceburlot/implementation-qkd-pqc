# Réseau QKD hybride (ETSI GS QKD 014 + PQC + WireGuard)

Simulation d'un réseau QKD multi-sites conforme à **ETSI GS QKD 014**, enrichie
d'une couche cryptographique **hybride QKD + PQC** puis d'un **tunnel WireGuard**,
suivant les schémas `img_scheme.jpg` (les 4 points) et `scheme_site.png`
(structure d'une QKD Node).

## Architecture

Chaque site est un **Trusted Node** = un couple **SAE + KME** conteneurisé.

### La QKD Node (`KME.py`, d'après `scheme_site.png`)

Le KME est structuré en composants correspondant au schéma :

| Composant schéma       | Classe               | Rôle                                                        |
|------------------------|----------------------|-------------------------------------------------------------|
| Key Management (vert)  | `KeyManagement`      | sert l'API ETSI 014 aux SAE (status / enc_keys / dec_keys)  |
| QKD Control (bleu)     | `QKDControl`         | pilote les stores et le forwarding (face « réseau QKD »)     |
| QKD Key Store Peer     | `QKDKeyStorePeer`    | **un store de clés par KME pair** (empilés sur le schéma)    |
| Forwarding Module      | `ForwardingModule`   | relaie le matériel de clé vers le KME pair (lien QKD simulé) |

L'API REST exposée reste strictement celle de l'ETSI (clauses 5.1–5.4) :

```
GET  /api/v1/keys/{slave_SAE_ID}/status
POST /api/v1/keys/{slave_SAE_ID}/enc_keys     # master SAE -> clé + key_ID
POST /api/v1/keys/{master_SAE_ID}/dec_keys    # slave  SAE -> clé par key_ID
POST /internal/sync_keys                       # lien QKD interne (Forwarding)
```

### La couche hybride côté SAE (les 4 points de `img_scheme.jpg`)

| # | Étape                                   | Où                                            |
|---|-----------------------------------------|-----------------------------------------------|
| 1 | SAE demande une clé QKD au KME          | `sae_API.SAEClient` (API ETSI 014)            |
| 2 | Établissement PQC **ML-KEM-768** (liboqs) + notif `key_ID` | `crypto_hybrid.PqcResponder` / `pqc_initiator_encapsulate` |
| 3 | `clé_finale = HKDF(clé_PQC ⊕ clé_QKD)`  | `crypto_hybrid.combine_keys`                  |
| 4 | Tunnel **WireGuard**, PSK = clé_finale  | `wireguard.bring_up` (ChaCha20-Poly1305)      |

**Pourquoi la clé va dans le PresharedKey WireGuard ?** WireGuard fait son
propre handshake (Noise/Curve25519) et dérive lui-même ses clés ChaCha20 : on
ne peut pas lui imposer une clé de session. Le PSK est le seul point d'injection
d'un secret externe, mélangé au handshake. Résultat : trafic ChaCha20-Poly1305
**et** sécurité qui dépend aussi du secret hybride QKD+PQC. Le PSK n'est jamais
transmis : il est recalculé à l'identique des deux côtés.

**Modèle hybride** : le secret combiné reste sûr tant qu'**au moins un** des deux
canaux tient (QKD couvre une éventuelle chute de ML-KEM ; PQC couvre une
compromission du lien/store QKD).

## Prérequis

- Docker + Docker Compose. Les SAE ont besoin de la capacité **NET_ADMIN**
  (déjà déclarée dans les composes) pour créer l'interface WireGuard.
- L'image SAE compile **liboqs** (ML-KEM-768) et installe **wireguard-tools**
  au build : la première construction est un peu longue.

## Option A — Démo hybride automatique à 2 sites (Figure 2 + 4 points)

```bash
docker compose -f docker-compose_demo.yml up --build
# SAE_A (maître) et SAE_B (esclave) : clé QKD -> PQC -> XOR -> tunnel wg0.
docker compose -f docker-compose_demo.yml logs sae-a sae-b   # PSK identique des 2 côtés
docker compose -f docker-compose_demo.yml down -v
```

Le canal classique (key_ID, clés publiques PQC/WireGuard, ciphertext) transite
par le volume partagé `chan` — c'est le « Step 2 (out-of-scope) » du protocole.

## Option B — Réseau interactif à N sites (Figure 1)

`docker-compose.yml` réplique 3 sites (A, B, C) en full mesh.

```bash
python3 generate-network.py A B C            # régénère docker-compose.yml
python3 generate-network.py A B C D E        # autant de sites que voulu
docker compose up --build -d
```

Les SAE restent inactifs (`sleep infinity`) ; on déclenche une opération à la
volée. Exemple : établir la clé hybride entre le site A et le site C.

```bash
# SAE_A (maître) : clé QKD pour SAE_C -> PQC -> XOR (le KME A réplique vers KME C)
docker compose exec -e SAE_ROLE=master -e PEER_SAE_ID=SAE_C -e HYBRID=1 \
  -e WG_LOCAL_IP=10.9.0.1/24 -e WG_PEER_ENDPOINT=sae-c:51820 \
  -e WG_PEER_ALLOWED_IPS=10.9.0.3/32 sae-a python sae_API.py

# SAE_C (esclave) : même clé hybride, monte son bout du tunnel
docker compose exec -e SAE_ROLE=slave -e PEER_SAE_ID=SAE_A -e HYBRID=1 \
  -e WG_LOCAL_IP=10.9.0.3/24 -e WG_PEER_ENDPOINT=sae-a:51820 \
  -e WG_PEER_ALLOWED_IPS=10.9.0.1/32 sae-c python sae_API.py
```

Mode **ETSI simple** (sans hybride, rétro-compatible) : omettre `HYBRID=1`.
Un site non impliqué qui tenterait `dec_keys` avec le même `key_ID` obtient une
erreur 400 : chaque KME ne connaît que les clés qui lui ont été destinées.

```bash
docker compose down -v      # arrêt + nettoyage
```

## Test rapide hors Docker

```bash
python3 crypto_hybrid.py    # rejoue points 2+3 (si liboqs présent)
python3 sae_API.py          # démo KME en mémoire (points 1, +2/3 si liboqs)
```

## Variables d'environnement SAE (mode hybride)

| Variable              | Rôle                                                  |
|-----------------------|-------------------------------------------------------|
| `SAE_ROLE`            | `master` ou `slave`                                   |
| `HYBRID=1`            | active les points 2→4 (sinon ETSI seul)               |
| `CHANNEL_DIR`         | répertoire du canal classique (volume partagé)        |
| `WG_LOCAL_IP`         | IP interne du tunnel, ex `10.9.0.1/24`                |
| `WG_LISTEN_PORT`      | port UDP WireGuard (défaut 51820)                     |
| `WG_PEER_ENDPOINT`    | `host:port` du pair                                   |
| `WG_PEER_ALLOWED_IPS` | réseau autorisé derrière le pair, ex `10.9.0.2/32`    |

## Avertissement

Projet de démonstration : la génération quantique, la réconciliation et la
privacy amplification sont hors périmètre (ETSI clause 1) et **simulées**. Le
stub de clés et le canal fichier ne conviennent pas à un usage réel.
