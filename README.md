# Hybrid QKD Network (ETSI GS QKD 014 + PQC + WireGuard)

Simulation of a multi-site QKD network compliant with **ETSI GS QKD 014**,
enriched with a **hybrid QKD + PQC** cryptographic layer and then a
**WireGuard tunnel**, following the diagrams `img_scheme.jpg` (the 4 points)
and `scheme_site.png` (structure of a QKD Node).

## Architecture

Each site is a **Trusted Node** = a containerized **SAE + KME** pair.

### The QKD Node (`KME.py`, based on `scheme_site.png`)

The KME is structured into components matching the diagram:

| Diagram component      | Class                | Role                                                          |
|------------------------|-----------------------|---------------------------------------------------------------|
| Key Management (green) | `KeyManagement`      | serves the ETSI 014 API to SAEs (status / enc_keys / dec_keys) |
| QKD Control (blue)     | `QKDControl`         | drives the stores and forwarding (the "QKD network" side)     |
| QKD Key Store Peer     | `QKDKeyStorePeer`    | **one key store per peer KME** (stacked in the diagram)       |
| Forwarding Module      | `ForwardingModule`   | relays key material to the peer KME (simulated QKD link)      |

The exposed REST API remains strictly the ETSI one (clauses 5.1–5.4):

```
GET  /api/v1/keys/{slave_SAE_ID}/status
POST /api/v1/keys/{slave_SAE_ID}/enc_keys     # master SAE -> key + key_ID
POST /api/v1/keys/{master_SAE_ID}/dec_keys    # slave  SAE -> key by key_ID
POST /internal/sync_keys                       # internal QKD link (Forwarding)
```

### The hybrid layer on the SAE side (the 4 points of `img_scheme.jpg`)

| # | Step                                    | Where                                          |
|---|------------------------------------------|-------------------------------------------------|
| 1 | SAE requests a QKD key from the KME      | `sae_API.SAEClient` (ETSI 014 API)             |
| 2 | PQC **ML-KEM-768** establishment (liboqs) + `key_ID` notification | `crypto_hybrid.PqcResponder` / `pqc_initiator_encapsulate` |
| 3 | `final_key = HKDF(PQC_key ⊕ QKD_key)`    | `crypto_hybrid.combine_keys`                   |
| 4 | **WireGuard** tunnel, PSK = final_key    | `wireguard.bring_up` (ChaCha20-Poly1305)       |

**Why does the key go into the WireGuard PresharedKey?** WireGuard performs
its own handshake (Noise/Curve25519) and derives its own ChaCha20 keys
itself: it cannot be forced to use a given session key. The PSK is the only
injection point for an external secret, mixed into the handshake. Result:
ChaCha20-Poly1305 traffic **and** security that also depends on the hybrid
QKD+PQC secret. The PSK is never transmitted: it is recomputed identically
on both sides.

**Hybrid model**: the combined secret remains secure as long as **at least
one** of the two channels holds (QKD covers a possible failure of ML-KEM;
PQC covers a compromise of the QKD link/store).

## Authentication

Two links are authenticated, for all site replications (2 sites as well as
N sites):

| Link                | Mechanism                                     | PQC dependency |
|-----------------------|------------------------------------------------|:--------------:|
| **SAE ↔ KME**        | classic mTLS (EC P-256 CA, `cryptography`)     | **none**        |
| **SAE ↔ SAE**        | **ML-DSA-65** signature (CRYSTALS-Dilithium, FIPS 204) on every message of the classic channel | yes (identity) |
| KME ↔ KME (internal) | unchanged, plaintext HTTP — out of scope       | none            |

- **SAE ↔ KME**: the KME exposes two ports — an **external** port
  (`KME_PORT`, 8000) reserved for SAEs, using mutual TLS
  (`ssl.CERT_REQUIRED`): an SAE without a valid client certificate (signed
  by the network's CA) simply cannot establish the connection. This is
  **deliberately 100% classical** (EC P-256, no dependency on liboqs on the
  KME side) — this is precisely the link that must NOT rely on PQC. A
  separate **internal** port (`KME_INTERNAL_PORT`, 8001) remains plain HTTP
  for KME↔KME replication (`ForwardingModule`), unchanged.
- **SAE ↔ SAE**: every message on the classic channel (`key_ID`
  notification, PQC public key, ciphertext, WireGuard public keys) is
  signed with **ML-DSA-65** by the sender
  (`sae_API.AuthenticatedChannel.put_signed`) and verified by the recipient
  (`get_verified`) against the peer's identity certificate (`pqc_cert.py`),
  itself signed by a local ML-DSA CA for the simulated network. Without
  this signature, a third party with access to the shared volume could
  substitute their own PQC public key (MITM); with it, any substitution is
  detected and rejects the establishment of the hybrid key.

### PKI (`pki_setup.py`)

A `pki-init` service (based on the SAE image, which already embeds liboqs +
`cryptography`) generates, once only, in `./certs/` (mounted on the host):

```
certs/tls/ca.crt, ca.key            # classic EC P-256 CA (mTLS SAE<->KME)
certs/tls/kme_<site>.crt/.key       # server identity of each KME
certs/tls/sae_<site>.crt/.key       # client identity of each SAE
certs/pqc/ca_pub.key, ca_priv.key   # ML-DSA-65 CA (SAE<->SAE)
certs/pqc/public/sae_<site>.cert.json   # public ML-DSA certificate per SAE
certs/pqc/private/sae_<site>.key        # private ML-DSA key per SAE
```

Idempotent: rerunning `pki-init` (e.g. after adding a site) does not
regenerate CAs/certs that already exist. All the `docker compose up`
commands below automatically start `pki-init` before the KME/SAE services
(`depends_on: condition: service_completed_successfully`).

## Prerequisites

- Docker + Docker Compose. The SAEs need the **NET_ADMIN** capability
  (already declared in the compose files) to create the WireGuard
  interface.
- The SAE image compiles **liboqs** (ML-KEM-768) and installs
  **wireguard-tools** at build time: the first build is a bit long.

## Option A — Automatic hybrid demo with 2 sites (Figure 2 + 4 points)

```bash
docker compose -f docker-compose_demo.yml up --build
# SAE_A (master) and SAE_B (slave): QKD key -> PQC -> XOR -> wg0 tunnel.
docker compose -f docker-compose_demo.yml logs sae-a sae-b   # identical PSK on both sides
docker compose -f docker-compose_demo.yml down -v
```

The classic channel (key_ID, PQC/WireGuard public keys, ciphertext) travels
through the shared `chan` volume — this is the "Step 2 (out-of-scope)" part
of the protocol.

## Option B — Interactive N-site network (Figure 1)

`docker-compose.yml` replicates 3 sites (A, B, C) in a full mesh.

```bash
python3 generate-network.py A B C            # regenerates docker-compose.yml
python3 generate-network.py A B C D E        # as many sites as needed
docker compose up --build -d
```

The SAEs stay idle (`sleep infinity`); an operation is triggered on demand.
Example: establishing the hybrid key between site A and site C.

```bash
# SAE_A (master): QKD key for SAE_C -> PQC -> XOR (KME A replicates to KME C)
docker compose exec -e SAE_ROLE=master -e PEER_SAE_ID=SAE_C -e HYBRID=1 \
  -e WG_LOCAL_IP=10.9.0.1/24 -e WG_PEER_ENDPOINT=sae-c:51820 \
  -e WG_PEER_ALLOWED_IPS=10.9.0.3/32 sae-a python sae_API.py

# SAE_C (slave): same hybrid key, brings up its end of the tunnel
docker compose exec -e SAE_ROLE=slave -e PEER_SAE_ID=SAE_A -e HYBRID=1 \
  -e WG_LOCAL_IP=10.9.0.3/24 -e WG_PEER_ENDPOINT=sae-a:51820 \
  -e WG_PEER_ALLOWED_IPS=10.9.0.1/32 sae-c python sae_API.py
```

**Plain ETSI** mode (no hybrid, backward-compatible): omit `HYBRID=1`.
An uninvolved site attempting `dec_keys` with the same `key_ID` gets a 400
error: each KME only knows the keys intended for it.

```bash
docker compose down -v      # stop + cleanup
```

## Quick test outside Docker

```bash
python3 crypto_hybrid.py    # replays points 2+3 (if liboqs is present)
python3 sae_API.py          # in-memory KME demo (point 1, +2/3 if liboqs)
```

## SAE Environment Variables (hybrid mode)

| Variable               | Role                                                   |
|-------------------------|---------------------------------------------------------|
| `SAE_ROLE`             | `master` or `slave`                                    |
| `HYBRID=1`             | enables points 2→4 (otherwise ETSI only)                |
| `CHANNEL_DIR`          | directory of the classic channel (shared volume)        |
| `WG_LOCAL_IP`          | internal tunnel IP, e.g. `10.9.0.1/24`                  |
| `WG_LISTEN_PORT`       | WireGuard UDP port (default 51820)                      |
| `WG_PEER_ENDPOINT`     | peer's `host:port`                                      |
| `WG_PEER_ALLOWED_IPS`  | allowed network behind the peer, e.g. `10.9.0.2/32`      |

## Disclaimer

Demonstration project: quantum generation, reconciliation, and privacy
amplification are out of scope (ETSI clause 1) and **simulated**. The key
stub and the file-based channel are not suitable for real-world use.
