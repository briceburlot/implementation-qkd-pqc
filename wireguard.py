"""
wireguard.py — Point 4 du schéma "img_scheme".

Monte un tunnel WireGuard entre SAE_A et SAE_B en injectant la clé hybride
(PQC ⊕ QKD, cf. crypto_hybrid.combine_keys) comme **PresharedKey (PSK)**.

Pourquoi le PSK, et pas la clé de session ?
    WireGuard réalise son propre handshake (protocole Noise / Curve25519) et
    dérive lui-même ses clés de session ChaCha20-Poly1305 : on ne peut pas lui
    imposer une clé symétrique arbitraire comme clé de trafic. Le seul point
    d'injection d'un secret externe est le champ PresharedKey, qui est mélangé
    au handshake Noise. Résultat : le trafic est chiffré en ChaCha20-Poly1305
    (comme demandé au point 4) ET sa sécurité dépend AUSSI de notre secret
    hybride QKD+PQC — un attaquant doit casser Curve25519 *et* obtenir le PSK.

Prérequis (fournis par l'image Docker) :
    - paquet `wireguard-tools` (commandes `wg`, `wg-quick`) ;
    - capacité noyau NET_ADMIN (cap_add dans docker-compose) pour créer
      l'interface `wg0` et manipuler le routage.

Ce module se contente de générer la configuration et d'appeler `wg`/`ip`.
La clé statique Curve25519 de chaque SAE est générée localement ; les clés
PUBLIQUES sont échangées via le même canal classique que le key_ID (hors
périmètre au sens ETSI). Le PSK, lui, n'est JAMAIS transmis : il est recalculé
de façon identique des deux côtés à partir de QKD+PQC.
"""

import ipaddress
import shutil
import subprocess


def wg_tools_available():
    """True si les commandes WireGuard sont présentes dans le PATH."""
    return shutil.which("wg") is not None and shutil.which("ip") is not None


def _run(cmd, **kw):
    """Exécute une commande et lève une erreur lisible en cas d'échec."""
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


# --------------------------------------------------------------------------- #
# Génération des clés statiques Curve25519 (handshake WireGuard)               #
# --------------------------------------------------------------------------- #
def generate_keypair():
    """Retourne (private_key_b64, public_key_b64) via `wg genkey|pubkey`."""
    priv = _run(["wg", "genkey"]).stdout.strip()
    pub = _run(["wg", "pubkey"], input=priv + "\n").stdout.strip()
    return priv, pub


# --------------------------------------------------------------------------- #
# Montée / descente du tunnel                                                  #
# --------------------------------------------------------------------------- #
def bring_up(
    *,
    iface="wg0",
    private_key,
    local_ip,
    listen_port,
    peer_public_key,
    peer_psk,
    peer_endpoint,
    peer_allowed_ips,
    keepalive=25,
):
    """Crée l'interface `iface` et configure le pair avec le PSK hybride.

    Paramètres :
      private_key       : clé privée Curve25519 locale (b64)
      local_ip          : IP interne du tunnel côté local, ex "10.9.0.1/24"
      listen_port       : port UDP d'écoute WireGuard (int)
      peer_public_key   : clé publique Curve25519 du pair (b64)
      peer_psk          : PresharedKey = clé hybride QKD+PQC (b64, 32 octets)
                          -> voir crypto_hybrid.to_wireguard_psk()
      peer_endpoint     : "host:port" joignable du pair, ou None (côté passif)
      peer_allowed_ips  : réseau autorisé derrière le pair, ex "10.9.0.2/32"
      keepalive         : persistent-keepalive en secondes (traversée NAT)

    Le PSK est passé à `wg set` via un descripteur de fichier temporaire pour
    ne pas l'exposer dans la ligne de commande / la table des processus.
    """
    if not wg_tools_available():
        raise RuntimeError(
            "wireguard-tools/iproute2 absents (installés dans l'image Docker)."
        )

    ip_only = str(ipaddress.ip_interface(local_ip).ip)
    prefix = local_ip.split("/")[1] if "/" in local_ip else "24"

    # 1) interface + adresse
    _run(["ip", "link", "add", iface, "type", "wireguard"])
    _run(["ip", "address", "add", f"{ip_only}/{prefix}", "dev", iface])

    # 2) clé privée + port d'écoute (via fichiers, jamais en argv)
    import os
    import tempfile

    with tempfile.NamedTemporaryFile("w", delete=False) as kf:
        kf.write(private_key + "\n")
        key_path = kf.name
    with tempfile.NamedTemporaryFile("w", delete=False) as pf:
        pf.write(peer_psk + "\n")
        psk_path = pf.name
    try:
        _run(["wg", "set", iface,
              "listen-port", str(listen_port),
              "private-key", key_path])

        # 3) pair + PresharedKey hybride
        peer_cmd = ["wg", "set", iface,
                    "peer", peer_public_key,
                    "preshared-key", psk_path,
                    "allowed-ips", peer_allowed_ips,
                    "persistent-keepalive", str(keepalive)]
        if peer_endpoint:
            peer_cmd += ["endpoint", peer_endpoint]
        _run(peer_cmd)
    finally:
        os.unlink(key_path)
        os.unlink(psk_path)

    # 4) activation
    _run(["ip", "link", "set", "up", "dev", iface])
    return iface


def bring_down(iface="wg0"):
    """Supprime l'interface tunnel (ignore l'erreur si déjà absente)."""
    try:
        _run(["ip", "link", "del", iface])
    except subprocess.CalledProcessError:
        pass


def show(iface="wg0"):
    """Retourne la sortie de `wg show <iface>` (diagnostic)."""
    return _run(["wg", "show", iface]).stdout


def render_config(
    *,
    private_key,
    local_ip,
    listen_port,
    peer_public_key,
    peer_psk,
    peer_endpoint,
    peer_allowed_ips,
    keepalive=25,
):
    """Rend un fichier .conf équivalent (utilisable avec `wg-quick`).

    Pratique pour inspection/débogage ; `bring_up` reste la voie normale.
    """
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {local_ip}",
        f"ListenPort = {listen_port}",
        "",
        "[Peer]",
        f"PublicKey = {peer_public_key}",
        f"PresharedKey = {peer_psk}",
        f"AllowedIPs = {peer_allowed_ips}",
    ]
    if peer_endpoint:
        lines.append(f"Endpoint = {peer_endpoint}")
    lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"
