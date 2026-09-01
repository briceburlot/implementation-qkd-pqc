"""
Brings up a WireGuard tunnel between SAE_A and SAE_B, injecting the hybrid
key (PQC ⊕ QKD, cf. crypto_hybrid.combine_keys) as the **PresharedKey (PSK)**.

Why the PSK, and not the session key?
    WireGuard performs its own handshake (Noise protocol / Curve25519) and
    derives its own ChaCha20-Poly1305 session keys itself: it cannot be
    forced to use an arbitrary symmetric key as the traffic key. The only
    injection point for an external secret is the PresharedKey field, which
    is mixed into the Noise handshake. Result: traffic is encrypted with
    ChaCha20-Poly1305 (as required by point 4) AND its security ALSO depends
    on our hybrid QKD+PQC secret — an attacker must break Curve25519 *and*
    obtain the PSK.

Prerequisites (provided by the Docker image):
    - the `wireguard-tools` package (`wg`, `wg-quick` commands);
    - the NET_ADMIN kernel capability (cap_add in docker-compose) to create
      the `wg0` interface and manipulate routing.

This module only generates the configuration and calls `wg`/`ip`.
Each SAE's static Curve25519 key is generated locally; PUBLIC keys are
exchanged over the same classic channel as the key_ID (out of scope in the
ETSI sense). The PSK itself is NEVER transmitted: it is recomputed
identically on both sides from QKD+PQC.
"""

import ipaddress
import shutil
import subprocess


def wg_tools_available():
    """True if the WireGuard commands are present in the PATH."""
    return shutil.which("wg") is not None and shutil.which("ip") is not None


def _run(cmd, **kw):
    """Runs a command and raises a readable error on failure."""
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


# --------------------------------------------------------------------------- #
# Generating the static Curve25519 keys (WireGuard handshake)                  #
# --------------------------------------------------------------------------- #
def generate_keypair():
    """Returns (private_key_b64, public_key_b64) via `wg genkey|pubkey`."""
    priv = _run(["wg", "genkey"]).stdout.strip()
    pub = _run(["wg", "pubkey"], input=priv + "\n").stdout.strip()
    return priv, pub


# --------------------------------------------------------------------------- #
# Bringing the tunnel up / down                                                #
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
    """Creates the `iface` interface and configures the peer with the hybrid PSK.

    Parameters:
      private_key       : local Curve25519 private key (b64)
      local_ip          : tunnel's local internal IP, e.g. "10.9.0.1/24"
      listen_port       : WireGuard UDP listen port (int)
      peer_public_key   : peer's Curve25519 public key (b64)
      peer_psk          : PresharedKey = hybrid QKD+PQC key (b64, 32 bytes)
                          -> see crypto_hybrid.to_wireguard_psk()
      peer_endpoint     : peer's reachable "host:port", or None (passive side)
      peer_allowed_ips  : network allowed behind the peer, e.g. "10.9.0.2/32"
      keepalive         : persistent-keepalive in seconds (NAT traversal)

    The PSK is passed to `wg set` via a temporary file descriptor, to avoid
    exposing it on the command line / in the process table.
    """
    if not wg_tools_available():
        raise RuntimeError(
            "wireguard-tools/iproute2 not found (installed in the Docker image)."
        )

    ip_only = str(ipaddress.ip_interface(local_ip).ip)
    prefix = local_ip.split("/")[1] if "/" in local_ip else "24"

    # 1) interface + address
    _run(["ip", "link", "add", iface, "type", "wireguard"])
    _run(["ip", "address", "add", f"{ip_only}/{prefix}", "dev", iface])

    # 2) private key + listen port (via files, never in argv)
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

        # 3) peer + hybrid PresharedKey
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
    """Removes the tunnel interface (ignores the error if already absent)."""
    try:
        _run(["ip", "link", "del", iface])
    except subprocess.CalledProcessError:
        pass


def show(iface="wg0"):
    """Returns the output of `wg show <iface>` (diagnostics)."""
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
    """Renders an equivalent .conf file (usable with `wg-quick`).

    Handy for inspection/debugging; `bring_up` remains the normal path.
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
