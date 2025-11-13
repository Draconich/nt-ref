# gh_runner_service/services/wireguard.py
import configparser
import logging
import re
import time
import json
from pathlib import Path

from ..common.exceptions import AppError
from ..common.models import ClientInfo
from ..common.utils import run_command, run_background_command
# NEW: Import the WARP config fetcher
from .cloudflare_warp import get_warp_config

# Constants
STUN_SERVER = "stun.l.google.com:19302"
WG_SERVER_PORT = 443
WG_SERVER_IP = "192.168.166.1"
WG_CLIENT_IP = "192.168.166.2"


def setup_client_mode(client: ClientInfo, private_key: str, base_dir: Path, config_dir: Path) -> None:
    logging.info("Setting up WireGuard in CLIENT mode (direct-connect).")
    config = configparser.ConfigParser()
    template_path = config_dir / "wg_client.conf"
    if not template_path.exists():
        raise AppError(f"Client config template not found: {template_path}")
    _ = config.read(template_path)
    config["Interface"]["PrivateKey"] = private_key
    config["Peer"]["Endpoint"] = f"{client.ip}:{client.port}"
    final_config_path = base_dir / "wg0-final.conf"
    with open(final_config_path, "w") as f:
        config.write(f)
    logging.info(f"Final client config written to {final_config_path}")

    logging.info("Starting amneziawg-go userspace daemon for wg0...")
    _ = run_background_command("bin/amneziawg-go -f wg0")

    logging.info("Configuring the userspace tunnel...")
    _ = run_command(f"ip address add dev wg0 {WG_CLIENT_IP}/30")
    _ = run_command(f"ip link set up dev wg0")
    _ = run_command(f"wg setconf wg0 {final_config_path}")

    logging.info("Detecting primary network interface using JSON output...")
    get_iface_cmd = "ip -j route show default"
    result = run_command(get_iface_cmd)

    try:
        route_info = json.loads(result.stdout)
        primary_interface = route_info[0]['dev']
    except (json.JSONDecodeError, IndexError, KeyError) as e:
        raise AppError(f"Could not parse primary interface from JSON output: {result.stdout}") from e

    logging.info(f"Detected primary network interface: {primary_interface}")

    _ = run_command("iptables -A FORWARD -i wg0 -j ACCEPT")
    _ = run_command("iptables -A FORWARD -o wg0 -j ACCEPT")
    _ = run_command(f"iptables -t nat -A POSTROUTING -o {primary_interface} -j MASQUERADE")
    logging.info("WireGuard (Client) is up and running.")
    _ = run_command("sleep 365d")


# NEW: The complete function for the A -> B -> C chained tunnel
def setup_client_warp_mode(client: ClientInfo, private_key: str, base_dir: Path, config_dir: Path) -> None:
    """
    Sets up a chained WireGuard connection: Client (A) -> Runner (B) -> WARP (C).
    Uses source-based policy routing on the Runner (B) to avoid routing loops.
    """
    logging.info("Setting up WireGuard in CLIENT+WARP mode (A -> B -> C).")

    # --- Part 1: Setup wg0 (A -> B tunnel, reverse connect) ---
    logging.info("--- Configuring wg0 (A -> B) tunnel ---")
    wg0_config = configparser.ConfigParser()
    wg0_template_path = config_dir / "wg_client.conf"
    if not wg0_template_path.exists():
        raise AppError(f"Client config template not found: {wg0_template_path}")
    _ = wg0_config.read(wg0_template_path)
    wg0_config["Interface"]["PrivateKey"] = private_key
    wg0_config["Peer"]["Endpoint"] = f"{client.ip}:{client.port}"
    wg0_final_config_path = base_dir / "wg0-final.conf"
    with open(wg0_final_config_path, "w") as f:
        wg0_config.write(f)

    logging.info("Starting amneziawg-go daemon for wg0...")
    _ = run_background_command("bin/amneziawg-go -f wg0")
    time.sleep(1) # Give the daemon a moment to start
    _ = run_command(f"ip address add dev wg0 {WG_CLIENT_IP}/30")
    _ = run_command("ip link set up dev wg0")
    _ = run_command(f"wg setconf wg0 {wg0_final_config_path}")
    logging.info("wg0 interface is configured.")

    # --- Part 2: Setup wg1 (B -> C tunnel, to WARP) ---
    logging.info("--- Configuring wg1 (B -> C) tunnel ---")
    logging.info("Fetching WARP configuration...")
    warp_config = get_warp_config()

    wg1_config = configparser.ConfigParser()
    wg1_template_path = config_dir / "wg_warp_client.conf"
    if not wg1_template_path.exists():
        raise AppError(f"WARP client config template not found: {wg1_template_path}")
    _ = wg1_config.read(wg1_template_path)
    wg1_config["Interface"]["PrivateKey"] = warp_config.private_key
    wg1_config["Interface"]["Address"] = warp_config.address_v4
    wg1_config["Peer"]["PublicKey"] = warp_config.public_key
    wg1_config["Peer"]["Endpoint"] = warp_config.endpoint_v4
    wg1_final_config_path = base_dir / "wg1-final.conf"
    with open(wg1_final_config_path, "w") as f:
        wg1_config.write(f)

    logging.info("Starting amneziawg-go daemon for wg1...")
    _ = run_background_command("bin/amneziawg-go -f wg1")
    time.sleep(1) # Give the daemon a moment to start
    _ = run_command(f"ip address add dev wg1 {warp_config.address_v4}")
    _ = run_command("ip link set up dev wg1")
    _ = run_command(f"wg setconf wg1 {wg1_final_config_path}")
    logging.info("wg1 interface is configured.")

    # --- Part 3: Implement Source-Based Policy Routing ---
    logging.info("--- Implementing source-based policy routing ---")
    TABLE_ID = "101"
    TABLE_NAME = "from_A_via_C"

    # 1. Create a new routing table
    _ = run_command(f'bash -c "echo \'{TABLE_ID} {TABLE_NAME}\' >> /etc/iproute2/rt_tables"')
    logging.info(f"Added custom routing table '{TABLE_NAME}' ({TABLE_ID}).")

    # 2. Add a policy rule to direct traffic FROM Host A's tunnel IP into the new table
    # This is the key to split-tunneling: only this specific source is affected.
    _ = run_command(f"ip rule add from {WG_CLIENT_IP}/32 table {TABLE_NAME}")
    logging.info(f"Added rule: traffic from {WG_CLIENT_IP} now uses table {TABLE_NAME}.")

    # 3. Populate the new table with a default route via the wg1 (WARP) interface
    _ = run_command(f"ip route add default dev wg1 table {TABLE_NAME}")
    logging.info(f"Added default route via wg1 to table {TABLE_NAME}.")

    # --- Part 4: Configure Firewall and NAT ---
    logging.info("--- Configuring iptables for forwarding and NAT ---")
    # Allow traffic to be forwarded from the client tunnel (wg0) to the WARP tunnel (wg1)
    _ = run_command("iptables -A FORWARD -i wg0 -o wg1 -j ACCEPT")
    # Allow return traffic
    _ = run_command("iptables -A FORWARD -i wg1 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT")
    # Apply NAT for traffic leaving the WARP tunnel, so it appears to come from the runner's WARP IP
    _ = run_command("iptables -t nat -A POSTROUTING -o wg1 -j MASQUERADE")
    logging.info("iptables rules applied successfully.")

    logging.info("Chained WireGuard setup is complete and running.")
    _ = run_command("sleep 365d")


def setup_server_mode(client: ClientInfo, private_key: str, base_dir: Path, config_dir: Path) -> None:
    """Configures the Action as a WireGuard SERVER listening for the user (hole-punch)."""
    logging.info("Setting up WireGuard in SERVER mode (hole-punch).")
    config = configparser.ConfigParser()
    template_path = config_dir / "wg_server.conf"
    if not template_path.exists():
        raise AppError(f"Server config template not found: {template_path}")
    _ = config.read(template_path)

    config["Interface"]["PrivateKey"] = private_key

    final_config_path = base_dir / "wg0-final.conf"
    with open(final_config_path, "w") as f:
        config.write(f)
    logging.info(f"Final server config written to {final_config_path}")

    logging.info("Detecting server's external IP and port mapping via STUN...")
    stun_cmd = f"stun -v {STUN_SERVER} -p {WG_SERVER_PORT}"
    result = run_command(stun_cmd)
    output = result.stdout + result.stderr
    mapped_addr_match = re.search(r"MappedAddress.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", output)
    if not mapped_addr_match:
        raise AppError("Could not determine server's external mapping via STUN.")
    server_ext_ip, server_ext_port = mapped_addr_match.groups()
    logging.info(f"Server mapped to {server_ext_ip}:{server_ext_port}")

    logging.info(f"Starting NAT punch towards client at {client.ip}:{client.port}")
    punch_cmd = (f"while true; do "
                 f"echo -n 'punch' | nc -u -p {WG_SERVER_PORT} {client.ip} {client.port}; "
                 f"sleep 25; "
                 f"done &")
    _ = run_command(punch_cmd)

    user_client_config = f"""[Interface]
ListenPort = {client.local_port}
Address = {WG_CLIENT_IP}/30
PrivateKey = <YOUR_CLIENT_PRIVATE_KEY_NEEDS_TO_BE_GENERATED>

[Peer]
PublicKey = {config['Peer']['PublicKey']}
Endpoint = {server_ext_ip}:{server_ext_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    logging.info("--- BEGIN WIREGUARD CLIENT CONFIG ---")
    print(user_client_config, flush=True)
    logging.info("--- END WIREGUARD CLIENT CONFIG ---")

    _ = run_command("ip link add dev wg0 type wireguard")
    _ = run_command(f"wg setconf wg0 {final_config_path}")
    _ = run_command(f"ip address add dev wg0 {WG_SERVER_IP}/30")
    _ = run_command(f"ip link set up dev wg0")
    _ = run_command("iptables -A FORWARD -i wg0 -j ACCEPT")
    _ = run_command("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")

    logging.info("WireGuard (Server) is up and running.")
