#!/usr/bin/env python3
import argparse
import configparser
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypedDict, cast

# --- Configuration ---
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
STUN_SERVER = "stun.l.google.com:19302"
WG_SERVER_PORT = 443
WG_SERVER_IP = "192.168.166.1"
WG_CLIENT_IP = "192.168.166.2"

# --- Setup ---
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"

# --- Type Definitions for JSON data ---
class WarpData(TypedDict):
    private_key: str
    public_key: str
    address_v4: str
    endpoint_v4: str
    reserved_dec: list[int]

class XrayWgPeer(TypedDict):
    publicKey: str
    endpoint: str

class XrayWgSettings(TypedDict):
    secretKey: str
    address: list[str]
    peers: list[XrayWgPeer]
    reserved: list[int]

class XrayVlessUser(TypedDict):
    id: str

class XrayVlessVnext(TypedDict):
    address: str
    users: list[XrayVlessUser]

class XrayVlessSettings(TypedDict):
    vnext: list[XrayVlessVnext]

# An outbound can be one of many types. Using a dictionary is the most practical approach.
# We suppress the strict 'reportExplicitAny' warning because the heterogeneity of the
# 'outbounds' list makes perfect typing overly verbose and impractical.
Outbound = dict[str, Any]  # pyright: ignore[reportExplicitAny]

class XrayConfig(TypedDict):
    outbounds: list[Outbound]

# --- Dataclass for Client Info ---
@dataclass
class ClientInfo:
    """Holds information about the connecting client."""
    ip: str
    port: int
    local_port: int | None = None

class ServerManagerError(Exception):
    """Custom exception for server-side errors."""
    pass

def run_command(command: str) -> None:
    """Helper to run a shell command and log its output."""
    logging.info(f"Executing: {command}")
    try:
        _ = subprocess.run(command, shell=True, check=True, text=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with exit code {e.returncode}")
        raise ServerManagerError(f"Execution failed for command: {command}") from e

def get_env_or_fail(var_name: str) -> str:
    """Gets an environment variable or exits if not found."""
    value = os.getenv(var_name)
    if not value:
        raise ServerManagerError(f"Required environment variable '{var_name}' is not set.")
    return value

def decrypt_payload(encrypted_payload: str, key: str) -> str:
    """Decrypts a payload using OpenSSL."""
    logging.info("Decrypting payload from commit message.")
    command = ["openssl", "enc", "-d", "-aes-256-cbc", "-a", "-pbkdf2", "-pass", f"pass:{key}"]
    try:
        process = subprocess.run(command, input=encrypted_payload, capture_output=True, text=True, check=True)
        return process.stdout.strip()
    except subprocess.CalledProcessError as e:
        stderr_typed = cast(str | None, e.stderr)
        error_msg = stderr_typed.strip() if stderr_typed else ""
        raise ServerManagerError(f"Payload decryption failed: {error_msg}")

def parse_commit(commit_message: str) -> tuple[str, str]:
    """Parses the commit message to get the mode and encrypted payload."""
    match = re.match(r"^(DT|HP|XR): (.+)$", commit_message)
    if not match:
        raise ServerManagerError("Commit message does not match expected format '[DT|HP|XR]: <payload>'.")
    
    mode_map = {"DT": "direct-connect", "HP": "hole-punch", "XR": "xray"}
    mode = mode_map[match.group(1)]
    payload = match.group(2)
    logging.info(f"Detected mode: {mode}")
    return mode, payload

def setup_common_environment() -> None:
    """Sets up SSH keys and IP forwarding."""
    logging.info("Configuring common environment settings.")
    auth_keys_file = BASE_DIR / "authorized_keys"
    if auth_keys_file.exists():
        run_command(f"sudo mkdir -p /root/.ssh && sudo cp {auth_keys_file} /root/.ssh/authorized_keys")
    run_command("sudo sysctl -w net.ipv4.ip_forward=1")

def setup_wireguard_client(client: ClientInfo, private_key: str) -> None:
    """Configures the Action as a WireGuard CLIENT connecting OUT to the user."""
    logging.info("Setting up AmneziaWG in CLIENT mode (direct-connect).")
    config = configparser.ConfigParser()
    template_path = CONFIG_DIR / "wg_client.conf"
    if not template_path.exists():
        raise ServerManagerError(f"Client config template not found: {template_path}")
    _ = config.read(template_path)

    config["Interface"]["PrivateKey"] = private_key
    config["Peer"]["Endpoint"] = f"{client.ip}:{client.port}"

    final_config_path = BASE_DIR / "wg0-final.conf"
    with open(final_config_path, "w") as f:
        config.write(f)
    logging.info(f"Final client config written to {final_config_path}")

    run_command(f"sudo amneziawg-go wg0")
    run_command(f"sudo wg setconf wg0 {final_config_path}")
    run_command(f"sudo ip link set dev wg0 up")
    run_command("sudo iptables -A FORWARD -i wg0 -j ACCEPT")
    run_command("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    
    logging.info("AmneziaWG (Client) is up and running.")
    run_command("sleep 365d")

def setup_wireguard_server(client: ClientInfo, private_key: str) -> None:
    """Configures the Action as a WireGuard SERVER listening for the user."""
    logging.info("Setting up AmneziaWG in SERVER mode (hole-punch).")
    config = configparser.ConfigParser()
    template_path = CONFIG_DIR / "wg_server.conf"
    if not template_path.exists():
        raise ServerManagerError(f"Server config template not found: {template_path}")
    _ = config.read(template_path)

    config["Interface"]["PrivateKey"] = private_key

    final_config_path = BASE_DIR / "wg0-final.conf"
    with open(final_config_path, "w") as f:
        config.write(f)
    logging.info(f"Final server config written to {final_config_path}")

    logging.info("Detecting server's external IP and port mapping via STUN...")
    stun_cmd = f"sudo stun -v {STUN_SERVER} -p {WG_SERVER_PORT}"
    result = subprocess.run(stun_cmd, shell=True, capture_output=True, text=True)
    output = result.stdout + result.stderr
    mapped_addr_match = re.search(r"MappedAddress.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", output)
    if not mapped_addr_match:
        raise ServerManagerError("Could not determine server's external mapping via STUN.")
    server_ext_ip, server_ext_port = mapped_addr_match.groups()
    logging.info(f"Server mapped to {server_ext_ip}:{server_ext_port}")

    logging.info(f"Starting NAT punch towards client at {client.ip}:{client.port}")
    punch_cmd = (f"sudo nping --udp --ttl 4 --no-capture --source-port {WG_SERVER_PORT} "
                 f"--count 20 --delay 28s --dest-port {client.port} {client.ip} &")
    run_command(punch_cmd)

    user_client_config = f"""
[Interface]
# This is YOUR local configuration. Save as wg_user.conf
ListenPort = {client.local_port}
Address = {WG_CLIENT_IP}/30
PrivateKey = <YOUR_CLIENT_PRIVATE_KEY>

[Peer]
PublicKey = {config['Peer']['PublicKey']}
Endpoint = {server_ext_ip}:{server_ext_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    logging.info("--- USER CLIENT WG CONFIGURATION (for hole-punch) ---")
    print(user_client_config)
    logging.info("-----------------------------------------------------")

    run_command(f"sudo amneziawg-go wg0")
    run_command(f"sudo wg setconf wg0 {final_config_path}")
    run_command(f"sudo ip link set dev wg0 up")
    run_command("sudo iptables -A FORWARD -i wg0 -j ACCEPT")
    run_command("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    
    logging.info("AmneziaWG (Server) is up and running.")
    run_command("sleep 365d")

def setup_xray(client: ClientInfo, uuid: str) -> None:
    """Configures and runs the Xray server."""
    logging.info("Setting up Xray server.")
    run_command("sudo sysctl -w net.core.default_qdisc=fq")
    run_command("sudo sysctl -w net.ipv4.tcp_congestion_control=bbr")
    logging.info("Fetching WARP registration data...")
    run_command(f"python3 {BASE_DIR / 'scripts/warp_registrar.py'} > warp-data.json")
    with open("warp-data.json") as f:
        warp_data = cast(WarpData, json.load(f))

    config_path = CONFIG_DIR / "bridge_with_warp.json"
    with open(config_path) as f:
        xray_config = cast(XrayConfig, json.load(f))

    vless_outbound_settings = cast(XrayVlessSettings, xray_config["outbounds"][0]["settings"])
    vless_outbound_settings["vnext"][0]["address"] = client.ip
    vless_outbound_settings["vnext"][0]["users"][0]["id"] = uuid
    
    wg_outbound_untyped = next(o for o in xray_config["outbounds"] if o.get("protocol") == "wireguard")
    wg_settings = cast(XrayWgSettings, wg_outbound_untyped["settings"])
    
    wg_settings["secretKey"] = warp_data["private_key"]
    wg_settings["address"] = [warp_data["address_v4"]]
    wg_settings["peers"][0]["publicKey"] = warp_data["public_key"]
    wg_settings["peers"][0]["endpoint"] = warp_data["endpoint_v4"]
    wg_settings["reserved"] = warp_data["reserved_dec"]
    
    final_config_path = BASE_DIR / "bridge-final.json"
    with open(final_config_path, "w") as f:
        json.dump(xray_config, f, indent=2)
    
    logging.info("Xray configuration generated successfully.")
    run_command(f"sudo xray run -c {final_config_path}")
    run_command("sleep 365d")

def main() -> None:
    """Main entry point for the server manager script."""
    parser = argparse.ArgumentParser(description="GitHub Actions Server Manager")
    _ = parser.add_argument("--commit-message", required=True, help="The git commit message that triggered the action.")
    args = parser.parse_args()

    try:
        encryption_key = get_env_or_fail("GHA_PAYLOAD_KEY")
        wg_private_key = os.getenv("WG_PRIVATE_KEY")
        xray_uuid = os.getenv("XRAY_UUID")

        commit_message = cast(str, args.commit_message)
        mode, encrypted_payload = parse_commit(commit_message)
        decrypted_payload = decrypt_payload(encrypted_payload, encryption_key)
        
        parts = decrypted_payload.split(":")
        if not (2 <= len(parts) <= 3):
            raise ServerManagerError("Decrypted payload has incorrect format.")
        
        client_info = ClientInfo(
            ip=parts[0],
            port=int(parts[1]),
            local_port=int(parts[2]) if len(parts) > 2 else None
        )

        setup_common_environment()

        if mode in ["direct-connect", "hole-punch"]:
            if not wg_private_key:
                raise ServerManagerError("WG_PRIVATE_KEY is required for this mode.")
            if mode == "direct-connect":
                setup_wireguard_client(client_info, wg_private_key)
            else: # hole-punch
                setup_wireguard_server(client_info, wg_private_key)
        elif mode == "xray":
            if not xray_uuid:
                raise ServerManagerError("XRAY_UUID is required for this mode.")
            setup_xray(client_info, xray_uuid)
        else:
            raise ServerManagerError(f"Unknown mode '{mode}' derived from commit message.")

    except (ServerManagerError, FileNotFoundError) as e:
        logging.error(f"A critical error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
