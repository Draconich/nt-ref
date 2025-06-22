#!/usr/bin/env python3
import argparse
import configparser
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
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
# The directory containing this script file
SCRIPT_DIR = Path(__file__).resolve().parent
# The project's root directory (one level up from 'scripts')
BASE_DIR = SCRIPT_DIR.parent
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

def decrypt_payload(encrypted_payload_hex: str, key: str) -> str:
    """Decrypts a hex-encoded payload using OpenSSL via stdin."""
    logging.info("Decrypting payload (hex -> base64 -> binary).")
    
    try:
        # Step 1: Decode the hex string back to the original Base64 bytes.
        encrypted_payload_b64_bytes = bytes.fromhex(encrypted_payload_hex)
        logging.info("Hex payload decoded back to Base64 bytes.")

    except (ValueError, TypeError) as e:
        raise ServerManagerError(f"Failed to decode hex payload: {e}")

    command = ["openssl", "enc", "-d", "-aes-256-cbc", "-a", "-pbkdf2", "-md", "sha256", "-pass", f"pass:{key}"]
    
    try:
        # Step 2: Pass the Base64 bytes directly to the command's stdin.
        process = subprocess.run(
            command,
            input=encrypted_payload_b64_bytes, # Pass bytes to stdin
            capture_output=True,
            check=True
            # --- FIX IS HERE: REMOVED text=True ---
            # text=False is the default. It expects bytes and returns bytes.
        )
        # Since stdout is now bytes, we must decode it to a string.
        return process.stdout.decode('utf-8').strip()
            
    except subprocess.CalledProcessError as e:
        # stderr is also bytes now, so we must decode it for the error message.
        stderr_decoded = e.stderr.decode('utf-8').strip() if e.stderr else "No stderr output."
        full_command_str = " ".join(command)
        raise ServerManagerError(f"Payload decryption failed. Command: '{full_command_str}'. Error: {stderr_decoded}")
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
    # Use SCRIPT_DIR to ensure the path is always relative to this file's location.
    warp_script_path = SCRIPT_DIR / 'warp_registrar.py'
    run_command(f"python3 {warp_script_path} > warp-data.json")
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
    xray_executable_path = BASE_DIR / "bin/xray"
    run_command(f"sudo {xray_executable_path} run -c {final_config_path}")
    run_command("sleep 365d")


def main() -> None:
    """Main entry point for the server manager script."""
    try:
        # --- Step 1: Get all configuration from environment variables ---
        logging.info("--- Step 1: Reading environment variables ---")
        encryption_key = get_env_or_fail("GHA_PAYLOAD_KEY")
        
        mode = get_env_or_fail("INPUT_MODE")
        encrypted_payload = get_env_or_fail("INPUT_CLIENT_INFO_PAYLOAD")
        
        wg_private_key = os.getenv("WG_PRIVATE_KEY")
        xray_uuid = os.getenv("XRAY_UUID")
        
        logging.info(f"Mode received: '{mode}'")
        logging.info(f"Encrypted payload received (length: {len(encrypted_payload)})")

 
        logging.info("--- Step 2: Validating mode-specific secrets ---")
        if mode in ["direct-connect", "hole-punch"]:
            if not wg_private_key:
                raise ServerManagerError("WG_PRIVATE_KEY secret is not set, but is required for WireGuard modes.")
        elif mode == "xray":
            if not xray_uuid:
                raise ServerManagerError("XRAY_UUID secret is not set, but is required for Xray mode.")
        logging.info("Mode-specific secrets are present.")


        logging.info("--- Step 3: Attempting decryption ---")
        decrypted_payload = decrypt_payload(encrypted_payload, encryption_key)
        
        logging.info("--- Step 4: Decryption successful! Parsing client info. ---")
        parts = decrypted_payload.split(":")
        if not (2 <= len(parts) <= 3):
            raise ServerManagerError("Decrypted payload has incorrect format.")
        
        client_info = ClientInfo(
            ip=parts[0],
            port=int(parts[1]),
            local_port=int(parts[2]) if len(parts) > 2 else None
        )

        logging.info(f"--- Step 5: Setting up mode '{mode}' ---")
        setup_common_environment()

        if mode == "direct-connect":
            setup_wireguard_client(client_info, wg_private_key)
        elif mode == "hole-punch":
            setup_wireguard_server(client_info, wg_private_key)
        elif mode == "xray":
            setup_xray(client_info, cast(str, xray_uuid))

    except (ServerManagerError, FileNotFoundError) as e:
        logging.error(f"A critical error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)
        
if __name__ == "__main__":
    main()
