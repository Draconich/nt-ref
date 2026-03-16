#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

# This line is crucial for running the script directly.
sys.path.append(str(Path(__file__).resolve().parent.parent))

from gh_runner_service.common.utils import check_dependencies, get_env_or_fail, ensure_apt_command_installed, ensure_pip_package
from gh_runner_service.common.crypto import encrypt_payload, decrypt_payload
from gh_runner_service.common.exceptions import AppError

# Dynamically install/check dependencies
ensure_pip_package("requests")
import requests
from gh_runner_service.common.gist import create_gist, read_gist, delete_gist

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

ENCRYPTION_KEY_ENV_VAR = "GHA_PAYLOAD_KEY"
STUN_SERVER = "stun.l.google.com:19302"


def get_public_ip() -> str:
    """Fetches the public IP from Cloudflare's diagnostic endpoint."""
    logging.info("Fetching public IP from Cloudflare trace...")
    try:
        response = requests.get("https://www.cloudflare.com/cdn-cgi/trace", timeout=10)
        response.raise_for_status()
        ip_match = re.search(r'^ip=(.+)$', response.text, re.MULTILINE)
        if not ip_match:
            raise AppError("Could not parse IP from Cloudflare trace response.")
        ip = ip_match.group(1).strip()
        logging.info(f"Detected public IP: {ip}")
        return ip
    except (requests.exceptions.RequestException, IndexError) as e:
        raise AppError(f"Could not fetch public IP from Cloudflare: {e}")


def run_stun_client(local_port: int) -> tuple[str, str]:
    """Runs the STUN client to determine external IP and mapped port (Legacy mode)."""
    logging.info(f"Running STUN client on local port {local_port}...")
    stun_cmd = f"stun -v {STUN_SERVER} -p {local_port}"
    result = subprocess.run(shlex.split(stun_cmd), capture_output=True, text=True, timeout=15)
    output = result.stdout + result.stderr
    if result.returncode > 10 or not output.strip():
        raise AppError(f"STUN client execution failed. Exit Code: {result.returncode}")

    mapped_addr_match = re.search(r"MappedAddress = (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)", output)
    nat_type_match = re.search(r"Primary: (.*)", output)
    if not mapped_addr_match or not nat_type_match:
        raise AppError("Could not parse STUN client output.")

    ipport = mapped_addr_match.group(1)
    nat_type = nat_type_match.group(1).strip()
    logging.info(f"STUN result: Mapped Address = {ipport}, NAT Type = {nat_type}")
    return ipport, nat_type


def main() -> None:
    """Main entry point for the V2 client."""
    check_dependencies("gh")

    parser = argparse.ArgumentParser(description="V2 Client for GitHub Actions NAT traversal.")
    _ = parser.add_argument(
        "mode",
        choices=["direct-connect", "hole-punch", "auto-hole-punch", "auto-hole-punch-warp", "xray", "xray-direct", "direct-connect-warp"],
        help="The operational mode."
    )
    _ = parser.add_argument(
        "--repo",
        help="The GitHub repository in 'owner/repo' format. Defaults to GH_REPO env var."
    )
    args = parser.parse_args()
    mode = cast(str, args.mode)
    repo = cast(str | None, args.repo) or get_env_or_fail("GH_REPO")

    run_id: int | None = None
    gist_id: str | None = None
    punch_proc: subprocess.Popen[str] | None = None

    try:
        encryption_key = get_env_or_fail(ENCRYPTION_KEY_ENV_VAR)
        github_token = os.environ.get("GH_PAT") or os.environ.get("GITHUB_TOKEN")
        if not github_token:
            raise AppError("Required environment variable 'GH_PAT' or 'GITHUB_TOKEN' is not set.")

        while True:
            try:
                logging.info(f"Preparing to trigger V2 workflow in '{mode}' mode.")
                payload_str = ""

                # --- Логика для разных режимов ---
                if mode in ["auto-hole-punch", "auto-hole-punch-warp"]:
                    check_dependencies("wg", "wg-quick")
                    ensure_apt_command_installed("stun", "stun-client")
                    ensure_apt_command_installed("nc", "netcat")

                    conf_path = Path("wg-gha.conf").resolve()
                    subprocess.run(["sudo", "wg-quick", "down", str(conf_path)], stderr=subprocess.DEVNULL)
                    
                    local_port = 20000 + (os.getpid() % 10000)
                    logging.info(f"Detecting external mapping for local port {local_port}...")
                    stun_cmd = f"stun -v {STUN_SERVER} -p {local_port}"
                    result = subprocess.run(shlex.split(stun_cmd), capture_output=True, text=True, check=True)
                    output = result.stdout + result.stderr
                    mapped_addr_match = re.search(r"MappedAddress.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", output)
                    if not mapped_addr_match:
                        raise AppError("Could not parse STUN output.")
                    ext_ip, ext_port_str = mapped_addr_match.groups()
                    
                    logging.info("Starting background NAT keep-alive punch...")
                    punch_cmd_str = f"while true; do echo -n 'punch' | nc -u -p {local_port} 3.3.3.3 443; sleep 10; done"
                    punch_proc = subprocess.Popen(punch_cmd_str, shell=True, preexec_fn=os.setsid)
                    
                    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
                    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
                    
                    client_data = json.dumps({"client_ip": ext_ip, "client_port": int(ext_port_str), "client_pub": pub})
                    enc_data = encrypt_payload(client_data, encryption_key)
                    gist_id = create_gist(github_token, enc_data)
                    payload_str = f"gist:{gist_id}"

                elif mode == "hole-punch":
                    ensure_apt_command_installed("stun", "stun-client")
                    ensure_apt_command_installed("nc", "netcat")
                    local_port = 20000 + (os.getpid() % 10000)
                    ipport, _ = run_stun_client(local_port)
                    payload_str = f"{ipport}:{local_port}"
                else: # direct-connect, xray, etc.
                    ip = get_public_ip()
                    payload_str = f"{ip}:443"

                # --- Общая часть для всех режимов ---
                encrypted_payload = encrypt_payload(payload_str, encryption_key)
                client_info_json = json.dumps({"payload_b64": encrypted_payload})

                logging.info("Triggering V2 workflow via 'gh'...")
                trigger_command = ['gh', 'workflow', 'run', 'v2_workflow.yml', '--repo', repo, '--field', f'mode={mode}', '--field', f'client_info_json={client_info_json}', '--ref', 'main']
                subprocess.run(trigger_command, check=True, capture_output=True)
                logging.info("Workflow triggered successfully.")

                logging.info("Waiting 15 seconds for the new run to appear...")
                time.sleep(15)

                # --- Логика ПОСЛЕ запуска ---
                if mode in ["auto-hole-punch", "auto-hole-punch-warp"] and gist_id:
                    runner_data = None
                    for _ in range(60): # Ждем до 10 минут
                        time.sleep(10)
                        try:
                            content = read_gist(github_token, gist_id)
                            if content != enc_data:
                                runner_data = json.loads(decrypt_payload(content, encryption_key))
                                break
                        except Exception as e:
                            logging.warning(f"Error reading Gist: {e}")
                            
                    delete_gist(github_token, gist_id); gist_id = None
                    
                    if punch_proc:
                        os.killpg(os.getpgid(punch_proc.pid), subprocess.signal.SIGTERM)
                        punch_proc = None
                    
                    if not runner_data:
                        raise AppError("Timeout waiting for runner configuration.")
                    
                    conf_path = Path("wg-gha.conf").resolve()
                    conf_content = f"""[Interface]
PrivateKey = {priv}
ListenPort = {local_port}
Address = 192.168.166.2/32
DNS = 1.1.1.1
MTU = 1360

[Peer]
PublicKey = {runner_data['runner_pub']}
Endpoint = {runner_data['runner_ip']}:{runner_data['runner_port']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
                    conf_path.write_text(conf_content)
                    subprocess.run(["sudo", "wg-quick", "up", str(conf_path)], check=True)
                    logging.info("✅ Tunnel is UP! Check your IP with 'curl ipinfo.io'")

                # Ждем 6 часов до следующего цикла
                wait_duration = 6 * 3600
                logging.info(f"Waiting for {wait_duration / 3600:.1f} hours. Press Ctrl+C to exit.")
                time.sleep(wait_duration)
                
                if mode in ["auto-hole-punch", "auto-hole-punch-warp"]:
                     subprocess.run(["sudo", "wg-quick", "down", str(Path("wg-gha.conf").resolve())], stderr=subprocess.DEVNULL)


            except (AppError, subprocess.CalledProcessError) as e:
                logging.error(f"An error occurred in the loop: {e}")
                if gist_id:
                    try: delete_gist(github_token, gist_id)
                    except: pass
                if punch_proc:
                    os.killpg(os.getpgid(punch_proc.pid), subprocess.signal.SIGTERM)
                    punch_proc = None
                time.sleep(60)

    except KeyboardInterrupt:
        logging.info("\nExiting gracefully...")
        if punch_proc:
            os.killpg(os.getpgid(punch_proc.pid), subprocess.signal.SIGTERM)
        if gist_id:
            try: delete_gist(github_token, gist_id)
            except: pass
        if mode in ["auto-hole-punch", "auto-hole-punch-warp"]:
            subprocess.run(["sudo", "wg-quick", "down", str(Path("wg-gha.conf").resolve())], stderr=subprocess.DEVNULL)
        sys.exit(0)

if __name__ == "__main__":
    main()
