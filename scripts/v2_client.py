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

from gh_runner_service.common.utils import check_dependencies, get_env_or_fail, ensure_pip_package
from gh_runner_service.common.crypto import encrypt_payload, decrypt_payload
from gh_runner_service.common.exceptions import AppError

# Dynamically install required packages if missing
ensure_pip_package("requests")
ensure_pip_package("pystun3", "stun")

import requests
import stun
from gh_runner_service.common.gist import create_gist, read_gist, delete_gist

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

ENCRYPTION_KEY_ENV_VAR = "GHA_PAYLOAD_KEY"
STUN_SERVER = "stun.l.google.com:19302"


def get_public_ip() -> str:
    """
    Fetches the public IP from Cloudflare's diagnostic endpoint.
    This is fast, reliable, and blends in with infrastructure traffic.
    """
    logging.info("Fetching public IP from Cloudflare trace...")
    try:
        response = requests.get("https://www.cloudflare.com/cdn-cgi/trace", timeout=10)
        response.raise_for_status()  # Raise an exception for bad status codes

        # The response is key-value text. We need the value from the 'ip=' line.
        ip_match = re.search(r'^ip=(.+)$', response.text, re.MULTILINE)

        if not ip_match:
            raise AppError("Could not parse IP from Cloudflare trace response.")

        ip = ip_match.group(1).strip()
        if not ip:
            raise AppError("Failed to get a valid public IP address from Cloudflare.")

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
    if "Independent Mapping" not in nat_type and "hole-punch" in sys.argv:
        raise AppError(f"Incompatible NAT type: '{nat_type}'.")
    return ipport, nat_type


def main() -> None:
    """Main entry point for the V2 client."""
    check_dependencies("gh")

    parser = argparse.ArgumentParser(description="V2 Client for GitHub Actions NAT traversal.")
    _ = parser.add_argument(
        "mode",
        choices=["direct-connect", "hole-punch", "auto-hole-punch", "xray", "xray-direct", "direct-connect-warp"],
        help="The operational mode."
    )
    _ = parser.add_argument(
        "--repo",
        help="The GitHub repository in 'owner/repo' format. Defaults to GH_REPO env var."
    )
    args = parser.parse_args()
    mode = cast(str, args.mode)
    repo_arg: str | None = cast(str | None, args.repo)

    run_id: int | None = None
    repo: str | None = None
    gist_id: str | None = None

    try:
        encryption_key = get_env_or_fail(ENCRYPTION_KEY_ENV_VAR)
        repo = repo_arg or get_env_or_fail("GH_REPO")
        
        # We need a token for both triggering the action and manipulating Gists
        github_token = os.environ.get("GH_PAT") or os.environ.get("GITHUB_TOKEN")
        if not github_token:
            raise AppError("Required environment variable 'GH_PAT' or 'GITHUB_TOKEN' is not set.")

        while True:
            gist_id = None
            try:
                logging.info(f"Preparing to trigger V2 workflow in '{mode}' mode.")
                payload_str = ""

                if mode == "auto-hole-punch":
                    check_dependencies("wg", "wg-quick")
                    
                    # 1. Generate local WireGuard keys
                    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
                    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
                    
                    # 2. Get STUN info for a dynamically chosen port via pystun3
                    local_port = 51820 + (os.getpid() % 1000)
                    logging.info(f"Resolving STUN for local port {local_port}...")
                    nat_type, ext_ip, ext_port = stun.get_ip_info("0.0.0.0", local_port, "stun.l.google.com", 19302)
                    if not ext_ip:
                        raise AppError("Failed to resolve STUN IP.")
                    time.sleep(1) # Give the OS a moment to safely release the UDP socket
                    
                    # 3. Save Client configuration to a secure Gist
                    client_data = json.dumps({"client_ip": ext_ip, "client_port": ext_port, "client_pub": pub})
                    enc_data = encrypt_payload(client_data, encryption_key)
                    gist_id = create_gist(github_token, enc_data)
                    logging.info(f"Created secure Gist ID: {gist_id}")
                    
                    payload_str = f"gist:{gist_id}"

                elif mode == "hole-punch":
                    check_dependencies("stun", "nc")
                    local_port = 20000 + (os.getpid() % 10000)
                    ipport, _ = run_stun_client(local_port)
                    payload_str = f"{ipport}:{local_port}"
                else:
                    ip = get_public_ip()
                    payload_str = f"{ip}:443"

                encrypted_payload = encrypt_payload(payload_str, encryption_key)
                client_info_json = json.dumps({"payload_b64": encrypted_payload})

                logging.info("Triggering V2 workflow via 'gh'...")
                trigger_command = [
                    'gh', 'workflow', 'run', 'v2_workflow.yml',
                    '--repo', repo,
                    '--field', f'mode={mode}',
                    '--field', f'client_info_json={client_info_json}',
                    '--ref', 'main'
                ]
                _ = subprocess.run(trigger_command, check=True, capture_output=True)
                logging.info("Workflow triggered successfully.")

                logging.info("Waiting 5 seconds for the new run to appear...")
                time.sleep(5)
                try:
                    logging.info("Attempting to find the run ID (single attempt)...")
                    run_list_json_str = subprocess.run(
                        ['gh', 'run', 'list', '--workflow=v2_workflow.yml', '--repo', repo, '--limit=1', '--json', 'databaseId'],
                        capture_output=True, text=True, check=True
                    ).stdout
                    run_list = cast(list[dict[str, int]], json.loads(run_list_json_str))
                    if run_list:
                        run_id = run_list[0]['databaseId']
                        logging.info(f"Detected new run with ID: {run_id}")
                except (IndexError, json.JSONDecodeError, subprocess.CalledProcessError) as e:
                    logging.warning(f"Could not immediately find run ID, but workflow was triggered. Error: {e}")

                if not run_id:
                    raise AppError("Could not find the triggered workflow run on the first attempt.")

                logging.info(f"Workflow run {run_id} is active on GitHub.")

                # ==== Auto Hole-Punch Sync & Connect Logic ====
                if mode == "auto-hole-punch" and gist_id:
                    logging.info("Waiting for Runner config via Gist (up to 10 minutes)...")
                    runner_data = None
                    for attempt in range(60):
                        time.sleep(10)
                        try:
                            content = read_gist(github_token, gist_id)
                            # If content changed, runner updated it
                            if content != enc_data:
                                decrypted_str = decrypt_payload(content, encryption_key)
                                runner_data = json.loads(decrypted_str)
                                if "runner_pub" in runner_data:
                                    break
                        except Exception as e:
                            logging.warning(f"Error reading Gist on attempt {attempt+1}: {e}")
                            
                    # Always clean up the gist once we have the data or timed out
                    delete_gist(github_token, gist_id)
                    gist_id = None
                    
                    if not runner_data:
                        raise AppError("Timeout waiting for runner configuration. Runner may have failed to start.")
                        
                    # 4. Auto-configure wg-quick tunnel
                    conf_path = Path("wg-gha.conf").resolve()
                    conf_content = f"""[Interface]
PrivateKey = {priv}
ListenPort = {local_port}
Address = 192.168.166.2/32

[Peer]
PublicKey = {runner_data['runner_pub']}
Endpoint = {runner_data['runner_ip']}:{runner_data['runner_port']}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 5
"""
                    conf_path.write_text(conf_content)
                    # Tear down existing interface if left hanging
                    subprocess.run(["sudo", "wg-quick", "down", str(conf_path)], stderr=subprocess.DEVNULL)
                    
                    logging.info("Starting wg-quick tunnel...")
                    subprocess.run(["sudo", "wg-quick", "up", str(conf_path)], check=True)
                    logging.info("✅ Auto UDP Hole-Punch Tunnel is UP!")
                    logging.info("All traffic is now routed securely through GitHub Actions.")

                # Wait for 6 hours before the next run (GitHub Actions max limit limit)
                wait_duration = 6 * 3600
                logging.info(f"Waiting for {wait_duration / 3600:.1f} hours before next trigger. Press Ctrl+C to cancel the current run and exit.")
                time.sleep(wait_duration)
                
                # Cleanup tunnel before starting new cycle
                if mode == "auto-hole-punch":
                    logging.info("Bringing down wg-quick interface for session refresh...")
                    subprocess.run(["sudo", "wg-quick", "down", str(Path("wg-gha.conf").resolve())], stderr=subprocess.DEVNULL)

            except (AppError, subprocess.CalledProcessError) as e:
                logging.error(f"An error occurred during the loop: {e}")
                
                if gist_id and mode == "auto-hole-punch":
                    try:
                        delete_gist(github_token, gist_id)
                        logging.info(f"Cleaned up orphaned Gist {gist_id}")
                    except Exception:
                        pass
                        
                if run_id and repo:
                    logging.info(f"Attempting to cancel run {run_id}...")
                    _ = subprocess.run(['gh', 'run', 'cancel', str(run_id), '--repo', repo])

                logging.info("Retrying after a 60-second delay due to error...")
                time.sleep(60)

    except KeyboardInterrupt:
        logging.info("\nCtrl+C detected.")
        if mode == "auto-hole-punch":
            logging.info("Bringing down wg-quick interface...")
            subprocess.run(["sudo", "wg-quick", "down", str(Path("wg-gha.conf").resolve())], stderr=subprocess.DEVNULL)
            if gist_id:
                try:
                    delete_gist(github_token, gist_id)
                except Exception:
                    pass
        if run_id and repo:
            logging.info(f"Attempting to cancel run {run_id}...")
            _ = subprocess.run(['gh', 'run', 'cancel', str(run_id), '--repo', repo])
        logging.info("Exiting gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
    main()
