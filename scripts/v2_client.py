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
from typing import cast

# We will reuse some modules, but client logic is mostly self-contained here
from pathlib import Path
# This adds the project root to Python's path, so it can find the 'gh_runner_service' package
sys.path.append(str(Path(__file__).resolve().parent.parent))

from gh_runner_service.common.exceptions import AppError
from gh_runner_service.common.utils import check_dependencies, get_env_or_fail
from gh_runner_service.crypto import encrypt_payload

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

ENCRYPTION_KEY_ENV_VAR = "GHA_PAYLOAD_KEY"

def get_public_ip() -> str:
    """Fetches the public IP address."""
    # ... (This function can be copied directly from the old client_trigger.py)
    # ... or from the new modules/client_logic.py if you created it.
    logging.info("Fetching public IP address...")
    try:
        result = subprocess.run(
            ['curl', '-s', 'https://icanhazip.com'],
            capture_output=True, text=True, check=True, timeout=10
        )
        ip = result.stdout.strip()
        if not ip:
            raise AppError("Failed to get a valid public IP address.")
        logging.info(f"Detected public IP: {ip}")
        return ip
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        raise AppError(f"Could not fetch public IP: {e}")


def run_stun_client(local_port: int) -> tuple[str, str]:
    """Runs the STUN client to determine external IP and mapped port."""
    # ... (This function can be copied from the final, fixed version in the old client)
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


def main():
    """Main entry point for the V2 client."""
    check_dependencies("git", "gh", "openssl", "curl")
    
    parser = argparse.ArgumentParser(description="V2 Client for GitHub Actions NAT traversal.")
    parser.add_argument(
        "mode",
        choices=["direct-connect", "hole-punch", "xray", "xray-direct"],
        help="The operational mode."
    )
    args = parser.parse_args()
    mode = cast(str, args.mode)
    
    run_id = None
    try:
        encryption_key = get_env_or_fail(ENCRYPTION_KEY_ENV_VAR)
        
        # 1. Gather Info
        logging.info(f"Preparing to trigger V2 workflow in '{mode}' mode.")
        payload_str = ""
        local_port = 0
        if mode == "hole-punch":
            check_dependencies("stun", "nc")
            local_port = 20000 + (os.getpid() % 10000)
            ipport, _ = run_stun_client(local_port)
            payload_str = f"{ipport}:{local_port}"
        else:
            ip = get_public_ip()
            payload_str = f"{ip}:443"

        # 2. Encrypt and package the payload
        encrypted_payload_hex = encrypt_payload(payload_str, encryption_key)
        client_info_json = json.dumps({"payload": encrypted_payload_hex})

        # 3. Trigger the workflow
        logging.info("Triggering V2 workflow via 'gh'...")
        trigger_command = [
            'gh', 'workflow', 'run', 'v2_workflow.yml',
            '--field', f'mode={mode}',
            '--field', f'client_info_json={client_info_json}',
            '--ref', 'main' # Trigger on the 'main' branch
        ]
        subprocess.run(trigger_command, check=True, capture_output=True)
        logging.info("Workflow triggered successfully.")

        # 4. Find the Run ID
        logging.info("Waiting for the new run to appear...")
        time.sleep(5) # Give GitHub a moment to create the run
        for _ in range(5):
            try:
                run_list_json = subprocess.run(
                    ['gh', 'run', 'list', '--workflow=v2_workflow.yml', '--limit=1', '--json', 'databaseId'],
                    capture_output=True, text=True, check=True
                ).stdout
                run_id = json.loads(run_list_json)[0]['databaseId']
                logging.info(f"Detected new run with ID: {run_id}")
                break
            except (IndexError, json.JSONDecodeError):
                time.sleep(3)
        if not run_id:
            raise AppError("Could not find the triggered workflow run.")

        # 5. Watch the run
        logging.info(f"Watching run {run_id}. Streaming logs...")
        watch_process = subprocess.run(['gh', 'run', 'watch', str(run_id)], check=True)
        
        if watch_process.returncode == 0:
            logging.info("Workflow completed successfully!")
            if mode == "hole-punch":
                logging.info("Downloading WireGuard configuration artifact...")
                # Download artifact
                dl_command = ['gh', 'run', 'download', str(run_id), '-n', f'client-config-{run_id}']
                subprocess.run(dl_command, check=True)
                
                # Move file to current directory
                artifact_dir = f"client-config-{run_id}"
                os.rename(os.path.join(artifact_dir, "wg_user.conf"), "wg_user.conf")
                os.rmdir(artifact_dir)
                logging.info("Success! Configuration saved to 'wg_user.conf'.")
                logging.info("Please generate a client private key and add it to the file, then connect.")
        else:
            raise AppError(f"Workflow run {run_id} failed or was cancelled.")

    except (AppError, subprocess.CalledProcessError) as e:
        logging.error(f"An error occurred: {e}")
        if run_id:
            logging.info(f"Attempting to cancel run {run_id}...")
            subprocess.run(['gh', 'run', 'cancel', str(run_id)])
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("Ctrl+C detected.")
        if run_id:
            logging.info(f"Attempting to cancel run {run_id}...")
            subprocess.run(['gh', 'run', 'cancel', str(run_id)])
        logging.info("Exiting gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
