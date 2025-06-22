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

# --- Configuration ---
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
STUN_SERVER = "stun.l.google.com:19302"
ENCRYPTION_KEY_ENV_VAR = "GHA_PAYLOAD_KEY"

# --- Setup ---
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

class ClientError(Exception):
    """Custom exception for client-side errors."""
    pass

def check_dependencies(*cmds: str) -> None:
    """Checks if required command-line tools are installed."""
    for cmd in cmds:
        if subprocess.run(['which', cmd], capture_output=True).returncode != 0:
            raise ClientError(f"Required command '{cmd}' not found. Please install it and ensure it's in your PATH.")

def get_env_or_fail(var_name: str) -> str:
    """Gets an environment variable or raises a specific error if not found."""
    value = os.getenv(var_name)
    if not value:
        raise ClientError(f"Required environment variable '{var_name}' is not set.")
    return value

def get_public_ip() -> str:
    # This function remains the same
    logging.info("Fetching public IP address...")
    try:
        result = subprocess.run(
            ['curl', '-s', 'https://icanhazip.com'],
            capture_output=True, text=True, check=True, timeout=10
        )
        ip = result.stdout.strip()
        if not ip:
            raise ClientError("Failed to get a valid public IP address.")
        logging.info(f"Detected public IP: {ip}")
        return ip
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        raise ClientError(f"Could not fetch public IP: {e}")

def run_stun_client(local_port: int) -> tuple[str, str]:
    # This function remains the same
    logging.info(f"Running STUN client on local port {local_port}...")
    stun_cmd = f"stun -v {STUN_SERVER} -p {local_port}"
    try:
        result = subprocess.run(shlex.split(stun_cmd), capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        if result.returncode > 10 or not output.strip():
            raise ClientError(f"STUN client execution failed. Is 'stun-client' installed? Exit Code: {result.returncode}")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise ClientError(f"STUN client execution failed: {e}")

    mapped_addr_match = re.search(r"MappedAddress = (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)", output)
    nat_type_match = re.search(r"Primary: (.*)", output)
    if not mapped_addr_match or not nat_type_match:
        raise ClientError(f"Could not parse STUN client output. Raw output:\n{output}")
    ipport = mapped_addr_match.group(1)
    nat_type = nat_type_match.group(1).strip()
    logging.info(f"STUN result: Mapped Address = {ipport}, NAT Type = {nat_type}")
    if "Independent Mapping" not in nat_type and "hole-punch" in sys.argv:
        raise ClientError(f"Incompatible NAT type: '{nat_type}'.")
    return ipport, nat_type

def encrypt_payload(payload: str, key: str) -> str:
    # This function remains the same
    logging.info("Encrypting payload...")
    command = ["openssl", "enc", "-aes-256-cbc", "-a", "-pbkdf2", "-salt", "-md", "sha256", "-pass", f"pass:{key}"]
    try:
        process = subprocess.run(command, input=payload.encode('utf-8'), capture_output=True, check=True)
        base64_payload = process.stdout.strip()
        return base64_payload.hex()
    except subprocess.CalledProcessError as e:
        raise ClientError(f"Payload encryption failed: {e.stderr.decode().strip()}")

def main():
    """Main entry point for the V2 client."""
    # Add 'gh' to dependency checks
    check_dependencies("git", "gh", "openssl", "curl")

    parser = argparse.ArgumentParser(description="V2 Client for GitHub Actions NAT traversal.")
    parser.add_argument("mode", choices=["direct-connect", "hole-punch", "xray"], help="The operational mode.")
    parser.add_argument("--repo", help="The GitHub repository in 'owner/repo' format. Defaults to GH_REPO env var.")
    parser.add_argument("--workflow", default="main.yml", help="The name of the workflow file.")
    args = parser.parse_args()
    
    # Use --repo flag or fall back to environment variable for convenience
    repo = args.repo or get_env_or_fail("GH_REPO")

    run_id = None
    try:
        # Get secrets from environment
        encryption_key = get_env_or_fail(ENCRYPTION_KEY_ENV_VAR)
        # GITHUB_TOKEN is read automatically by the 'gh' CLI
        _ = get_env_or_fail("GITHUB_TOKEN")

        # 1. Gather Info
        logging.info(f"Preparing to trigger workflow in '{args.mode}' mode.")
        payload_str = ""
        local_port = 0
        if args.mode == "hole-punch":
            check_dependencies("stun", "nc")
            local_port = 20000 + (os.getpid() % 10000)
            ipport, _ = run_stun_client(local_port)
            payload_str = f"{ipport}:{local_port}"
        else:
            ip = get_public_ip()
            payload_str = f"{ip}:443"

        # 2. Encrypt the payload
        encrypted_payload_hex = encrypt_payload(payload_str, encryption_key)

        # 3. Trigger the workflow using 'gh workflow run'
        logging.info("Triggering workflow via 'gh'...")
        trigger_command = [
            'gh', 'workflow', 'run', args.workflow,
            '--repo', repo,
            '--field', f'mode={args.mode}',
            '--field', f'client_info_payload={encrypted_payload_hex}',
            '--ref', 'main'
        ]
        subprocess.run(trigger_command, check=True, capture_output=True)
        logging.info("Workflow triggered successfully.")

        # 4. Find the Run ID
        logging.info("Waiting for the new run to appear...")
        time.sleep(5) # Give GitHub a moment to create the run
        for _ in range(5):
            try:
                run_list_json = subprocess.run(
                    ['gh', 'run', 'list', '--workflow', args.workflow, '--repo', repo, '--limit=1', '--json', 'databaseId'],
                    capture_output=True, text=True, check=True
                ).stdout
                run_id = json.loads(run_list_json)[0]['databaseId']
                logging.info(f"Detected new run with ID: {run_id}")
                break
            except (IndexError, json.JSONDecodeError):
                time.sleep(3)
        if not run_id:
            raise ClientError("Could not find the triggered workflow run.")

        # 5. Watch the run and stream logs
        logging.info(f"Watching run {run_id}. Streaming logs... (Press Ctrl+C to cancel)")
        watch_process = subprocess.run(['gh', 'run', 'watch', str(run_id), '--repo', repo], check=True)

        if watch_process.returncode == 0:
            logging.info("Workflow completed successfully!")
            # Future improvement: Add artifact download here if needed.
        else:
            raise ClientError(f"Workflow run {run_id} failed or was cancelled.")

    except (ClientError, subprocess.CalledProcessError) as e:
        if isinstance(e, subprocess.CalledProcessError) and hasattr(e, 'stderr') and e.stderr:
            logging.error(f"A command failed. Error details:\n---\n{e.stderr.decode().strip()}\n---")
        else:
            logging.error(f"An error occurred: {e}")
        
        if run_id:
            logging.info(f"Attempting to cancel run {run_id}...")
            subprocess.run(['gh', 'run', 'cancel', str(run_id), '--repo', repo])
        sys.exit(1)
    except KeyboardInterrupt:
        logging.info("\nCtrl+C detected.")
        if run_id:
            logging.info(f"Attempting to cancel run {run_id}...")
            subprocess.run(['gh', 'run', 'cancel', str(run_id), '--repo', repo])
        logging.info("Exiting gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
