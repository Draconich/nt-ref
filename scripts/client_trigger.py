#!/usr/bin/env python3
import argparse
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

def get_public_ip() -> str:
    """Fetches the public IP address."""
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
    """
    Runs the STUN client to determine external IP and mapped port.
    Returns (external_ip:port, nat_type).
    """
    logging.info(f"Running STUN client on local port {local_port}...")
    stun_cmd = f"stun -v {STUN_SERVER} -p {local_port}"
    try:
        result = subprocess.run(
            shlex.split(stun_cmd),
            capture_output=True, text=True, check=True, timeout=15
        )
        output = result.stdout + result.stderr
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise ClientError(f"STUN client execution failed. Is 'stun-client' installed? Error: {e}")

    mapped_addr_match = re.search(r"MappedAddress = (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)", output)
    nat_type_match = re.search(r"Primary: (.*)", output)

    if not mapped_addr_match or not nat_type_match:
        raise ClientError("Could not parse STUN client output. NAT traversal may not be possible.")

    ipport = mapped_addr_match.group(1)
    nat_type = nat_type_match.group(1).strip()

    logging.info(f"STUN result: Mapped Address = {ipport}, NAT Type = {nat_type}")

    if "Independent Mapping" not in nat_type:
        raise ClientError(
            (f"Incompatible NAT type: '{nat_type}'. "
             "This method requires 'Independent Mapping' to function correctly.")
        )

    return ipport, nat_type

def encrypt_payload(payload: str, key: str) -> str:
    """Encrypts a payload using OpenSSL and returns a Base64 string."""
    logging.info("Encrypting payload for commit message.")
    command = ["openssl", "enc", "-aes-256-cbc", "-a", "-pbkdf2", "-salt", "-md", "sha256", "-pass", f"pass:{key}"] 
    try:
        process = subprocess.run(command, input=payload, capture_output=True, text=True, check=True)
        return process.stdout.strip()
    except subprocess.CalledProcessError as e:
        # FIX: Use `cast` to inform the linter of the correct type (str | None).
        stderr_typed = cast(str | None, e.stderr)
        error_msg = stderr_typed.strip() if stderr_typed else ""
        raise ClientError(f"Payload encryption failed. Is OpenSSL installed? Error: {error_msg}")

def git_commit_and_push(message: str) -> None:
    """Creates an empty commit with the given message and pushes it."""
    logging.info("Committing and pushing trigger to the repository...")
    try:
        _ = subprocess.run(["git", "commit", "-m", message, "--allow-empty"], check=True, capture_output=True, text=True)
        _ = subprocess.run(["git", "push"], check=True, capture_output=True, text=True)
        logging.info("Trigger commit pushed successfully.")
    except subprocess.CalledProcessError as e:
        _ = subprocess.run(["git", "reset", "HEAD~1"], capture_output=True)
        # FIX: Use `cast` to inform the linter of the correct type (str | None).
        stderr_typed = cast(str | None, e.stderr)
        error_msg = stderr_typed.strip() if stderr_typed else ""
        raise ClientError(f"Git operation failed: {error_msg}")

def keep_nat_alive(local_port: int) -> None:
    """Sends periodic UDP packets to keep a NAT mapping alive."""
    logging.info("NAT does not preserve ports. Starting NAT keep-alive process.")
    logging.info("Press CTRL+C to stop AFTER connecting to the VPN.")
    while True:
        try:
            _ = subprocess.run(
                ["nc", "-n", "-u", "-p", str(local_port), "3.3.3.3", "443"],
                input=b'', timeout=5, capture_output=True
            )
            time.sleep(10)
        except subprocess.TimeoutExpired:
            continue
        except FileNotFoundError:
            raise ClientError("`nc` (netcat) is required for NAT keep-alive but was not found.")

def cancel_github_runs() -> None:
    """Cancels any in-progress GitHub Actions runs for this repository."""
    logging.info("Cancelling in-progress GitHub Actions runs...")
    try:
        command = r"""
        gh run list --json databaseId,status -q '.[] | select(.status == "in_progress" or .status == "queued" or .status == "waiting") | .databaseId' | xargs -r -n1 gh run cancel
        """
        _ = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        logging.info("Cleanup command sent.")
    except subprocess.CalledProcessError as e:
        # FIX: Use `cast` to inform the linter of the correct type (str | None).
        stderr_typed = cast(str | None, e.stderr)
        error_msg = stderr_typed.strip() if stderr_typed else ""
        logging.warning(f"Failed to cancel GitHub runs. You may need to do this manually. Error: {error_msg}")

def main_loop(mode: str, encryption_key: str) -> None:
    """The main execution loop that triggers the GitHub Action."""
    while True:
        try:
            payload = ""
            nat_type = ""
            local_port = 0

            if mode == "hole-punch":
                check_dependencies("stun", "nc")
                local_port = 20000 + (os.getpid() % 10000)
                ipport, nat_type = run_stun_client(local_port)
                payload = f"{ipport}:{local_port}"
                commit_prefix = "HP"
            else:
                ip = get_public_ip()
                payload = f"{ip}:443"
                commit_prefix = "DT" if mode == "direct-connect" else "XR"

            encrypted_payload = encrypt_payload(payload, encryption_key)
            commit_message = f"{commit_prefix}: {encrypted_payload}"

            git_commit_and_push(commit_message)

            if mode == "hole-punch" and "preserves ports" not in nat_type:
                keep_nat_alive(local_port)
            else:
                logging.info("Trigger sent. The GitHub Action is starting.")
                logging.info("This script will re-trigger every 6 hours. Press Ctrl+C to exit.")
                time.sleep(6 * 3600)

        except ClientError as e:
            logging.error(f"An error occurred: {e}")
            logging.error("Exiting.")
            sys.exit(1)
        except KeyboardInterrupt:
            logging.info("Ctrl+C detected.")
            cancel_github_runs()
            logging.info("Exiting gracefully.")
            sys.exit(0)
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}", exc_info=True)
            sys.exit(1)


if __name__ == "__main__":
    check_dependencies("git", "gh", "openssl", "curl")

    parser = argparse.ArgumentParser(
        description="Client-side trigger for GitHub Actions NAT traversal.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    _ = parser.add_argument(
        "mode",
        choices=["direct-connect", "hole-punch", "xray"],
        help="""The operational mode:
- direct-connect: For WireGuard direct connection.
- hole-punch:     For WireGuard with NAT hole punching.
- xray:           For Xray server."""
    )

    args = parser.parse_args()
    mode = cast(str, args.mode)

    encryption_key = os.getenv(ENCRYPTION_KEY_ENV_VAR)
    if not encryption_key:
        logging.error(f"Encryption key not found. Please set the '{ENCRYPTION_KEY_ENV_VAR}' environment variable.")
        sys.exit(1)

    main_loop(mode, encryption_key)
