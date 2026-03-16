#!/usr/bin/env python3
import json
import logging
import sys # 'os' is no longer needed here
from pathlib import Path
from typing import cast

# This line is crucial for running the script directly.
sys.path.append(str(Path(__file__).resolve().parent.parent))

from gh_runner_service.common.crypto import decrypt_payload
from gh_runner_service.common.exceptions import AppError
from gh_runner_service.common.models import ClientInfo
from gh_runner_service.common.utils import get_env_or_fail, ensure_apt_command_installed
from gh_runner_service.services import (
    base_setup,
    wireguard,
    xray_direct,
    xray_warp,
)

# --- Setup ---
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
CONFIG_DIR = BASE_DIR / "config"

def main() -> None:
    """Main entry point for the V2 server manager script."""
    try:
        logging.info("--- V2 Workflow Started ---")

        # Step 1: Get config from environment variables
        encryption_key = get_env_or_fail("GHA_PAYLOAD_KEY")
        mode = get_env_or_fail("INPUT_MODE")
        client_info_json = get_env_or_fail("INPUT_CLIENT_INFO_JSON")

        logging.info(f"Mode received: {mode}")

        # Step 2: Decrypt payload and determine if it's a Gist or direct IP
        client_data = cast(dict[str, str], json.loads(client_info_json))
        encrypted_payload = client_data["payload_b64"]
        decrypted_payload = decrypt_payload(encrypted_payload, encryption_key)

        client_info: ClientInfo | None = None
        gist_id: str | None = None
        
        if decrypted_payload.startswith("gist:"):
            gist_id = decrypted_payload.split(":")[1]
            logging.info("Gist payload detected. Skipping direct IP parse.")
        else:
            parts = decrypted_payload.split(":")
            client_info = ClientInfo(
                ip=parts[0],
                port=int(parts[1]),
                local_port=int(parts[2]) if len(parts) > 2 else None
            )
            logging.info("Direct payload decrypted successfully.")

        # Step 3: Set up the common environment
        base_setup.setup_common_environment(BASE_DIR)

        # Step 4: Run mode-specific logic with clear branching
        if mode in ["auto-hole-punch", "auto-hole-punch-warp"]:
            logging.info(f"Starting {mode} setup...")
            wg_private_key = get_env_or_fail("WG_PRIVATE_KEY")
            ensure_apt_command_installed("wireguard-tools", "wireguard")
            if not gist_id:
                raise AppError("Gist ID is required for auto-hole-punch modes but was not found.")
            
            wireguard.setup_auto_hole_punch_server(
                gist_id, 
                wg_private_key, 
                BASE_DIR, 
                CONFIG_DIR, 
                use_warp=(mode == "auto-hole-punch-warp")
            )
        
        elif mode in ["direct-connect", "hole-punch", "direct-connect-warp"]:
            logging.info(f"Starting legacy mode {mode} setup...")
            if not client_info:
                 raise AppError(f"ClientInfo is required for mode '{mode}' but was not found.")
            
            wg_private_key = get_env_or_fail("WG_PRIVATE_KEY")
            wireguard_args = (client_info, wg_private_key, BASE_DIR, CONFIG_DIR)

            if mode == "hole-punch":
                ensure_apt_command_installed("stun", "stun-client")
                wireguard.setup_server_mode(*wireguard_args)
            elif mode == "direct-connect":
                wireguard.setup_client_mode(*wireguard_args)
            elif mode == "direct-connect-warp":
                wireguard.setup_client_warp_mode(*wireguard_args)

        elif mode in ["xray", "xray-direct"]:
            logging.info(f"Starting {mode} setup...")
            if not client_info:
                raise AppError(f"ClientInfo is required for mode '{mode}' but was not found.")
            
            xray_uuid = get_env_or_fail("XRAY_UUID")
            xray_args = (client_info, xray_uuid, BASE_DIR, CONFIG_DIR)
            if mode == "xray":
                xray_warp.setup_service(*xray_args)
            else: # xray-direct
                xray_direct.setup_service(*xray_args)
        else:
             raise AppError(f"Unknown mode '{mode}' received.")

        logging.info("--- V2 Workflow Finished Successfully ---")

    except AppError as e:
        logging.error(f"A critical error occurred: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)
