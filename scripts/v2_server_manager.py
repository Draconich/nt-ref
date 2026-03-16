#!/usr/bin/env python3
import json
import logging
import sys
from pathlib import Path
from typing import cast

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

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
CONFIG_DIR = BASE_DIR / "config"

def main() -> None:
    try:
        logging.info("--- V2 Workflow Started ---")

        encryption_key = get_env_or_fail("GHA_PAYLOAD_KEY")
        mode = get_env_or_fail("INPUT_MODE")
        client_info_json = get_env_or_fail("INPUT_CLIENT_INFO_JSON")

        logging.info(f"Mode received: {mode}")

        client_data = cast(dict[str, str], json.loads(client_info_json))
        encrypted_payload = client_data["payload_b64"]
        decrypted_payload = decrypt_payload(encrypted_payload, encryption_key)

        client_info: ClientInfo | None = None
        gist_id: str | None = None
        
        if decrypted_payload.startswith("gist:"):
            gist_id = decrypted_payload.split(":")[1]
            logging.info(f"Gist ID detected: {gist_id}")
        else:
            parts = decrypted_payload.split(":")
            client_info = ClientInfo(
                ip=parts[0],
                port=int(parts[1]),
                local_port=int(parts[2]) if len(parts) > 2 else None
            )
            logging.info("Direct IP payload detected.")

        base_setup.setup_common_environment(BASE_DIR)

        # Четкое разделение логики по режимам
        if mode in ["auto-hole-punch", "auto-hole-punch-warp"]:
            if not gist_id:
                raise AppError("Gist ID missing for auto mode.")
            
            wg_private_key = get_env_or_fail("WG_PRIVATE_KEY")
            wireguard.setup_auto_hole_punch_server(
                gist_id, 
                wg_private_key, 
                BASE_DIR, 
                CONFIG_DIR, 
                use_warp=(mode == "auto-hole-punch-warp")
            )
        
        elif mode in ["direct-connect", "hole-punch", "direct-connect-warp"]:
            if not client_info:
                 raise AppError("Client info missing for legacy mode.")
            
            wg_private_key = get_env_or_fail("WG_PRIVATE_KEY")
            if mode == "hole-punch":
                ensure_apt_command_installed("stun", "stun-client")
                wireguard.setup_server_mode(client_info, wg_private_key, BASE_DIR, CONFIG_DIR)
            elif mode == "direct-connect":
                wireguard.setup_client_mode(client_info, wg_private_key, BASE_DIR, CONFIG_DIR)
            elif mode == "direct-connect-warp":
                wireguard.setup_client_warp_mode(client_info, wg_private_key, BASE_DIR, CONFIG_DIR)

        elif mode in ["xray", "xray-direct"]:
            if not client_info:
                raise AppError("Client info missing for xray.")
            xray_uuid = get_env_or_fail("XRAY_UUID")
            if mode == "xray":
                xray_warp.setup_service(client_info, xray_uuid, BASE_DIR, CONFIG_DIR)
            else:
                xray_direct.setup_service(client_info, xray_uuid, BASE_DIR, CONFIG_DIR)
        else:
             raise AppError(f"Unknown mode '{mode}'")

        logging.info("--- V2 Workflow Finished Successfully ---")

    except Exception as e:
        logging.error(f"FATAL ERROR: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
