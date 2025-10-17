# gh_runner_service/services/xray_warp.py
import json
import logging
import time
from datetime import timedelta
from pathlib import Path
from typing import cast

from ..common.exceptions import AppError
from ..common.models import (
    ClientInfo,
    XrayConfig,
    XrayVlessOutbound,
    XrayWireguardOutbound,
)
from ..common.utils import manage_process, run_command
from .cloudflare_warp import get_warp_config

# --- Constants ---
XRAY_CONFIG_TEMPLATE = "bridge_with_warp.json"
XRAY_FINAL_CONFIG = "bridge-final.json"
XRAY_EXECUTABLE = "bin/xray"

PROTOCOL_VLESS = "vless"
PROTOCOL_WIREGUARD = "wireguard"


def _generate_xray_config(
    client: ClientInfo,
    uuid: str,
    base_dir: Path,
    config_dir: Path,
) -> Path:
    """
    Generates the final Xray JSON configuration file.

    It fetches a new WARP configuration, loads the template, injects the
    client-specific and WARP-specific details, and saves the final config.

    Args:
        client: Information about the connecting user.
        uuid: The VLESS user UUID for authentication.
        base_dir: The project's base directory path.
        config_dir: The directory containing configuration templates.

    Returns:
        The path to the generated final configuration file.

    Raises:
        AppError: If the configuration template is not found or if the
                  VLESS/WireGuard outbounds are missing from the template.
    """
    warp_config = get_warp_config()

    config_template_path = config_dir / XRAY_CONFIG_TEMPLATE
    if not config_template_path.exists():
        raise AppError(f"WARP Xray config template not found: {config_template_path}")

    with open(config_template_path) as f:
        xray_config = cast(XrayConfig, json.load(f))

    vless_found = False
    wg_found = False
    for outbound in xray_config["outbounds"]:
        if outbound["protocol"] == PROTOCOL_VLESS:
            vless_outbound = cast(XrayVlessOutbound, outbound)
            vless_outbound["settings"]["vnext"][0]["address"] = client.ip
            vless_outbound["settings"]["vnext"][0]["users"][0]["id"] = uuid
            vless_found = True
        elif outbound["protocol"] == PROTOCOL_WIREGUARD:
            wg_outbound = cast(XrayWireguardOutbound, outbound)
            settings = wg_outbound["settings"]
            settings["secretKey"] = warp_config.private_key
            settings["address"] = [warp_config.address_v4]
            settings["peers"][0]["publicKey"] = warp_config.public_key
            settings["peers"][0]["endpoint"] = warp_config.endpoint_v4
            settings["reserved"] = warp_config.reserved_dec
            wg_found = True

    if not vless_found or not wg_found:
        raise AppError(
            f"Could not find required VLESS or WireGuard outbound in {XRAY_CONFIG_TEMPLATE}"
        )

    final_config_path = base_dir / XRAY_FINAL_CONFIG
    with open(final_config_path, "w") as f:
        json.dump(xray_config, f, indent=2)

    logging.info(f"Xray+WARP configuration generated successfully at {final_config_path}")
    return final_config_path


def setup_service(client: ClientInfo, uuid: str, base_dir: Path, config_dir: Path) -> None:
    """
    Sets up and runs the Xray service with a WARP outbound.

    This function orchestrates the entire process:
    1. Sets kernel parameters for performance.
    2. Generates the Xray configuration.
    3. Uses a common process manager to safely run the Xray process.
    4. Puts the main thread to sleep, relying on the context manager
       for guaranteed cleanup when the workflow ends.

    Args:
        client: Information about the connecting user.
        uuid: The VLESS user UUID for authentication.
        base_dir: The project's base directory path.
        config_dir: The directory containing configuration templates.
    """
    logging.info("Setting up Xray server with WARP.")
    _ = run_command("sysctl -w net.core.default_qdisc=fq", check=False)
    _ = run_command("sysctl -w net.ipv4.tcp_congestion_control=bbr", check=False)

    try:
        final_config_path = _generate_xray_config(client, uuid, base_dir, config_dir)
        xray_executable_path = base_dir / XRAY_EXECUTABLE
        command = f"{xray_executable_path} run -c {final_config_path}"

        with manage_process(command) as process:
            time.sleep(1)
            if process.poll() is not None:
                raise AppError(
                    f"Xray failed to start or exited unexpectedly. Exit code: {process.returncode}"
                )

            sleep_duration = timedelta(hours=5, minutes=59, seconds=56)
            logging.info(f"Service running. Sleeping for {sleep_duration} before shutdown...")
            time.sleep(sleep_duration.total_seconds())

        logging.info("Service operation concluded. Xray has been shut down.")

    except AppError as e:
        logging.error(f"A critical error occurred during service setup: {e}")
        raise
