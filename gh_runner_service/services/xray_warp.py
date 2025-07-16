# gh_runner_service/services/xray_warp.py
import json
import logging
from pathlib import Path
import time # Import time for sleep
import signal # Import signal for graceful shutdown
import subprocess # Import subprocess for Popen type hinting
from typing import cast
from ..common.exceptions import AppError
from ..common.models import (
    ClientInfo,
    XrayConfig,
    XrayVlessOutbound,
    XrayWireguardOutbound,
)
from ..common.utils import run_command, run_background_command # Import run_background_command
from .cloudflare_warp import get_warp_config

def setup_service(client: ClientInfo, uuid: str, base_dir: Path, config_dir: Path) -> None:
    """Configures and runs the Xray server with WARP."""
    logging.info("Setting up Xray server with WARP.")
    _ = run_command("sysctl -w net.core.default_qdisc=fq")
    _ = run_command("sysctl -w net.ipv4.tcp_congestion_control=bbr")

    warp_config = get_warp_config()

    config_path = config_dir / "bridge_with_warp.json"
    if not config_path.exists():
        raise AppError(f"WARP Xray config not found: {config_path}")

    with open(config_path) as f:
        xray_config = cast(XrayConfig, json.load(f))

    for outbound in xray_config["outbounds"]:
        if outbound["protocol"] == "vless":
            vless_outbound = cast(XrayVlessOutbound, outbound)
            vless_outbound["settings"]["vnext"][0]["address"] = client.ip
            vless_outbound["settings"]["vnext"][0]["users"][0]["id"] = uuid
        elif outbound["protocol"] == "wireguard":
            wg_outbound = cast(XrayWireguardOutbound, outbound)
            wg_outbound["settings"]["secretKey"] = warp_config.private_key
            wg_outbound["settings"]["address"] = [warp_config.address_v4]
            wg_outbound["settings"]["peers"][0]["publicKey"] = warp_config.public_key
            wg_outbound["settings"]["peers"][0]["endpoint"] = warp_config.endpoint_v4
            wg_outbound["settings"]["reserved"] = warp_config.reserved_dec

    final_config_path = base_dir / "bridge-final.json"
    with open(final_config_path, "w") as f:
        json.dump(xray_config, f, indent=2)

    logging.info("Xray+WARP configuration generated successfully.")
    xray_executable_path = base_dir / "bin/xray"

    xray_process: subprocess.Popen[str] | None = None
    try:
        # Start Xray in the background
        xray_process = run_background_command(f"{xray_executable_path} run -c {final_config_path}")
        logging.info(f"Xray started with PID: {xray_process.pid}")

        # Calculate sleep duration: 5 hours 59 minutes 50 seconds in seconds
        sleep_duration_seconds = (5 * 3600) + (59 * 60) + 50
        logging.info(f"Sleeping for {sleep_duration_seconds} seconds before graceful shutdown...")
        time.sleep(sleep_duration_seconds)

        logging.info("Sleep duration finished. Attempting graceful shutdown of Xray...")
        if xray_process.poll() is None: # Check if Xray is still running
            xray_process.send_signal(signal.SIGTERM) # Send SIGTERM for graceful shutdown
            logging.info("SIGTERM sent to Xray. Waiting for process to terminate...")
            try:
                xray_process.wait(timeout=5) # Wait up to 5 seconds for graceful exit
                logging.info(f"Xray terminated gracefully with exit code {xray_process.returncode}.")
            except subprocess.TimeoutExpired:
                logging.warning("Xray did not terminate gracefully within 10 seconds. Forcing kill.")
                xray_process.kill() # Force kill if it doesn't respond to SIGTERM
                xray_process.wait()
                logging.info(f"Xray forced killed with exit code {xray_process.returncode}.")
        else:
            logging.info(f"Xray was already stopped with exit code {xray_process.returncode}.")

    except AppError as e:
        logging.error(f"Error starting or managing Xray: {e}")
        # Ensure Xray is cleaned up if an error occurs during its management
        if xray_process and xray_process.poll() is None:
            logging.info("Attempting to kill Xray process due to error.")
            xray_process.kill()
            xray_process.wait()
        raise # Re-raise the error to propagate it

    logging.info("Xray operation concluded.")
    # The script will now exit, and the GitHub Actions job will complete.
