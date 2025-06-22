# gh_runner_service/services/cloudflare_warp.py
import base64
import logging
from datetime import datetime, timezone
from typing import cast

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from requests import Session

from ..models import WarpConfig
from ..common.exceptions import AppError

class WarpApiClient:
    """Manages registration and configuration fetching for Cloudflare WARP."""
    API_URL: str = "https://api.cloudflareclient.com/v0a2158/reg"
    CLIENT_VERSION: str = "a-7.21-0721"
    USER_AGENT: str = "okhttp/3.12.1"

    _session: Session

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": self.USER_AGENT,
            "CF-Client-Version": self.CLIENT_VERSION,
            "Content-Type": "application/json",
        })

    def _generate_keys(self) -> tuple[str, str]:
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return (
            base64.b64encode(private_bytes).decode("utf-8"),
            base64.b64encode(public_bytes).decode("utf-8"),
        )

    def _register_api_account(self, public_key: str) -> dict:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        payload = {"key": public_key, "tos": timestamp, "type": "Android"}
        try:
            response = self._session.post(self.API_URL, json=payload, timeout=30)
            response.raise_for_status()
            logging.info("Successfully received WARP API response.")
            return cast(dict, response.json())
        except requests.exceptions.RequestException as e:
            error_body = e.response.text if e.response else "No response body"
            raise AppError(f"WARP API request failed: {e}. Body: {error_body}")

    def register_and_get_config(self) -> WarpConfig:
        private_key, public_key = self._generate_keys()
        api_data = self._register_api_account(public_key)

        try:
            logging.info("Formatting final WARP configuration.")
            peer = api_data["config"]["peers"][0]
            reserved_str = api_data["config"]["client_id"]
            reserved_bytes = base64.b64decode(reserved_str)
            interface_addrs = api_data["config"]["interface"]["addresses"]

            return WarpConfig(
                endpoint_v4=peer["endpoint"]["v4"],
                private_key=private_key,
                public_key=peer["public_key"],
                address_v4=interface_addrs["v4"],
                reserved_dec=list(reserved_bytes),
            )
        except (KeyError, IndexError) as e:
            raise AppError(f"Failed to parse WARP API response due to missing data: {e}")

def get_warp_config() -> WarpConfig:
    """High-level function to register and fetch a WARP configuration."""
    logging.info("Fetching new WARP registration data...")
    client = WarpApiClient()
    return client.register_and_get_config()
