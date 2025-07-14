# gh_runner_service/services/cloudflare_warp.py
import base64
import logging
from datetime import datetime, timezone
from typing import TypedDict, cast

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from requests import Session

# Correctly import from the shared models and exceptions modules
from ..common.exceptions import AppError
from ..common.models import WarpConfig

# --- Type Definitions for the raw API response ---
# By defining these, we make the parsing code type-safe and clear.
class _WarpApiPeerEndpoint(TypedDict):
    v4: str

class _WarpApiPeer(TypedDict):
    public_key: str
    endpoint: _WarpApiPeerEndpoint

class _WarpApiInterfaceAddresses(TypedDict):
    v4: str

class _WarpApiInterface(TypedDict):
    addresses: _WarpApiInterfaceAddresses

class _WarpApiConfig(TypedDict):
    client_id: str
    peers: list[_WarpApiPeer]
    interface: _WarpApiInterface

class _WarpApiResponse(TypedDict):
    config: _WarpApiConfig


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
        private_key_obj = x25519.X25519PrivateKey.generate()
        public_key_obj = private_key_obj.public_key()
        private_bytes = private_key_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = public_key_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return (
            base64.b64encode(private_bytes).decode("utf-8"),
            base64.b64encode(public_bytes).decode("utf-8"),
        )

    def _register_api_account(self, public_key: str) -> _WarpApiResponse:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        payload: dict[str, str] = {"key": public_key, "tos": timestamp, "type": "Android"}

        try:
            response = self._session.post(self.API_URL, json=payload, timeout=30)
            response.raise_for_status()
            logging.info("Successfully received WARP API response.")
            # Cast the JSON response to our specific TypedDict for safety
            return cast(_WarpApiResponse, response.json())
        except requests.exceptions.RequestException as e:
            error_body = e.response.text if e.response else "No response body"
            raise AppError(f"WARP API request failed: {e}. Body: {error_body}")


    def register_and_get_config(self) -> WarpConfig:
        """High-level function to register and fetch a WARP configuration."""
        private_key, public_key = self._generate_keys()
        api_data = self._register_api_account(public_key)

        try:
            logging.info("Formatting final WARP configuration.")
            peer = api_data["config"]["peers"][0]
            reserved_str = api_data["config"]["client_id"]
            reserved_bytes = base64.b64decode(reserved_str)
            interface_addrs = api_data["config"]["interface"]["addresses"]


            # The API is returning a port of 0, which is invalid.
            # We must manually construct the correct endpoint.
            api_endpoint_v4 = peer["endpoint"]["v4"]
            logging.info(f"Received endpoint from API: {api_endpoint_v4}")

            # Split the IP from the invalid port
            ip_address_v4 = api_endpoint_v4.split(":")[0]
            
            # Construct the correct endpoint with the known WARP port 2408
            correct_endpoint_v4 = f"{ip_address_v4}:2408"
            logging.info(f"Corrected endpoint to use: {correct_endpoint_v4}")
            
            # Use the corrected endpoint when creating the config object
            return WarpConfig(
                endpoint_v4=correct_endpoint_v4, # Use the corrected value
                private_key=private_key,
                public_key=peer["public_key"],
                address_v4=interface_addrs["v4"],
                reserved_dec=list(reserved_bytes),
            )
        except (KeyError, IndexError) as e:
            raise AppError(f"Failed to parse WARP API response due to missing data: {e}")


def get_warp_config() -> WarpConfig:
    """High-level factory function to get a WARP configuration."""
    logging.info("Fetching new WARP registration data...")
    client = WarpApiClient()
    return client.register_and_get_config()
