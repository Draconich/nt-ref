#!/usr/bin/env python3
import base64
import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import TypedDict, cast

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from requests import Session

# --- Type Definitions for API Response (for clarity) ---
class Endpoint(TypedDict):
    v4: str
    v6: str

class Peer(TypedDict):
    public_key: str
    endpoint: Endpoint

class InterfaceAddresses(TypedDict):
    v4: str
    v6: str

class Interface(TypedDict):
    addresses: InterfaceAddresses

class WarpConfig(TypedDict):
    client_id: str
    peers: list[Peer]
    interface: Interface

class WarpApiResponse(TypedDict):
    config: WarpConfig

# --- Dataclass for Structured Output ---
@dataclass
class FinalConfig:
    """A dataclass to hold the final, formatted configuration."""
    endpoint_v4: str
    endpoint_v6: str
    reserved_dec: list[int]
    private_key: str
    public_key: str
    address_v4: str
    address_v6: str


class WarpClient:
    """
    Manages registration and configuration fetching for Cloudflare WARP.
    """
    API_URL: str = "https://api.cloudflareclient.com/v0a2158/reg"
    CLIENT_VERSION: str = "a-7.21-0721"
    USER_AGENT: str = "okhttp/3.12.1"

    _session: Session

    def __init__(self) -> None:
        """Initializes the WarpClient and a requests session."""
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": self.USER_AGENT,
            "CF-Client-Version": self.CLIENT_VERSION,
            "Content-Type": "application/json",
        })

    def _generate_keys(self) -> tuple[str, str]:
        """Generates and returns a new Base64-encoded X25519 keypair."""
        logging.info("Generating new X25519 keypair.")
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

    def _register_api_account(self, public_key: str) -> WarpApiResponse | None:
        """Calls the Cloudflare API to register the account."""
        logging.info("Registering new account with Cloudflare API...")
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        payload = {"key": public_key, "tos": timestamp, "type": "Android"}
        try:
            response = self._session.post(self.API_URL, json=payload, timeout=30)
            response.raise_for_status()
            logging.info("Successfully received API response.")
            return cast(WarpApiResponse, response.json())
        except requests.exceptions.RequestException as e:
            logging.error(f"API request failed: {e}")
            if e.response:
                logging.error(f"Response Body: {e.response.text}")
            return None

    def register_and_format(self) -> FinalConfig | None:
        """Executes the full registration and formatting process."""
        private_key, public_key = self._generate_keys()
        api_data = self._register_api_account(public_key)

        if not api_data:
            return None

        try:
            logging.info("Formatting final configuration.")
            peer = api_data["config"]["peers"][0]
            reserved_str = api_data["config"]["client_id"]
            reserved_bytes = base64.b64decode(reserved_str)
            interface_addrs = api_data["config"]["interface"]["addresses"]

            return FinalConfig(
                endpoint_v4=peer["endpoint"]["v4"],
                endpoint_v6=peer["endpoint"]["v6"],
                private_key=private_key,
                public_key=peer["public_key"],
                address_v4=interface_addrs["v4"],
                address_v6=interface_addrs["v6"],
                reserved_dec=list(reserved_bytes),
            )
        except (KeyError, IndexError) as e:
            logging.error(f"Failed to parse API response due to missing data: {e}")
            return None


def main() -> None:
    """Sets up logging and runs the client."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    client = WarpClient()
    final_config = client.register_and_format()

    if final_config:
        print(json.dumps(asdict(final_config), indent=2))
    else:
        logging.critical("Failed to generate WARP configuration.")
        sys.exit(1)


if __name__ == "__main__":
    # This script requires external dependencies. The YAML will install them.
    main()
