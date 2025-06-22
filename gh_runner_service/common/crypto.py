# gh_runner_service/crypto.py
import subprocess
import tempfile

from .common.exceptions import AppError
from .common.utils import run_command

def decrypt_payload(encrypted_payload_hex: str, key: str) -> str:
    """Decrypts a hex-encoded payload using OpenSSL via a temporary file."""
    try:
        encrypted_payload_b64 = bytes.fromhex(encrypted_payload_hex).decode('utf-8')
    except (ValueError, TypeError) as e:
        raise AppError(f"Failed to decode hex payload: {e}")

    command = ["openssl", "enc", "-d", "-aes-256-cbc", "-a", "-pbkdf2", "-md", "sha256", "-pass", f"pass:{key}"]
    
    with tempfile.NamedTemporaryFile(mode='w', delete=True, suffix=".txt", encoding='utf-8') as tmp:
        tmp.write(encrypted_payload_b64)
        tmp.flush()
        command_with_file = command + ["-in", tmp.name]
        process = run_command(" ".join(command_with_file))
        return process.stdout.strip()

def encrypt_payload(payload: str, key: str) -> str:
    """Encrypts a payload using OpenSSL and returns a hex-encoded Base64 string."""
    command = ["openssl", "enc", "-aes-256-cbc", "-a", "-pbkdf2", "-salt", "-md", "sha256", "-pass", f"pass:{key}"]
    try:
        process = subprocess.run(command, input=payload, capture_output=True, text=True, check=True)
        base64_payload = process.stdout
        return base64_payload.encode('utf-8').hex()
    except subprocess.CalledProcessError as e:
        raise AppError(f"Payload encryption failed: {e.stderr.strip()}")
