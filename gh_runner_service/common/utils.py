# gh_runner_service/common/utils.py
import logging
import os
import subprocess
from typing import cast 

from .exceptions import AppError

def run_command(command: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Helper to run a shell command and log its output."""
    logging.info(f"Executing: {command}")
    try:
        # Since text=True, the successful return's stdout/stderr are strings.
        return subprocess.run(command, shell=True, check=check, text=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with exit code {e.returncode}")

        # FIX: Use `cast` to explicitly tell the linter the type of these attributes.
        # Because text=True was used, we expect `str` or `None`.
        stdout_val = cast(str | None, e.stdout)
        stderr_val = cast(str | None, e.stderr)

        # Now, work with the safely typed variables.
        stdout_log = stdout_val.strip() if stdout_val else "No stdout"
        stderr_log = stderr_val.strip() if stderr_val else "No stderr"

        logging.error(f"STDOUT: {stdout_log}")
        logging.error(f"STDERR: {stderr_log}")
        raise AppError(f"Execution failed for command: {command}") from e

def run_background_command(command: str) -> subprocess.Popen[str]:
    """
    Runs a shell command in the background and returns the Popen object.
    Uses start_new_session=True to put the process in a new process group,
    making it more robust to signals sent to the parent.
    """
    logging.info(f"Executing in background: {command}")
    try:
        process = subprocess.Popen(command, shell=True, text=True, start_new_session=True)
        return process
    except Exception as e:
        raise AppError(f"Failed to start background command '{command}': {e}")

def get_env_or_fail(var_name: str) -> str:
    """Gets an environment variable or raises a specific error if not found."""
    value = os.getenv(var_name)
    if not value:
        raise AppError(f"Required environment variable '{var_name}' is not set.")
    return value

def check_dependencies(*cmds: str) -> None:
    """Checks if required command-line tools are installed."""
    for cmd in cmds:
        if subprocess.run(['which', cmd], capture_output=True).returncode != 0:
            raise AppError(f"Required command '{cmd}' not found. Please install it and ensure it's in your PATH.")

def ensure_apt_command_installed(command_name: str, package_name: str | None = None) -> None:
    """
    Checks if a command is available in PATH. If not, attempts to install it
    using apt-get. Assumes the script is already running with root privileges.
    """
    if subprocess.run(['which', command_name], capture_output=True).returncode != 0:
        actual_package_name = package_name if package_name else command_name
        logging.info(f"Command '{command_name}' not found. Attempting to install '{actual_package_name}' via apt...")
        try:
            run_command("apt-get update")
            run_command(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {actual_package_name}")
            logging.info(f"Successfully installed '{actual_package_name}'.")
        except AppError as e:
            raise AppError(f"Failed to install required command '{command_name}' (package: {actual_package_name}): {e}")
