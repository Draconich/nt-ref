# gh_runner_service/common/utils.py
import logging
import os
import shlex
import signal
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from typing import cast

from .exceptions import AppError


def run_command(command: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """
    Helper to run a shell command and log its output, avoiding `shell=True`.

    Args:
        command: The command string to execute.
        check: If True, raises CalledProcessError on non-zero exit codes.

    Returns:
        The CompletedProcess object.

    Raises:
        AppError: If the command fails and check is True.
    """
    logging.info(f"Executing: {command}")
    args = shlex.split(command)
    try:
        return subprocess.run(
            args, check=check, text=True, capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed with exit code {e.returncode}")

        # Use `cast` to explicitly tell the linter the type of these attributes.
        # Because text=True was used, we expect `str` or `None`.
        stdout_val = cast(str | None, e.stdout)
        stderr_val = cast(str | None, e.stderr)

        # Now, work with the safely typed variables. This resolves the `reportAny` warnings.
        stdout_log = stdout_val.strip() if stdout_val else "No stdout"
        stderr_log = stderr_val.strip() if stderr_val else "No stderr"

        logging.error(f"STDOUT: {stdout_log}")
        logging.error(f"STDERR: {stderr_log}")
        raise AppError(f"Execution failed for command: {command}") from e
    except FileNotFoundError as e:
        logging.error(f"Command not found: {args[0]}")
        raise AppError(f"Required command '{args[0]}' not found in PATH.") from e


def run_background_command(command: str) -> subprocess.Popen[str]:
    """
    Executes a shell command in the background and returns the Popen object.

    Args:
        command: The command string to execute.

    Returns:
        The Popen object for the running process.
    """
    logging.info(f"Executing in background: {command}")
    args = shlex.split(command)
    process = subprocess.Popen(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return process


@contextmanager
def manage_process(command: str) -> Generator[subprocess.Popen[str], None, None]:
    """
    Manages the lifecycle of a subprocess using a context manager.
    """
    process: subprocess.Popen[str] | None = None
    try:
        process = run_background_command(command)
        logging.info(f"Process started with PID: {process.pid} for command: {command}")
        yield process
    finally:
        if process and process.poll() is None:
            logging.info(f"Attempting graceful shutdown of PID {process.pid}...")
            process.send_signal(signal.SIGTERM)
            try:
                return_code = process.wait(timeout=5)
                logging.info(f"Process {process.pid} terminated gracefully with exit code {return_code}.")
            except subprocess.TimeoutExpired:
                logging.warning(f"Process {process.pid} did not terminate gracefully. Forcing kill.")
                process.kill()
                return_code = process.wait()
                logging.info(f"Process {process.pid} force-killed with exit code {return_code}.")
        elif process:
            logging.info(f"Process {process.pid} had already stopped with exit code {process.returncode}.")
        else:
            logging.warning("Process was not started, no cleanup needed.")


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
            _ = run_command("apt-get update -y")
            _ = run_command(f"apt-get install -y --no-install-recommends {actual_package_name}")
            logging.info(f"Successfully installed '{actual_package_name}'.")
        except AppError as e:
            raise AppError(f"Failed to install required command '{command_name}' (package: {actual_package_name}): {e}")
