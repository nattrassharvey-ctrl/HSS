"""Client for an HSS PowerShell server on a trusted local network."""

from __future__ import annotations

import argparse
import ctypes
import msvcrt
import os
from queue import Empty, Queue
import socket
import sys
import threading
import time
from typing import BinaryIO


PASSWORD = "WeltaITBusinessIncorperatedITSecurePasswordHSSSystem"
DEFAULT_PORT = 8765
MAX_RETRY_DELAY = 10.0
BLUE = "\033[94m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
REMOTE_CWD_MARKER = "__HSS_REMOTE_CWD__:"


def enable_terminal_colors() -> None:
	if os.name != "nt" or not sys.stdout.isatty():
		return
	try:
		handle = msvcrt.get_osfhandle(sys.stdout.fileno())
		mode = ctypes.c_uint()
		kernel32 = ctypes.windll.kernel32
		if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
			kernel32.SetConsoleMode(handle, mode.value | 0x0004)
	except (AttributeError, OSError, ValueError):
		pass


def styled(text: str, color: str) -> str:
	if not sys.stdout.isatty():
		return text
	return f"{color}{text}{RESET}"


def make_prompt(remote_path: str) -> str:
	return f"{styled('PS', BLUE)} {styled(remote_path, CYAN)}{styled('>', BLUE)} "


class AuthenticationError(Exception):
	"""Raised when the server rejects the shared password."""


def connect_and_authenticate(host: str, port: int, timeout: float = 10.0) -> socket.socket:
	connection = socket.create_connection((host, port), timeout=timeout)
	reader = connection.makefile("rb")
	try:
		banner = reader.readline().decode("utf-8", errors="replace").rstrip("\r\n")
		if banner != "HSS/1":
			raise OSError("The server returned an unexpected HSS protocol banner.")

		connection.sendall(f"AUTH {PASSWORD}\n".encode("utf-8"))
		response = reader.readline().decode("utf-8", errors="replace").rstrip("\r\n")
		if response != "OK authenticated":
			raise AuthenticationError(response.removeprefix("ERR ") or "Authentication failed.")
		connection.settimeout(None)
		return connection
	except (OSError, AuthenticationError):
		connection.close()
		raise
	finally:
		reader.close()


def receive_output(reader: BinaryIO, cwd_updates: Queue[str]) -> None:
	try:
		for raw_line in reader:
			line = raw_line.decode("utf-8", errors="replace")
			if line.startswith("ERR "):
				print(styled(line[4:].rstrip("\r\n"), RED), flush=True)
			elif line.startswith("OUT "):
				output = line[4:]
				if output.startswith(REMOTE_CWD_MARKER):
					cwd = output[len(REMOTE_CWD_MARKER):].rstrip("\r\n")
					if cwd:
						cwd_updates.put(cwd)
				else:
					print(output, end="", flush=True)
			else:
				print(line, end="", flush=True)
	except OSError:
		pass
	finally:
		print("\nHSS connection closed.")


def run_client(host: str, port: int) -> None:
	retry_delay = 1.0
	while True:
		connection: socket.socket | None = None
		reader: BinaryIO | None = None
		try:
			connection = connect_and_authenticate(host, port)
			reader = connection.makefile("rb")
			print(styled(f"Connected to {host}:{port}.", GREEN) + " Enter :quit to disconnect.")
			cwd_updates: Queue[str] = Queue()
			threading.Thread(target=receive_output, args=(reader, cwd_updates), daemon=True).start()
			try:
				remote_path = cwd_updates.get(timeout=10)
			except Empty as error:
				raise OSError("The server did not report the PowerShell working directory.") from error
			retry_delay = 1.0

			while True:
				command = input(make_prompt(remote_path))
				connection.sendall((command + "\n").encode("utf-8"))
				if command in {":quit", ":exit"}:
					return
				try:
					remote_path = cwd_updates.get(timeout=60)
				except Empty as error:
					raise OSError("The server did not report the PowerShell working directory after the command.") from error
		except AuthenticationError as error:
			raise SystemExit(f"HSS authentication failed: {error}") from error
		except (EOFError, KeyboardInterrupt):
			if connection is not None:
				try:
					connection.sendall(b":quit\n")
				except OSError:
					pass
			return
		except OSError as error:
			message = f"HSS connection to {host}:{port} failed ({error}); retrying in {retry_delay:.0f}s."
			print(styled(message, YELLOW))
			time.sleep(retry_delay)
			retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY)
		finally:
			if reader is not None:
				reader.close()
			if connection is not None:
				connection.close()


def main() -> None:
	enable_terminal_colors()
	parser = argparse.ArgumentParser(description="Open a PowerShell session through HSS")
	parser.add_argument("host", nargs="?", help="IP address or hostname of the HSS server")
	parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server TCP port")
	args = parser.parse_args()

	host = args.host or input("HSS server IP address: ").strip()
	if not host:
		raise SystemExit("A server IP address is required.")
	run_client(host, args.port)


if __name__ == "__main__":
	main()
