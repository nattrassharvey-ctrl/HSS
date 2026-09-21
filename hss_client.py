"""HSS client for connecting to an authorized HSS server."""

from __future__ import annotations

import argparse
import getpass
import os
import socket
import threading


# Set to False to run commands without displaying remote PowerShell output.
SHOW_REMOTE_OUTPUT = True
MIN_TOKEN_LENGTH = 5


def read_token() -> str:
    token = os.environ.get("HSS_TOKEN")
    if token is None:
        token = getpass.getpass("HSS shared token (minimum 5 digits): ")
    if not token.isdigit() or len(token) < MIN_TOKEN_LENGTH:
        raise SystemExit("HSS shared token must contain at least 5 digits.")
    return token


def receive_output(reader) -> None:
    try:
        for raw_line in reader:
            line = raw_line.decode("utf-8", errors="replace")
            if not SHOW_REMOTE_OUTPUT:
                continue
            if line.startswith("OUT "):
                print(line[4:], end="")
            elif line.startswith("ERR "):
                print(line[4:], end="", flush=True)
            else:
                print(line, end="", flush=True)
    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        print("\nHSS connection closed.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Open a PowerShell session through HSS")
    parser.add_argument("host", nargs="?", help="IP address or hostname of the HSS server")
    parser.add_argument("--port", type=int, default=8765, help="TCP port")
    args = parser.parse_args()

    host = args.host or input("HSS server IP or hostname: ").strip()
    if not host:
        raise SystemExit("A server IP address or hostname is required.")

    token = read_token()
    with socket.create_connection((host, args.port), timeout=10) as connection:
        reader = connection.makefile("rb")
        banner = reader.readline().decode("utf-8", errors="replace")
        if banner != "HSS/1\n":
            raise SystemExit("The target is not an HSS server.")

        connection.sendall(f"AUTH {token}\n".encode("utf-8"))
        response = reader.readline().decode("utf-8", errors="replace")
        if not response.startswith("OK "):
            raise SystemExit(response.strip() or "HSS authentication failed.")

        print("Connected. Type PowerShell commands; use :quit to disconnect.")
        output_thread = threading.Thread(target=receive_output, args=(reader,), daemon=True)
        output_thread.start()

        try:
            while True:
                command = input("PS> ")
                connection.sendall((command + "\n").encode("utf-8"))
                if command in {":quit", ":exit"}:
                    break
        except (EOFError, KeyboardInterrupt):
            connection.sendall(b":quit\n")


if __name__ == "__main__":
    main()