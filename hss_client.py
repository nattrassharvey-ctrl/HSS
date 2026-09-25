"""HSS client for connecting to an authorized HSS server."""

from __future__ import annotations

import argparse
import getpass
import os
import socket
import threading
import time


# Set to False to run commands without displaying remote PowerShell output.
SHOW_REMOTE_OUTPUT = True
MIN_TOKEN_LENGTH = 5
DISCOVERY_PORT = 8766


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


def discover_server(tcp_port: int, timeout: float = 1.0) -> tuple[str, int]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as discovery_socket:
        discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        discovery_socket.settimeout(timeout)
        discovery_socket.sendto(b"HSS_DISCOVER\n", ("255.255.255.255", DISCOVERY_PORT))
        while True:
            response, address = discovery_socket.recvfrom(256)
            if response.decode("utf-8", errors="replace").strip() == f"HSS/1 {tcp_port}":
                return address[0], tcp_port


def connect_and_authenticate(host: str, port: int, token: str) -> socket.socket:
    connection = socket.create_connection((host, port), timeout=10)
    connection.settimeout(None)
    reader = connection.makefile("rb")
    banner = reader.readline().decode("utf-8", errors="replace")
    if banner != "HSS/1\n":
        reader.close()
        connection.close()
        raise OSError("The target is not an HSS server.")

    connection.sendall(f"AUTH {token}\n".encode("utf-8"))
    response = reader.readline().decode("utf-8", errors="replace")
    if not response.startswith("OK "):
        reader.close()
        connection.close()
        raise OSError(response.strip() or "HSS authentication failed.")
    return connection


def main() -> None:
    parser = argparse.ArgumentParser(description="Open a PowerShell session through HSS")
    parser.add_argument("host", nargs="?", help="IP address or hostname of the HSS server")
    parser.add_argument("--port", type=int, default=8765, help="TCP port")
    args = parser.parse_args()

    token = read_token()
    retry_delay = 1.0
    while True:
        connection = None
        reader = None
        try:
            host = args.host
            if not host:
                print("Searching for an HSS server on the local network...")
                host, port = discover_server(args.port)
            else:
                port = args.port

            connection = connect_and_authenticate(host, port, token)
            reader = connection.makefile("rb")
            print(f"Connected to {host}. Type PowerShell commands; use :quit to disconnect.")
            threading.Thread(target=receive_output, args=(reader,), daemon=True).start()
            retry_delay = 1.0

            while True:
                command = input("PS> ")
                connection.sendall((command + "\n").encode("utf-8"))
                if command in {":quit", ":exit"}:
                    return
        except (EOFError, KeyboardInterrupt):
            if connection is not None:
                try:
                    connection.sendall(b":quit\n")
                except OSError:
                    pass
            return
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError) as error:
            print(f"HSS connection lost ({error}); retrying in {retry_delay:.0f}s.")
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 10.0)
        finally:
            if reader is not None:
                reader.close()
            if connection is not None:
                connection.close()


if __name__ == "__main__":
    main()