"""HSS server for an authorized Windows LAN.

This is a learning prototype, not a production SSH replacement. Traffic is
not encrypted, so use it only on a trusted private network.
"""

from __future__ import annotations

import argparse
import getpass
import hmac
import os
import socketserver
import subprocess
import threading


MAX_COMMAND_LENGTH = 8192
MIN_TOKEN_LENGTH = 5
DISCOVERY_PORT = 8766


def read_token() -> str:
    token = os.environ.get("HSS_TOKEN")
    if token is None:
        token = getpass.getpass("HSS shared token (minimum 5 digits): ")
    if not token.isdigit() or len(token) < MIN_TOKEN_LENGTH:
        raise SystemExit("HSS shared token must contain at least 5 digits.")
    return token


class HssRequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server = self.server
        writer = self.wfile

        writer.write(b"HSS/1\n")
        writer.flush()

        auth_line = self.rfile.readline(4096).decode("utf-8", errors="replace")
        if not auth_line.startswith("AUTH "):
            writer.write(b"ERR authentication required\n")
            writer.flush()
            return

        supplied_token = auth_line[5:].rstrip("\r\n")
        if not hmac.compare_digest(supplied_token, server.token):
            writer.write(b"ERR authentication failed\n")
            writer.flush()
            return

        writer.write(b"OK authenticated\n")
        writer.flush()
        print(f"Authenticated HSS client: {self.client_address[0]}")

        powershell = subprocess.Popen(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        output_threads = [
            threading.Thread(
                target=self.forward_output,
                args=(powershell.stdout, b"OUT "),
                daemon=True,
            ),
            threading.Thread(
                target=self.forward_output,
                args=(powershell.stderr, b"ERR "),
                daemon=True,
            ),
        ]
        for thread in output_threads:
            thread.start()

        try:
            try:
                for raw_line in self.rfile:
                    command = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                    if command in {":quit", ":exit"}:
                        break
                    if len(command) > MAX_COMMAND_LENGTH:
                        writer.write(b"ERR command too long\n")
                        writer.flush()
                        continue
                    if not command:
                        continue
                    if powershell.stdin is None:
                        break
                    powershell.stdin.write(command + "\n")
                    powershell.stdin.flush()
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                pass
        finally:
            if powershell.stdin is not None:
                powershell.stdin.close()
            try:
                powershell.wait(timeout=3)
            except subprocess.TimeoutExpired:
                powershell.kill()
                powershell.wait()
            print(f"HSS client disconnected: {self.client_address[0]}")

    def forward_output(self, stream, prefix: bytes) -> None:
        for line in iter(stream.readline, ""):
            try:
                self.wfile.write(prefix + line.encode("utf-8", errors="replace"))
                self.wfile.flush()
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                return


class HssDiscoveryHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        message, discovery_socket = self.request
        if message.decode("utf-8", errors="replace").strip() == "HSS_DISCOVER":
            discovery_socket.sendto(
                f"HSS/1 {self.server.tcp_port}\n".encode("utf-8"),
                self.client_address,
            )


class HssDiscoveryServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], tcp_port: int):
        self.tcp_port = tcp_port
        super().__init__(address, HssDiscoveryHandler)


class HssServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], token: str):
        self.token = token
        super().__init__(address, HssRequestHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the HSS PowerShell server")
    parser.add_argument("--host", default="0.0.0.0", help="Address to listen on")
    parser.add_argument("--port", type=int, default=8765, help="TCP port")
    args = parser.parse_args()

    token = read_token()

    print("HSS server starting. Use only on a private network you control.")
    print(f"Listening on {args.host}:{args.port}; press Ctrl+C to stop.")
    with HssServer((args.host, args.port), token) as server, HssDiscoveryServer(
        (args.host, DISCOVERY_PORT), args.port
    ) as discovery_server:
        discovery_thread = threading.Thread(target=discovery_server.serve_forever, daemon=True)
        discovery_thread.start()
        print(f"LAN discovery enabled on UDP port {DISCOVERY_PORT}.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nHSS server stopped.")


if __name__ == "__main__":
    main()