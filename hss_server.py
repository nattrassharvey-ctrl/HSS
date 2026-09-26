"""HSS server for an authorized Windows LAN.

This is a learning prototype, not a production SSH replacement. Traffic is
not encrypted, so use it only on a trusted private network.
"""
# The module documentation explains the prototype's purpose and network limitation.

from __future__ import annotations  # Delays evaluation of type annotations until they are needed.

import argparse  # Parses server command-line options.
import socketserver  # Supplies threaded TCP and UDP server classes.
import subprocess  # Starts the local PowerShell process.
import sys  # Identifies the Windows runtime for firewall setup.
import threading  # Runs output forwarding and discovery service work concurrently.


MAX_COMMAND_LENGTH = 8192  # Limits the maximum size of one client command.
DISCOVERY_PORT = 8766  # Defines the UDP port used by the discovery service.
password = "WeltaITBusinessIncorperatedITSecurePasswordHSSSystem"


def ensure_firewall_rule(port: int) -> None:
    if sys.platform != "win32":
        return

    rule_name = f"HSS_TCP_{port}"
    existing_rule = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
        capture_output=True,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if existing_rule.returncode == 0:
        return

    rule_arguments = (
        f"advfirewall firewall add rule name={rule_name} dir=in action=allow "
        f"protocol=TCP localport={port} remoteip=localsubnet profile=private"
    )
    powershell_command = (
        f"$rule = Start-Process -FilePath netsh.exe -ArgumentList '{rule_arguments}' "
        "-Verb RunAs -Wait -PassThru; exit $rule.ExitCode"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", powershell_command],
        capture_output=True,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        raise SystemExit(
            "Could not add the Windows Firewall rule. Approve the UAC prompt and "
            "make sure this network is set to Private."
        )
    print(f"Added a Private-network firewall rule for TCP port {port}.")


class HssRequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server = self.server  # Stores the server instance so its configured password can be accessed.
        writer = self.wfile  # Stores the client output stream used for protocol responses.

        writer.write(b"HSS/1\n")  # Sends the HSS protocol version banner.
        writer.flush()  # Ensures the banner reaches the client immediately.

        auth_line = self.rfile.readline(4096).decode("utf-8", errors="replace")  # Reads and decodes the client's authentication message.
        if not auth_line.startswith("AUTH "):
            writer.write(b"ERR authentication required\n")  # Rejects messages that do not use the AUTH protocol format.
            writer.flush()  # Sends the rejection immediately.
            return  # Ends this client session.

        supplied_password = auth_line[5:].rstrip("\r\n")  # Extracts the password and removes its line ending.
        if supplied_password != server.password:
            writer.write(b"ERR authentication failed\n")  # Rejects a password that does not match the configured password.
            writer.flush()  # Sends the rejection immediately.
            return  # Ends this unauthenticated session.

        writer.write(b"OK authenticated\n")  # Confirms successful authentication to the client.
        writer.flush()  # Sends the confirmation immediately.
        print(f"Authenticated HSS client: {self.client_address[0]}")  # Logs the authenticated client's address.

        powershell = subprocess.Popen(  # Starts an isolated PowerShell process for this authenticated client.
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],  # Configures PowerShell to read commands from standard input.
            stdin=subprocess.PIPE,  # Captures a pipe for sending client commands to PowerShell.
            stdout=subprocess.PIPE,  # Captures normal PowerShell output for forwarding to the client.
            stderr=subprocess.PIPE,  # Captures PowerShell error output for forwarding to the client.
            text=True,  # Makes the subprocess streams operate on text strings.
            bufsize=1,  # Requests line-buffered stream behavior.
        )

        output_threads = [  # Creates one forwarding thread for normal output and one for errors.
            threading.Thread(  # Configures a thread to forward normal PowerShell output.
                target=self.forward_output,  # Selects the shared forwarding method as the thread target.
                args=(powershell.stdout, b"OUT "),  # Supplies the normal-output stream and protocol prefix.
                daemon=True,  # Allows the thread to end automatically when the server process exits.
            ),
            threading.Thread(  # Configures a thread to forward PowerShell error output.
                target=self.forward_output,  # Selects the shared forwarding method as the thread target.
                args=(powershell.stderr, b"ERR "),  # Supplies the error stream and protocol prefix.
                daemon=True,  # Allows the thread to end automatically when the server process exits.
            ),
        ]
        for thread in output_threads:  # Visits each output-forwarding thread.
            thread.start()  # Starts forwarding output concurrently with command processing.

        try:
            try:
                for raw_line in self.rfile:  # Processes each command line received from the client.
                    command = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")  # Decodes the command and removes its line ending.
                    if command in {":quit", ":exit"}:
                        break  # Leaves the command loop when the client requests disconnection.
                    if len(command) > MAX_COMMAND_LENGTH:
                        writer.write(b"ERR command too long\n")  # Rejects commands exceeding the configured limit.
                        writer.flush()  # Sends the length error immediately.
                        continue  # Waits for the next client command.
                    if not command:
                        continue  # Ignores empty command lines.
                    if powershell.stdin is None:
                        break  # Stops if the PowerShell input pipe is unavailable.
                    powershell.stdin.write(command + "\n")  # Sends the client's command to PowerShell.
                    powershell.stdin.flush()  # Makes PowerShell receive the command immediately.
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                pass  # Ends command processing when the client connection closes unexpectedly.
        finally:
            if powershell.stdin is not None:
                powershell.stdin.close()  # Closes PowerShell input so the subprocess can finish.
            try:
                powershell.wait(timeout=3)  # Waits briefly for PowerShell to exit normally.
            except subprocess.TimeoutExpired:
                powershell.kill()  # Forces PowerShell to stop if it does not exit promptly.
                powershell.wait()  # Waits for the forced termination to complete.
            print(f"HSS client disconnected: {self.client_address[0]}")  # Logs the end of the client session.

    def forward_output(self, stream, prefix: bytes) -> None:
        for line in iter(stream.readline, ""):  # Reads PowerShell output one line at a time until end-of-stream.
            try:
                self.wfile.write(prefix + line.encode("utf-8", errors="replace"))  # Adds the output type prefix and sends encoded text.
                self.wfile.flush()  # Delivers each output line to the client immediately.
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                return  # Stops forwarding when the client socket is no longer available.


class HssDiscoveryHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        message, discovery_socket = self.request  # Separates the received UDP message from the reply socket.
        if message.decode("utf-8", errors="replace").strip() == "HSS_DISCOVER":
            discovery_socket.sendto(  # Replies to valid discovery requests.
                f"HSS/1 {self.server.tcp_port}\n".encode("utf-8"),  # Encodes the advertised TCP port in the HSS protocol format.
                self.client_address,  # Sends the reply to the requesting client address.
            )


class HssDiscoveryServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True  # Allows the discovery UDP port to be reused after restart.
    daemon_threads = True  # Allows discovery worker threads to end with the server.

    def __init__(self, address: tuple[str, int], tcp_port: int):
        self.tcp_port = tcp_port  # Stores the TCP port that discovery responses should advertise.
        super().__init__(address, HssDiscoveryHandler)  # Initializes the threaded UDP server.


class HssServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True  # Allows the TCP port to be reused after restart.
    daemon_threads = True  # Allows client handler threads to end with the server.

    def __init__(self, address: tuple[str, int], password: str):
        self.password = password  # Stores the shared password for request authentication.
        super().__init__(address, HssRequestHandler)  # Initializes the threaded TCP server.


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the HSS PowerShell server")  # Creates the command-line parser.
    parser.add_argument("--host", default="0.0.0.0", help="Address to listen on")  # Accepts the server bind address.
    parser.add_argument("--port", type=int, default=8765, help="TCP port")  # Accepts the TCP port with its default value.
    args = parser.parse_args()  # Parses the actual command-line arguments.

    print("HSS server starting. Use only on a private network you control.")  # Warns that the server should stay on a controlled network.
    print(f"Listening on server address {args.host}:{args.port}; press Ctrl+C to stop.")  # Reports the configured bind address and port.
    with HssServer((args.host, args.port), password) as server, HssDiscoveryServer(  # Opens both the TCP service and UDP discovery service.
        (args.host, DISCOVERY_PORT), args.port  # Binds discovery and advertises the configured TCP port.
    ) as discovery_server:  # Keeps both servers active until shutdown.
        ensure_firewall_rule(args.port)  # Adds the inbound firewall rule on first startup when needed.
        discovery_thread = threading.Thread(target=discovery_server.serve_forever, daemon=True)  # Creates the background discovery loop.
        discovery_thread.start()  # Starts listening for UDP discovery messages.
        print(f"LAN discovery enabled on UDP port {DISCOVERY_PORT}.")  # Reports the active discovery port.
        try:
            server.serve_forever()  # Runs the main TCP server loop.
        except KeyboardInterrupt:
            print("\nHSS server stopped.")  # Reports a normal Ctrl+C shutdown.


if __name__ == "__main__":
    main()  # Starts the server only when this file is run directly.