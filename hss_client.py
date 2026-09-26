"""HSS client for connecting to an authorized HSS server."""  # Documents the purpose of this client module.

from __future__ import annotations  # Delays evaluation of type annotations until they are needed.

import argparse  # Parses command-line options such as the server address and port.
import socket  # Creates and manages TCP and UDP network connections.
import threading  # Runs output handling in a background thread.
import time  # Provides delays between connection retries.


# Set to False to run commands without displaying remote PowerShell output.
SHOW_REMOTE_OUTPUT = True  # Controls whether output received from PowerShell is printed.
DISCOVERY_PORT = 8766  # Defines the UDP port used by the legacy server-discovery helper.
password = "WeltaITBusinessIncorperatedITSecurePasswordHSSSystem"


def receive_output(reader) -> None:
    try:
        for raw_line in reader:  # Processes each protocol line received from the server.
            line = raw_line.decode("utf-8", errors="replace")  # Converts bytes into readable text while replacing invalid bytes.
            if not SHOW_REMOTE_OUTPUT:
                continue  # Skips display output when remote output has been disabled.
            if line.startswith("OUT "):
                print(line[4:], end="")  # Prints normal PowerShell output without its protocol prefix.
            elif line.startswith("ERR "):
                print(line[4:], end="", flush=True)  # Prints error output without its prefix and flushes immediately.
            else:
                print(line, end="", flush=True)  # Prints any other server message unchanged.
    except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
        pass  # Silently ends output handling when the connection closes unexpectedly.
    finally:
        print("\nHSS connection closed.")  # Informs the user that the output connection has ended.


def discover_server(tcp_port: int, timeout: float = 1.0) -> tuple[str, int]:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as discovery_socket:  # Opens a temporary IPv4 UDP socket for discovery.
        discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Allows the discovery request to use a broadcast address.
        discovery_socket.settimeout(timeout)  # Limits how long each discovery receive operation may wait.
        discovery_socket.sendto(b"HSS_DISCOVER\n", ("255.255.255.255", DISCOVERY_PORT))  # Broadcasts the discovery request on the configured UDP port.
        while True:  # Keeps checking responses until one advertises the requested TCP port.
            response, address = discovery_socket.recvfrom(256)  # Reads a discovery response and its sender address.
            if response.decode("utf-8", errors="replace").strip() == f"HSS/1 {tcp_port}":
                return address[0], tcp_port  # Returns the responding server address and TCP port.


def connect_and_authenticate(host: str, port: int, password: str) -> socket.socket:
    connection = socket.create_connection((host, port), timeout=10)  # Opens a TCP connection to the specified HSS server.
    connection.settimeout(None)  # Removes the connection timeout after the initial connection succeeds.
    reader = connection.makefile("rb")  # Creates a buffered reader for line-based protocol responses.
    banner = reader.readline().decode("utf-8", errors="replace")  # Reads and decodes the server protocol banner.
    if banner != "HSS/1\n":
        reader.close()  # Closes the temporary reader when the banner is invalid.
        connection.close()  # Closes the socket when the target is not the expected server.
        raise OSError("The target is not an HSS server.")  # Reports the protocol mismatch to the caller.

    connection.sendall(f"AUTH {password}\n".encode("utf-8"))  # Sends the shared password using the HSS authentication message format.
    response = reader.readline().decode("utf-8", errors="replace")  # Reads and decodes the authentication result.
    if not response.startswith("OK "):
        reader.close()  # Releases the response reader after authentication fails.
        connection.close()  # Releases the socket after authentication fails.
        raise OSError(response.strip() or "HSS authentication failed.")  # Reports the server's rejection or a generic error.
    return connection  # Returns the authenticated socket for interactive commands.


def main() -> None:
    parser = argparse.ArgumentParser(description="Open a PowerShell session through HSS")  # Creates the command-line parser.
    parser.add_argument("host", nargs="?", help="IP address or hostname of the HSS server")  # Accepts an optional server address.
    parser.add_argument("--port", type=int, default=8765, help="TCP port")  # Accepts the server TCP port with its default value.
    args = parser.parse_args()  # Parses the actual command-line arguments.

    host = args.host or input("HSS server IP address: ").strip()  # Uses the argument or interactively asks for the server address.
    if not host:
        raise SystemExit("A server IP address is required.")  # Stops when the user provides no server address.
    retry_delay = 1.0  # Starts the reconnect delay at one second.
    while True:  # Keeps retrying after recoverable network failures.
        connection = None  # Tracks the active socket so cleanup can happen safely.
        reader = None  # Tracks the active response reader so cleanup can happen safely.
        try:
            connection = connect_and_authenticate(host, args.port, password)  # Connects to and authenticates with the server.
            reader = connection.makefile("rb")  # Creates a reader for server output after authentication.
            print(f"Connected to {host}. Type PowerShell commands; use :quit to disconnect.")  # Shows the active session status.
            threading.Thread(target=receive_output, args=(reader,), daemon=True).start()  # Displays server output in the background.
            retry_delay = 1.0  # Resets the retry delay after a successful connection.

            while True:  # Reads and sends commands until the user exits.
                command = input("PS> ")  # Reads one PowerShell command from the user.
                connection.sendall((command + "\n").encode("utf-8"))  # Sends the command as one UTF-8 protocol line.
                if command in {":quit", ":exit"}:
                    return  # Ends the client when the user requests disconnection.
        except (EOFError, KeyboardInterrupt):
            if connection is not None:
                try:
                    connection.sendall(b":quit\n")  # Requests a clean server-side shutdown of the session.
                except OSError:
                    pass  # Ignores errors if the connection has already closed.
            return  # Ends the client after input is interrupted or closed.
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError) as error:
            print(f"HSS connection lost ({error}); retrying in {retry_delay:.0f}s.")  # Reports a recoverable network failure.
            time.sleep(retry_delay)  # Waits before attempting the connection again.
            retry_delay = min(retry_delay * 2, 10.0)  # Applies exponential backoff capped at ten seconds.
        finally:
            if reader is not None:
                reader.close()  # Closes the response reader during every exit path.
            if connection is not None:
                connection.close()  # Closes the socket during every exit path.


if __name__ == "__main__":
    main()  # Starts the client only when this file is run directly.