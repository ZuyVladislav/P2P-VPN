# net/orchestrator.py

import socket
import threading
import logging
from handshake_core import create_handshake_request, process_handshake_request, process_handshake_response
from net import SecureConnection, connect_to_server
from utils.users import USERS


class Orchestrator:
    """
    Orchestrator manages the initiation and handling of secure handshake connections.
    It uses persistent RSA keys for the local user (loaded via utils.load_private_key) and coordinates
    the handshake protocol for both outgoing (initiator) and incoming (responder) connections.
    """

    def __init__(self, current_user: dict):
        """
        Initialize the Orchestrator with the current user's configuration.
        Starts a background thread to listen for incoming handshake connections.

        :param current_user: Dictionary with current user's data (login, password, ip).
        """
        self.user = current_user
        self.username = current_user.get("login")  # e.g., "User1"
        self.ip = current_user.get("ip")  # local IP address of this user
        self._online_peers = set()  # cache of online peers (updated via check_peers)
        self.connections = {}  # dict to store established SecureConnection objects by peer name

        # Start a thread to listen for incoming handshake connections on the user's IP.
        # Using a fixed port (e.g., 5000) for all handshake connections.
        self.listen_port = 5000
        self._listening = True
        self._server_thread = threading.Thread(target=self._listen_for_connections, daemon=True)
        self._server_thread.start()
        logging.info(f"Orchestrator: Listening for incoming connections on port {self.listen_port}")

    def _listen_for_connections(self):
        """Background thread method: listen on a TCP port and handle incoming handshake requests."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow immediate reuse of the port if the program restarts
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            # Bind to all interfaces (or could bind to self.ip specifically) on the handshake port
            server_sock.bind(("", self.listen_port))
            server_sock.listen(5)
        except Exception as e:
            logging.error(f"Orchestrator: Failed to bind listening socket on port {self.listen_port}: {e}")
            self._listening = False
            server_sock.close()
            return

        # Accept incoming connections until stopped
        while self._listening:
            try:
                client_sock, addr = server_sock.accept()
            except Exception as e:
                if not self._listening:
                    break  # socket closed intentionally to stop listening
                logging.error(f"Orchestrator: Error accepting connection: {e}")
                continue
            # Handle the handshake in a separate thread so we can accept multiple connections
            threading.Thread(target=self._handle_handshake, args=(client_sock, addr), daemon=True).start()
        # Clean up server socket when stopping
        try:
            server_sock.close()
        except Exception:
            pass

    def _handle_handshake(self, client_sock: socket.socket, addr):
        """
        Handle the handshake protocol as the responder for a single incoming connection.
        Automatically processes the handshake request and sends a response.
        """
        remote_addr = f"{addr[0]}:{addr[1]}"
        logging.info(f"Orchestrator: Accepted connection from {remote_addr}")
        try:
            # Receive handshake request data (assuming a single JSON message)
            client_sock.settimeout(5.0)
            request_data = b""
            # Read until we get the complete JSON (assuming '}' ends the JSON handshake message)
            while True:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                request_data += chunk
                if b'}' in chunk:
                    break
        except socket.timeout:
            # Timeout waiting for handshake data
            logging.warning(f"Orchestrator: Timeout waiting for handshake data from {remote_addr}")
            client_sock.close()
            return
        except Exception as e:
            logging.error(f"Orchestrator: Error receiving handshake data from {remote_addr}: {e}")
            client_sock.close()
            return

        if not request_data:
            logging.warning(f"Orchestrator: No handshake data received from {remote_addr}")
            client_sock.close()
            return

        # Process the handshake request to obtain the session key and peer's name
        try:
            response_data, session_key, peer_name = process_handshake_request(self.username, request_data)
        except Exception as e:
            logging.error(f"Orchestrator: Handshake request processing failed: {e}")
            client_sock.close()
            return

        # At this point, in a full implementation we could prompt the user to accept or reject the connection.
        # For simplicity, we auto-accept all incoming connections and proceed to send the handshake response.
        try:
            client_sock.sendall(response_data)
        except Exception as e:
            logging.error(f"Orchestrator: Failed to send handshake response to {peer_name} ({remote_addr}): {e}")
            client_sock.close()
            return

        # Wrap the socket in a SecureConnection for encrypted communication
        secure_conn = SecureConnection(client_sock, session_key, peer_name)
        self.connections[peer_name] = secure_conn
        logging.info(f"Handshake successful with {peer_name}. Session key established.")
        # (If needed, further communication with peer_name can use self.connections[peer_name].send()/receive())

    def initiate_handshake(self, target_user: str):
        """
        Initiate a handshake with a target user (acting as the initiator).
        Uses the target user's IP from USERS to connect and perform the handshake.

        :param target_user: Username of the target peer to connect to.
        :raises Exception: if the connection or handshake fails.
        """
        if target_user not in USERS:
            raise ValueError(f"Unknown target user: {target_user}")
        target_info = USERS[target_user]
        target_ip = target_info.get("ip")
        target_name = target_info.get("login", target_user)
        if not target_ip:
            raise ValueError(f"No IP address for target user {target_user}")

        logging.info(f"Orchestrator: Initiating handshake to {target_user} at {target_ip}:{self.listen_port}")
        try:
            # Use the handshake_core protocol to connect and establish a SecureConnection
            secure_conn = connect_to_server(target_ip, self.listen_port, self.username, target_name)
        except Exception as e:
            # Log and re-raise exception to notify UI that connection failed
            logging.error(f"Orchestrator: Handshake initiation to {target_user} failed: {e}")
            raise
        # Store the established secure connection
        self.connections[target_name] = secure_conn
        logging.info(f"Handshake successful with {target_name}. Session key established.")
        return secure_conn  # Return the SecureConnection in case the caller needs it

    def get_online_peers(self):
        """
        Return a list of user names that are currently online (reachable).
        This list is typically updated by calling check_peers().
        """
        return list(self._online_peers)

    def check_peers(self):
        """
        Update the status of other users by sending a ping (UDP) to each and waiting for a pong.
        Marks users as online if a pong response is received.
        """
        online = set()
        # Use UDP discovery ping/pong on the handshake port to check if peers are online
        for user, info in USERS.items():
            if info.get("login") == self.username:
                continue  # skip current user
            peer_ip = info.get("ip")
            if not peer_ip:
                continue
            try:
                # Send a UDP "PING" to the peer's handshake port
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.5)
                sock.sendto(b"PING", (peer_ip, self.listen_port))
                # Wait for a "PONG" response
                data, _ = sock.recvfrom(1024)
                if data and data.upper() == b"PONG":
                    online.add(info.get("login", user))
            except Exception:
                # No response or error, treat as offline
                continue
            finally:
                sock.close()
        self._online_peers = online
        logging.info(
            f"Orchestrator: Online peers updated -> {', '.join(self._online_peers) if self._online_peers else 'None'}")
        return list(self._online_peers)

    def abort(self):
        """
        Abort any ongoing handshake or stop listening for new connections.
        This can be called to decline an incoming connection or to clean up.
        """
        # In this simplified implementation, we auto-accept handshakes immediately.
        # So abort will mainly be used to stop the listening thread when shutting down.
        self._listening = False
        logging.info("Orchestrator: Stopping listener and aborting any pending handshakes.")
        try:
            # Create a dummy connection to self to unblock the accept() call, causing the thread to exit
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("127.0.0.1", self.listen_port))
        except Exception:
            pass