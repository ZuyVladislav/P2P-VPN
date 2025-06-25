import socket
import threading
import logging

"""
Network thread module: listens for incoming TCP connections and handles handshake initialization.
Also includes a UDP DiscoveryResponder for PING/PONG discovery.
"""

# Get module-level logger for diagnostics
logger = logging.getLogger(__name__)

# 6. UDP responder class that listens for "PING" messages on a UDP port and responds with "PONG"
class DiscoveryResponder(threading.Thread):
    """DiscoveryResponder listens for UDP PING messages and replies with PONG."""
    def __init__(self, port: int = 5000):
        super().__init__(daemon=True)
        self.port = port
        self.sock = None
        self._running = True

    def run(self):
        try:
            # Setup UDP socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Allow address reuse in case socket was recently closed
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Bind to all interfaces on the given port
            self.sock.bind(("", self.port))
            logger.info(f"DiscoveryResponder: Listening for UDP PING on port {self.port}")
        except Exception as e:
            logger.error(f"DiscoveryResponder: Failed to bind UDP socket on port {self.port}: {e}", exc_info=True)
            self._running = False

        # Listen loop for incoming UDP messages
        while self._running:
            try:
                # Block until a datagram is received or socket is closed
                data, addr = self.sock.recvfrom(1024)
            except OSError as e:
                # Socket closed or other error
                if self._running:
                    logger.error(f"DiscoveryResponder: Socket error: {e}", exc_info=True)
                break
            if not data:
                # No data received (should not usually happen for UDP)
                continue
            # Decode message (assuming UTF-8 text)
            message = None
            try:
                message = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                # Non-text data, ignore this packet
                continue
            # Check if the message is a "PING" (case-insensitive)
            if message and message.upper() == "PING":
                try:
                    # Respond with "PONG" to the sender's address
                    self.sock.sendto(b"PONG", addr)
                    logger.debug(f"DiscoveryResponder: Sent PONG to {addr}")
                except Exception as e:
                    logger.error(f"DiscoveryResponder: Failed to send PONG to {addr}: {e}", exc_info=True)
        # Cleanup on exit
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        logger.info("DiscoveryResponder: Stopped")

    def stop(self):
        """Stop the UDP responder."""
        self._running = False
        if self.sock:
            try:
                # Closing the socket will unblock recvfrom and cause the thread loop to exit
                self.sock.close()
            except Exception:
                pass

# 1. NetworkThread listens for incoming TCP connections on a given port and handles them
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot

class NetworkThread(QThread):
    """
    NetworkThread listens for incoming TCP connections on the specified port.
    For each connection, it creates a KDContext and Orchestrator, and runs the handshake as a responder.
    Also launches a UDP DiscoveryResponder to handle PING/PONG discovery messages.
    """
    # Signal emitted when a new connection requires user confirmation (after initial handshake steps are done).
    # Arguments: handshake_id (int), remote_id (str)
    incoming_request = pyqtSignal(int, str)

    def __init__(self, port: int = 5000, parent=None):
        super().__init__(parent)
        self.port = port
        self._running = True
        self.sock = None             # TCP listening socket
        self.discovery = None        # DiscoveryResponder thread for UDP
        # Dictionary to track pending handshakes awaiting user confirmation:
        # key: handshake ID, value: dict with keys 'orchestrator', 'context', 'socket', 'event', 'accepted'
        self._pending_handshakes = {}
        self._pending_lock = threading.Lock()
        self._next_handshake_id = 1

    def run(self):
        # 1. Initialize TCP server socket to listen for connections
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("", self.port))
            self.sock.listen(5)
            # Set a timeout for the accept call to allow checking _running periodically
            self.sock.settimeout(1.0)
            logger.info(f"NetworkThread: Listening for TCP connections on port {self.port}")
        except Exception as e:
            logger.error(f"NetworkThread: Failed to start TCP server on port {self.port}: {e}", exc_info=True)
            self._running = False

        # 6. Start UDP discovery responder thread to answer PING with PONG
        if self._running:
            self.discovery = DiscoveryResponder(port=self.port)
            self.discovery.start()

        # Accept incoming connections loop
        while self._running:
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                # Timeout used to re-check _running flag regularly
                continue
            except Exception as e:
                if not self._running:
                    break  # Socket was closed to stop the thread
                logger.error(f"NetworkThread: Error accepting connection: {e}", exc_info=True)
                continue

            # 5. Handle each connection in a new thread for parallel processing
            threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()

        # Cleanup when stopping the network thread
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        if self.discovery:
            self.discovery.stop()
            self.discovery = None
        logger.info("NetworkThread: Stopped")

    def stop(self):
        """Stop the network thread and close listening sockets."""
        self._running = False
        # Closing the listening socket will cause the accept loop to exit on next iteration
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        # Also stop the discovery responder if it's running
        if self.discovery:
            self.discovery.stop()

    # 2. Determine remote user identifier either by first received line or by IP address
    def _handle_connection(self, conn: socket.socket, addr):
        """
        Handle an individual incoming connection from the given address.
        Determines the remote user's identifier, performs handshake initialization as responder,
        and waits for user confirmation via GUI before completing the handshake.
        """
        remote_id = f"{addr[0]}:{addr[1]}"
        first_line = ""
        remaining_data = b""
        try:
            # Set a short timeout for receiving the remote identifier (first line)
            conn.settimeout(5.0)
            buffer = b""
            # Read until newline or until buffer length limit
            while b"\n" not in buffer and len(buffer) < 1024:
                chunk = conn.recv(64)
                if not chunk:
                    # Connection closed by peer before sending any data
                    break
                buffer += chunk
                if b"\n" in chunk:
                    # Newline found, stop reading further for now
                    break
        except socket.timeout:
            logger.warning(f"NetworkThread: No ID received from {addr} within timeout, using IP as identifier.")
        except Exception as e:
            logger.error(f"NetworkThread: Error reading identifier from {addr}: {e}", exc_info=True)
        finally:
            # Remove the timeout (make socket blocking again for handshake)
            try:
                conn.settimeout(None)
            except Exception:
                pass

        # If any data was read, separate the first line and any extra data after newline
        if buffer:
            if b"\n" in buffer:
                line_bytes, remaining_data = buffer.split(b"\n", 1)
            else:
                line_bytes = buffer
                remaining_data = b""
            try:
                first_line = line_bytes.decode('utf-8', errors='ignore').strip()
            except Exception:
                first_line = ""
        # Use the first line as remote_id if available, otherwise fallback to IP:port
        if first_line:
            remote_id = first_line
        else:
            remote_id = f"{addr[0]}:{addr[1]}"
        logger.info(f"NetworkThread: Incoming connection from {addr}, identified as '{remote_id}'")

        # 3. Create KDContext and Orchestrator for this connection (responder side)
        try:
            # Import inside method to avoid import conflicts or circular dependencies
            from orchestrator import Orchestrator
            from kdcontext import KDContext
            # Initialize context with remote identifier and socket, then create orchestrator
            context = KDContext(remote_id, conn)
            orchestrator = Orchestrator(context, responder=True)
        except Exception as e:
            logger.error(f"NetworkThread: Failed to initialize handshake for {remote_id}: {e}", exc_info=True)
            try:
                conn.close()
            except Exception:
                pass
            return

        # If any leftover data beyond the first line was received, provide it to the handshake process
        if remaining_data:
            try:
                if hasattr(orchestrator, "feed_initial_data"):
                    orchestrator.feed_initial_data(remaining_data)
                elif hasattr(context, "feed_initial_data"):
                    context.feed_initial_data(remaining_data)
                else:
                    # Store leftover data in context for later processing (fallback)
                    context._initial_data = remaining_data
                    logger.debug("NetworkThread: Stored initial leftover data for handshake processing")
            except Exception as e:
                logger.warning(f"NetworkThread: Could not feed initial data to handshake context: {e}")

        # 4. Run the initial handshake protocol (chapters 1–8) as the responder
        try:
            logger.info(f"NetworkThread: Running handshake (responder initial) with {remote_id}")
            # This executes the handshake steps up to the point of user confirmation
            orchestrator.run_responder_initial()
        except Exception as e:
            logger.error(f"NetworkThread: Handshake error with {remote_id}: {e}", exc_info=True)
            # On handshake failure, close the connection and exit this thread
            try:
                conn.close()
            except Exception:
                pass
            return

        # If run_responder_initial returns, handshake has reached a pause awaiting user confirmation
        logger.info(f"NetworkThread: Handshake initial sequence with '{remote_id}' completed (awaiting user confirmation)")
        # 5. Handshake is now waiting for user confirmation in the GUI.
        # Emit a signal to inform the GUI about the incoming connection request (e.g., show IncomingRequestDialog).
        with self._pending_lock:
            handshake_id = self._next_handshake_id
            self._next_handshake_id += 1
            # Create an event to wait for the user's decision and store handshake info
            event = threading.Event()
            self._pending_handshakes[handshake_id] = {
                "orchestrator": orchestrator,
                "context": context,
                "socket": conn,
                "event": event,
                "accepted": None
            }
        # Notify the GUI of the incoming handshake request (handshake_id and remote user identifier)
        self.incoming_request.emit(handshake_id, remote_id)
        logger.debug(f"NetworkThread: Emitted incoming_request signal for '{remote_id}' (handshake #{handshake_id})")

        # Wait for the user's decision (the event will be signaled by accept_connection/decline_connection)
        event.wait()
        # Event is set, meaning the user has responded via the GUI. Check the decision.
        with self._pending_lock:
            accepted = self._pending_handshakes.get(handshake_id, {}).get("accepted")
        if accepted:
            logger.info(f"NetworkThread: User accepted connection with '{remote_id}', completing handshake...")
            try:
                # If there's a method to finalize the handshake after confirmation, call it
                if hasattr(orchestrator, "run_responder_final"):
                    orchestrator.run_responder_final()
                elif hasattr(orchestrator, "continue_handshake"):
                    orchestrator.continue_handshake()
                # If no specific final step method, assume handshake is already complete or not needed
                logger.info(f"NetworkThread: Handshake with '{remote_id}' completed successfully")
            except Exception as e:
                logger.error(f"NetworkThread: Error completing handshake with {remote_id}: {e}", exc_info=True)
                try:
                    conn.close()
                except Exception:
                    pass
                # Remove the pending handshake entry on error
                with self._pending_lock:
                    self._pending_handshakes.pop(handshake_id, None)
                return
        else:
            # User declined the connection
            logger.info(f"NetworkThread: User declined connection with '{remote_id}'. Closing connection.")
            try:
                # If orchestrator has an abort/cancel method, call it to terminate handshake gracefully
                if hasattr(orchestrator, "abort"):
                    orchestrator.abort()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

        # Remove the pending handshake entry now that a decision has been made
        with self._pending_lock:
            self._pending_handshakes.pop(handshake_id, None)
        # This thread will now exit (for accepted connections, further communication is handled by orchestrator/other components)

    # Slot methods to handle user confirmation from the GUI
    @pyqtSlot(int)
    def accept_connection(self, handshake_id: int):
        """Slot to be called by GUI when the user accepts an incoming connection."""
        with self._pending_lock:
            entry = self._pending_handshakes.get(handshake_id)
        if entry:
            entry["accepted"] = True
            # Signal the waiting handshake thread to continue
            entry["event"].set()
            logger.debug(f"NetworkThread: accept_connection for handshake #{handshake_id} (accepted by user)")

    @pyqtSlot(int)
    def decline_connection(self, handshake_id: int):
        """Slot to be called by GUI when the user declines an incoming connection."""
        with self._pending_lock:
            entry = self._pending_handshakes.get(handshake_id)
        if entry:
            entry["accepted"] = False
            # Signal the waiting handshake thread to continue (it will handle cleanup)
            entry["event"].set()
            logger.debug(f"NetworkThread: decline_connection for handshake #{handshake_id} (declined by user)")
