import socket
import threading
import logging
from PyQt5.QtCore import QThread, pyqtSignal, pyqtSlot

logger = logging.getLogger(__name__)

class DiscoveryResponder(threading.Thread):
    """DiscoveryResponder listens for UDP PING messages and replies with PONG."""
    def __init__(self, port: int = 5000):
        super().__init__(daemon=True)
        self.port = port
        self.sock = None
        self._running = True

    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("", self.port))
            logger.info(f"DiscoveryResponder: Listening for UDP PING on port {self.port}")
        except Exception as e:
            logger.error(f"DiscoveryResponder: Failed to bind UDP socket on port {self.port}: {e}", exc_info=True)
            self._running = False
        while self._running:
            try:
                data, addr = self.sock.recvfrom(1024)
            except OSError as e:
                if self._running:
                    logger.error(f"DiscoveryResponder: Socket error: {e}", exc_info=True)
                break
            if not data:
                continue
            try:
                message = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                continue
            if message and message.upper() == "PING":
                try:
                    self.sock.sendto(b"PONG", addr)
                    logger.debug(f"DiscoveryResponder: Sent PONG to {addr}")
                except Exception as e:
                    logger.error(f"DiscoveryResponder: Failed to send PONG to {addr}: {e}", exc_info=True)
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
                self.sock.close()
            except Exception:
                pass

class NetworkThread(QThread):
    """
    NetworkThread слушает входящие TCP соединения на указанном порту.
    Для каждого соединения создаёт KDContext и Orchestrator для выполнения handshake в режиме отвечающего.
    Также запускает UDP DiscoveryResponder для PING/PONG обнаружения узлов.
    """
    incoming_request = pyqtSignal(int, str)  # сигнал: новый входящий запрос (handshake_id, remote_id)

    def __init__(self, port: int = 5000, current_user: dict = None, parent=None):
        super().__init__(parent)
        self.port = port
        self.current_user = current_user
        self._running = True
        self.sock = None
        self.discovery = None
        # Счётчик для handshake_id (входящие соединения)
        self._pending_handshakes = {}
        self._pending_lock = threading.Lock()
        self._next_handshake_id = 1

    def run(self):
        # Инициализируем TCP-сервер для входящих соединений
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("", self.port))
            self.sock.listen(5)
            self.sock.settimeout(1.0)
            logger.info(f"NetworkThread: Listening for TCP connections on port {self.port}")
        except Exception as e:
            logger.error(f"NetworkThread: Failed to start TCP server on port {self.port}: {e}", exc_info=True)
            self._running = False

        if self._running:
            self.discovery = DiscoveryResponder(port=self.port)
            self.discovery.start()

        # Основной цикл приёма входящих соединений
        while self._running:
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except Exception as e:
                if not self._running:
                    break
                logger.error(f"NetworkThread: Error accepting connection: {e}", exc_info=True)
                continue

            threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()

        # Завершение работы потока: закрываем сокеты
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
        """Остановить сетевой поток и закрыть все слушающие сокеты."""
        self._running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.discovery:
            self.discovery.stop()

    def _handle_connection(self, conn: socket.socket, addr):
        """Обработка входящего подключения."""
        remote_id = f"{addr[0]}:{addr[1]}"
        first_line = ""
        remaining_data = b""
        try:
            conn.settimeout(5.0)
            buffer = b""
            while b"\n" not in buffer and len(buffer) < 1024:
                chunk = conn.recv(64)
                if not chunk:
                    break
                buffer += chunk
                if b"\n" in chunk:
                    break
        except socket.timeout:
            logger.warning(f"NetworkThread: No ID received from {addr} within timeout, using IP as identifier.")
        except Exception as e:
            logger.error(f"NetworkThread: Error reading identifier from {addr}: {e}", exc_info=True)
        finally:
            try:
                conn.settimeout(None)
            except Exception:
                pass

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
        if first_line:
            remote_id = first_line
        else:
            remote_id = f"{addr[0]}:{addr[1]}"
        logger.info(f"NetworkThread: Incoming connection from {addr}, identified as '{remote_id}'")

        try:
            from net.orchestrator import Orchestrator
            from net.kdcontext import KDContext
            context = KDContext(remote_id, conn)
            orchestrator = Orchestrator(self.current_user, context=context)
        except Exception as e:
            logger.error(f"NetworkThread: Failed to initialize handshake for {remote_id}: {e}", exc_info=True)
            try:
                conn.close()
            except Exception:
                pass
            return

        if remaining_data:
            try:
                if hasattr(orchestrator, "feed_initial_data"):
                    orchestrator.feed_initial_data(remaining_data)
                elif hasattr(context, "feed_initial_data"):
                    context.feed_initial_data(remaining_data)
                else:
                    context._initial_data = remaining_data
                    logger.debug("NetworkThread: Stored initial leftover data for handshake processing")
            except Exception as e:
                logger.warning(f"NetworkThread: Could not feed initial data to handshake context: {e}")

        try:
            logger.info(f"NetworkThread: Running handshake (responder initial) with '{remote_id}'")
            orchestrator.run_responder_initial()
        except Exception as e:
            logger.error(f"NetworkThread: Handshake error with {remote_id}: {e}", exc_info=True)
            try:
                conn.close()
            except Exception:
                pass
            return

        # Инициируем запрос подтверждения соединения через GUI
        with self._pending_lock:
            handshake_id = self._next_handshake_id
            self._next_handshake_id += 1
            event = threading.Event()
            self._pending_handshakes[handshake_id] = {
                "orchestrator": orchestrator,
                "context": context,
                "socket": conn,
                "event": event,
                "accepted": None
            }
        self.incoming_request.emit(handshake_id, remote_id)
        logger.debug(f"NetworkThread: Emitted incoming_request signal for '{remote_id}' (handshake #{handshake_id})")

        # Ожидаем решения пользователя (accept_connection/decline_connection выставят event)
        event.wait()
        with self._pending_lock:
            accepted = self._pending_handshakes.get(handshake_id, {}).get("accepted")
        if accepted:
            logger.info(f"NetworkThread: User accepted connection with '{remote_id}', completing handshake...")
            try:
                if hasattr(orchestrator, "run_responder_final"):
                    orchestrator.run_responder_final()
                elif hasattr(orchestrator, "continue_handshake"):
                    orchestrator.continue_handshake()
                logger.info(f"NetworkThread: Handshake with '{remote_id}' completed successfully")
            except Exception as e:
                logger.error(f"NetworkThread: Error completing handshake with {remote_id}: {e}", exc_info=True)
                try:
                    conn.close()
                except Exception:
                    pass
                with self._pending_lock:
                    self._pending_handshakes.pop(handshake_id, None)
                return
        else:
            logger.info(f"NetworkThread: User declined connection with '{remote_id}'. Closing connection.")
            try:
                if hasattr(orchestrator, "abort"):
                    orchestrator.abort()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

        with self._pending_lock:
            self._pending_handshakes.pop(handshake_id, None)

    @pyqtSlot(int)
    def accept_connection(self, handshake_id: int):
        """Вызывается из GUI, когда пользователь принимает входящее соединение."""
        with self._pending_lock:
            entry = self._pending_handshakes.get(handshake_id)
        if entry:
            entry["accepted"] = True
            entry["event"].set()
            logger.debug(f"NetworkThread: accept_connection for handshake #{handshake_id} (accepted by user)")

    @pyqtSlot(int)
    def decline_connection(self, handshake_id: int):
        """Вызывается из GUI, когда пользователь отклоняет входящее соединение."""
        with self._pending_lock:
            entry = self._pending_handshakes.get(handshake_id)
        if entry:
            entry["accepted"] = False
            entry["event"].set()
            logger.debug(f"NetworkThread: decline_connection for handshake #{handshake_id} (declined by user)")