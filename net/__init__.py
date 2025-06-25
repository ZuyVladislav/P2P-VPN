import socket
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from handshake_core import create_handshake_request, process_handshake_request, process_handshake_response
from utils import load_private_key


class SecureConnection:
    """A wrapper for a socket connection that has an established session key for encryption."""

    def __init__(self, sock: socket.socket, session_key: bytes, peer_name: str):
        self.sock = sock
        self.peer_name = peer_name
        # Create a Fernet cipher for symmetric encryption using the session key:contentReference[oaicite:12]{index=12}
        # Fernet expects a URL-safe base64-encoded 32-byte key.
        self.session_key = session_key
        fernet_key = base64.urlsafe_b64encode(session_key)
        self.cipher = Fernet(fernet_key)

    def send(self, data: bytes):
        """Encrypt and send data over the socket."""
        token = self.cipher.encrypt(data)
        # Send a 4-byte length prefix followed by the encrypted token
        length = len(token)
        self.sock.sendall(length.to_bytes(4, 'big') + token)

    def receive(self) -> bytes:
        """Receive and decrypt data from the socket."""
        # Read 4-byte length prefix
        length_data = b''
        while len(length_data) < 4:
            chunk = self.sock.recv(4 - len(length_data))
            if not chunk:
                return b''
            length_data += chunk
        length = int.from_bytes(length_data, 'big')
        # Read the encrypted token of specified length
        token = b''
        while len(token) < length:
            chunk = self.sock.recv(length - len(token))
            if not chunk:
                break
            token += chunk
        if len(token) < length:
            return b''  # connection may have closed
        # Decrypt the token to retrieve original data
        data = self.cipher.decrypt(token)
        return data

    def close(self):
        self.sock.close()


def start_server(host: str, port: int, my_name: str) -> SecureConnection:
    """Start a server that waits for one handshake connection. Returns a SecureConnection on success."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((host, port))
    server_sock.listen(1)
    print(f"Listening for connection on {host}:{port}...")
    client_sock, addr = server_sock.accept()
    print(f"Accepted connection from {addr}")
    # Receive handshake request (assuming small message, read until '}' which signals JSON end)
    request_data = b''
    client_sock.settimeout(5.0)
    try:
        while True:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            request_data += chunk
            if b'}' in chunk:
                break
    except socket.timeout:
        pass
    # Process handshake request and prepare response
    response_data, session_key, peer_name = process_handshake_request(my_name, request_data)
    # Send handshake response
    client_sock.sendall(response_data)
    # Wrap the socket in SecureConnection with established session key
    secure_conn = SecureConnection(client_sock, session_key, peer_name)
    print(f"Handshake successful with {peer_name}. Session key established.")
    return secure_conn


def connect_to_server(host: str, port: int, my_name: str, target_name: str) -> SecureConnection:
    """Connect to a server and perform handshake. Returns a SecureConnection on success."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    # Create handshake request and get session key
    request_data, session_key = create_handshake_request(my_name, target_name)
    # Send handshake request to server
    sock.sendall(request_data)
    # Receive handshake response
    response_data = b''
    sock.settimeout(5.0)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if b'}' in chunk:
                break
    except socket.timeout:
        pass
    # Verify handshake response
    success = process_handshake_response(my_name, response_data)
    if not success:
        sock.close()
        raise ConnectionError("Handshake failed or invalid response")
    # If successful, wrap socket in SecureConnection
    secure_conn = SecureConnection(sock, session_key, target_name)
    print(f"Handshake successful with {target_name}. Session key established.")
    return secure_conn