import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from utils import load_private_key, load_public_key

# Handshake protocol implementation:
# The handshake uses RSA encryption for key exchange and RSA signatures for authentication.
# As a key exchange method, RSA allows one party to encrypt a random secret (session key)
# with the public key of the other party:contentReference[oaicite:5]{index=5}. Only the corresponding private key can decrypt it.
# We also sign the handshake message with the sender's private key, allowing the receiver to verify
# the sender's identity using the sender's public key:contentReference[oaicite:6]{index=6}.

def create_handshake_request(my_name: str, target_name: str):
    """Create a handshake initiation message from user my_name to target_name.
    Returns a tuple (request_bytes, session_key)."""
    # Load keys
    priv_key = load_private_key(my_name)
    target_pub_key = load_public_key(target_name)
    if priv_key is None or target_pub_key is None:
        raise ValueError("Could not load keys for handshake")
    # Generate a random symmetric session key (32 bytes)
    import os
    session_key = os.urandom(32)
    # Encrypt the session key with target's public key (using RSA-OAEP):contentReference[oaicite:7]{index=7}
    encrypted_key = target_pub_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Sign the session key with my private key (using RSA-PSS):contentReference[oaicite:8]{index=8}
    signature = priv_key.sign(
        session_key,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Build handshake message as JSON
    message = {
        "from": my_name,
        "to": target_name,
        "enc_key": base64.b64encode(encrypted_key).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8')
    }
    # Return the JSON message as bytes and the session key
    return json.dumps(message).encode('utf-8'), session_key


def process_handshake_request(my_name: str, request_data: bytes):
    """Process an incoming handshake request. Returns (response_data, session_key, peer_name)."""
    # Parse JSON message
    message = json.loads(request_data.decode('utf-8'))
    sender = message.get("from")
    enc_key_b64 = message.get("enc_key")
    signature_b64 = message.get("signature")
    if sender is None or enc_key_b64 is None or signature_b64 is None:
        raise ValueError("Invalid handshake request format")
    # Load our private key (to decrypt) and sender's public key (to verify)
    priv_key = load_private_key(my_name)
    sender_pub_key = load_public_key(sender)
    if priv_key is None or sender_pub_key is None:
        raise ValueError("Could not load keys for handshake processing")
    # Decode the encrypted key and signature from base64
    encrypted_key = base64.b64decode(enc_key_b64)
    signature = base64.b64decode(signature_b64)
    # Decrypt the session key using our private key:contentReference[oaicite:9]{index=9}
    session_key = priv_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Verify the signature using sender's public key
    try:
        sender_pub_key.verify(
            signature,
            session_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        raise ValueError("Handshake signature verification failed") from e
    # If verification succeeds, prepare handshake response (acknowledgment)
    # (Optionally, we could include a signature from our side for mutual authentication)
    response = {
        "status": "OK",
        "to": sender,
        "from": my_name
    }
    response_data = json.dumps(response).encode('utf-8')
    # Return response, the established session key, and the peer's name
    return response_data, session_key, sender


def process_handshake_response(my_name: str, response_data: bytes):
    """Process an incoming handshake response. Returns True if handshake was successful."""
    message = json.loads(response_data.decode('utf-8'))
    if message.get("status") == "OK" and message.get("to") == my_name:
        return True
    return False