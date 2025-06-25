from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import hashes
from typing import Dict, List, Tuple, Union, Any

def _dh_peer_pub(p: int, g: int, Y_peer: int):
    """
    Construct a DHPublicKey object from given DH parameters and a peer's public value.
    """
    param_numbers = dh.DHParameterNumbers(p, g)
    public_numbers = dh.DHPublicNumbers(Y_peer, param_numbers)
    return public_numbers.public_key(default_backend())

class Node:
    def __init__(self):
        # Generate RSA key pair for this node
        self._rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._rsa_public_key = self._rsa_private_key.public_key()
        # Dictionaries to hold DH parameters and keys per channel
        self.dh_params: Dict[str, Union[dh.DHParameters, Tuple[int, int]]] = {}
        self.dh_privs: Dict[str, Any] = {}   # DHPrivateKey for each channel
        self.dh_peerY: Dict[str, Any] = {}   # DHPublicKey for each channel (peer's key)
        self.dh_shared: Dict[str, bytes] = {}  # Raw shared secret bytes per channel
        # Simulated network input buffer
        self.inbox: List[bytes] = []
    def pub(self) -> RSAPublicKey:
        """
        Return the RSA public key of this node.
        """
        return self._rsa_public_key
    def dh_generate(self, chan_name: str) -> Tuple[int, int, int]:
        """
        Generate a Diffie-Hellman key pair for the given channel.
        If parameters for the channel do not exist, generate new DH parameters and keys.
        If parameters exist (provided by peer), use them to generate a new DH private key and public value.
        Returns a tuple of (p, g, Y) for the channel.
        """
        # Prevent regenerating if already have a DH private key for this channel
        if chan_name in self.dh_privs:
            raise ValueError(f"DH key already generated for channel '{chan_name}'")
        if chan_name not in self.dh_params:
            # Create new DH parameters and private key
            parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            # Store parameters and private key for this channel
            self.dh_params[chan_name] = parameters
            self.dh_privs[chan_name] = private_key
            # Extract numbers to return
            public_numbers = public_key.public_numbers()
            p = public_numbers.parameter_numbers.p
            g = public_numbers.parameter_numbers.g
            Y = public_numbers.y
            return (p, g, Y)
        else:
            # Use existing parameters (e.g., provided by peer) to generate keys
            params = self.dh_params[chan_name]
            # If stored parameters are in tuple form, convert to DHParameters object
            if isinstance(params, tuple):
                p, g = params
                param_numbers = dh.DHParameterNumbers(p, g)
                params_obj = param_numbers.parameters(default_backend())
                self.dh_params[chan_name] = params_obj
                params = params_obj
            # Generate new private key and public key using the existing parameters
            private_key = params.generate_private_key()
            public_key = private_key.public_key()
            # Store the private key for this channel
            self.dh_privs[chan_name] = private_key
            # Extract p, g, Y (should match p, g with existing ones)
            public_numbers = public_key.public_numbers()
            p = public_numbers.parameter_numbers.p
            g = public_numbers.parameter_numbers.g
            Y = public_numbers.y
            return (p, g, Y)
    def dh_set_peer(self, chan_name: str, Y_peer: int) -> None:
        """
        Set the peer's public DH value for the given channel.
        This stores the peer's public key and computes the shared secret.
        """
        if chan_name not in self.dh_privs:
            raise ValueError(f"No DH private key for channel '{chan_name}'")
        # Ensure DH parameters are properly stored as an object
        params = self.dh_params.get(chan_name)
        if params is None:
            raise ValueError(f"No DH parameters for channel '{chan_name}'")
        if isinstance(params, tuple):
            p, g = params
            param_numbers = dh.DHParameterNumbers(p, g)
            params = param_numbers.parameters(default_backend())
            self.dh_params[chan_name] = params
        # Construct peer's public key object and store it
        public_numbers = dh.DHPublicNumbers(Y_peer, params.parameter_numbers())
        peer_pub_key = public_numbers.public_key(default_backend())
        self.dh_peerY[chan_name] = peer_pub_key
        # Compute the shared secret and store it
        secret = self.dh_privs[chan_name].exchange(peer_pub_key)
        self.dh_shared[chan_name] = secret
    def dh_key(self, chan_name: str) -> bytes:
        """
        Derive the shared key for the given channel by hashing the shared secret.
        Returns the hash (bytes) of the shared secret.
        """
        if chan_name not in self.dh_shared:
            # If shared secret not computed yet, do it now
            if chan_name not in self.dh_privs or chan_name not in self.dh_peerY:
                raise ValueError(f"DH shared key not available for channel '{chan_name}'")
            secret = self.dh_privs[chan_name].exchange(self.dh_peerY[chan_name])
            self.dh_shared[chan_name] = secret
        else:
            secret = self.dh_shared[chan_name]
        # Hash the shared secret to produce the key
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(secret)
        key_bytes = digest.finalize()
        return key_bytes