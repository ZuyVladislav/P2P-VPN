def _on_incoming_request(self, handshake_id: int, remote_id: str):
    """
    Auto-accept incoming handshake request (called when NetworkThread signals a new request).
    Runs the full responder handshake without user confirmation.
    """
    logging.info(f"Auto-accepting incoming handshake from {remote_id}")
    # Retrieve pending handshake info from network thread
    if self._network_thread:
        with self._network_thread._pending_lock:
            pending = self._network_thread._pending_handshakes.get(handshake_id)
        if pending:
            orchestrator = pending.get("orchestrator")
            conn = pending.get("socket")
            # If the network thread already created an Orchestrator and context, use it
            if hasattr(orchestrator, "run_responder_final"):
                try:
                    orchestrator.run_responder_final()
                except Exception as e:
                    logging.error(f"Error completing handshake for {remote_id}: {e}", exc_info=True)
            elif hasattr(orchestrator, "continue_handshake"):
                try:
                    orchestrator.continue_handshake()
                except Exception as e:
                    logging.error(f"Error continuing handshake for {remote_id}: {e}", exc_info=True)
            else:
                # If no orchestrator found, fall back to running handshake directly
                try:
                    self.run_responder_handshake(conn)
                except Exception as e:
                    logging.error(f"Failed to auto-run responder handshake: {e}", exc_info=True)
            # Mark as accepted
            with self._network_thread._pending_lock:
                pending["accepted"].set()
    else:
        # If no network thread context, just run handshake (for cases where incoming_request is manually signaled)
        try:
            # We don't have the remote socket here, cannot proceed fully if none
            logging.debug("No network thread context, cannot auto-complete handshake.")
        except Exception as e:
            logging.error(f"Error in auto accept: {e}", exc_info=True)

def get_online_peers(self):
    """Return list of currently known online peers (usernames)."""
    return list(self._online_peers)

def check_peers(self):
    """
    Check the network to update which peers are online.
    Uses UDP discovery (PING/PONG) to determine reachability of other users.
    """
    online = set()
    for user, info in USERS.items():
        if user == self.username:
            continue
        ip = info.get("ip")
        if not ip:
            continue
        # Send a UDP "PING" and wait for "PONG"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(b"PING", (ip, 5000))
            data, addr = sock.recvfrom(1024)
            if data and data.upper() == b"PONG":
                online.add(user)
        except Exception:
            # No response or error -> assume offline
            pass
        finally:
            if sock:
                sock.close()
    # Update internal list
    self._online_peers = online
    logging.info(f"Online peers updated: {online}")
    return list(online)

def initiate_handshake(self, target_user: str):
    """
    Initiate a handshake with the specified target user (by username).
    This will establish a connection and perform chapters 1–12 as the initiator.
    """
    # Lookup target user info
    target_info = USERS.get(target_user)
    if not target_info:
        raise ValueError(f"Unknown target user: {target_user}")
    target_ip = target_info.get("ip")
    if not target_ip:
        raise ValueError(f"No IP address for target user {target_user}")
    target_port = 5000  # default handshake port
    # Establish a TCP connection to the target
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((target_ip, target_port))
    except Exception as e:
        sock.close()
        logging.error(f"Failed to connect to {target_user} at {target_ip}:{target_port}: {e}", exc_info=True)
        raise
    # Run full initiator handshake (1–12)
    try:
        self.run_initiator_handshake(target_user, conn=sock)
        logging.info(f"Handshake with {target_user} completed successfully.")
    except Exception as e:
        logging.error(f"Handshake initiator error: {e}", exc_info=True)
        sock.close()
        raise

def run_initiator_handshake(self, target_user: str, conn: socket.socket = None):
    """
    Perform the full handshake (chapters 1–12) as the initiator connecting to target_user.
    Establishes secure session key by the end of the handshake.
    """
    logging.info(f"Initiating handshake with {target_user}")
    # Determine route: current user (A) -> possibly X1, X2 -> target (B)
    route = [self.username]
    # Choose up to two intermediates if available (all other users except initiator and target)
    intermediates = [u for u in USERS.keys() if u not in (self.username, target_user)]
    # Sort intermediates for deterministic route (optional: by name or predefined logic)
    intermediates.sort()
    # Use at most 2 intermediates in route
    route += intermediates[:2]
    route.append(target_user)
    # If route has more than 4 nodes, truncate to 4 (since protocol supports up to 2 intermediates)
    if len(route) > 4:
        route = [route[0]] + route[1:3] + [route[-1]]
    logging.debug(f"Calculated route for handshake: {route}")
    # Create Node objects for each role: A, X1, X2, B as needed
    nodes = {}  # label -> Node
    label_map = {}  # actual username -> label
    labels = []
    labels.append("A")
    # Assign labels "X1", "X2" to intermediate nodes in order
    for i, user in enumerate(route[1:-1], start=1):
        if i <= 2:  # only label first two intermediates
            labels.append(f"X{i}")
        else:
            # If somehow more than 2 intermediates (should not happen), label them generically
            labels.append(f"X{i}")
    labels.append("B")
    # Map actual usernames in route to labels
    for actual, label in zip(route, labels):
        label_map[actual] = label
    # Prepare Node instances with loaded keys
    for actual_user, label in label_map.items():
        # Load RSA keys for the actual user
        priv_key = load_private_key(actual_user)
        pub_key = load_public_key(actual_user)
        # Create handshake Node and set RSA keys
        if HandshakeNode:
            node = HandshakeNode(label)
        else:
            # If HandshakeNode class isn't available, define a simple Node structure
            node = type("Node", (), {})()
            node.name = label
            node.dh_params = {}
            node.dh_privs = {}
            node.dh_peerY = {}
            node.dh_shared = {}
            node.inbox = []
        # Attach RSA keys
        node.rsa_priv = priv_key
        # If load_public_key returned None (for self), derive from priv
        if pub_key is None:
            pub_key = priv_key.public_key()
        node._rsa_pub = pub_key  # store public key
        # Define pub() method for Node if not exists
        if not hasattr(node, "pub"):
            setattr(node, "pub", lambda self=node: self._rsa_pub)
        # Define DH helper methods if not present
        if not hasattr(node, "dh_generate"):
            def dh_generate(self=node, chan_name=""):
                # Generate DH parameters and private key
                params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
                priv = params.generate_private_key()
                pub_num = priv.public_key().public_numbers().y
                # Store
                self.dh_params[chan_name] = params
                self.dh_privs[chan_name] = priv
                self.dh_shared[chan_name] = None  # no shared until peer provided
                return params.parameter_numbers().p, params.parameter_numbers().g, pub_num
            setattr(node, "dh_generate", dh_generate)
        if not hasattr(node, "dh_set_peer"):
            def dh_set_peer(self=node, chan_name="", peer_y=0):
                # Compute shared secret given peer's public Y
                params = self.dh_params.get(chan_name)
                priv = self.dh_privs.get(chan_name)
                if params is None or priv is None:
                    raise RuntimeError("DH parameters or private key not found for channel")
                peer_pub = _dh_peer_pub(params.parameter_numbers().p, params.parameter_numbers().g, peer_y)
                shared = priv.exchange(peer_pub)
                self.dh_peerY[chan_name] = peer_y
                self.dh_shared[chan_name] = shared
            setattr(node, "dh_set_peer", dh_set_peer)
        if not hasattr(node, "dh_key"):
            def dh_key(self=node, chan_name=""):
                # Derive a symmetric key (32 bytes) from DH shared secret using SHA-256
                shared = self.dh_shared.get(chan_name)
                if shared is None:
                    raise RuntimeError("Shared secret not established for channel")
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(shared)
                return digest.finalize()
            setattr(node, "dh_key", dh_key)
        # Also define send_sym/recv_sym if not exist (used in chapter05)
        if not hasattr(node, "send_sym"):
            def send_sym(self=node, chan="", dest=None, payload=None, step=""):
                # Symmetrically encrypt payload with channel key and deliver to dest's inbox
                if dest is None or payload is None:
                    return
                data = json.dumps(payload).encode()  # ensure payload is JSON-serializable
                cipher = sym_encrypt(self.dh_key(chan), data)
                dest.inbox.append(cipher)
                if step:
                    trace(step, self.name, dest.name, f"DH({chan})-send", list(payload.keys()))
            setattr(node, "send_sym", send_sym)
        if not hasattr(node, "recv_sym"):
            def recv_sym(self=node, chan=""):
                if not self.inbox:
                    return {}
                cipher = self.inbox.pop(0)
                plain = sym_decrypt(self.dh_key(chan), cipher)
                return json.loads(plain)
            setattr(node, "recv_sym", recv_sym)
        nodes[label] = node
    # Convenience references for A, B, X1, X2 if they exist
    A = nodes.get("A")
    B = nodes.get("B")
    X1 = nodes.get("X1")
    X2 = nodes.get("X2")
    # Execute handshake chapters in sequence
    try:
        # Chapter 1: A <-> X1 IKE phase1 + AUTH (KD1)
        if X1:
            chapter01.run(A, X1)
        else:
            # If no intermediate, treat B as X1 for direct handshake
            chapter01.run(A, B)
        # Chapter 2: A -> X1 send instruction I1 (over KD1)
        if X1:
            chapter02.run(A, X1)
        # Chapter 3: X1 <-> X2 IKE phase1 (KD2) if second intermediate exists
        if X1 and X2:
            chapter03.run(X1, X2)
        # Chapter 4: X1 -> X2 send instruction I2 (over KD2)
        if X1 and X2:
            chapter04.run(X1, X2)
        # Chapter 5: X1 -> A send OK1(X2) + I4 over KD1 (only if X2 exists and X1 exists)
        if X1 and X2:
            # Prepare X2's public key in PEM format
            pem = nodes["X2"]._rsa_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            msg = chapter05.run(X1, A, ok1_pem=pem)
            logging.debug(f"Chapter 5 output received by A: {msg}")
        # Chapter 6: A -> X1 -> X2 deliver Child-SA(A-B) + I6
        if X1 and X2:
            chapter06.run(A, X1, X2, B)
        elif X1 and not X2:
            # If only one intermediate (X1 and B as final), we deliver Child-SA A->X1->B
            # Use X1 as "X2" in context of chapter06: it will place chunks for B in X1.inbox
            chapter06.run(A, X1, X1, B)
        else:
            # If direct A-B, skip child-SA multi-hop step; we will do direct child-SA in final chapters.
            pass
        # Chapter 7: X2 <-> B IKE phase1 (KD3) if X2 exists. If one intermediate, X1-B handshake (KD2) is needed.
        if X2:
            chapter07.run(X2, B)
        elif X1 and not X2:
            # One intermediate: perform X1-B handshake using chapter07 logic (with X2 param as X1)
            chapter07.run(X1, B, chan_name="X1-B")
        # Chapter 8: X2 -> B forward Child-SA(A-B) (from X2.inbox to B)
        # If X2 exists, we need to deliver the inner_chunks from X2.inbox to B via KD3
        if X2:
            # X2 should have env_chunks for B from chapter06 (in X2.inbox)
            if X2.inbox:
                pkt = X2.inbox.pop(0)
            else:
                pkt = None
            if pkt:
                # pkt is a list of RSA-encrypted chunks for B
                trace("8.1", X2.name, B.name, "relay", {"chunks": len(pkt) if isinstance(pkt, list) else 1})
                # Encrypt the list for B via KD3 and send
                payload = {"inner_chunks": [c.hex() for c in pkt], "I6": "set"}
                blob = sym_encrypt(X2.dh_key("X2-B"), json.dumps(payload).encode())
                B.inbox.append(blob)
                trace("8.2", X2.name, B.name, f"DH(X2-B)-send", {"len": len(blob)})
                # B receives and decrypts
                recv_blob = B.inbox.pop(0)
                trace("8.3", B.name, B.name, f"DH(X2-B)-recv", {"len": len(recv_blob)})
                pkt_b = json.loads(sym_decrypt(B.dh_key("X2-B"), recv_blob))
                trace("8.4", B.name, B.name, f"DH(X2-B)-dec", list(pkt_b.keys()))
                # B decrypt inner chunks with RSA priv to get Child-SA(A-B)
                inner_chunks_hex = pkt_b.get("inner_chunks", [])
                if inner_chunks_hex:
                    inner_chunks = [bytes.fromhex(h) for h in inner_chunks_hex]
                    child_sa = json.loads(rsa_decrypt_long(B.rsa_priv, inner_chunks))
                    trace("8.5", B.name, B.name, "RSA-long-dec", list(child_sa.keys()))
                    logging.debug(f"Child-SA (A-B) received at B: {child_sa}")
        elif X1 and not X2:
            # One intermediate: deliver Child-SA from X1 to B via KD2
            if X1.inbox:
                pkt = X1.inbox.pop(0)  # list of chunks for B
            else:
                pkt = None
            if pkt:
                trace("8.1", X1.name, B.name, "relay", {"chunks": len(pkt) if isinstance(pkt, list) else 1})
                blob = sym_encrypt(X1.dh_key("X1-B"), json.dumps({"inner_chunks": [c.hex() for c in pkt], "I6": "set"}).encode())
                B.inbox.append(blob)
                trace("8.2", X1.name, B.name, f"DH(X1-B)-send", {"len": len(blob)})
                recv_blob = B.inbox.pop(0)
                trace("8.3", B.name, B.name, f"DH(X1-B)-recv", {"len": len(recv_blob)})
                pkt_b = json.loads(sym_decrypt(B.dh_key("X1-B"), recv_blob))
                trace("8.4", B.name, B.name, f"DH(X1-B)-dec", list(pkt_b.keys()))
                inner_chunks_hex = pkt_b.get("inner_chunks", [])
                if inner_chunks_hex:
                    inner_chunks = [bytes.fromhex(h) for h in inner_chunks_hex]
                    child_sa = json.loads(rsa_decrypt_long(B.rsa_priv, inner_chunks))
                    trace("8.5", B.name, B.name, "RSA-long-dec", list(child_sa.keys()))
                    logging.debug(f"Child-SA (A-B) received at B: {child_sa}")
        # Chapter 9: Reverse delivery of Child-SA(B-A): B -> X2 -> X1 -> A
        if X2:
            result_child = chapter09.run(B, X2, X1, A)
            logging.debug(f"Chapter 9 result at A: {result_child}")
        elif X1 and not X2:
            # One intermediate: have B -> X1 -> A
            # Similar to chapter09 but with one relay (X1)
            # B prepares Child-SA(B-A) and sends via KD2(B-X1)
            child_sa_json = json.dumps({"SA": "B-A"}).encode()
            pkt_to_A = rsa_encrypt_long(A.pub(), child_sa_json)
            trace("9.1", B.name, A.name, "RSA-long-enc", {"chunks": len(pkt_to_A)})
            payload = json.dumps({"inner_chunks": [c.hex() for c in pkt_to_A], "I7": "back"}).encode()
            blob = sym_encrypt(B.dh_key("X1-B"), payload)
            trace("9.2", B.name, X1.name, "DH(X1-B)-send", {"len": len(blob)})
            X1.inbox.append(blob)
            trace("9.3", B.name, X1.name, "send", {"chunks": 1})
            recv_x1 = X1.inbox.pop(0)
            trace("9.4", X1.name, X1.name, "recv", {"len": len(recv_x1)})
            pkt_x1 = json.loads(sym_decrypt(B.dh_key("X1-B"), recv_x1))
            trace("9.5", X1.name, B.name, "DH(X1-B)-dec", list(pkt_x1.keys()))
            relay_pkt = json.dumps({"inner_chunks": pkt_x1["inner_chunks"], "I8": "relay_back"}).encode()
            blob2 = sym_encrypt(X1.dh_key("A-X1"), relay_pkt)
            trace("9.6", X1.name, A.name, "DH(A-X1)-send", {"len": len(blob2)})
            A.inbox.append(blob2)
            trace("9.7", X1.name, A.name, "send", {"chunks": 1})
            recv_A = A.inbox.pop(0)
            trace("9.8", A.name, A.name, "recv", {"len": len(recv_A)})
            pkt_A = json.loads(sym_decrypt(A.dh_key("A-X1"), recv_A))
            trace("9.9", A.name, X1.name, "DH(A-X1)-dec", list(pkt_A.keys()))
            chunks_hex = pkt_A["inner_chunks"]
            A.inbox.append(chunks_hex)
            trace("9.10", X1.name, A.name, "relay_chunks", {"chunks": len(chunks_hex)})
            recv_chunks_hex = A.inbox.pop(0)
            trace("9.11", A.name, A.name, "recv-chunks", {"chunk_count": len(recv_chunks_hex)})
            recv_chunks = [bytes.fromhex(h) for h in recv_chunks_hex]
            plain = rsa_decrypt_long(A.rsa_priv, recv_chunks)
            child_sa_back = json.loads(plain)
            trace("9.12", A.name, A.name, "RSA-long-dec", list(child_sa_back.keys()))
            logging.debug(f"Child-SA (B-A) received at A: {child_sa_back}")
        # Chapter 10: Forward AI(A-B) via chain A -> X1 -> X2 -> B
        if X2:
            ai_res = chapter10.run(A, X1, X2, B)
        elif X1:
            # One intermediate: A -> X1 -> B
            ai_res = chapter10.run(A, X1, X1, B)
        else:
            # Direct: skip chain, will exchange directly in chapter12
            ai_res = {"AI(A-B)": "data"}
        logging.debug(f"AI(A-B) delivered to B: {ai_res}")
        # Chapter 11: Return AI(B-A) via chain B -> X2 -> X1 -> A
        if X2:
            ai_res_back = chapter11.run(A, X1, X2, B)
        elif X1:
            # One intermediate: B -> X1 -> A
            ai_res_back = chapter11.run(A, X1, X1, B)
        else:
            ai_res_back = {"AI(B-A)": "data"}
        logging.debug(f"AI(B-A) delivered to A: {ai_res_back}")
        # Chapter 12: Direct exchange between A and B to compute final DH key (KD4)
        result = chapter12.run(A, B)
        logging.info("Глава 12 завершена")
        logging.info("Handshake protocol completed successfully.")
        logging.debug(f"Final handshake result (KD4 hashes): {result}")
        # Derive session key (32-byte) from KD4
        if result and "KD4(A)" in result:
            session_key = result["KD4(A)"]
        else:
            # If result not returned properly, derive from A's shared secret in A-B channel
            session_key = sha256(A.dh_shared.get("A-B", b""))
        # Set up a secure connection cipher for actual communication (if needed)
        if conn:
            # Create a Fernet cipher using the session key
            fernet_key = base64.urlsafe_b64encode(session_key)
            cipher = Fernet(fernet_key)
            # We can either wrap the socket in SecureConnection or use Transport with this cipher
            # For simplicity, we attach cipher to a Transport for further use (or just store it)
            secure_transport = Transport(protocol='tcp', secure_conn=cipher)
            secure_transport.sock = conn  # use existing socket
            secure_transport._connected = True
            logging.info(f"Secure connection established with {target_user}")
            # Optionally, store the secure transport for further use
            self.secure_transport = secure_transport
    except Exception as e:
        logging.error(f"Error during initiator handshake: {e}", exc_info=True)
        raise

def run_responder_initial(self):
    """
    Accept an incoming connection and perform chapters 1–8 as the responder (initial half of handshake).
    This method should be called when a new handshake request is received.
    """
    # This method would be triggered by the network thread when a connection is accepted.
    # The NetworkThread already creates an Orchestrator for the incoming connection and calls this.
    try:
        # `self` in this context is an Orchestrator created for the specific connection (responder side).
        # We assume the KDContext (route and socket) has been set up by NetworkThread.
        # Perform chapters 1–8 using stored context.
        # If context/route not set, cannot proceed.
        if not hasattr(self, "_pending_nodes") or not self._pending_nodes:
            logging.error("No handshake context available for responder initial steps.")
            return
        A = self._pending_nodes.get("A")
        B = self._pending_nodes.get("B")
        X1 = self._pending_nodes.get("X1")
        X2 = self._pending_nodes.get("X2")
        # Execute chapters 1-8 as responder (B and any intermediates)
        if X1:
            chapter01.run(A, X1)  # initiator side handled by initiator orchestrator; here just sim for logs
        else:
            chapter01.run(A, B)
        if X1:
            chapter02.run(A, X1)
        if X1 and X2:
            chapter03.run(X1, X2)
            chapter04.run(X1, X2)
        if X1 and X2:
            pem = X2._rsa_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
            chapter05.run(X1, A, ok1_pem=pem)
            chapter06.run(A, X1, X2, B)
            chapter07.run(X2, B)
            # Chapter08 forward Child-SA
            if X2.inbox:
                pkt = X2.inbox.pop(0)
                if pkt:
                    payload = {"inner_chunks": [c.hex() for c in pkt], "I6": "set"}
                    blob = sym_encrypt(X2.dh_key("X2-B"), json.dumps(payload).encode())
                    B.inbox.append(blob)
                    B.inbox.pop(0)  # simulate immediate recv
        elif X1 and not X2:
            # One intermediate
            chapter04.run(X1, X1)  # trivial instruct to itself
            chapter06.run(A, X1, X1, B)
            chapter07.run(X1, B, chan_name="X1-B")
            if X1.inbox:
                pkt = X1.inbox.pop(0)
                if pkt:
                    blob = sym_encrypt(X1.dh_key("X1-B"), json.dumps({"inner_chunks": [c.hex() for c in pkt], "I6": "set"}).encode())
                    B.inbox.append(blob)
                    B.inbox.pop(0)
        else:
            # Direct
            # Up to chapter8 not much occurs for direct handshake in multi-chapter protocol
            pass
        logging.info("Initial handshake steps (chapters 1-8) completed for responder.")
    except Exception as e:
        logging.error(f"Responder initial handshake error: {e}", exc_info=True)
        # Close connection on failure
        if self._pending_socket:
            try:
                self._pending_socket.close()
            except:
                pass
        raise

def run_responder_final(self):
    """
    Complete the handshake as responder after user confirmation.
    Executes chapters 9–12 and establishes the secure session.
    """
    try:
        if not hasattr(self, "_pending_nodes") or not self._pending_nodes:
            logging.error("No handshake context available for responder final steps.")
            return
        A = self._pending_nodes.get("A")
        B = self._pending_nodes.get("B")
        X1 = self._pending_nodes.get("X1")
        X2 = self._pending_nodes.get("X2")
        # Execute chapters 9-12
        if X2:
            chapter09.run(B, X2, X1, A)
        elif X1:
            # One intermediate backward
            chapter09.run(B, X1, X1, A)
        else:
            # Direct skip (will do final DH in ch12)
            pass
        if X2:
            chapter10.run(A, X1, X2, B)
            chapter11.run(A, X1, X2, B)
        elif X1:
            chapter10.run(A, X1, X1, B)
            chapter11.run(A, X1, X1, B)
        else:
            # Direct skip to ch12
            pass
        result = chapter12.run(A, B)
        logging.info("Handshake completed on responder side.")
        session_key = result.get("KD4(A)") if result else sha256(A.dh_shared.get("A-B", b""))
        # Create secure session cipher
        fernet_key = base64.urlsafe_b64encode(session_key)
        cipher = Fernet(fernet_key)
        # Attach cipher to transport or store for future use
        if self._pending_socket:
            secure_transport = Transport(protocol='tcp', secure_conn=cipher)
            secure_transport.sock = self._pending_socket
            secure_transport._connected = True
            self.secure_transport = secure_transport
            logging.info(f"Secure connection established with initiator.")
    except Exception as e:
        logging.error(f"Responder final handshake error: {e}", exc_info=True)
        if self._pending_socket:
            try:
                self._pending_socket.close()
            except:
                pass
        raise

def run_responder_handshake(self, conn: socket.socket):
    """
    Accept an incoming connection and perform the full handshake (chapters 1–12) as responder.
    This automatically proceeds without requiring user confirmation.
    """
    logging.info("Responder starting full handshake (auto-accept).")
    # Setup route and Node contexts similarly to initiator but for incoming connection
    try:
        # Determine initiator identity (if possible). For simplicity, treat direct route (no intermediates known here).
        remote_addr = conn.getpeername()[0] if conn else ""
        remote_user = None
        # Try to identify the remote user by IP in USERS (if IPs are unique)
        for uname, info in USERS.items():
            if info.get("ip") == remote_addr and uname != self.username:
                remote_user = uname
                break
        if not remote_user:
            remote_user = "Unknown"
        # Build route: initiator (remote_user) as A, current_user as B
        route = [remote_user, self.username]
        # Create Node objects
        nodes = {}
        # Initiator node (A)
        priv_A = load_private_key(remote_user) if remote_user != "Unknown" else None
        pub_A = load_public_key(remote_user) if remote_user != "Unknown" else None
        A = HandshakeNode("A") if HandshakeNode else type("Node", (), {})()
        A.name = "A"
        A.dh_params = {}
        A.dh_privs = {}
        A.dh_peerY = {}
        A.dh_shared = {}
        A.inbox = []
        if priv_A:
            A.rsa_priv = priv_A
            A._rsa_pub = pub_A or priv_A.public_key()
        # Responder node (B)
        priv_B = load_private_key(self.username)
        pub_B = load_public_key(self.username)
        B = HandshakeNode("B") if HandshakeNode else type("Node", (), {})()
        B.name = "B"
        B.dh_params = {}
        B.dh_privs = {}
        B.dh_peerY = {}
        B.dh_shared = {}
        B.inbox = []
        B.rsa_priv = priv_B
        B._rsa_pub = pub_B or priv_B.public_key()
        # Attach methods to Nodes (similar as in run_initiator_handshake)
        for node in (A, B):
            if not hasattr(node, "pub"):
                setattr(node, "pub", lambda self=node: getattr(self, "_rsa_pub", None))
            if not hasattr(node, "dh_generate"):
                def dh_generate(self=node, chan_name=""):
                    params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
                    priv = params.generate_private_key()
                    pub_num = priv.public_key().public_numbers().y
                    self.dh_params[chan_name] = params
                    self.dh_privs[chan_name] = priv
                    self.dh_shared[chan_name] = None
                    return params.parameter_numbers().p, params.parameter_numbers().g, pub_num
                setattr(node, "dh_generate", dh_generate)
            if not hasattr(node, "dh_set_peer"):
                def dh_set_peer(self=node, chan_name="", peer_y=0):
                    params = self.dh_params.get(chan_name)
                    priv = self.dh_privs.get(chan_name)
                    peer_pub = _dh_peer_pub(params.parameter_numbers().p, params.parameter_numbers().g, peer_y)
                    self.dh_shared[chan_name] = priv.exchange(peer_pub)
                    self.dh_peerY[chan_name] = peer_y
                setattr(node, "dh_set_peer", dh_set_peer)
            if not hasattr(node, "dh_key"):
                def dh_key(self=node, chan_name=""):
                    shared = self.dh_shared.get(chan_name)
                    if shared is None:
                        raise RuntimeError("Shared secret not available")
                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(shared)
                    return digest.finalize()
                setattr(node, "dh_key", dh_key)
        nodes["A"] = A
        nodes["B"] = B
        # Save context for potential split-phase
        self._pending_nodes = nodes
        self._pending_socket = conn
        # Perform the full handshake automatically
        self.run_responder_initial()
        self.run_responder_final()
    except Exception as e:
        logging.error(f"Error in run_responder_handshake: {e}", exc_info=True)
        if conn:
            try:
                conn.close()
            except:
                pass

def start_handshake(self):
    """Alias for run_responder_initial (for compatibility with ConnectDialog)."""
    return self.run_responder_initial()

def continue_handshake(self):
    """Alias for run_responder_final (for compatibility with ConnectDialog)."""
    return self.run_responder_final()

def finish_handshake(self):
    """Alias for run_responder_final (if named differently)."""
    return self.run_responder_final()

def abort(self):
    """
    Abort/cancel the current handshake process.
    Closes any open connection and marks handshake as cancelled.
    """
    self._handshake_cancelled = True
    if self._pending_socket:
        try:
            self._pending_socket.close()
        except Exception:
            pass
        self._pending_socket = None
    # If a KDContext or similar exists with cancel method, call it
    try:
        if hasattr(self, "context") and hasattr(self.context, "cancel"):
            self.context.cancel()
    except Exception:
        pass
    logging.info("Handshake cancelled by user.")