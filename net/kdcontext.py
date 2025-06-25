import logging


class KDContext:
    """
    KDContext stores the state of a key exchange (IKE-like handshake) session.

    Attributes:
        route (list): Full list of nodes from initiator to responder (e.g. [initiator, X1, X2, ..., responder]).
        initiator: Reference to the initiator node (same as route[0]).
        responder: Reference to the responder node (same as route[-1]).
        current_chapter (int or None): Current chapter number in the handshake protocol.
        current_step (int or None): Current step number within the current chapter.
        temp_params (dict): Dictionary of temporary parameters for the handshake (e.g., SA, nonces, DH parameters).
        cancelled (bool): Flag indicating if the handshake has been cancelled/aborted.
        trace_log (list): A list of log strings for handshake steps (for tracing and debugging).
    """

    def __init__(self, route):
        """
        Initialize a KDContext for a handshake session.

        Args:
            route (list): The full route of nodes from initiator to responder.
                          The first element is the initiator, the last is the responder.
        """
        if not isinstance(route, list) or len(route) < 2:
            raise ValueError("Route must be a list of at least two nodes (initiator and responder).")

        self.route = route
        self.initiator = route[0]
        self.responder = route[-1]

        # Current chapter and step in the handshake protocol (e.g., chapter 3 step 1 -> 3.1).
        self.current_chapter = None
        self.current_step = None

        # Dictionary for storing temporary handshake parameters (e.g., SA proposals, nonces, DH keys).
        self.temp_params = {}

        # List for tracing the handshake steps for debugging or UI display.
        self.trace_log = []

        # Flag to indicate if the handshake has been cancelled/aborted.
        self.cancelled = False

    def log_step(self, message, level="DEBUG"):
        """
        Log a handshake step with the current chapter and step number, and record it in the trace log.

        This will prepend the current chapter and step (e.g., "3.1") to the message and log it.
        The message is also stored in trace_log for tracing purposes.

        Args:
            message (str): Description of the handshake step (e.g., "A -> X1 (RSA) [ 'SA','nonce','DH']").
            level (str): Logging level as a string (e.g., "DEBUG", "INFO"). Default is "DEBUG".
        """
        # Determine prefix for the log message
        if self.current_chapter is not None and self.current_step is not None:
            prefix = f"{self.current_chapter}.{self.current_step}"
        else:
            prefix = "(no chapter.step)"
        log_message = f"{prefix} {message}"

        # Log the message at the specified level (assuming logging is configured in the application)
        level = level.upper()
        if level == "DEBUG":
            logging.debug(log_message)
        elif level == "INFO":
            logging.info(log_message)
        elif level == "WARNING":
            logging.warning(log_message)
        elif level == "ERROR":
            logging.error(log_message)
        elif level == "CRITICAL":
            logging.critical(log_message)
        else:
            # Unknown level: default to DEBUG
            logging.debug(log_message)

        # Append to trace log for debugging or UI
        self.trace_log.append(log_message)

    def cancel(self):
        """
        Cancel/abort the handshake. Sets the cancelled flag to True.

        This can be used to signal that the handshake should be terminated
        (for example, if the user rejects the handshake or an error occurs).
        """
        self.cancelled = True
        # Log the cancellation for traceability
        logging.info("Handshake cancelled by user.")

    def __repr__(self):
        """Return a string representation of the KDContext (for debugging)."""
        return (f"<KDContext initiator={self.initiator}, responder={self.responder}, "
                f"current_chapter={self.current_chapter}, current_step={self.current_step}, "
                f"cancelled={self.cancelled}>")
