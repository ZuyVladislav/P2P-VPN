from handshake.chapters import (
    chapter01, chapter02, chapter03, chapter04,
    chapter05, chapter06, chapter07, chapter08,
    chapter09, chapter10, chapter11, chapter12
)
from net.transport import Transport

CHAPTERS = [
    chapter01, chapter02, chapter03, chapter04,
    chapter05, chapter06, chapter07, chapter08,
    chapter09, chapter10, chapter11, chapter12
]

def run_initiator(remote_host: str, remote_port: int, transport_type: str = "TCP"):
    transport = Transport(protocol=transport_type)
    try:
        transport.connect(remote_host, remote_port)
        for chapter in CHAPTERS:
            if hasattr(chapter, "run_initiator"):
                chapter.run_initiator(transport)
            elif hasattr(chapter, "execute"):
                chapter.execute(transport, role="initiator")
            else:
                raise AttributeError(f"Chapter {chapter.__name__} has no initiator function")
        return transport
    except Exception as e:
        try:
            transport.close()
        except Exception:
            pass
        print(f"Handshake initiator error: {e}")
        raise

def run_responder(local_port: int, transport_type: str = "TCP", local_host: str = "0.0.0.0"):
    transport = Transport(protocol=transport_type)
    try:
        if transport_type.upper() == "TCP":
            transport.listen(local_host, local_port)
            transport.accept()
        else:
            transport.bind(local_host, local_port)
        for chapter in CHAPTERS:
            if hasattr(chapter, "run_responder"):
                chapter.run_responder(transport)
            elif hasattr(chapter, "execute"):
                chapter.execute(transport, role="responder")
            else:
                raise AttributeError(f"Chapter {chapter.__name__} has no responder function")
        return transport
    except Exception as e:
        try:
            transport.close()
        except Exception:
            pass
        print(f"Handshake responder error: {e}")
        raise