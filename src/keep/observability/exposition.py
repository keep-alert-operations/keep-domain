"""Serve ``GET /metrics`` on a dedicated port (REV-74, observability 7).

The public application ports never serve metrics. ``KEEP_METRICS_PORT`` names the
port; unset means no listener. Prometheus and an OpenTelemetry collector's
Prometheus receiver both scrape this.
"""

import os
from socketserver import ThreadingMixIn
from threading import Lock, Thread
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from prometheus_client import GCCollector, PlatformCollector, ProcessCollector, make_wsgi_app

from keep.observability.metrics import REGISTRY, gauge

_lock = Lock()
_server = None
_runtime_registered = False

BUILD = gauge("keep_build_info", "The running build; always 1.", ("service", "role", "version"))


def _register_runtime():
    global _runtime_registered
    if not _runtime_registered:
        ProcessCollector(registry=REGISTRY)
        PlatformCollector(registry=REGISTRY)
        GCCollector(registry=REGISTRY)
        _runtime_registered = True


_metrics = make_wsgi_app(REGISTRY)


def metrics_app(environ, start_response):
    """Answer only ``GET /metrics``; everything else is 404."""
    if environ.get("PATH_INFO") != "/metrics" or environ.get("REQUEST_METHOD") != "GET":
        start_response("404 Not Found", [("Content-Length", "0")])
        return [b""]
    return _metrics(environ, start_response)


class _Server(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass  # A scrape is not an event (observability 5).


def start_metrics_server(environ=None):
    """Start the listener once, if a port is configured. Returns the port or None."""
    global _server
    environ = os.environ if environ is None else environ
    port = environ.get("KEEP_METRICS_PORT")
    if not port:
        return None
    with _lock:
        if _server is None:
            _register_runtime()
            from keep.observability import logs

            identity = logs._identity
            BUILD.labels(
                identity["service"], identity["role"] or "", identity["version"] or "unknown"
            ).set(1)
            host = environ.get("KEEP_METRICS_HOST", "127.0.0.1")
            _server = make_server(
                host, int(port), metrics_app, server_class=_Server, handler_class=_Quiet
            )
            Thread(target=_server.serve_forever, name="keep-metrics", daemon=True).start()
        return _server.server_port


def stop_metrics_server():
    global _server
    with _lock:
        if _server is not None:
            _server.shutdown()
            _server.server_close()
            _server = None
