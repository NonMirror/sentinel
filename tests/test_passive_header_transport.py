"""One harmless loopback response verifies duplicate header preservation."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

from sentinel.scanner.client import HttpClient
from sentinel.scanner.headers import inspect_security_headers


def test_duplicate_policy_fields_survive_real_client_transport():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Opener-Policy", "unsafe-none")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            client = HttpClient()
            result = client.get(f"http://127.0.0.1:{server.server_port}/")
            assert result.status == 200 and client.request_count == 1
            assert [v for k, v in result.header_items if k == "Cross-Origin-Opener-Policy"] == ["same-origin", "unsafe-none"]
            findings = inspect_security_headers(result)
            assert [f.param for f in findings] == ["Cross-Origin-Opener-Policy"]
            assert findings[0].severity.value == "info"
        finally:
            server.shutdown()
            thread.join(timeout=2)
