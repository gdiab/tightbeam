import contextlib
import http.server
import importlib.util
import io
import json
import pathlib
import socket
import tempfile
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROBE_PATH = ROOT / "scripts" / "gateway_down_probe.py"
SPEC = importlib.util.spec_from_file_location("gateway_down_probe", PROBE_PATH)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class VersionHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/version":
            self.send_error(404)
            return

        body = b'{"server":"tightbeam","version":"test"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class ClientOnlySocket(socket.socket):
    bind_calls = 0
    listen_calls = 0

    def bind(self, address):
        type(self).bind_calls += 1
        raise AssertionError(f"probe attempted to bind {address!r}")

    def listen(self, backlog=0):
        type(self).listen_calls += 1
        raise AssertionError(f"probe attempted to listen with backlog {backlog}")


class GatewayDownProbeTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.evidence_file = pathlib.Path(self.temp_dir.name) / "gateway-down.ndjson"
        ClientOnlySocket.bind_calls = 0
        ClientOnlySocket.listen_calls = 0

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_probe(self, port):
        stdout = io.StringIO()
        stderr = io.StringIO()
        original_socket = socket.socket
        socket.socket = ClientOnlySocket

        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = PROBE.run(
                    port=port,
                    timeout_seconds=1,
                    evidence_file=self.evidence_file,
                )
        finally:
            socket.socket = original_socket

        self.assertEqual(ClientOnlySocket.bind_calls, 0)
        self.assertEqual(ClientOnlySocket.listen_calls, 0)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_up_gets_version_without_recording_or_listening(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), VersionHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()

        try:
            status, stdout, stderr = self.run_probe(server.server_port)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

        self.assertEqual(status, 0)
        self.assertIn("HEALTHY tightbeam gateway", stdout)
        self.assertEqual(stderr, "")
        self.assertFalse(self.evidence_file.exists())

    def test_connection_refused_records_durable_event_and_alerts(self):
        reservation = socket.socket()
        reservation.bind(("127.0.0.1", 0))
        unused_port = reservation.getsockname()[1]
        reservation.close()

        status, stdout, stderr = self.run_probe(unused_port)

        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertIn("ALERT tightbeam gateway down", stderr)
        event = json.loads(self.evidence_file.read_text(encoding="utf-8"))
        self.assertEqual(event["event"], "gateway-down")
        self.assertEqual(event["endpoint"], f"http://127.0.0.1:{unused_port}/version")
        self.assertIn("ConnectionRefusedError", event["error"])
        self.assertRegex(event["at"], r"^\d{4}-\d{2}-\d{2}T.*Z$")

    def test_systemd_runner_enforces_no_socket_binding_and_no_recovery(self):
        service = (
            ROOT / "packaging" / "systemd" / "tightbeam-gateway-down-probe.service"
        ).read_text(encoding="utf-8")
        timer = (
            ROOT / "packaging" / "systemd" / "tightbeam-gateway-down-probe.timer"
        ).read_text(encoding="utf-8")

        self.assertIn("Type=oneshot", service)
        self.assertIn("SocketBindDeny=any", service)
        self.assertNotIn("restart", service.lower())
        self.assertNotIn("wake", service.lower())
        self.assertIn("OnUnitActiveSec=60s", timer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
