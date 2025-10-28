import socket
import threading
import unittest

import app


def _start_mock_server(handler):
    ready = threading.Event()
    errors = []
    port_holder = {}

    def run():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", 0))
                server.listen(1)
                port_holder['port'] = server.getsockname()[1]
                ready.set()
                conn, _ = server.accept()
                with conn:
                    handler(conn)
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(exc)
            ready.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    if not ready.wait(timeout=1):
        raise RuntimeError("Mock server failed to start")
    return port_holder['port'], thread, errors


class Socks5UtilitiesTest(unittest.TestCase):
    def test_parse_and_normalize_url(self):
        entry = app.parse_socks_url('socks5://user:pass@example.com:1080')
        self.assertEqual(entry['scheme'], 'socks5')
        self.assertEqual(entry['host'], 'example.com')
        self.assertEqual(entry['port'], 1080)
        self.assertEqual(entry['username'], 'user')
        self.assertEqual(entry['password'], 'pass')
        self.assertEqual(app.normalize_socks_url(entry), 'socks5://user:pass@example.com:1080')

        with self.assertRaises(ValueError):
            app.parse_socks_url('http://example.com:80')

        with self.assertRaises(ValueError):
            app.parse_socks_url('socks5://host')

    def test_verify_socks5_no_auth_connect_success(self):
        captured = {}

        def handler(conn):
            conn.settimeout(2)
            captured['greeting'] = app.recv_exact(conn, 4)
            conn.sendall(b'\x05\x00')
            expected_req = b'\x05\x01\x00\x01' + socket.inet_aton('1.1.1.1') + (53).to_bytes(2, 'big')
            captured['connect'] = app.recv_exact(conn, len(expected_req))
            conn.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('8.8.8.8') + (1080).to_bytes(2, 'big'))

        port, thread, errors = _start_mock_server(handler)
        result = app.verify_socks5_proxy('127.0.0.1', port, timeout_ms=800, validate_connect=True, connect_target=('1.1.1.1', 53))
        thread.join(timeout=0.5)
        if errors:
            raise errors[0]

        self.assertEqual(captured['greeting'], b'\x05\x02\x00\x02')
        self.assertEqual(captured['connect'], b'\x05\x01\x00\x01' + socket.inet_aton('1.1.1.1') + (53).to_bytes(2, 'big'))
        self.assertEqual(result['classification'], 'connect-success')
        self.assertEqual(result['auth_type'], 'none')
        self.assertEqual(result['auth_result'], 'not-required')
        self.assertEqual(result['connect_result'], 'success')

    def test_verify_socks5_auth_failure(self):
        captured = {}

        def handler(conn):
            conn.settimeout(2)
            captured['greeting'] = app.recv_exact(conn, 4)
            conn.sendall(b'\x05\x02')
            captured['auth'] = app.recv_exact(conn, 1 + 1 + 4 + 1 + 4)  # 0x01, len/user, len/pass
            conn.sendall(b'\x01\x01')

        port, thread, errors = _start_mock_server(handler)
        result = app.verify_socks5_proxy('127.0.0.1', port, username='user', password='pass', timeout_ms=800, validate_connect=False)
        thread.join(timeout=0.5)
        if errors:
            raise errors[0]

        self.assertEqual(captured['greeting'], b'\x05\x02\x00\x02')
        self.assertEqual(captured['auth'], b'\x01\x04user\x04pass')
        self.assertEqual(result['classification'], 'socks5-auth-failed')
        self.assertEqual(result['auth_result'], 'failed')
        self.assertEqual(result['connect_result'], 'skipped')

    def test_not_socks_service(self):
        captured = {}

        def handler(conn):
            conn.settimeout(2)
            captured['greeting'] = app.recv_exact(conn, 4)
            conn.sendall(b'\x05\xff')

        port, thread, errors = _start_mock_server(handler)
        result = app.verify_socks5_proxy('127.0.0.1', port, timeout_ms=800, validate_connect=False)
        thread.join(timeout=0.5)
        if errors:
            raise errors[0]

        self.assertEqual(captured['greeting'], b'\x05\x02\x00\x02')
        self.assertEqual(result['classification'], 'not-socks5')
        self.assertEqual(result['auth_type'], 'unknown')
        self.assertEqual(result['connect_result'], 'skipped')


if __name__ == '__main__':
    unittest.main()
