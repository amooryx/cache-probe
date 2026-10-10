import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from cache_probe import inspect_cache_headers


class _FixtureHandler(BaseHTTPRequestHandler):
    requests = []

    def do_HEAD(self):
        type(self).requests.append((self.command, self.path))
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/destination?token=redirect-secret")
            self.send_header("Cache-Control", "no-store")
        else:
            self.send_response(200)
            self.send_header("X-Cache", "HIT")
            self.send_header("Age", "12")
        self.end_headers()

    def do_GET(self):
        type(self).requests.append((self.command, self.path))
        self.send_response(500)
        self.end_headers()

    def log_message(self, format, *args):
        pass


class InspectCacheHeadersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _FixtureHandler.requests = []
        cls.server = HTTPServer(("127.0.0.1", 0), _FixtureHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def setUp(self):
        _FixtureHandler.requests.clear()

    def test_single_head_request_reports_cache_headers_and_redacts_query(self):
        url = f"{self.base_url}/item?token=secret-value&empty="

        result = inspect_cache_headers(url, "127.0.0.1")

        self.assertEqual(result["status"], 200)
        self.assertEqual(result["method"], "HEAD")
        self.assertEqual(result["cache_headers"], {"age": "12", "x-cache": "HIT"})
        self.assertEqual(
            result["url"],
            f"{self.base_url}/item?token=%5BREDACTED%5D&empty=%5BREDACTED%5D",
        )
        self.assertNotIn("secret-value", str(result))
        self.assertEqual(_FixtureHandler.requests, [("HEAD", "/item?token=secret-value&empty=")])
        self.assertIn("do not prove a cache hit", result["interpretation"])

    def test_redirect_is_reported_without_following_it(self):
        result = inspect_cache_headers(f"{self.base_url}/redirect", "127.0.0.1")

        self.assertEqual(result["status"], 302)
        self.assertEqual(result["cache_headers"], {"cache-control": "no-store"})
        self.assertEqual(_FixtureHandler.requests, [("HEAD", "/redirect")])

    def test_target_outside_exact_host_scope_is_rejected_before_request(self):
        with self.assertRaisesRegex(ValueError, "exactly match"):
            inspect_cache_headers(f"{self.base_url}/item", "localhost")

        self.assertEqual(_FixtureHandler.requests, [])

    def test_credentials_in_target_url_are_rejected(self):
        url = f"http://user:password@127.0.0.1:{self.server.server_port}/item"

        with self.assertRaisesRegex(ValueError, "Credentials"):
            inspect_cache_headers(url, "127.0.0.1")

        self.assertEqual(_FixtureHandler.requests, [])

    def test_timeout_must_be_positive_and_bounded(self):
        with self.assertRaisesRegex(ValueError, "Timeout"):
            inspect_cache_headers(f"{self.base_url}/item", "127.0.0.1", timeout=10.01)

        self.assertEqual(_FixtureHandler.requests, [])


if __name__ == "__main__":
    unittest.main()
