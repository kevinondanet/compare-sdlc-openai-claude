import json
import unittest

from service.health import health_status, make_app


def _call(app, path="/health", method="GET"):
    captured = {}

    def start_response(status, headers):
        captured["status"] = status

    body = b"".join(app({"PATH_INFO": path, "REQUEST_METHOD": method}, start_response))
    return captured["status"], json.loads(body or b"{}")


class HealthTest(unittest.TestCase):
    def test_all_ok(self) -> None:
        code, body = health_status({"db": lambda: True, "cache": lambda: True})
        self.assertEqual(code, 200)
        self.assertEqual(body["checks"], {"db": "ok", "cache": "ok"})

    def test_failing_check_names_dependency(self) -> None:
        code, body = health_status({"db": lambda: False, "cache": lambda: True})
        self.assertEqual(code, 503)
        self.assertEqual(body["failing"], ["db"])

    def test_wsgi_route(self) -> None:
        app = make_app({"db": lambda: True})
        status, body = _call(app)
        self.assertTrue(status.startswith("200"))
        self.assertEqual(body["status"], "ok")
        self.assertTrue(_call(app, path="/nope")[0].startswith("404"))
