import unittest

from detector import inspect_event


def event(payload: str) -> dict[str, str]:
    return {
        "timestamp": "2026-10-09T09:00:00Z",
        "source": "10.0.0.24",
        "destination": "10.0.0.5",
        "protocol": "http",
        "payload": payload,
    }


class DetectorTests(unittest.TestCase):
    def test_benign_request_has_no_alert(self):
        self.assertEqual(inspect_event(event("GET /welcome HTTP/1.1\nHost: example.test")), [])

    def test_detects_path_traversal(self):
        alerts = inspect_event(event("GET /files/../../notes.txt HTTP/1.1"))
        self.assertEqual(alerts[0].rule_id, "WEB-001")
        self.assertEqual(alerts[0].severity, "high")

    def test_detects_scanner_agent(self):
        alerts = inspect_event(event("GET / HTTP/1.1\nUser-Agent: Nikto"))
        self.assertEqual(alerts[0].rule_id, "WEB-003")

    def test_ignores_non_string_payload(self):
        self.assertEqual(inspect_event({"payload": 42}), [])


if __name__ == "__main__":
    unittest.main()
