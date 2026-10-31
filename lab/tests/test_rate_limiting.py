#!/usr/bin/env python3
import os
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from safety.rate_limiter import RateLimiter


class FakeResp:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.text = ""


class FakeSession:
    def __init__(self, statuses=None):
        self.statuses = list(statuses) if statuses else [200]
        self.i = 0
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        sc = self.statuses[self.i % len(self.statuses)]
        self.i += 1
        return FakeResp(sc)

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)


class TestRateLimiting(unittest.TestCase):

    def test_min_interval_configured_for_5rps(self):
        rl = RateLimiter(max_rps=5.0, max_concurrent=10)
        self.assertAlmostEqual(rl.min_interval, 0.2, places=5)
        self.assertEqual(rl.max_concurrent, 10)

    def test_send_success_resets_5xx(self):
        session = FakeSession([200])
        rl = RateLimiter(max_rps=100, max_concurrent=10)
        with patch("time.sleep"):
            resp = rl.send(session, "GET", "http://127.0.0.1:8080/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(rl.consecutive_5xx, 0)

    def test_5xx_increments_and_aborts_after_3(self):
        session = FakeSession([500, 500, 500])
        rl = RateLimiter(max_rps=100, max_concurrent=10, max_5xx_retries=3)
        with patch("time.sleep"):
            rl.send(session, "GET", "http://127.0.0.1:8080/")
            self.assertEqual(rl.consecutive_5xx, 1)
            rl.send(session, "GET", "http://127.0.0.1:8080/")
            self.assertEqual(rl.consecutive_5xx, 2)
            rl.send(session, "GET", "http://127.0.0.1:8080/")
            self.assertEqual(rl.consecutive_5xx, 3)
            with self.assertRaises(RuntimeError):
                rl.send(session, "GET", "http://127.0.0.1:8080/")

    def test_429_triggers_backoff_and_retry(self):
        session = FakeSession([429, 200])
        rl = RateLimiter(max_rps=100, max_concurrent=10)
        with patch("time.sleep") as sl:
            resp = rl.send(session, "GET", "http://127.0.0.1:8080/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(session.calls), 2)
        # backoff sleep called at least once
        self.assertTrue(sl.called)

    def test_non_5xx_resets_counter(self):
        session = FakeSession([500, 200])
        rl = RateLimiter(max_rps=100, max_concurrent=10)
        with patch("time.sleep"):
            rl.send(session, "GET", "http://127.0.0.1:8080/")
            self.assertEqual(rl.consecutive_5xx, 1)
            rl.send(session, "GET", "http://127.0.0.1:8080/")
            self.assertEqual(rl.consecutive_5xx, 0)

    def test_max_concurrent_slot_attribute(self):
        rl = RateLimiter(max_rps=5, max_concurrent_requests=4)
        self.assertEqual(rl.max_concurrent, 4)


if __name__ == "__main__":
    unittest.main()
