#!/usr/bin/env python3
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aslr.aslr_calc import calculate_aslr_window
from aslr.aslr_sweep import sweep_aslr


class FakeResp:
    def __init__(self, text="ok", status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {}
        self.cookies = []
        self.content = b""
        self.ok = True


class FakeSession:
    def __init__(self, resp=None, resps=None):
        self._resp = resp if resp is not None else FakeResp("ok")
        self._resps = resps
        self.i = 0
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self._resps:
            r = self._resps[self.i % len(self._resps)]
            self.i += 1
            return r
        return self._resp

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        if self._resps:
            r = self._resps[self.i % len(self._resps)]
            self.i += 1
            return r
        return self._resp

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if self._resps:
            r = self._resps[self.i % len(self._resps)]
            self.i += 1
            return r
        return self._resp


class TestAslrCalc(unittest.TestCase):
    def test_calculate_aslr_window(self):
        result = calculate_aslr_window()
        self.assertEqual(result[0], 387)
        self.assertEqual(result[1], 0x183000)
        self.assertEqual(result[2], 1.51)
        self.assertEqual(result[3], 38.7)

    def test_calculate_aslr_window_unpack(self):
        pages, disp_bytes, disp_mb, est = calculate_aslr_window()
        self.assertEqual(pages, 387)
        self.assertEqual(disp_bytes, 0x183000)
        self.assertAlmostEqual(disp_mb, 1.51)
        self.assertAlmostEqual(est, 38.7)

    def test_attribute_access(self):
        w = calculate_aslr_window()
        self.assertEqual(w.pages, 387)
        self.assertEqual(w.dispersion_bytes, 0x183000)


class TestAslrSweep(unittest.TestCase):
    def test_sweep_success_first_page(self):
        session = FakeSession(FakeResp("uid=0(root)"))
        success, page, elapsed = sweep_aslr("http://127.0.0.1:8080/", session, "id")
        self.assertTrue(success)
        self.assertEqual(page, 0)
        self.assertGreaterEqual(elapsed, 0)

    def test_sweep_finds_page(self):
        resps = [FakeResp("no"), FakeResp("no"), FakeResp("uid=0")]
        session = FakeSession(resps=resps)
        success, page, elapsed = sweep_aslr("http://127.0.0.1:8080/", session, "id", pages=5)
        self.assertTrue(success)
        self.assertEqual(page, 2)

    def test_sweep_no_success(self):
        session = FakeSession(FakeResp("", 500))
        # FakeResp text empty and status 500 -> no success
        session = FakeSession(FakeResp("", 500))
        # Make _is_success false by empty text and 5xx
        success, page, elapsed = sweep_aslr("http://127.0.0.1:8080/", session, "id", pages=3)
        self.assertFalse(success)
        self.assertEqual(page, -1)

    def test_sweep_call_count(self):
        session = FakeSession(FakeResp("ok"))
        sweep_aslr("http://127.0.0.1:8080/", session, "id", pages=4)
        self.assertEqual(len(session.calls), 1)  # stops at first success


if __name__ == "__main__":
    unittest.main()
