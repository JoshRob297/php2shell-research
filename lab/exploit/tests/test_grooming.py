#!/usr/bin/env python3
import os
import sys
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from grooming.heap_warmup import warmup_heap, build_warmup_body
from grooming.worker_saturation import saturate_workers, WorkerSaturator, _HolderThread
from grooming.allocator_oracle import oracle_bin128


class FakeResp:
    def __init__(self, text="", headers=None, cookies=None, content=None):
        self.text = text
        self.headers = headers or {}
        self.cookies = cookies or []
        self.content = content if content is not None else b""
        self.status_code = 200


class FakeSession:
    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self._resp

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self._resp

    def get(self, url, **kwargs):
        return self._resp


class TestHeapWarmup(unittest.TestCase):
    def test_build_warmup_body_size(self):
        body = build_warmup_body(1024)
        self.assertGreaterEqual(len(body), 1024)

    def test_warmup_heap_calls_post(self):
        resp = FakeResp(text="ok")
        session = FakeSession(resp)
        r = warmup_heap("http://127.0.0.1:8080/", session, size_mb=1)
        self.assertEqual(r, resp)
        self.assertTrue(len(session.calls) >= 1)
        self.assertEqual(session.calls[0][0], "POST")

    def test_warmup_heap_default_size(self):
        resp = FakeResp(text="ok")
        session = FakeSession(resp)
        warmup_heap("http://127.0.0.1:8080/", session)
        data = session.calls[0][2].get("data", b"")
        self.assertGreater(len(data), 1024 * 1024)


class TestWorkerSaturation(unittest.TestCase):
    def test_saturator_n_holders(self):
        sat = WorkerSaturator("http://127.0.0.1:8080/", 4, timeout=0.1)
        self.assertEqual(sat.n_holders, 3)
        self.assertEqual(int(sat), 3)

    def test_saturator_rejects_less_than_2(self):
        with self.assertRaises(ValueError):
            WorkerSaturator("http://127.0.0.1:8080/", 1, timeout=0.1)

    @patch("grooming.worker_saturation.socket.create_connection")
    def test_acquire_opens_n_minus_1(self, mock_conn):
        fake_sock = MagicMock()
        mock_conn.return_value = fake_sock
        sat = WorkerSaturator("http://127.0.0.1:8080/", 3, timeout=0.1)
        sat.acquire()
        self.assertEqual(mock_conn.call_count, 2)
        sat.release()

    @patch("grooming.worker_saturation.socket.create_connection")
    def test_saturate_workers_hold_false_returns_count(self, mock_conn):
        fake_sock = MagicMock()
        mock_conn.return_value = fake_sock
        r = saturate_workers("http://127.0.0.1:8080/", None, 3, timeout=0.1, hold=False)
        self.assertEqual(r, 2)


class TestAllocatorOracle(unittest.TestCase):
    def test_oracle_bin128_returns_dict(self):
        resp = FakeResp(text="hello")
        session = FakeSession(resp)
        r = oracle_bin128("http://127.0.0.1:8080/", session)
        self.assertIsInstance(r, dict)
        self.assertIn("hit", r)
        self.assertFalse(r["hit"])

    def test_oracle_bin128_parses_state(self):
        text = "ORACLE_STATE free_pages=0 chunks=2 fs11=0x0 sc=1 len=4000 size=100 real=9000000\nORACLE_OOM sc=1 len=4000"
        resp = FakeResp(text=text)
        session = FakeSession(resp)
        r = oracle_bin128("http://127.0.0.1:8080/", session)
        self.assertTrue(r["hit"])
        self.assertEqual(r["free_pages"], 0)
        self.assertEqual(r["fs11"], "0x0")


if __name__ == "__main__":
    unittest.main()