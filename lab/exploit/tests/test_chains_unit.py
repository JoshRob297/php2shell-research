#!/usr/bin/env python3
import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def _module_available(name):
    try:
        __import__(name)
        return True
    except Exception:
        return False


HAS_FORGE = any(
    _module_available(m)
    for m in ("forge.ub_write_forge", "forge.htable_forge", "forge.chunk_forge")
)



class FakeResp:
    def __init__(self, text="", content=b"", status_code=200):
        self.text = text
        self.content = content
        self.status_code = status_code
        self.headers = {}
        self.cookies = []


class FakeSession:
    def __init__(self, resp=None):
        self._resp = resp if resp is not None else FakeResp("ok")
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self._resp

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self._resp

    def get(self, url, **kwargs):
        return self._resp


class TestChainsUnit(unittest.TestCase):
    def test_chain_modphp_runs(self):
        from chains.chain_modphp import run_chain_modphp
        session = FakeSession(FakeResp("uid=0"))
        res = run_chain_modphp("http://127.0.0.1:8080/", session, cmd="id")
        self.assertEqual(res["chain"], "modphp")
        self.assertTrue(res["success"])
        self.assertIn("forged_chunk", res)

    def test_chain_modphp_alias(self):
        import chains.chain_modphp as m
        session = FakeSession()
        res = m.chain_modphp("http://127.0.0.1:8080/", session, cmd="id")
        self.assertTrue(res["success"])

    @unittest.skipUnless(HAS_FORGE, "forge/ not distributed in the public lab")
    def test_chain_fpm_runs(self):
        from chains.chain_fpm import run_chain_fpm
        session = FakeSession(FakeResp("ok"))
        res = run_chain_fpm("http://127.0.0.1:8080/", session, cmd="id",
                            d_addr=0x7ffff6264000, ubwrite_addr=0x555556ae2dd0,
                            system_addr=0x7ffff7070090)
        self.assertEqual(res["chain"], "fpm")
        self.assertTrue(res["success"])
        self.assertEqual(res["n_value"], -2932019265844)

    @unittest.skipUnless(HAS_FORGE, "forge/ not distributed in the public lab")
    def test_chain_cli_runs(self):
        from chains.chain_cli import run_chain_cli
        session = FakeSession(FakeResp("ok"))
        res = run_chain_cli("http://127.0.0.1:8080/", session, cmd="id",
                            zif_system_addr=0x7f1234567890)
        self.assertEqual(res["chain"], "cli")
        self.assertTrue(res["success"])
        self.assertEqual(res["total_size"], 384)

    def test_chain_cli_leak_sizes(self):
        from chains import chain_cli
        session = FakeSession(FakeResp("ok"))
        # patch leak functions to return fixed values
        chain_cli.leak_heap_base = lambda *a, **k: (0x7f0000000000, b"\x00" * 256)
        chain_cli.leak_ptr = lambda *a, **k: (0x7f9999999999, b"\x00" * 16)
        res = chain_cli.run_chain_cli("http://127.0.0.1:8080/", session, cmd="id")
        self.assertEqual(res["heap_base"], 0x7f0000000000)
        self.assertEqual(res["zval_ptr_dtor"], 0x7f9999999999)

    def test_chain_modphp_mocked_leak(self):
        import chains.chain_modphp as chain_modphp
        session = FakeSession(FakeResp("ok"))
        chain_modphp.leak_cookie = lambda *a, **k: (b"\x00" * 4000, [0x7f0000000000])
        chain_modphp.forge_chunk_b = lambda ptrs, cmd: (b"FORGED", 6)
        res = chain_modphp.run_chain_modphp("http://127.0.0.1:8080/", session, cmd="id")
        self.assertTrue(res["success"])
        self.assertEqual(res["chunk_size"], 6)


if __name__ == "__main__":
    unittest.main()