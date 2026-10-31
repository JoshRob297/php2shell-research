#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recon import detect_architecture, calibrate_offsets, detect_aslr, detect_sapi


class FakeResp:
    def __init__(self, headers, text="", cookies=None):
        self.headers = headers
        self.text = text
        self.cookies = cookies or []
        self.status_code = 200


class FakeSession:
    def __init__(self, resp):
        self._resp = resp

    def request(self, method, url, **kwargs):
        return self._resp

    def get(self, url, **kwargs):
        return self._resp


class TestRecon(unittest.TestCase):

    def test_detect_sapi_apache(self):
        headers = {"server": "Apache/2.4.58 (Ubuntu)", "x-powered-by": "PHP/8.4.26"}
        sapi = detect_sapi(headers)
        self.assertEqual(sapi["sapi_hint"], "apache2handler")

    def test_detect_sapi_nginx_fpm(self):
        headers = {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.4.26"}
        sapi = detect_sapi(headers)
        self.assertEqual(sapi["sapi_hint"], "fpm-proxy")

    def test_detect_sapi_cli(self):
        headers = {"server": "PHP/8.4.26 Development Server"}
        sapi = detect_sapi(headers)
        self.assertEqual(sapi["sapi_hint"], "cli-server")

    def test_detect_architecture_apache(self):
        headers = {"server": "Apache/2.4.58 (Ubuntu)", "x-powered-by": "PHP/8.4.26"}
        resp = FakeResp(headers)
        session = FakeSession(resp)
        arch = detect_architecture("http://127.0.0.1:8080/", session)
        self.assertEqual(arch["sapi_hint"], "apache2handler")
        self.assertEqual(arch["php_version"], "8.4.26")
        self.assertEqual(arch["recommended_chain"], "modphp")
        self.assertFalse(arch["aslr_on"] or arch["aslr"])

    def test_detect_architecture_fpm(self):
        headers = {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.3.35"}
        resp = FakeResp(headers)
        session = FakeSession(resp)
        arch = detect_architecture("http://127.0.0.1:8080/", session)
        self.assertEqual(arch["sapi_hint"], "fpm-proxy")
        self.assertEqual(arch["php_version"], "8.3.35")
        self.assertEqual(arch["recommended_chain"], "fpm")

    def test_detect_architecture_cli(self):
        headers = {"server": "PHP/8.4.26 Development Server"}
        resp = FakeResp(headers)
        session = FakeSession(resp)
        arch = detect_architecture("http://127.0.0.1:8080/", session)
        self.assertEqual(arch["sapi_hint"], "cli-server")
        self.assertEqual(arch["recommended_chain"], "cli")

    def test_calibrate_offsets_cli(self):
        headers = {"server": "PHP/8.4.26 Development Server"}
        resp = FakeResp(headers)
        session = FakeSession(resp)
        arch = detect_architecture("http://127.0.0.1:8080/", session)
        arch["zval_ptr_dtor"] = "0x7ffff7a00000"
        offs = calibrate_offsets("http://127.0.0.1:8080/", session, arch)
        self.assertEqual(offs["chain"], "cli")
        self.assertEqual(offs["zif_system"], hex(0x7ffff7a00000 - 0x204BC0))

    def test_detect_aslr_off(self):
        headers = {"server": "Apache/2.4.58", "x-powered-by": "PHP/8.4.26"}
        resp = FakeResp(headers)
        session = FakeSession(resp)
        aslr_on, bits = detect_aslr("http://127.0.0.1:8080/", session, samples=3)
        self.assertFalse(aslr_on)

    def test_detect_aslr_on(self):
        responses = [
            FakeResp({"x-addr": "0x7f1234567890"}, text="leak 0x7f1234567890"),
            FakeResp({"x-addr": "0x7f9999999999"}, text="leak 0x7f9999999999"),
            FakeResp({"x-addr": "0x7fabcdef0123"}, text="leak 0x7fabcdef0123"),
        ]
        class SeqSession:
            def __init__(self, resps):
                self.resps = list(resps)
                self.i = 0
            def request(self, method, url, **kwargs):
                r = self.resps[self.i % len(self.resps)]
                self.i += 1
                return r
            def get(self, url, **kwargs):
                return self.request("GET", url, **kwargs)
        session = SeqSession(responses)
        aslr_on, bits = detect_aslr("http://127.0.0.1:8080/", session, samples=3)
        self.assertTrue(aslr_on)
        self.assertGreater(bits, 0)


if __name__ == "__main__":
    unittest.main()
