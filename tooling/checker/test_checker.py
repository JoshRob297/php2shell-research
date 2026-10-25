#!/usr/bin/env python3
"""
test_checker.py - Pruebas unitarias y de integracion para php2shell-checker.
"""

import warnings
warnings.filterwarnings("ignore")

import unittest
from unittest.mock import MagicMock, patch
import requests

from fingerprint import parse_semver, is_version_vulnerable, detect_sapi, analyze_fingerprint
from session import parse_set_cookies, check_session_strict_mode, sanitize_cookie_val
from network import check_upload_progress_posture
from checker import evaluate_scoring, validate_target_guard, load_config


class TestCheckerModules(unittest.TestCase):

    def test_parse_semver(self):
        self.assertEqual(parse_semver("8.4.26"), (8, 4, 26))
        self.assertEqual(parse_semver("8.3.35-ubuntu1"), (8, 3, 35))
        self.assertIsNone(parse_semver("invalid"))

    def test_version_vulnerable(self):
        patched = {"8.4": "8.4.27", "8.3": "8.3.36"}
        is_vuln, branch, target = is_version_vulnerable("8.4.26", patched)
        self.assertTrue(is_vuln)
        self.assertEqual(branch, "8.4")
        self.assertEqual(target, "8.4.27")

        is_vuln, branch, target = is_version_vulnerable("8.4.27", patched)
        self.assertFalse(is_vuln)

        is_vuln, branch, target = is_version_vulnerable("8.4.28", patched)
        self.assertFalse(is_vuln)

    def test_detect_sapi(self):
        headers_mod = {"Server": "Apache/2.4.52 (Ubuntu) PHP/8.2.10", "X-Powered-By": "PHP/8.2.10"}
        sapi_mod = detect_sapi(headers_mod)
        self.assertEqual(sapi_mod["sapi_hint"], "mod_php")

        headers_fpm = {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.4.26"}
        sapi_fpm = detect_sapi(headers_fpm)
        self.assertEqual(sapi_fpm["sapi_hint"], "fpm-proxy")

    def test_session_strict_mode_mitigated(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Set-Cookie": "PHPSESSID=new_random_token_12345; path=/"}
        mock_resp.raw.headers.getlist.return_value = ["PHPSESSID=new_random_token_12345; path=/"]
        mock_session.get.return_value = mock_resp

        res = check_session_strict_mode("http://fake.target/", mock_session)
        self.assertTrue(res["set_cookie_received"])
        self.assertTrue(res["session_cookie_replaced"])
        self.assertTrue(res["use_strict_mode_detected"])

    def test_session_strict_mode_exposed(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        # Simular que el servidor refleja el SID arbitrario enviado
        def fake_get(url, headers, **kwargs):
            cookie_hdr = headers.get("Cookie", "")
            sid = cookie_hdr.split("=")[1]
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Set-Cookie": f"PHPSESSID={sid}; path=/"}
            resp.raw.headers.getlist.return_value = [f"PHPSESSID={sid}; path=/"]
            return resp

        mock_session.get.side_effect = fake_get
        res = check_session_strict_mode("http://fake.target/", mock_session)
        self.assertTrue(res["set_cookie_received"])
        self.assertFalse(res["session_cookie_replaced"])
        self.assertFalse(res["use_strict_mode_detected"])

    def test_target_guards(self):
        # Loopback sin --local -> Bloqueado
        ok, msg = validate_target_guard("http://127.0.0.1:8080/", is_local_flag=False, is_authorized_flag=False)
        self.assertFalse(ok)

        # Loopback con --local -> Permitido
        ok, msg = validate_target_guard("http://127.0.0.1:8080/", is_local_flag=True, is_authorized_flag=False)
        self.assertTrue(ok)

        # Externo sin --authorized -> Bloqueado
        ok, msg = validate_target_guard("https://target.com/", is_local_flag=False, is_authorized_flag=False)
        self.assertFalse(ok)

        # Externo con --authorized -> Permitido
        ok, msg = validate_target_guard("https://target.com/", is_local_flag=False, is_authorized_flag=True)
        self.assertTrue(ok)

    def test_scoring_matrix_exposed(self):
        config = load_config()
        fp = {
            "is_php": True,
            "is_unpatched_version": True,
            "php_version": "8.4.26",
            "patched_target": "8.4.27",
            "sapi": {"sapi_hint": "fpm-proxy"},
        }
        sess = {"use_strict_mode_detected": False}
        net = {"upload_progress_supported": True, "body_limit_detected": False}

        verdict, score, breakdown, rems = evaluate_scoring(fp, sess, net, config)
        self.assertEqual(verdict, "EXPOSED")
        self.assertGreaterEqual(score, 51.0)
        self.assertGreater(len(rems), 0)

    def test_scoring_matrix_mitigated(self):
        config = load_config()
        fp = {
            "is_php": True,
            "is_unpatched_version": False,
            "php_version": "8.4.27",
            "patched_target": "8.4.27",
            "sapi": {"sapi_hint": "fpm-proxy"},
        }
        sess = {"use_strict_mode_detected": True}
        net = {"upload_progress_supported": False, "body_limit_detected": True}

        verdict, score, breakdown, rems = evaluate_scoring(fp, sess, net, config)
        self.assertEqual(verdict, "MITIGATED")
        self.assertLessEqual(score, 25.0)


if __name__ == "__main__":
    unittest.main()
