"""Offline diagnostic-harness tests. Never use actual API credentials."""
from pathlib import Path
import runpy
import sys
import unittest

helpers = runpy.run_path(str(Path(__file__).parents[1] / "diagnose-live-codex.py"))


class LiveDiagnosticTest(unittest.TestCase):
    def test_provider_settings_do_not_override_reserved_builtin_id(self):
        for websockets in (True, False):
            args = helpers["provider_options"](websockets)
            self.assertFalse(any("model_providers.openai." in arg for arg in args))
            self.assertIn('model_provider="agentvault-diagnostic"', args)
            self.assertIn('model_providers.agentvault-diagnostic.base_url="https://api.openai.com/v1"', args)
            self.assertIn(f'model_providers.agentvault-diagnostic.supports_websockets={str(websockets).lower()}', args)

    def test_full_and_masked_credentials_and_terminal_controls_are_redacted(self):
        result = helpers["redact"]("fake-token sk-proj-****1234 \x1b[31m", "fake-token")
        self.assertNotIn("fake-token", result)
        self.assertNotIn("1234", result)
        self.assertNotIn("\x1b", result)

    def test_real_process_exit_status_and_output(self):
        code, text, timeout = helpers["capture"]([sys.executable, "-c", "print('synthetic'); raise SystemExit(7)"], {})
        self.assertEqual(code, 7)
        self.assertEqual(text.strip(), "synthetic")
        self.assertFalse(timeout)

    def test_real_process_timeout_and_oversized_capture(self):
        _code, _text, expired = helpers["capture"]([sys.executable, "-c", "import time; time.sleep(5)"], {}, timeout=0.1)
        self.assertTrue(expired)
        _code, text, _expired = helpers["capture"]([sys.executable, "-c", "print('SYNTHETIC_TOKEN'*100)"], {}, limit=32)
        self.assertIn("withheld", text)
        self.assertNotIn("SYNTHETIC", text)

    def test_echoed_prompt_is_not_a_verified_reply(self):
        self.assertFalse(helpers["verified"]("AGENTVAULT_LIVE_CODEX_OK"))
        self.assertTrue(helpers["verified"]('{"type":"item.completed","item":{"type":"agent_message","text":"AGENTVAULT_LIVE_CODEX_OK"}}'))

    def test_provider_quota_error_stops_transport_retry_but_model_text_does_not(self):
        self.assertTrue(helpers["quota_blocked"]('{"type":"error","message":"Quota exceeded. Check your plan and billing details."}'))
        self.assertTrue(helpers["quota_blocked"]('{"type":"turn.failed","error":{"message":"insufficient_quota"}}'))
        self.assertFalse(helpers["quota_blocked"]('{"type":"error","message":"invalid peer certificate: UnknownIssuer"}'))
        self.assertFalse(helpers["quota_blocked"]('{"type":"item.completed","item":{"type":"agent_message","text":"Quota exceeded"}}'))


if __name__ == "__main__":
    unittest.main()
