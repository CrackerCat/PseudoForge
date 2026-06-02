from __future__ import annotations

import unittest

from ida_pseudoforge.core.llm_failures import (
    format_llm_fallback_warning,
    is_llm_provider_cyber_policy_block,
    summarize_llm_failure,
)


CYBER_POLICY_ERROR = (
    "CLI rename provider failed with exit 1: API Error: Claude Code is unable to respond to this request, "
    "which appears to violate our Usage Policy (https://www.anthropic.com/legal/aup). "
    "This request triggered cyber-related safeguards. To request an adjustment pursuant to our Cyber "
    "Verification Program, fill out https://claude.com/form/cyber-use-case?token=secret-token. "
    "Request ID: req_011CbdZaSq3CPVkGzJzLVbmB"
)


class LlmFailureTests(unittest.TestCase):
    def test_cyber_policy_block_is_classified_and_summarized(self) -> None:
        self.assertTrue(is_llm_provider_cyber_policy_block(CYBER_POLICY_ERROR))

        summary = summarize_llm_failure(CYBER_POLICY_ERROR)

        self.assertEqual(summary, "provider cyber policy block request_id=req_011CbdZaSq3CPVkGzJzLVbmB")

    def test_cyber_policy_warning_is_user_visible_and_redacted(self) -> None:
        warning = format_llm_fallback_warning(CYBER_POLICY_ERROR)

        self.assertIn("blocked by provider cyber policy", warning)
        self.assertIn("deterministic fallback used", warning)
        self.assertIn("req_011CbdZaSq3CPVkGzJzLVbmB", warning)
        self.assertNotIn("secret-token", warning)

    def test_non_policy_failure_keeps_generic_fallback_message(self) -> None:
        warning = format_llm_fallback_warning("provider unavailable at https://example.invalid/path")

        self.assertIn("LLM rename assist failed; deterministic fallback used", warning)
        self.assertIn("[url]", warning)
        self.assertNotIn("example.invalid/path", warning)


if __name__ == "__main__":
    unittest.main()
