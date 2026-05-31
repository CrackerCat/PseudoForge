from __future__ import annotations

import unittest

from tools.profile_load_smoke import run_smoke


class ProfileLoadSmokeTests(unittest.TestCase):
    def test_split_family_smoke_uses_split_file_without_monolithic_profile(self) -> None:
        result = run_smoke("functions", repeat=3)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["profile_file"], "kernel_functions.json")
        self.assertGreater(result["entry_count"], 0)
        self.assertIn("kernel_functions.json", result["active_profiles"])
        self.assertTrue(result["loaded_split_profile"])
        self.assertFalse(result["loaded_monolithic_profile"])
        self.assertEqual(result["warnings"], [])
        self.assertEqual(result["failures"], [])

    def test_smoke_reports_optional_timing_threshold_failures(self) -> None:
        result = run_smoke("functions", repeat=1, max_cold_ms=0.000001)

        self.assertEqual(result["status"], "failed")
        self.assertTrue(
            any("cold load" in failure for failure in result["failures"]),
            result["failures"],
        )


if __name__ == "__main__":
    unittest.main()
