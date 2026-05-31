from __future__ import annotations

import unittest

from ida_pseudoforge.core.render_ntset import normalize_ntset_system_information_body


class RenderNtSetTests(unittest.TestCase):
    def test_normalize_ntset_body_uses_stable_m128_alias_for_typed_access(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS NTAPI NtSetSystemInformation(",
                "        SYSTEM_INFORMATION_CLASS systemInformationClass,",
                "        PVOID systemInformation,",
                "        ULONG systemInformationLength)",
                "{",
                "  __m128i *systemInfo128;",
                "  KPROCESSOR_MODE previousMode;",
                "  NTSTATUS status;",
                "",
                "  systemInfo128 = systemInformation;",
                "  systemInformationClass = &systemInformation->m128i_i8[(unsigned int)systemInformationLength];",
                "  status = systemInformation->m128i_i32[0];",
                "  status += systemInformation[1].m128i_i32[0];",
                "  capturedBlock0 = *systemInformation;",
                "}",
            ]
        )

        rendered = normalize_ntset_system_information_body(text)

        self.assertIn("PVOID userProbeEnd;", rendered)
        self.assertIn("systemInfo128 = (__m128i *)systemInformation;", rendered)
        self.assertIn("userProbeEnd = &systemInfo128->m128i_i8[(unsigned int)systemInformationLength];", rendered)
        self.assertIn("status = systemInfo128->m128i_i32[0];", rendered)
        self.assertIn("status += systemInfo128[1].m128i_i32[0];", rendered)
        self.assertIn("capturedBlock0 = *systemInfo128;", rendered)
        self.assertNotIn("systemInformation->m128i_", rendered)
        self.assertNotIn("systemInformationClass = &", rendered)

    def test_normalize_ntset_body_splits_reused_m128_alias(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS NTAPI NtSetSystemInformation(",
                "        SYSTEM_INFORMATION_CLASS systemInformationClass,",
                "        PVOID systemInformation,",
                "        ULONG systemInformationLength)",
                "{",
                "  __m128i *systemInfo128 = (__m128i *)systemInformation;",
                "  KPROCESSOR_MODE previousMode;",
                "  NTSTATUS status;",
                "",
                "  systemInfo128 = (__m128i *)Buf1;",
                "  status = systemInformation->m128i_i32[0];",
                "  systemInformationClass = &systemInformation->m128i_i8[(unsigned int)systemInformationLength];",
                "}",
            ]
        )

        rendered = normalize_ntset_system_information_body(text)

        self.assertIn("__m128i *systemInformation128 = (__m128i *)systemInformation;", rendered)
        self.assertIn("__m128i *infoBuffer128 = systemInformation128;", rendered)
        self.assertIn("infoBuffer128 = (__m128i *)Buf1;", rendered)
        self.assertIn("status = systemInformation128->m128i_i32[0];", rendered)
        self.assertIn(
            "userProbeEnd = &systemInformation128->m128i_i8[(unsigned int)systemInformationLength];",
            rendered,
        )
        self.assertNotIn("systemInfo128", rendered)
        self.assertNotIn("systemInformation->m128i_", rendered)

    def test_normalize_ntset_body_keeps_existing_user_probe_end_declaration(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS NTAPI NtSetSystemInformation(",
                "        SYSTEM_INFORMATION_CLASS systemInformationClass,",
                "        PVOID systemInformation,",
                "        ULONG systemInformationLength)",
                "{",
                "  __m128i *systemInfo128;",
                "  KPROCESSOR_MODE previousMode;",
                "  PVOID userProbeEnd;",
                "",
                "  systemInfo128 = systemInformation;",
                "  systemInformationClass = &systemInformation->m128i_i8[(unsigned int)systemInformationLength];",
                "}",
            ]
        )

        rendered = normalize_ntset_system_information_body(text)

        self.assertEqual(rendered.count("PVOID userProbeEnd;"), 1)
        self.assertIn("userProbeEnd = &systemInfo128->m128i_i8[(unsigned int)systemInformationLength];", rendered)


if __name__ == "__main__":
    unittest.main()
