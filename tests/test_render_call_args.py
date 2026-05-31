from __future__ import annotations

import unittest

from ida_pseudoforge.core.render_call_args import rewrite_parameter_low_byte_call_arguments


class RenderCallArgTests(unittest.TestCase):
    def test_rewrite_parameter_low_byte_call_arguments_rewrites_next_call_argument(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS Sample(PVOID systemInformation, ULONG systemInformationLength)",
                "{",
                "  LOBYTE(systemInformationLength) = PreviousMode;",
                "  ProbeForWrite(systemInformation, systemInformationLength, 1u);",
                "}",
            ]
        )

        rewritten = rewrite_parameter_low_byte_call_arguments(text)

        self.assertNotIn("LOBYTE(systemInformationLength)", rewritten)
        self.assertIn("ProbeForWrite(systemInformation, (unsigned __int8)PreviousMode, 1u);", rewritten)

    def test_rewrite_parameter_low_byte_call_arguments_ignores_locals(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS Sample(PVOID systemInformation, ULONG systemInformationLength)",
                "{",
                "  LOBYTE(localLength) = PreviousMode;",
                "  ProbeForWrite(systemInformation, localLength, 1u);",
                "}",
            ]
        )

        self.assertEqual(rewrite_parameter_low_byte_call_arguments(text), text)

    def test_rewrite_parameter_low_byte_call_arguments_requires_next_call_use(self) -> None:
        text = "\n".join(
            [
                "NTSTATUS Sample(PVOID systemInformation, ULONG systemInformationLength)",
                "{",
                "  LOBYTE(systemInformationLength) = PreviousMode;",
                "  ProbeForWrite(systemInformation, originalLength, 1u);",
                "}",
            ]
        )

        self.assertEqual(rewrite_parameter_low_byte_call_arguments(text), text)


if __name__ == "__main__":
    unittest.main()
