from __future__ import annotations

import unittest

from ida_pseudoforge.core.render_style import enforce_generated_code_style


class RenderStyleTests(unittest.TestCase):
    def test_style_pass_splits_inline_braces_and_expands_else_if(self) -> None:
        styled = enforce_generated_code_style(
            "if ( x ) {\n"
            "  do_x();\n"
            "} else if ( y ) {\n"
            "  do_y();\n"
            "}\n"
        )

        self.assertNotIn("} else", styled)
        self.assertNotIn("else if", styled)
        self.assertIn("if ( x )\n{\n  do_x();\n}", styled)
        self.assertIn("else\n{\n  if ( y )\n  {\n    do_y();\n  }\n}", styled)

    def test_style_pass_wraps_bodies_and_inverts_terminal_else_guards(self) -> None:
        styled = enforce_generated_code_style(
            "if ( ready && count >= 4 )\n"
            "  do_work();\n"
            "else\n"
            "  return STATUS_INFO_LENGTH_MISMATCH;\n"
            "finish();\n"
        )

        self.assertIn("if ( !ready || count < 4 )\n{\n  return STATUS_INFO_LENGTH_MISMATCH;\n}", styled)
        self.assertIn("do_work();\nfinish();", styled)


if __name__ == "__main__":
    unittest.main()
