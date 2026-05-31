from __future__ import annotations

import unittest

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.core.lvar_analysis import build_clean_plan
from ida_pseudoforge.core.render import render_cleaned_pseudocode
from ida_pseudoforge.core.render_style import enforce_generated_code_style


STYLE_SAMPLE = r"""
__int64 __fastcall StyleSample(int a1)
{
  int v1;

  v1 = 0;
  if ( a1 )
    return 1;
  else if ( a1 == 2 )
    v1 = 2;
  else
    v1 = 3;
  while ( v1 )
    --v1;
  return v1;
}
"""


GUARD_INVERSION_SAMPLE = r"""
__int64 __fastcall GuardSample(int a1, int a2)
{
  int v1;

  v1 = 0;
  if ( a1 && a2 >= 4 )
  {
    v1 = a2 + 1;
  }
  else
  {
    return 3221225476LL;
  }
  return v1;
}
"""


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

    def test_generated_code_style(self) -> None:
        capture = capture_from_pseudocode(STYLE_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("else if", rendered)
        self.assertNotIn("while (false);", rendered)
        self.assertNotIn("pseudoForgeResult", rendered)
        self.assertIn("  if ( argument0 )\n  {\n    return 1;\n  }", rendered)
        self.assertIn("  if ( argument0 == 2 )\n  {", rendered)
        self.assertIn("  else\n  {", rendered)
        self.assertIn("  while ( v1 )\n  {\n    --v1;\n  }", rendered)

    def test_positive_guard_inversion(self) -> None:
        capture = capture_from_pseudocode(GUARD_INVERSION_SAMPLE)
        plan = build_clean_plan(capture)
        rendered = render_cleaned_pseudocode(capture, plan)

        self.assertNotIn("if ( argument0 && argument1 >= 4 )", rendered)
        self.assertIn("if ( !argument0 || argument1 < 4 )", rendered)
        self.assertIn("return STATUS_INFO_LENGTH_MISMATCH;", rendered)
        self.assertIn("argument1 + 1;", rendered)


if __name__ == "__main__":
    unittest.main()
