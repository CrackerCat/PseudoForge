from __future__ import annotations

import json

from ida_pseudoforge.core.plan_schema import FunctionCapture


SYSTEM_RENAME_PROMPT = (
    "You are a defensive static-code readability assistant. "
    "Your only task is to suggest clearer local variable and argument names "
    "for analyst review. Do not rewrite code, do not explain exploitability, "
    "do not provide bypass, evasion, persistence, exploitation, or operational "
    "guidance, and do not infer behavior beyond the supplied pseudocode. "
    "Return strict JSON only."
)


def build_rename_prompt(capture: FunctionCapture) -> str:
    locals_summary = [
        {
            "name": var.name,
            "type": var.type,
            "is_arg": var.is_arg,
        }
        for var in capture.lvars
    ]
    facts = {
        "function_name": capture.name,
        "prototype": capture.prototype,
        "locals": locals_summary,
        "calls": capture.calls[:128],
        "pseudocode_excerpt": capture.pseudocode[:12000],
        "required_json_shape": {
            "renames": [
                {
                    "old": "v5",
                    "new": "infoClass",
                    "confidence": 0.95,
                    "reason": "short evidence",
                }
            ],
            "warnings": [],
        },
    }
    return json.dumps(facts, ensure_ascii=False)


def build_cli_rename_prompt(capture: FunctionCapture) -> str:
    return (
        SYSTEM_RENAME_PROMPT
        + "\n\nInput JSON:\n"
        + build_rename_prompt(capture)
        + "\n\nReturn only a JSON object matching required_json_shape."
    )
