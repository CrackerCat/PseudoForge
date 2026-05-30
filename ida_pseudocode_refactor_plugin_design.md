# IDA Pseudocode Refactor Plugin Design

## Purpose

This document defines the design for PseudoForge, an IDA Pro / Hex-Rays plugin that makes decompiled pseudocode easier to review without weakening IDB safety boundaries.

The goal is not a simple LLM auto-rename tool. The plugin must support:

1. Semantic renaming for Hex-Rays parameters and local variables.
2. Readable cleanup for IDA artifacts such as `if / else` ladders, subtraction-based dispatch, and `goto LABEL_x` cleanup paths.
3. A strict split between changes that may be safely written to the IDB and changes that must remain preview/export artifacts.
4. Cleaned pseudocode that can still be compared against the original, especially for large kernel functions with deep branches and private helpers.

## Reference Project

The primary reference is JusticeRage/Gepetto:

- Repository: `https://github.com/JusticeRage/Gepetto`
- Checked revision: `795a5493efbd558196d7000e929b829c3b0427e7`

Useful Gepetto structures:

1. Plugin entrypoint
   - `PLUGIN_ENTRY()` loads configuration and returns a plugin class.
2. Action registration
   - IDA actions, menus, hotkeys, and context-menu hooks are registered cleanly.
   - Pseudocode-view context menu integration is a good fit for PseudoForge.
3. Rename workflow
   - Current-function decompile output is sent to a model.
   - Rename JSON is previewed in a chooser before selected items are applied.
4. Comment workflow
   - Pseudocode line metadata is collected and comments are applied with `cfunc.set_user_cmt()`.
5. Main-thread wrappers
   - IDA read/write execution boundaries are separated.
6. Provider abstraction
   - OpenAI, Gemini, Claude, Ollama, LM Studio, and similar providers can be plugged in independently.
7. Tool-calling concept
   - A model can request decompile, rename, comment, xref, and byte-read tasks.

## Key Differences From Gepetto

Gepetto focuses mainly on explanation, comments, and renames. PseudoForge focuses on pseudocode structure cleanup, so it needs different boundaries.

1. LLM output is not applied directly.
   - An LLM can suggest rename candidates and block summaries.
   - Deterministic rules and validators perform the actual transformation decisions.
2. IDB-safe work is separated from read-only artifacts.
   - IDB-safe:
     - Local variable rename.
     - Argument rename.
     - Optional user comments when the exact anchor is known.
   - Read-only artifacts:
     - Pseudocode reconstructed from an `if / else` ladder into a switch-like outline.
     - Cleanup-label normalization.
     - Full-function pretty render.
3. String-only rename is avoided.
   - Prefer Hex-Rays lvar identity when possible.
   - Old-name strings are used for preview and reports only.
4. Large functions are a first-class target.
   - Partial recovery must be valid output.
   - Warnings must explain uncertain regions.
   - Original line anchors should be retained where possible.
5. Kernel reversing profiles are supported.
   - NTSTATUS, pool tags, LIST_ENTRY, ERESOURCE, callbacks, WDK prototypes, and native API classes should be interpreted by deterministic metadata first.

## Product Naming

The working product name is `PseudoForge`.

IDA action names should use the `pseudoforge:*` prefix to avoid collisions.

## Directory Structure

```text
pseudoforge.py
ida-plugin.json
ida_pseudoforge/
  ida/
    plugin.py
    actions.py
    decompiler.py
    apply_changes.py
    ui_preview.py
    async_runner.py
    thread_helpers.py
  core/
    capture.py
    plan_schema.py
    lvar_analysis.py
    validation.py
    flow_recovery.py
    cleanup_rewriter.py
    kernel_semantics.py
    kernel_api.py
    kernel_rewrites.py
    deterministic/
      schema.py
      context.py
      loader.py
      engine.py
      validators.py
      emitters.py
      matchers/
        regex.py
    render.py
    forge_store.py
    llm_assist.py
  profiles/
    kernel_api.json
    kernel_api_overrides.json
    status_codes.json
    process_information_class.json
    system_information_class.json
  rules/
    builtin/
      local_renames.json
      kernel_comments.json
  models/
    base.py
    provider_registry.py
    provider_factory.py
    openai_compatible.py
    cli_provider.py
    prompting.py
  config.py
  logging.py
tools/
  pseudoforge_cli.py
  pseudoforge_ida_batch.py
  validate_pseudoforge_rules.py
tests/
  test_core_engine.py
```

## End-to-End Flow

1. Capture
   - Get the current cursor EA.
   - Call `ida_hexrays.decompile()` to obtain `cfunc`.
   - Capture pseudocode text, function prototype, lvars, lvar types, comments, function name, and call names.
   - Preserve line anchors and ctree item locations when available.
2. Normalize
   - Strip IDA color tags.
   - Build a raw identifier list.
   - Lock strong parameter rename candidates from prototypes.
   - Resolve numeric constants through enum and kernel profiles.
3. Analyze
   - Detect dispatcher variables.
   - Recover case arithmetic such as `v115 = v5 - 235; if (!v115)`.
   - Infer variable roles from API semantics.
   - Classify cleanup labels and common return tails.
   - Run deterministic JSON rules for supported v1 phases.
4. Optional LLM assist
   - Do not give the model permission to rewrite the whole function.
   - Provide facts, use-def summaries, call lists, and profile hints.
   - Require strict JSON output.
5. Validate
   - Verify that rename targets exist.
   - Enforce C identifier validity.
   - Reject duplicate names and reserved keywords.
   - Apply confidence thresholds.
   - Compare recovered flow shape against original evidence.
6. Preview
   - Show renames, comments, flow outline, rule report, and export output.
   - Apply only user-selected IDB-safe changes.
7. Apply or export
   - Apply selected renames with `ida_hexrays.rename_lvar()` or an IDA name API when appropriate.
   - Apply comments only when exact anchors are known and the user opted in.
   - Export cleaned pseudocode, rename map, flow report, switch outline, and rule report.

## IDA Actions

Actions:

```text
pseudoforge:analyze-current
pseudoforge:preview-cleaned
pseudoforge:preview-analyzed-current
pseudoforge:export-cleaned
pseudoforge:configure-llm
pseudoforge:show-settings
pseudoforge:apply-selected-renames
```

Main menu:

```text
Edit/PseudoForge/
  Analyze current function
  Preview cleaned pseudocode
  Preview analyzed current function
  Export cleaned pseudocode
  Configure LLM rename assist
  Show settings
  Advanced/
    Apply selected renames to IDB
```

Pseudocode context menu:

```text
PseudoForge/
  Analyze current function
  Preview cleaned pseudocode
  Preview analyzed current function
  Export cleaned pseudocode
  Configure LLM rename assist
  Show settings
  Advanced/
    Apply selected renames to IDB
```

Default hotkeys:

```text
Ctrl+Alt+F        Analyze current function
Ctrl+Alt+P        Preview cleaned pseudocode
Ctrl+Alt+Shift+P  Preview analyzed current function
Ctrl+Alt+Shift+F  Export cleaned pseudocode
```

## CleanPlan Schema

The core engine emits a `CleanPlan` rather than directly changing the IDB.

```python
@dataclass
class RenameSuggestion:
    old_name: str
    new_name: str
    kind: str
    confidence: float
    reason: str
    source: str
    apply: bool = False

@dataclass
class FlowRewrite:
    kind: str
    confidence: float
    original_anchor: str
    rendered_text: str
    warnings: list[str]

@dataclass
class CleanComment:
    anchor: str
    text: str
    kind: str
    confidence: float

@dataclass
class CleanPlan:
    function_ea: int
    function_name: str
    renames: list[RenameSuggestion]
    comments: list[CleanComment]
    flow_rewrites: list[FlowRewrite]
    warnings: list[str]
    metadata: dict[str, Any]
```

Design rules:

1. The plan is serializable to JSON.
2. Every item records its source and confidence.
3. IDB-writeable items must be individually selectable.
4. Export-only items must never be applied to the IDB.
5. Rule reports should be additive metadata, not a replacement for validation.

## Capture Model

The capture layer should avoid losing Hex-Rays identity information.

Required fields:

- Function EA and name.
- Prototype text.
- Raw pseudocode lines.
- Normalized pseudocode text.
- Lvar list.
- Parameter list.
- Lvar type strings.
- Call target names.
- Current user comments.
- Optional ctree location anchors.

The offline CLI uses text-only capture and should produce compatible `FunctionCapture` objects with fewer identity fields.

## Rename Strategy

Priority order:

1. Explicit function prototypes and known native API signatures.
2. Deterministic kernel semantics.
3. Deterministic JSON rules.
4. API argument and use-def evidence.
5. Optional LLM suggestions.
6. Existing names when uncertainty is high.

Validation rejects:

- Missing targets.
- Reserved C/C++ keywords.
- Invalid C identifiers.
- Duplicate names in the function scope.
- Weak large-dispatcher names for numeric temporaries.
- PascalCase names from LLM sources when they look like authoritative type or field names.
- Names that only restate raw decompiler argument positions such as `argument0`.

## Flow Recovery Strategy

### Dispatcher Detection

Candidate patterns:

```c
v115 = infoClass - 235;
if (!v115)
{
    ...
}
else if (v115 == 1)
{
    ...
}
```

```c
if (infoClass == SystemBasicInformation)
{
    ...
}
else if (infoClass == SystemProcessorInformation)
{
    ...
}
```

The recovery should record:

- Dispatcher variable.
- Base expression.
- Case value.
- Original comparison text.
- Branch anchor.
- Confidence.
- Warnings.

### Path Constraint

The engine should not synthesize a switch body unless the recovered body is conservative. Safe output examples:

- Single `return STATUS_...;`.
- Simple direct assignment plus return.
- Case label with a pointer back to the original pseudocode for complex body review.

Unsafe output examples:

- Shared branch body with multiple predecessors.
- Fallthrough that cannot be represented accurately.
- Deep nested side effects with incomplete anchor evidence.

### Output Policy

The normalized original pseudocode remains the primary review surface. Recovered switch output is an auxiliary outline.

## Goto Cleanup

IDA often emits labels such as:

```c
LABEL_63:
  ExReleaseResourceLite(Resource);
  KeLeaveCriticalRegion();
  return status;
```

PseudoForge should classify labels into roles:

- `Cleanup`
- `InvalidParameter`
- `CorruptListEntry`
- `Failure`
- `ReturnStatus`

Rules:

1. Preserve labels when removing them would obscure control flow.
2. Rename semantic labels for readability.
3. Add stable suffixes for duplicate label roles.
4. Keep labels at column zero in generated pseudocode.
5. Do not force a `do { } while (false)` single-exit rewrite unless the structure is already present and safe.

## UI Design

The first production UI is intentionally simple:

1. Analyze action
   - Runs capture and planning.
   - Writes or updates `.forge`.
   - Shows a completion popup and opens the cached preview.
2. Preview action
   - Opens existing `.forge` content only.
   - Does not decompile, call an LLM, or analyze.
3. Current-function preview
   - Opens only the cached section matching the current function EA.
4. Export action
   - Writes an export bundle.
5. Rename apply action
   - Uses a chooser.
   - Applies only selected validated renames.
6. Settings action
   - Shows current config paths and masked credential status.

Longer-term UI:

- Dockable side-by-side raw/cleaned preview.
- Inline rule report pane.
- Rename conflict inspector.
- Batch analysis progress view.

## Model Provider Design

LLM assist is optional and must be replaceable.

Provider interface:

```python
class RenameAssistProvider(Protocol):
    def suggest_renames(self, capture: FunctionCapture) -> str:
        ...
```

Supported providers:

- OpenAI-compatible HTTP.
- OpenRouter.
- DeepSeek API.
- Codex CLI.
- ChatGPT OAuth via Codex CLI.
- Claude login via Claude CLI.
- Claude CLI.

Provider rules:

1. LLM providers return suggestions only.
2. Responses must parse as strict JSON.
3. Provider failures become warnings and deterministic fallback.
4. API keys are never logged.
5. Model discovery failures use static fallback lists.
6. CLI providers must be configured explicitly and receive prompts through stdin and/or temporary files.

## Prompt Principles

Prompts should:

1. Ask for rename candidates and evidence, not full rewritten code.
2. Include function prototype, local declarations, call names, and deterministic hints.
3. Include known kernel semantics when available.
4. Require strict JSON.
5. Require confidence values.
6. Forbid invented APIs, invented types, and direct control-flow rewrites.

Prompt output shape:

```json
{
  "renames": [
    {
      "old_name": "v12",
      "new_name": "status",
      "kind": "lvar",
      "confidence": 0.88,
      "reason": "Local receives NTSTATUS return values"
    }
  ],
  "comments": [],
  "warnings": []
}
```

## Safety Policy

1. Preview/export is the primary output.
2. IDB writes are opt-in and limited to validated renames unless a future feature explicitly adds another gated write path.
3. LLM output is never applied directly.
4. Control-flow rewrites are preview/export-only.
5. Text rewrites must never modify the IDB.
6. Rule files are data-only JSON.
7. User Python from rule files is not executed.
8. Rule loading failures are non-fatal and reported.
9. Logs and comments stay ASCII-only.
10. Secrets and API keys are never written to reports.

## MVP Scope

MVP implemented scope:

- IDA action registration and core plugin entrypoint.
- Current-function capture.
- Local and parameter rename suggestions.
- Rename validation.
- Kernel semantics for common driver patterns.
- NTSTATUS and selected enum profile lookup.
- Dispatcher outline recovery.
- Cleanup label classification.
- `.forge` aggregate preview storage.
- Offline CLI.
- Headless IDA batch path.
- Optional LLM rename assist.
- Deterministic rules matching engine v1 for JSON rename and semantic comment rules.
- Rule validator CLI and per-function rule reports.

## Phase 2

Planned phase 2 work:

1. Migrate more deterministic hard-coded paths into JSON rules after parity tests.
2. Add `call_arg_rewrite` rule support.
3. Add preview-only `text_rewrite` rule support with strong gating.
4. Improve ctree identity tracking.
5. Improve side-by-side review UX.

## Phase 3

Planned phase 3 work:

1. Rich function-scope dataflow facts.
2. Profile version management by target OS build.
3. Rule authoring diagnostics inside IDA.
4. Wider kernel API semantic overlays.
5. Snapshot tests for real target families.

## Test Strategy

Required tests:

1. Core engine unit tests for capture, rename, validation, flow recovery, rendering, and deterministic rules.
2. Regression samples for known kernel pseudocode fragments.
3. CLI smoke tests for offline export.
4. JSON validation tests for profiles and rule packs.
5. Compile checks for plugin and tool modules.
6. Manual IDA GUI validation for action registration, preview, export, and rename apply.

Representative commands:

```powershell
python -B -m unittest discover -s tests -v
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools
python -B .\tools\validate_pseudoforge_rules.py .\ida_pseudoforge\rules\builtin
python -B .\tools\pseudoforge_cli.py .\samples\pseudocode\NtSetSystemInformation_switch_renamed.cpp --out $env:TEMP\pseudoforge_cli_smoke
git diff --check -- .
```

## Recommended Implementation Order

1. Keep existing deterministic hard-coded paths active.
2. Add rule reporting and mirror rules first.
3. Prove output parity with regression tests.
4. Migrate only low-risk deterministic rules.
5. Add rule authoring documentation and validation tooling.
6. Expand to higher-risk rewrite phases only after preview/export validation is stable.

## Conclusion

PseudoForge should behave like a conservative compiler pass for reverse-engineering review artifacts. Deterministic analysis owns the final plan, optional LLM assist supplies suggestions only, and every IDB write remains explicit, narrow, and validator-gated.
