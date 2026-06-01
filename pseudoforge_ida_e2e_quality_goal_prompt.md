# PseudoForge IDA End-to-End Quality Goal Prompt

You are Codex working in `F:\kernullist\PseudoForge`.

Your goal is to repeatedly evaluate and improve PseudoForge pseudocode quality against a no-PDB IDA workflow until you judge the output quality is sufficiently high for practical reverse-engineering use.

## Critical Constraints

1. Do not hardcode for a single sample function, address, pool tag, symbol name, test-driver path, or observed output string.
2. Every improvement must be expressed as a generic rule, reusable heuristic, profile-backed semantic rule, structural parser improvement, or renderer cleanup that can apply to the same decompiler pattern across unrelated binaries.
3. If a narrow exception is unavoidable, isolate it, document why it is not sample-specific, and add regression tests proving it is gated by structural evidence rather than names or addresses.
4. Preserve preview/export safety. PseudoForge must not modify the IDB unless the existing workflow explicitly supports an apply operation and the task requires it. Prefer preview-only analysis.
5. Keep comments, generated code comments, and log output ASCII-only.
6. Do not remove user changes. Work with the current git tree.
7. Use git commits only when explicitly requested. If committing, use `kernullist <gloryo@naver.com>`.

## IDA Environment

Use this IDA executable:

```text
C:\Program Files\IDA Professional 9.0\ida.exe
```

Load the test driver without PDB symbols. If there are existing repo scripts for IDA batch export, decompilation, PseudoForge analysis, or comparison reports, use those first. If scripts are missing or insufficient, add generic automation that can:

1. Open the test driver in IDA with PDB loading disabled or with symbol paths unavailable.
2. Enumerate functions.
3. Decompile each function one by one.
4. Capture raw Hex-Rays pseudocode.
5. Run PseudoForge cleanup/rendering.
6. Save per-function raw, cleaned, diff, metadata, warnings, and quality notes.
7. Produce an aggregate quality report.

Do not assume the exact test-driver filename if it can be discovered from repo fixtures, docs, generated outputs, or user-provided artifacts. If more than one plausible driver exists, choose the most relevant PseudoForge test driver and record the selection rationale in the report.

## End-to-End Loop

Run this loop until the output quality is good enough by your engineering judgment, or until you are blocked by missing external input.

### Phase 1: Discover Current Workflow

1. Read the relevant README, implementation status, improvement plan, test files, IDA plugin/action code, batch tooling, and existing generated artifact conventions.
2. Identify the current supported way to run PseudoForge over IDA-decompiled functions.
3. Identify where no-PDB assumptions are already handled.
4. Find any existing test-driver fixture, batch sample, generated comparison report, or documented command.
5. Record the chosen workflow and exact commands in your working notes.

### Phase 2: Baseline No-PDB IDA Run

1. Launch IDA using the configured path.
2. Load the test driver without PDB symbols.
3. Let IDA auto-analysis complete.
4. Enumerate all decompilable functions.
5. For each function:
   - Capture function name, EA, prototype, raw pseudocode, local variables, and calls when available.
   - Run PseudoForge analysis and rendering.
   - Save the raw and cleaned pseudocode.
   - Save warnings, rename candidates, semantic comments, flow rewrites, and renderer metadata.
6. If a function fails to decompile, record the failure and continue.
7. Produce a baseline report with:
   - Total functions.
   - Decompile success/failure counts.
   - PseudoForge success/failure counts.
   - Warning distribution.
   - Rename quality issues.
   - Structural cleanup issues.
   - Kernel semantic recovery misses.
   - Obvious false-positive rewrites.
   - Top priority improvement candidates.

### Phase 3: Quality Analysis

Analyze every cleaned function, not only the first interesting one.

For each function, score practical output quality across these dimensions:

1. Readability:
   - Are compiler temporaries, scratch aliases, and single-use decompiler artifacts reduced?
   - Are names helpful without inventing unsupported semantics?
   - Are declarations concise and still type-safe enough for review?

2. Semantic preservation:
   - Are calls preserved when return values are unused?
   - Are side effects retained?
   - Are branches, loops, cleanup tails, and switch cases structurally equivalent?
   - Are preview-only rewrites clearly safe?

3. Kernel-domain recovery:
   - Are IRP, IOCTL, DriverEntry, Zw/Nt, registry callback, memory manager, pool, list, callback, and status patterns recovered when evidence is present?
   - Are status constants and NT_SUCCESS/NT_ERROR style checks used only with strong context?
   - Are union-arm rewrites, structure fields, and pointer casts gated by sufficient evidence?

4. No-PDB robustness:
   - Does the cleanup rely on symbols that are absent in the no-PDB load?
   - Can it infer roles from call names, prototypes, WDK profiles, field offsets, control-flow shape, or repeated usage patterns?
   - Does it degrade conservatively when evidence is weak?

5. Warning quality:
   - Are actionable warnings still shown?
   - Are known LLM or decompiler noise warnings suppressed only when deterministic evidence has already handled them?
   - Are warnings phrased in a way that helps reverse engineering?

6. Genericity:
   - Would the same rule help a different function or driver with the same structural pattern?
   - Is the rule independent of concrete addresses, sample-specific names, exact function EAs, pool tags, or one-off strings?

### Phase 4: Select Improvements

Prioritize issues by practical impact:

P0:
1. Incorrect rewrites.
2. Lost side effects.
3. Broken syntax.
4. Crashes in batch/IDA/PseudoForge.
5. Severe false positives.

P1:
1. Major readability problems repeated across several functions.
2. Missed generic kernel semantics.
3. Repeated noisy scratch variables or aliases.
4. Warnings that hide useful output or overwhelm the preview.

P2:
1. Cosmetic but recurring cleanup opportunities.
2. Documentation gaps.
3. Test coverage gaps.

Only implement changes that are justified by structural evidence from the end-to-end run.

### Phase 5: Implement Generic Fixes

For each selected improvement:

1. Identify the smallest reusable abstraction or rule location.
2. Prefer existing architecture:
   - deterministic rules,
   - kernel semantic helpers,
   - renderer cleanup helpers,
   - profile-backed API metadata,
   - validation filters,
   - flow recovery,
   - warning display filters.
3. Avoid broad refactors unless necessary.
4. Add focused tests before or with the fix.
5. Tests must include:
   - positive case,
   - negative guard case,
   - collision or liveness safety case when relevant,
   - no-PDB style input when relevant.
6. Do not use one sample address, function name, exact test-driver-only variable, or pool tag as the rule gate.
7. If the improvement changes expected output, update snapshots or docs only after verifying the new output is better and safe.

### Phase 6: Review Mode After Each Development Cycle

After each implementation cycle, switch into review mode before continuing.

In review mode:

1. Re-read the changed code paths.
2. Inspect the diff for:
   - hidden hardcoding,
   - overbroad regexes,
   - lost side effects,
   - incorrect liveness assumptions,
   - broken syntax generation,
   - field/member rename corruption,
   - stale header metadata,
   - warning suppression that hides actionable findings,
   - tests that only assert the current sample output.
3. Run targeted tests for the touched area.
4. Run the full test suite.
5. Re-run the relevant IDA/PseudoForge end-to-end subset.
6. If review finds a bug, fix it immediately and repeat review mode.
7. Continue only when the implementation survives review mode.

### Phase 7: Re-run End-to-End Quality Evaluation

After fixes pass tests:

1. Re-run the no-PDB IDA workflow over all functions.
2. Compare the new artifacts against the previous baseline.
3. Measure whether:
   - output is more readable,
   - syntax remains valid,
   - side effects are preserved,
   - warnings are more useful,
   - false positives did not increase,
   - generic rules helped more than one pattern where applicable.
4. Update the aggregate report with before/after notes.
5. Decide whether another improvement cycle is needed.

Repeat Phases 3 through 7 until either:

1. The cleaned output is consistently practical for reverse-engineering the no-PDB driver, or
2. Remaining issues require new domain knowledge, another binary, unavailable IDA data, or user input.

## Quality Bar

Do not stop just because tests pass. Stop only when the end-to-end no-PDB driver output is good enough by this bar:

1. No known incorrect rewrite remains in reviewed output.
2. No obvious side-effecting call is removed.
3. No widespread compiler temp or alias noise remains when it can be safely removed generically.
4. Kernel API semantics are recovered where there is clear evidence.
5. Warning detail is concise and actionable.
6. The rules added are generic and regression-tested.
7. The improvement plan and implementation status docs reflect completed work.
8. The full test suite passes.
9. The end-to-end report explains remaining limitations honestly.

## Required Artifacts

Create or update artifacts under repo-appropriate paths. Prefer existing conventions if present.

Required outputs:

1. Baseline report for the first no-PDB run.
2. Per-cycle quality report or changelog.
3. Final end-to-end quality report.
4. Updated `pseudoforge_improvement_plan.md` marking completed items.
5. Updated `pseudoforge_implementation_status.md` if behavior changed.
6. Updated README when user-facing workflow or capabilities changed.
7. Regression tests for every generic cleanup or semantic improvement.

The final report must include:

1. IDA executable path used.
2. Test driver path and no-PDB loading method.
3. Total function count and decompile success count.
4. List of implemented generic improvements.
5. Examples of before/after output for representative functions.
6. Remaining known limitations.
7. Validation commands and results.
8. A hardcoding audit explaining why new rules are generic.

## Validation Commands

At minimum, run:

```powershell
python -B -m unittest discover -s tests -v
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools
git diff --check -- .
```

Also run the IDA end-to-end workflow commands discovered or added during the task.

If a command cannot run, record:

1. Exact command.
2. Exact failure.
3. Whether it blocks the goal.
4. What was validated instead.

## Final Response Requirements

When done, answer with:

1. Concise summary of what was improved.
2. Confirmation that no hardcoded sample-specific rules were added, or a clear explanation of any constrained exception.
3. End-to-end IDA/no-PDB result summary.
4. Test and validation results.
5. Paths to reports and updated docs.
6. Whether the working tree is clean.

Do not claim the goal is complete unless the end-to-end no-PDB run and review-mode cycle have actually been completed.
