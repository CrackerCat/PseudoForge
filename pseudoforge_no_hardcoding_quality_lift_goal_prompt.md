# PseudoForge No-Hardcoding Quality Lift Goal Prompt

You are Codex working in `F:\kernullist\PseudoForge`.

Your goal is to raise PseudoForge's no-PDB IDA pseudocode quality beyond the
current cycle4 baseline without adding sample-specific hardcoding. Treat the
existing no-PDB 46-function kernel-pattern-driver run as the baseline, then
iterate until the cleaned output is substantially more useful for practical
reverse engineering while preserving semantic safety.

## Current Baseline

Use the latest validated baseline as the starting point:

```text
IDA: C:\Program Files\IDA Professional 9.0\ida.exe
Driver: samples\kernel_pattern_driver\x64\Release\PfKernelPattern.sys
No-PDB final baseline: pseudoforge_out\ida_e2e_quality\cycle4_20260601_200922
Functions: 46 processed, 46 succeeded, 0 failed, 0 skipped, 0 warnings
Tests: 345 passed, 5 subtests passed
```

Read `pseudoforge_ida_e2e_quality_report.md`,
`pseudoforge_improvement_plan.md`, and `pseudoforge_implementation_status.md`
before making changes.

## Non-Negotiable Constraints

1. Do not hardcode for a single function, address, pool tag, exact variable
   name, binary path, test-driver behavior, or observed output string.
2. Do not make output prettier by inventing unsupported semantics.
3. Every improvement must be based on reusable evidence:
   - WDK/profile metadata,
   - parsed structure or alias metadata,
   - dataflow/use-def facts,
   - call argument roles,
   - ownership or lifecycle pairs,
   - control-flow shape,
   - repeated layout evidence,
   - architecture-neutral decompiler artifact patterns.
4. If a field, type, or union member is not present in trusted profile data,
   leave it raw unless there is a generic profile-builder improvement that
   recovers it.
5. Preserve preview/export safety. Do not modify the IDB.
6. Keep generated comments and logs ASCII-only.
7. Add negative tests with every new cleanup rule.
8. After every development cycle, enter review mode, find bugs, fix them, and
   rerun validation before continuing.
9. Mark completed items in `pseudoforge_improvement_plan.md`.
10. Update `pseudoforge_implementation_status.md` and the quality report when
    behavior or validation evidence changes.

## Target Outcome

Raise output quality from "deterministic cleanup suitable for review" toward
"high-confidence source-like analysis aid" for recognized patterns, while
remaining conservative on weak evidence.

Expected improvements should come from these tracks:

1. Quality Scoring
   - Add or improve an automated per-function quality scorer.
   - Penalize raw Hex-Rays artifacts such as `a1`, `v12`, raw pointer offset
     loads, `LOBYTE`, `qword_`, untyped `__int64`, unresolved status literals,
     scratch sink globals, and helper thunks.
   - Reward trusted semantic recovery such as typed kernel callbacks,
     `NTSTATUS`, `PIRP`, `OBJECT_ATTRIBUTES`, symbolic enums, `NT_SUCCESS`,
     `CONTAINING_RECORD`, profile-backed field access, and safe artifact
     reductions.
   - Produce a report that ranks the worst remaining functions and explains
     why.

2. Profile and Layout Recovery
   - Improve profile parsing or profile consumption before adding renderer
     rewrites.
   - Support generic recovery for unions, anonymous structs/unions, bitfields,
     arrays, pointer aliases, SAL-derived roles, and architecture-sized fields
     when possible.
   - Rewrite fields only when they are present in trusted profile data.
   - If a desired field is missing, improve the profile builder generically
     instead of hardcoding it in the renderer.

3. Dataflow and Evidence Facts
   - Extend assignment, use-def, call-argument, out-parameter, return-value,
     and liveness facts.
   - Use these facts for local naming, alias collapse, scalar out-param cleanup,
     unused-return preservation, and field/union-arm selection.
   - Prefer dataflow evidence over variable names.

4. Generic Decompiler Artifact Reduction
   - Safely reduce repeated Hex-Rays artifacts:
     - single-assignment pointer aliases,
     - scalar out-parameter arrays,
     - unrolled copy/set patterns,
     - compiler helper wrappers,
     - scratch result sinks,
     - redundant casts,
     - low-byte writes when the full scalar is proven safe.
   - Preserve side effects and avoid deleting calls unless the replacement
     keeps the call visible, such as `(void)Call(...)`.

5. Kernel Semantic Expansion
   - Improve recognized no-PDB kernel patterns only through generic evidence:
     DriverEntry, IRP dispatch, IOCTL, OB callbacks, registry callbacks,
     memory-manager probes, Zw/Nt API probes, pool/list patterns, callback
     registration, object references, and status handling.
   - Add API contract metadata where useful:
     return kind, parameter role, out-buffer role, enum/flags role,
     allocation/free pairs, register/unregister pairs, ref/deref pairs, and
     handle close requirements.

## Iteration Loop

Repeat this loop until you judge the remaining quality gap requires new domain
knowledge, a broader corpus, or user input.

### 1. Measure

Run the current no-PDB IDA batch workflow against the test driver. Generate raw,
cleaned, diff, metadata, warning, and quality-score artifacts for all functions.

Use:

```powershell
.\tools\run_pseudoforge_ida_batch.ps1 -IdaPath 'C:\Program Files\IDA Professional 9.0\ida.exe' -IdbPath <fresh-no-pdb-input-sys> -TargetPath <fresh-no-pdb-input-sys> -OutputDir <new-output-dir> -ForgePath <new-output-dir>\PfKernelPattern.forge -CompareDir <new-output-dir>\compare -ReportPath <new-output-dir>\ida_batch.jsonl -IdaLogPath <new-output-dir>\ida.log -NoPdb -SkipLibThunk
```

Use a fresh copied `.sys` input directory so PDB state and prior IDB state do
not contaminate the run.

### 2. Rank

Rank functions by practical cleanup opportunity:

1. Incorrect or risky rewrites.
2. Side-effect preservation risks.
3. High raw-artifact density.
4. Repeated missed kernel semantics.
5. Missing profile/layout data.
6. Noisy or unhelpful warnings.

Do not choose a fix just because it improves one function. Choose fixes that
address a reusable pattern.

### 3. Implement

For each cycle, pick a small number of high-impact generic improvements.

Implementation rules:

1. Reuse existing architecture before adding new abstractions.
2. Keep renderer changes narrow and evidence-gated.
3. Prefer profile/dataflow improvements over regex-only cleanup.
4. Add positive and negative tests.
5. Add syntax/liveness/side-effect tests when the rewrite can alter code shape.
6. Update snapshots only when the output improvement is intentional and safe.

### 4. Review Mode

After implementation, switch to review mode before declaring progress.

Review checklist:

1. Search the diff for hidden hardcoding.
2. Check whether any regex is overbroad.
3. Verify field rewrites are profile-backed or structurally proven.
4. Verify no side-effecting call was removed.
5. Verify alias collapse does not change liveness.
6. Verify warning suppression does not hide actionable issues.
7. Verify tests are not only matching one current sample output.
8. Add a negative regression for any discovered false-positive path.
9. Fix review findings immediately.

### 5. Validate

Run at minimum:

```powershell
python -B -m unittest discover -s tests -v
python -m pytest -q
python -B -m compileall .\pseudoforge.py .\ida_pseudoforge .\tests .\tools
git diff --check -- .
```

Then rerun the no-PDB IDA batch workflow over all 46 functions.

### 6. Document

Update:

1. `pseudoforge_improvement_plan.md`
   - mark completed items with `[x]`;
   - add new follow-up items for remaining quality gaps.
2. `pseudoforge_implementation_status.md`
   - record behavior changes and validation counts.
3. the current quality report
   - include baseline, cycle output path, quality-score deltas, representative
     before/after snippets, hardcoding audit, validation commands, and remaining
     limitations.

## Quality Bar For Completion

Do not stop just because tests pass. Stop only when all are true:

1. No known incorrect rewrite remains in reviewed output.
2. No known side-effecting call is lost.
3. The worst remaining functions are explicitly ranked and explained.
4. New improvements are generic, profile-backed, dataflow-backed, or otherwise
   structurally evidenced.
5. Negative tests cover false-positive risks.
6. Full tests pass.
7. No-PDB IDA batch passes across all 46 functions.
8. The hardcoding audit is updated.
9. Completed items are marked in `pseudoforge_improvement_plan.md`.
10. Remaining limitations are honest and actionable.

## Final Response Requirements

When finished, report:

1. What quality metric or scorer was added or improved.
2. Which generic rules or profile/dataflow improvements were implemented.
3. Why the changes are not sample-specific hardcoding.
4. The no-PDB IDA batch result.
5. Full test results.
6. Paths to updated reports and artifacts.
7. Remaining quality gaps ranked by next impact.
8. Current git status.
