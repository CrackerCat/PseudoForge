# Renderer Snapshots

These files are golden outputs for `render_cleaned_pseudocode()`. They protect
renderer refactors from silent output drift across representative kernel and
generic decompiler cases.

Update snapshots only when the rendered output change is intentional:

```powershell
$env:PSEUDOFORGE_UPDATE_SNAPSHOTS = '1'
python -B -m unittest tests.test_render_snapshots -v
Remove-Item Env:PSEUDOFORGE_UPDATE_SNAPSHOTS
git diff -- tests/snapshots tests/test_render_snapshots.py
```
