import subprocess
import unittest
from unittest.mock import patch

from ida_pseudoforge.core.capture import capture_from_pseudocode
from ida_pseudoforge.models.cli_provider import CliRenameProvider
from ida_pseudoforge.models.model_discovery import discover_provider_models
from ida_pseudoforge.models import subprocess_utils
from ida_pseudoforge.models.subprocess_utils import hidden_subprocess_kwargs
from ida_pseudoforge.models.provider_registry import (
    PROVIDER_CLAUDE_CLI,
    PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI,
    PROVIDER_CODEX_CLI,
)


SAMPLE = r"""
__int64 __fastcall sample(__int64 a1)
{
  return a1;
}
"""


class LlmCliProviderTests(unittest.TestCase):
    def test_hidden_subprocess_kwargs_request_hidden_windows_console(self):
        class FakeStartupInfo:
            def __init__(self):
                self.dwFlags = 0
                self.wShowWindow = -1

        with (
            patch("ida_pseudoforge.models.subprocess_utils.os.name", "nt"),
            patch.object(subprocess_utils.subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True),
            patch.object(subprocess_utils.subprocess, "STARTUPINFO", FakeStartupInfo, create=True),
            patch.object(subprocess_utils.subprocess, "STARTF_USESHOWWINDOW", 1, create=True),
            patch.object(subprocess_utils.subprocess, "SW_HIDE", 0, create=True),
        ):
            kwargs = hidden_subprocess_kwargs()

        self.assertEqual(kwargs["creationflags"], 0x08000000)
        self.assertEqual(kwargs["startupinfo"].dwFlags, 1)
        self.assertEqual(kwargs["startupinfo"].wShowWindow, 0)

    def test_cli_provider_runs_argv_without_shell_by_default(self):
        capture = capture_from_pseudocode(SAMPLE)
        provider = CliRenameProvider(
            command_template="fakecli --model {model} --output {output_file} -",
            model="test model",
        )
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='{"renames": []}',
            stderr="",
        )

        with patch("ida_pseudoforge.models.cli_provider.subprocess.run", return_value=completed) as run:
            self.assertEqual(provider.suggest_renames(capture), '{"renames": []}')

        command = run.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertEqual(command[:3], ["fakecli", "--model", "test model"])
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_cli_provider_hides_windows_console_windows(self):
        capture = capture_from_pseudocode(SAMPLE)
        provider = CliRenameProvider(command_template="fakecli -")
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='{"renames": []}',
            stderr="",
        )

        with patch("ida_pseudoforge.models.cli_provider.subprocess.run", return_value=completed) as run:
            provider.suggest_renames(capture)

        hidden_kwargs = hidden_subprocess_kwargs()
        if "creationflags" in hidden_kwargs:
            self.assertEqual(run.call_args.kwargs["creationflags"], hidden_kwargs["creationflags"])
        if "startupinfo" in hidden_kwargs:
            self.assertIn("startupinfo", run.call_args.kwargs)

    def test_cli_provider_keeps_raw_shell_mode_explicit(self):
        capture = capture_from_pseudocode(SAMPLE)
        provider = CliRenameProvider(command_template="shell:fakecli --output {output_file} -")
        completed = subprocess.CompletedProcess(
            args="",
            returncode=0,
            stdout='{"renames": []}',
            stderr="",
        )

        with patch("ida_pseudoforge.models.cli_provider.subprocess.run", return_value=completed) as run:
            self.assertEqual(provider.suggest_renames(capture), '{"renames": []}')

        self.assertIsInstance(run.call_args.args[0], str)
        self.assertTrue(run.call_args.kwargs["shell"])

    def test_codex_model_discovery_runs_without_shell(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='{"models": [{"slug": "gpt-test"}]}',
            stderr="",
        )

        with patch("ida_pseudoforge.models.model_discovery.subprocess.run", return_value=completed) as run:
            result = discover_provider_models(PROVIDER_CODEX_CLI)

        self.assertEqual(result.models, ["gpt-test"])
        self.assertEqual(run.call_args.args[0], ["codex", "debug", "models"])
        self.assertFalse(run.call_args.kwargs["shell"])

        hidden_kwargs = hidden_subprocess_kwargs()
        if "creationflags" in hidden_kwargs:
            self.assertEqual(run.call_args.kwargs["creationflags"], hidden_kwargs["creationflags"])
        if "startupinfo" in hidden_kwargs:
            self.assertIn("startupinfo", run.call_args.kwargs)

    def test_claude_login_model_discovery_uses_static_list_without_warning(self):
        result = discover_provider_models(PROVIDER_CLAUDE_LOGIN_VIA_CLAUDE_CLI)

        self.assertEqual(result.models[0], "claude-opus-4-8")
        self.assertIn("claude-sonnet-4-6", result.models)
        self.assertIn("claude-haiku-4-5", result.models)
        self.assertIn("sonnet", result.models)
        self.assertNotIn("claude-opus-4.6", result.models)
        self.assertEqual(result.source, "static provider list")
        self.assertEqual(result.warning, "")

    def test_claude_cli_model_discovery_uses_static_list_without_warning(self):
        result = discover_provider_models(PROVIDER_CLAUDE_CLI)

        self.assertEqual(result.models[0], "claude-opus-4-8")
        self.assertIn("claude-sonnet-4-6", result.models)
        self.assertIn("claude-haiku-4-5", result.models)
        self.assertIn("sonnet", result.models)
        self.assertNotIn("claude-opus-4.6", result.models)
        self.assertEqual(result.source, "static provider list")
        self.assertEqual(result.warning, "")


if __name__ == "__main__":
    unittest.main()
