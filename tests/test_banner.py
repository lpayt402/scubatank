"""Terminal decoration must never contaminate machine-readable command output."""
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from scubatank import __main__ as cli


class Terminal(io.StringIO):
    def __init__(self, interactive=True):
        super().__init__()
        self.interactive = interactive

    def isatty(self):
        return self.interactive


class BannerTests(unittest.TestCase):
    def invoke(self, args, terminals=(True, True, True)):
        streams = [Terminal(interactive) for interactive in terminals]
        with patch.object(cli.sys, "stdin", streams[0]), patch.object(cli.sys, "stdout", streams[1]), patch.object(cli.sys, "stderr", streams[2]), patch.object(cli.sys, "argv", ["scubatank", *args]):
            try:
                status = cli.main()
            except SystemExit as exit_status:
                status = exit_status.code
        return status, streams[1].getvalue(), streams[2].getvalue()

    def test_interactive_banner_leaves_stdout_valid_json(self):
        status, output, diagnostics = self.invoke(["plan"])
        self.assertEqual(status, 0)
        self.assertEqual(diagnostics, cli.BANNER + "\n\n")
        self.assertEqual(len(json.loads(output)["implemented_rules"]), 6)

    def test_redirecting_any_stream_suppresses_the_banner(self):
        for terminals in ((False, True, True), (True, False, True), (True, True, False), (False, False, False)):
            with self.subTest(terminals=terminals):
                status, output, diagnostics = self.invoke(["plan"], terminals)
                self.assertEqual(status, 0)
                self.assertEqual(diagnostics, "")
                json.loads(output)

    def test_quiet_before_or_after_command_keeps_the_result(self):
        for args in (["--quiet", "plan"], ["plan", "--quiet"], ["--qui", "plan"], ["plan", "--qui"]):
            with self.subTest(args=args):
                status, output, diagnostics = self.invoke(args)
                self.assertEqual(status, 0)
                self.assertEqual(diagnostics, "")
                self.assertEqual(json.loads(output)["network_access"], False)

    def test_help_obeys_interactive_and_quiet_modes(self):
        for args, terminals, banner in ((["--help"], (True, True, True), True),
                (["plan", "--help"], (True, True, True), True),
                (["--quiet", "--help"], (True, True, True), False),
                (["plan", "--quiet", "--help"], (True, True, True), False),
                (["--help"], (False, False, False), False)):
            with self.subTest(args=args, terminals=terminals):
                status, output, diagnostics = self.invoke(args, terminals)
                self.assertEqual(status, 0)
                self.assertIn("usage:", output)
                self.assertEqual(diagnostics, cli.BANNER + "\n\n" if banner else "")

    def test_every_command_accepts_quiet_help(self):
        for command in ("plan", "import", "validate", "assess", "report", "demo"):
            with self.subTest(command=command):
                status, output, diagnostics = self.invoke([command, "--quiet", "--help"])
                self.assertEqual(status, 0)
                self.assertIn("--quiet", output)
                self.assertEqual(diagnostics, "")

    def test_readme_uses_the_same_ascii_art(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8-sig")
        self.assertIn("```text\n" + cli.BANNER + "\n```", readme)
        self.assertTrue(cli.BANNER.isascii())
        self.assertLessEqual(max(map(len, cli.BANNER.splitlines())), 64)


if __name__ == "__main__":
    unittest.main()
