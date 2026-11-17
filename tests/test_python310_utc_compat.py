"""Guard the Python 3.10 compatibility floor against datetime.UTC regressions."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Python310UtcCompatibilityTests(unittest.TestCase):
    def test_no_datetime_utc_symbol_in_project_sources(self):
        violations = []
        for path in ROOT.rglob("*.py"):
            if any(part in {".git", ".venv", "venv", "__pycache__"} for part in path.parts):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "datetime":
                    if any(alias.name == "UTC" for alias in node.names):
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: from datetime import UTC")
                elif isinstance(node, ast.Attribute) and node.attr == "UTC":
                    if isinstance(node.value, ast.Name) and node.value.id == "datetime":
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: datetime.UTC")
        self.assertEqual(violations, [], "\n".join(violations))


if __name__ == "__main__":
    unittest.main()
