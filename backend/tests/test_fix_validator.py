import pytest
from pathlib import Path
from app.ai.fix_validator import FixValidator
from app.scanners.base import RawFinding

@pytest.fixture
def corpus_dir():
    return Path(__file__).resolve().parent.parent / "app" / "benchmark" / "corpus" / "vulnerable_app"

@pytest.mark.asyncio
async def test_fix_validation_loop(corpus_dir):
    finding = RawFinding(
        tool="semgrep",
        rule_id="python.lang.security.audit.sqli.formatted-query-execute",
        title="SQL Injection",
        message="Vulnerable f-string execute",
        severity="CRITICAL",
        file_path="routes/users.py",
        start_line=15,
        end_line=15,
        code_snippet="cursor.execute(query)"
    )

    # Valid proposed patch that replaces the f-string with a parameterized call
    proposed_patch = """--- a/routes/users.py
+++ b/routes/users.py
@@ -12,3 +12,3 @@
-    query = f"SELECT * FROM users WHERE id = '{user_id}'"
-    cursor.execute(query)
+    cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
"""

    validator = FixValidator()
    is_valid, details = await validator.validate_patch(
        finding=finding,
        proposed_patch=proposed_patch,
        repo_root=corpus_dir
    )

    assert is_valid is True
    assert details["re_scan_clean"] is True
    assert details["syntax_valid"] is True
