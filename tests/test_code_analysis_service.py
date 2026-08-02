"""Tests for the code analysis service wrapping external dev tools.

All subprocess interaction is mocked so the suite runs without any of the
external tools installed; the only real subprocess used is the Python
interpreter itself.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from services.code_analysis import CodeAnalysisService, TOOL_SPECS
from src.exceptions import CodeAnalysisToolError, CodeAnalysisToolNotFoundError


def _fake_proc(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Build a fake subprocess result."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


@pytest.fixture
def service(tmp_path):
    return CodeAnalysisService(project_root=tmp_path)


def test_all_tool_statuses_returns_every_tool(service, monkeypatch):
    monkeypatch.setattr(service, "find_executable", lambda exe: None)
    statuses = service.all_tool_statuses()
    assert len(statuses) == len(TOOL_SPECS)
    assert all(s.available is False for s in statuses)


def test_tool_status_unavailable(service, monkeypatch):
    monkeypatch.setattr(service, "find_executable", lambda exe: None)
    status = service.tool_status("ripgrep")
    assert status.available is False
    assert status.executable == "rg"


def test_tool_status_available_with_version(service, monkeypatch):
    monkeypatch.setattr(
        service, "find_executable", lambda exe: "C:\\fake\\rg.exe"
    )
    monkeypatch.setattr(
        service,
        "_run",
        lambda *a, **k: _fake_proc("ripgrep 15.2.0\nsecond line\n"),
    )
    status = service.tool_status("ripgrep")
    assert status.available is True
    assert status.version == "ripgrep 15.2.0"
    assert status.path == "C:\\fake\\rg.exe"


def test_codeql_uses_version_subcommand(service, monkeypatch):
    captured = {}

    def fake_run(args, cwd=None, timeout=None, check=True):
        captured["args"] = list(args)
        return _fake_proc("CodeQL command-line toolchain release 2.26.2.")

    monkeypatch.setattr(service, "find_executable", lambda exe: "C:\\fake\\codeql.exe")
    monkeypatch.setattr(service, "_run", fake_run)
    assert service.codeql_version() == "CodeQL command-line toolchain release 2.26.2."
    assert captured["args"] == ["codeql", "version"]


def test_search_parses_ripgrep_json(service, monkeypatch):
    match_line = json.dumps(
        {
            "type": "match",
            "data": {
                "path": {"text": "src\\example.py"},
                "lines": {"text": "def hello():\n"},
                "line_number": 5,
                "submatches": [{"match": {"text": "hello"}}],
            },
        }
    )
    begin_line = json.dumps({"type": "begin", "data": {"path": {"text": "src"}}})
    monkeypatch.setattr(service, "find_executable", lambda exe: "C:\\fake\\rg.exe")
    monkeypatch.setattr(
        service, "_run", lambda *a, **k: _fake_proc(f"{begin_line}\n{match_line}\n")
    )
    matches = service.search("hello")
    assert len(matches) == 1
    assert matches[0]["path"] == "src\\example.py"
    assert matches[0]["line_number"] == 5
    assert matches[0]["submatches"] == ["hello"]


def test_search_raises_when_tool_missing(service, monkeypatch):
    monkeypatch.setattr(service, "find_executable", lambda exe: None)
    with pytest.raises(CodeAnalysisToolNotFoundError):
        service.search("hello")


def test_generate_tags_parses_ctags_json(service, monkeypatch):
    tag_line = json.dumps(
        {
            "_type": "tag",
            "name": "hello",
            "path": "src\\example.py",
            "pattern": "/^def hello/",
            "kind": "func",
            "line": 5,
        }
    )
    monkeypatch.setattr(service, "find_executable", lambda exe: "C:\\fake\\ctags.exe")
    monkeypatch.setattr(service, "_run", lambda *a, **k: _fake_proc(tag_line + "\n"))
    tags = service.generate_tags(service._project_root)
    assert len(tags) == 1
    assert tags[0]["name"] == "hello"
    assert tags[0]["kind"] == "func"
    assert tags[0]["line"] == 5


def test_parse_file_reports_success(service, monkeypatch):
    monkeypatch.setattr(
        service, "find_executable", lambda exe: "C:\\fake\\tree-sitter.exe"
    )
    monkeypatch.setattr(
        service,
        "_run",
        lambda *a, **k: _fake_proc("(module (function_definition name: (identifier)))\n"),
    )
    source = service._project_root / "example.py"
    source.write_text("def hello():\n    pass\n", encoding="utf-8")
    result = service.parse_file(source)
    assert result["success"] is True
    assert result["file"] == str(source)


def test_semgrep_scan_normalizes_results(service, monkeypatch):
    payload = json.dumps(
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-usage",
                    "path": "example.py",
                    "start": {"line": 3},
                    "extra": {"message": "avoid eval", "severity": "WARNING"},
                }
            ]
        }
    )
    monkeypatch.setattr(service, "find_executable", lambda exe: "C:\\fake\\semgrep.exe")
    monkeypatch.setattr(service, "_run", lambda *a, **k: _fake_proc(payload))
    findings = service.semgrep_scan()
    assert len(findings) == 1
    assert findings[0]["rule"] == "python.lang.security.audit.eval-usage"
    assert findings[0]["line"] == 3
    assert findings[0]["severity"] == "WARNING"


def test_semgrep_scan_invalid_json_raises(service, monkeypatch):
    monkeypatch.setattr(service, "find_executable", lambda exe: "C:\\fake\\semgrep.exe")
    monkeypatch.setattr(service, "_run", lambda *a, **k: _fake_proc("not json"))
    with pytest.raises(CodeAnalysisToolError):
        service.semgrep_scan()


def test_codeql_resolve_languages(service, monkeypatch):
    monkeypatch.setattr(service, "find_executable", lambda exe: "C:\\fake\\codeql.exe")
    monkeypatch.setattr(
        service, "_run", lambda *a, **k: _fake_proc("python\njava\njavascript\n")
    )
    languages = service.codeql_resolve_languages()
    assert languages == ["python", "java", "javascript"]


def test_language_server_status_rejects_non_lsp(service):
    with pytest.raises(ValueError):
        service.language_server_status("semgrep")


def test_build_command_routes_cmd_shims_through_cmd_exe(service, monkeypatch):
    monkeypatch.setattr(
        service, "find_executable", lambda exe: "C:\\fake\\tree-sitter.CMD"
    )
    assert service._build_command(["tree-sitter", "parse", "a.py"]) == [
        "cmd.exe",
        "/c",
        "tree-sitter",
        "parse",
        "a.py",
    ]


def test_build_command_passes_plain_executables_through(service, monkeypatch):
    monkeypatch.setattr(service, "find_executable", lambda exe: "C:\\fake\\rg.exe")
    assert service._build_command(["rg", "--json", "x"]) == ["rg", "--json", "x"]


def test_run_raises_on_nonzero_exit(service):
    with pytest.raises(CodeAnalysisToolError):
        service._run([sys.executable, "-c", "import sys; sys.exit(3)"], check=True)


def test_run_captures_success(service):
    proc = service._run([sys.executable, "-c", "print('ok')"], check=True)
    assert proc.returncode == 0
    assert "ok" in proc.stdout
