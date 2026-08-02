"""Code analysis service wrapping external developer tools.

Provides a thin, timeout-protected layer over ripgrep, universal-ctags,
tree-sitter, semgrep, CodeQL, clangd, and rust-analyzer. The service
degrades gracefully when a tool is not installed: ``tool_status`` reports
it as unavailable and operations raise ``CodeAnalysisToolNotFoundError``
instead of crashing the host application.

Every subprocess spawn is routed through ``_run`` so tests can substitute
a fake runner without touching the real toolchain.
"""

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.constants import CODE_ANALYSIS_CONSTANTS
from src.exceptions import (
    CodeAnalysisError,
    CodeAnalysisToolError,
    CodeAnalysisToolNotFoundError,
)
from src.timeout import run_with_timeout

from .tools import TOOL_EXECUTABLES, TOOL_SPECS_BY_KEY, TOOL_KEYS

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT: int = CODE_ANALYSIS_CONSTANTS["TOOL_TIMEOUT_SECONDS"]
SEARCH_MAX_RESULTS: int = CODE_ANALYSIS_CONSTANTS["SEARCH_MAX_RESULTS"]
TAGS_MAX_RESULTS: int = CODE_ANALYSIS_CONSTANTS["TAGS_MAX_RESULTS"]


@dataclass
class ToolStatus:
    """Availability snapshot of one code-analysis tool."""

    key: str
    executable: str
    available: bool
    version: Optional[str] = None
    path: Optional[str] = None


class CodeAnalysisService:
    """Orchestrates the external code-analysis toolchain.

    Follows the Model role in MVC: encapsulates subprocess state and tool
    discovery independently from any UI widget.
    """

    def __init__(
        self,
        project_root: Optional[Union[str, Path]] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._project_root = Path(project_root) if project_root else Path.cwd()
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Tool discovery
    # ------------------------------------------------------------------

    def find_executable(self, executable: str) -> Optional[str]:
        """Return the absolute path to ``executable`` or None if missing."""
        return shutil.which(executable)

    def tool_status(self, key: str) -> ToolStatus:
        """Return an availability snapshot for a single tool."""
        spec = TOOL_SPECS_BY_KEY[key]
        path = self.find_executable(spec.executable)
        if path is None:
            return ToolStatus(key, spec.executable, False)
        return ToolStatus(
            key,
            spec.executable,
            True,
            version=self._safe_version(spec),
            path=path,
        )

    def all_tool_statuses(self) -> List[ToolStatus]:
        """Return availability snapshots for every known tool."""
        return [self.tool_status(key) for key in TOOL_KEYS]

    def _safe_version(self, spec) -> Optional[str]:
        """Probe a tool version, tolerating absence or probe failure."""
        try:
            proc = self._run(
                [spec.executable, *spec.version_args],
                cwd=self._project_root,
                timeout=self._timeout,
                check=False,
            )
        except Exception:
            return None
        if proc.returncode != 0:
            return None
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line:
                return line
        return None

    # ------------------------------------------------------------------
    # Primitive subprocess runner
    # ------------------------------------------------------------------

    def _build_command(self, args: List[str]) -> List[str]:
        """Resolve the executable, routing .cmd/.bat shims through cmd.exe.

        npm/pip installs sometimes expose only ``.cmd``/``.bat`` launchers,
        which Windows ``CreateProcess`` cannot execute directly; they must
        run under ``cmd.exe /c``.
        """
        executable = args[0]
        resolved = self.find_executable(executable)
        if resolved and Path(resolved).suffix.lower() in (".cmd", ".bat"):
            return ["cmd.exe", "/c", executable, *[str(a) for a in args[1:]]]
        return [str(a) for a in args]

    def _run(
        self,
        args: List[str],
        cwd: Optional[Union[str, Path]] = None,
        timeout: Optional[float] = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run a tool subprocess, enforcing a deadline.

        Args:
            args: Command line (executable + arguments).
            cwd: Working directory for the subprocess.
            timeout: Override for the default per-tool deadline.
            check: If True, raise ``CodeAnalysisToolError`` on non-zero exit.

        Returns:
            The completed subprocess result.

        Raises:
            CodeAnalysisToolError: On non-zero exit when ``check`` is True.
        """

        def _invoke() -> subprocess.CompletedProcess:
            return subprocess.run(
                self._build_command(args),
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout if timeout is not None else self._timeout,
            )

        proc = run_with_timeout(
            _invoke, timeout if timeout is not None else self._timeout
        )
        if check and proc.returncode != 0:
            raise CodeAnalysisToolError(
                f"Tool '{args[0]}' exited with code {proc.returncode}: "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        return proc

    def _require(self, key: str) -> None:
        """Ensure a tool is installed, else raise a not-found error."""
        executable = TOOL_EXECUTABLES[key]
        if self.find_executable(executable) is None:
            raise CodeAnalysisToolNotFoundError(
                f"Code-analysis tool '{key}' ('{executable}') is not "
                "installed or not on PATH."
            )

    # ------------------------------------------------------------------
    # ripgrep
    # ------------------------------------------------------------------

    def search(
        self,
        pattern: str,
        search_path: Optional[Union[str, Path]] = None,
        case_sensitive: bool = False,
        max_results: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Search source with ripgrep, returning normalized JSON matches.

        Args:
            pattern: Regex pattern to search for.
            search_path: Directory or file to search (defaults to project root).
            case_sensitive: Disable case-insensitive matching when True.
            max_results: Cap on matches per file.

        Returns:
            A list of match records (path, line_number, lines, submatches).
        """
        self._require("ripgrep")
        path = Path(search_path) if search_path else self._project_root
        args = ["rg", "--json", "--no-heading", "-n"]
        if not case_sensitive:
            args.append("-i")
        limit = max_results if max_results is not None else SEARCH_MAX_RESULTS
        args.extend(["-m", str(limit), pattern, str(path)])
        proc = self._run(args, cwd=self._project_root, check=False)

        matches: List[Dict[str, Any]] = []
        for raw_line in (proc.stdout or "").splitlines():
            try:
                obj = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "match":
                continue
            data = obj.get("data", {})
            matches.append(
                {
                    "path": (data.get("path") or {}).get("text"),
                    "line_number": data.get("line_number"),
                    "lines": (data.get("lines") or {}).get("text", ""),
                    "submatches": [
                        (sm.get("match") or {}).get("text", "")
                        for sm in data.get("submatches", [])
                    ],
                }
            )
        return matches

    # ------------------------------------------------------------------
    # universal-ctags
    # ------------------------------------------------------------------

    def generate_tags(
        self,
        source_path: Optional[Union[str, Path]] = None,
        max_results: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Generate source tags with universal-ctags (JSON on stdout).

        Args:
            source_path: File or directory to tag (defaults to project root).
            max_results: Cap on emitted tags.

        Returns:
            A list of tag records (name, kind, path, line, pattern).
        """
        self._require("universal_ctags")
        path = Path(source_path) if source_path else self._project_root

        args = ["ctags", "-o", "-", "--output-format=json", "--fields=+n"]
        config = self._project_root / CODE_ANALYSIS_CONSTANTS["CTAGS_CONFIG_REL"]
        if config.exists():
            args.append(f"--options={config}")
        if max_results is not None:
            args.append(f"--max-count={max_results}")
        if path.is_dir():
            args.append("-R")
        args.append(str(path))

        proc = self._run(args, cwd=self._project_root, check=False)

        tags: List[Dict[str, Any]] = []
        for raw_line in (proc.stdout or "").splitlines():
            try:
                obj = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            if obj.get("_type") != "tag":
                continue
            tags.append(
                {
                    "name": obj.get("name"),
                    "kind": obj.get("kind"),
                    "path": obj.get("path"),
                    "line": obj.get("line"),
                    "pattern": obj.get("pattern"),
                }
            )
        return tags

    # ------------------------------------------------------------------
    # tree-sitter
    # ------------------------------------------------------------------

    def parse_file(self, source_file: Union[str, Path]) -> Dict[str, Any]:
        """Parse a single file with the tree-sitter CLI.

        Returns:
            A record with the file path, exit code, success flag, and the
            printed concrete syntax tree.
        """
        self._require("tree_sitter")
        path = Path(source_file)
        args = ["tree-sitter", "parse", str(path)]
        proc = self._run(args, cwd=self._project_root, check=False)
        return {
            "file": str(path),
            "exit_code": proc.returncode,
            "success": proc.returncode == 0,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }

    # ------------------------------------------------------------------
    # semgrep
    # ------------------------------------------------------------------

    def semgrep_scan(
        self,
        scan_path: Optional[Union[str, Path]] = None,
        config: Optional[Union[str, Path]] = None,
    ) -> List[Dict[str, Any]]:
        """Run a semgrep scan and normalize the JSON findings.

        Args:
            scan_path: Directory or file to scan (defaults to project root).
            config: semgrep rule file/dir; falls back to the repo ruleset.

        Returns:
            A list of findings (rule, path, line, message, severity).
        """
        self._require("semgrep")
        path = Path(scan_path) if scan_path else self._project_root
        rule_config = (
            Path(config)
            if config
            else self._project_root / CODE_ANALYSIS_CONSTANTS["SEMGREP_CONFIG_REL"]
        )
        args = ["semgrep", "scan", "--json", "--quiet"]
        if rule_config.exists():
            args.extend(["--config", str(rule_config)])
        args.append(str(path))

        proc = self._run(args, cwd=self._project_root, check=False)
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise CodeAnalysisToolError(
                f"semgrep produced invalid JSON: {exc}"
            ) from exc

        results: List[Dict[str, Any]] = []
        for finding in data.get("results", []):
            extra = finding.get("extra") or {}
            results.append(
                {
                    "rule": finding.get("check_id"),
                    "path": finding.get("path"),
                    "line": (finding.get("start") or {}).get("line"),
                    "message": extra.get("message", ""),
                    "severity": extra.get("severity"),
                }
            )
        return results

    # ------------------------------------------------------------------
    # CodeQL
    # ------------------------------------------------------------------

    def codeql_version(self) -> Optional[str]:
        """Return the CodeQL toolchain version string, if installed."""
        self._require("codeql")
        spec = TOOL_SPECS_BY_KEY["codeql"]
        proc = self._run(
            [spec.executable, *spec.version_args],
            cwd=self._project_root,
            check=False,
        )
        if proc.returncode != 0:
            return None
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line:
                return line
        return None

    def codeql_resolve_languages(self) -> List[str]:
        """Return languages the installed CodeQL toolchain supports."""
        self._require("codeql")
        proc = self._run(
            ["codeql", "resolve", "languages"],
            cwd=self._project_root,
            check=False,
        )
        if proc.returncode != 0:
            return []
        languages = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "[")):
                languages.append(line)
        return languages

    # ------------------------------------------------------------------
    # Language servers (clangd / rust-analyzer)
    # ------------------------------------------------------------------

    def language_server_status(self, key: str) -> ToolStatus:
        """Alias for ``tool_status`` restricted to language-server keys."""
        if key not in ("clangd", "rust_analyzer"):
            raise ValueError(
                f"'{key}' is not a language server; use tool_status() instead."
            )
        return self.tool_status(key)
