"""Registry of external code-analysis tools the service can invoke.

Each tool is identified by a stable logical key and an executable name
that must be resolvable on PATH. Version probing differs per tool (CodeQL
uses `codeql version`, everything else accepts `--version`).
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple

# Logical key -> executable name on PATH.
TOOL_EXECUTABLES: Dict[str, str] = {
    "ripgrep": "rg",
    "universal_ctags": "ctags",
    "tree_sitter": "tree-sitter",
    "semgrep": "semgrep",
    "codeql": "codeql",
    "clangd": "clangd",
    "rust_analyzer": "rust-analyzer",
}

# Default version probe; overridden per tool where the flag differs.
_VERSION_ARG_DEFAULT: Tuple[str, ...] = ("--version",)


@dataclass(frozen=True)
class ToolSpec:
    """Static metadata describing one code-analysis tool."""

    key: str
    executable: str
    description: str
    version_args: Tuple[str, ...] = _VERSION_ARG_DEFAULT


TOOL_SPECS: Tuple[ToolSpec, ...] = (
    ToolSpec("ripgrep", "rg", "fast regex search"),
    ToolSpec("universal_ctags", "ctags", "source code tag index"),
    ToolSpec("tree_sitter", "tree-sitter", "incremental parser CLI"),
    ToolSpec("semgrep", "semgrep", "static analysis / pattern matching"),
    ToolSpec("codeql", "codeql", "semantic code analysis engine",
             version_args=("version",)),
    ToolSpec("clangd", "clangd", "C/C++ language server"),
    ToolSpec("rust_analyzer", "rust-analyzer", "Rust language server"),
)

TOOL_SPECS_BY_KEY: Dict[str, ToolSpec] = {spec.key: spec for spec in TOOL_SPECS}

TOOL_KEYS: List[str] = [spec.key for spec in TOOL_SPECS]
