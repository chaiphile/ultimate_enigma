"""Code analysis service package.

Wraps external developer tools (ripgrep, universal-ctags, tree-sitter,
semgrep, CodeQL, clangd, rust-analyzer) behind a single timeout-protected,
gracefully-degrading Python service.
"""

from .code_analysis_service import CodeAnalysisService, ToolStatus
from .tools import TOOL_EXECUTABLES, TOOL_SPECS

__all__ = ["CodeAnalysisService", "ToolStatus", "TOOL_EXECUTABLES", "TOOL_SPECS"]
