# Developer Toolchain (optional)

This directory wires optional external code-analysis tools into the repo.
The tools are **developer utilities only** — the app degrades gracefully
when any of them is missing (`CodeAnalysisService.all_tool_statuses()`
reports them as unavailable).

| Tool            | Executable     | Purpose                                    |
|-----------------|----------------|--------------------------------------------|
| tree-sitter     | `tree-sitter`  | Incremental parser CLI (syntax trees)      |
| universal-ctags | `ctags`        | Source tag index                           |
| ripgrep         | `rg`           | Fast regex search                          |
| clangd          | `clangd`       | C/C++ language server                      |
| rust-analyzer   | `rust-analyzer`| Rust language server                       |
| semgrep         | `semgrep`      | Static analysis / pattern matching         |
| CodeQL          | `codeql`       | Semantic code analysis engine              |

## Install

```powershell
powershell -ExecutionPolicy Bypass -File tools\devtools\setup_devtools.ps1
```

Idempotent: re-run to repair anything missing. ripgrep/clangd come from
winget, tree-sitter from npm, semgrep from pip, and universal-ctags,
rust-analyzer, and the CodeQL bundle from GitHub releases into
`%LOCALAPPDATA%\Programs` (no admin needed). Open a **new terminal** after
installing so PATH changes take effect.

## Files

| File                          | Used by                            |
|-------------------------------|------------------------------------|
| `setup_devtools.ps1`          | one-shot installer                 |
| `ctags.cnf`                   | `ctags --options=...`              |
| `semgrep.rules.yaml`          | `semgrep --config ...`             |
| `.clangd` (repo root)         | clangd (auto-loaded)               |
| `.rgignore` (repo root)       | ripgrep (auto-loaded)              |

## Manual usage

```bash
rg -n "get_connection" --json .                    # search
ctags -o - --output-format=json --options=tools/devtools/ctags.cnf -R .
tree-sitter parse app.py                            # syntax tree
semgrep scan --config tools/devtools/semgrep.rules.yaml .
codeql version && codeql resolve languages
clangd --version && rust-analyzer --version         # language servers
```

### tree-sitter grammar note

`tree-sitter parse` returns a clean "no grammar" error until you configure
parser directories and give it a compiled grammar (this is a per-machine
setup, not something the repo should vendor):

```bash
tree-sitter init-config            # creates the config file
# then add a "parser-directories" entry pointing at a tree-sitter grammar
# (e.g. a checkout of tree-sitter-python), and build it with the CLI.
```

Until then `CodeAnalysisService.parse_file()` reports `success: False`
with the CLI's stderr attached — the tool is installed and version-probes
fine; only grammar loading is pending. The other six tools work as-is.

## In-app integration

`services/code_analysis/code_analysis_service.py` wraps all seven tools
behind a timeout-protected service:

```python
from services.code_analysis import CodeAnalysisService

svc = CodeAnalysisService()
print(svc.all_tool_statuses())
matches = svc.search("get_connection")
findings = svc.semgrep_scan()
tags = svc.generate_tags(".")
```
