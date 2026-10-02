#!/usr/bin/env bash
# SPDX-License-Identifier: 0BSD
# Source-checkout setup and local gates; all project behavior stays in Python.
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: bash scripts/dev.sh setup|check [--python EXECUTABLE] [--venv RELATIVE_PATH]

setup  Create/reuse a dedicated venv, install hash-locked development dependencies,
       install this checkout without resolving dependencies again, and validate it.
check  Run the local lint, typing, test, coverage and catalog gates.

Defaults: --python python3, --venv .venv. Paths are anchored to this checkout.
The bootstrap --python option is used only by setup. No activation is required.'
}

fail() {
    printf 'dev.sh: %s\n' "$1" >&2
    exit 1
}

if [[ $# -eq 0 || "$1" == '--help' || "$1" == '-h' ]]; then
    usage
    exit 0
fi
action=$1
shift
[[ "$action" == 'setup' || "$action" == 'check' ]] || fail 'Choose setup or check.'
bootstrap_python=python3
venv=.venv
while [[ $# -gt 0 ]]; do
    case "$1" in
        --python|--venv)
            [[ $# -ge 2 && -n "$2" ]] || fail "Missing value for $1."
            if [[ "$1" == '--python' ]]; then bootstrap_python=$2; else venv=$2; fi
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done

script_dir=.
script_path=${BASH_SOURCE[0]}
# Git Bash can receive a Windows path from a native caller such as PowerShell.
if [[ "$script_path" == [A-Za-z]:* ]]; then script_path=${script_path//\\//}; fi
if [[ "$script_path" == */* ]]; then script_dir=${script_path%/*}; fi
repo_root=$(cd -- "$script_dir/.." && pwd -P)
cd -- "$repo_root"
[[ -f pyproject.toml && -f requirements-ci.lock ]] || fail 'Checkout metadata is missing.'
# A relative environment stays within this checkout; refuse traversal and links.
[[ "$venv" != /* && "$venv" != *\\* && "$venv" != *:* ]] || fail '--venv must be a relative path inside the checkout.'
IFS='/' read -r -a components <<< "$venv"
venv_path=$repo_root
for component in "${components[@]}"; do
    case "$component" in
        ''|.) continue ;;
        ..) fail '--venv cannot contain parent-directory traversal.' ;;
    esac
    venv_path="$venv_path/$component"
    [[ ! -L "$venv_path" ]] || fail 'The environment path cannot contain symbolic links.'
done
[[ "$venv_path" != "$repo_root" ]] || fail 'The checkout itself cannot be the environment.'
if [[ -e "$venv_path" && ! -f "$venv_path/pyvenv.cfg" ]]; then
    fail 'Existing environment path is not a virtual environment; it was left unchanged.'
fi

runtime_probe="# supported-runtime
import sys, sysconfig
ok = (sys.implementation.name == 'cpython' and (3, 11) <= sys.version_info[:2] < (3, 16) and not sysconfig.get_config_var('Py_GIL_DISABLED'))
if not ok: print('Use standard CPython 3.11 through 3.15.', file=sys.stderr)
sys.exit(0 if ok else 1)"

isolated_python() (
    # pip's editable-build backend launches child Python without -I.
    unset PYTHONPATH PYTHONHOME PYTHONPLATLIBDIR
    exec "$@"
)

if [[ "$action" == 'setup' && ! -e "$venv_path" ]]; then
    printf 'Creating dedicated environment: %s\n' "$venv_path"
    isolated_python "$bootstrap_python" -I -c "$runtime_probe"
    isolated_python "$bootstrap_python" -I -m venv "$venv_path"
fi
if [[ -f "$venv_path/Scripts/python.exe" ]]; then
    env_python="$venv_path/Scripts/python.exe"
elif [[ -x "$venv_path/bin/python" ]]; then
    env_python="$venv_path/bin/python"
else
    fail 'Environment interpreter is missing. Choose a new --venv path and run setup.'
fi
run_python() {
    isolated_python "$env_python" -I "$@"
}
run_python -c "$runtime_probe"
# --isolated alone still loads global and virtualenv pip configuration. Use
# this interpreter's null device for each pip invocation, without changing the
# caller's environment; Git Bash's Windows Python needs "nul", not /dev/null.
pip_config_file=$(run_python -c 'import os; print(os.devnull)')
pip_config_file=${pip_config_file%$'\r'}
run_pip() {
    PIP_CONFIG_FILE="$pip_config_file" run_python -m pip --isolated --require-virtualenv "$@"
}

if [[ "$action" == 'setup' ]]; then
    printf 'Installing hash-locked development dependencies.\n'
    run_pip install --require-hashes -r "$repo_root/requirements-ci.lock"
    run_pip install -e "$repo_root" --no-deps --no-build-isolation
    run_pip check
    run_python -m cpe_access_atlas validate
    printf 'Setup passed. Run this helper with check for the development gates.\n'
else
    printf 'Checking dependencies, lint, formatting and types.\n'
    run_pip check
    run_python -m ruff check src tests scripts
    run_python -m ruff format --check src tests scripts
    run_python -m mypy src scripts
    run_python -m compileall -q src
    canonical=$(run_python -c "# canonical-reference
import sys
print('1' if sys.version_info[:2] == (3, 14) else '0')")
    canonical=${canonical%$'\r'}
    if [[ "$canonical" == '1' ]]; then
        run_python scripts/generate_cli_reference.py --check
    else
        printf 'CLI reference freshness is checked on the canonical Python 3.14 CI job.\n'
    fi
    printf 'Checking tests, coverage and catalog.\n'
    run_python -m coverage run -m unittest discover -s tests -t . -v
    run_python -m coverage report -m
    run_python -m cpe_access_atlas validate
    printf 'Local development gates passed.\n'
fi
