# SPDX-License-Identifier: 0BSD
"""Execute the shell helpers with isolated, synthetic Python environments."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]


def available_shells() -> list[tuple[str, list[str]]]:
    shells = []
    if os.name == "nt":
        git = shutil.which("git")
        bash = Path(git).parent.parent / "bin/bash.exe" if git else None
        if bash is not None and bash.is_file():
            shells.append(("bash", [str(bash), str(ROOT / "scripts/dev.sh")]))
    else:
        bash = shutil.which("bash")
        if bash:
            shells.append(("bash", [bash, str(ROOT / "scripts/dev.sh")]))
    pwsh = shutil.which("pwsh")
    if pwsh:
        policy = subprocess.run(  # noqa: S603 -- installed shell, fixed policy query
            [pwsh, "-NoProfile", "-Command", "[string](Get-ExecutionPolicy)"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout.strip()
        if policy not in {"Restricted", "AllSigned"}:
            shells.append(("pwsh", [pwsh, "-NoProfile", "-File", str(ROOT / "scripts/dev.ps1")]))
    return shells


class ShellHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.shells = available_shells()
        if not self.shells:
            self.skipTest("No permitted Bash or PowerShell 7 runtime is available")
        parent = ROOT / ".tmp"
        parent.mkdir(exist_ok=True)
        if not parent.resolve().is_relative_to(ROOT.resolve()):
            raise RuntimeError("Test temporary directory is outside the checkout")
        temporary = TemporaryDirectory(prefix="shell helper test ", dir=parent)
        self.base = Path(temporary.name)
        if not self.base.resolve().is_relative_to(parent.resolve()):
            raise RuntimeError("Unexpected temporary directory")
        self.addCleanup(temporary.cleanup)
        self.caller = self.base / "different working directory"
        self.caller.mkdir()
        self.environment = os.environ.copy()
        self.environment.pop("PYTHONPATH", None)
        self.environment.pop("PYTHONHOME", None)
        self.environment.pop("PYTHONPLATLIBDIR", None)
        self.environment["PYTHONNOUSERSITE"] = "1"
        self.environment["PYTHONDONTWRITEBYTECODE"] = "1"

    def virtual_environment(
        self, additional_modules: tuple[str, ...] = (), *, real_pip: bool = False
    ) -> tuple[Path, Path]:
        environment = self.base / "environment with spaces"
        subprocess.run(  # noqa: S603 -- current interpreter, isolated test venv
            [
                sys.executable,
                "-I",
                "-m",
                "venv",
                *([] if real_pip else ["--without-pip"]),
                str(environment),
            ],
            check=True,
            timeout=120,
            env=self.environment,
        )
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        site = subprocess.run(  # noqa: S603 -- freshly created test interpreter
            [str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
            env=self.environment,
        ).stdout.strip()
        log = self.base / "synthetic-commands.jsonl"
        # The synthetic installer never downloads or installs anything. Real
        # native process calls still exercise quoting, cwd, and exit propagation.
        for name in (*(() if real_pip else ("pip",)), "cpe_access_atlas", *additional_modules):
            package = Path(site) / name
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "__main__.py").write_text(
                "import json, os, subprocess, sys\n"
                "from pathlib import Path\n"
                "child = None\n"
                f"if {name!r} == 'pip' and os.environ.get('CPE_ATLAS_SYNTHETIC_CHILD'):\n"
                "    child = json.loads(subprocess.run([sys.executable, '-c', "
                '"import importlib.util, json, os, socket, ssl, sys; print(json.dumps({'
                "'isolated': sys.flags.isolated, 'pythonpath': os.environ.get('PYTHONPATH'), "
                "'pythonhome': os.environ.get('PYTHONHOME'), "
                "'pythonplatlibdir': os.environ.get('PYTHONPLATLIBDIR'), "
                "'hostile_import': importlib.util.find_spec('hostile_import') is not None}))\"], "
                "check=True, capture_output=True, text=True, timeout=30).stdout)\n"
                f"with Path({str(log)!r}).open('a', encoding='utf-8') as stream:\n"
                f"    stream.write(json.dumps({{'module': {name!r}, 'args': sys.argv[1:], "
                "'cwd': str(Path.cwd()), 'prefix': sys.prefix, 'isolated': sys.flags.isolated, "
                "'pip_config_file': os.environ.get('PIP_CONFIG_FILE'), 'child': child}) + '\\n')\n"
                "sys.exit(int(os.environ.get('CPE_ATLAS_SYNTHETIC_EXIT', '0')))\n",
                encoding="utf-8",
            )
        return environment, log

    def test_canonical_reference_gate_handles_native_line_endings(self) -> None:
        environment, log = self.virtual_environment(("ruff", "mypy", "coverage"))
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        site = subprocess.run(  # noqa: S603 -- isolated synthetic interpreter
            [str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
            env=self.environment,
        ).stdout.strip()
        # Only this disposable venv synthesizes the formatter version. The real
        # Python process prints its platform's native newline, including CRLF.
        # Stop at the reference command without executing or changing that doc.
        (Path(site) / "sitecustomize.py").write_text(
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "if any('canonical-reference' in arg for arg in sys.orig_argv):\n"
            "    canonical = os.environ['CPE_ATLAS_SYNTHETIC_CANONICAL'] == '1'\n"
            "    sys.version_info = (3, 14) if canonical else (3, 13)\n"
            "if any(arg.endswith('generate_cli_reference.py') for arg in sys.orig_argv):\n"
            f"    with Path({str(log)!r}).open('a', encoding='utf-8') as stream:\n"
            "        stream.write(json.dumps({'module': 'reference'}) + '\\n')\n"
            "    os._exit(19)\n",
            encoding="utf-8",
        )
        for shell in self.shells:
            for canonical in ("0", "1"):
                with self.subTest(shell=shell[0], canonical=canonical):
                    log.unlink(missing_ok=True)
                    self.environment["CPE_ATLAS_SYNTHETIC_CANONICAL"] = canonical
                    result = self.invoke(shell, "check", environment.relative_to(ROOT).as_posix())
                    self.assertEqual(
                        result.returncode,
                        19 if canonical == "1" else 0,
                        result.stdout + result.stderr,
                    )
                    calls = [json.loads(line) for line in log.read_text().splitlines()]
                    self.assertEqual(
                        any(call["module"] == "reference" for call in calls), canonical == "1"
                    )
                    if canonical == "0":
                        coverage = next(
                            call["args"]
                            for call in calls
                            if call["module"] == "coverage" and call["args"][0] == "run"
                        )
                        # Run the helper's real discovery command against one
                        # maintenance test module. Under -I it must explicitly
                        # add the trusted checkout root for imports of scripts.
                        discovered = subprocess.run(  # noqa: S603 -- real coverage, reviewed tests
                            [
                                sys.executable,
                                "-I",
                                "-m",
                                "coverage",
                                "run",
                                "--data-file",
                                str(self.base / "discovery.coverage"),
                                *coverage[1:],
                                "-p",
                                "test_release_candidate.py",
                            ],
                            cwd=ROOT,
                            env=self.environment,
                            capture_output=True,
                            text=True,
                            timeout=90,
                        )
                        self.assertEqual(
                            discovered.returncode, 0, discovered.stdout + discovered.stderr
                        )
                        self.assertIn("test_exact_dated_first_heading", discovered.stderr)

    def invoke(
        self,
        shell: tuple[str, list[str]],
        action: str,
        environment: str,
        *,
        python: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        name, command = shell
        args = [*command, action, "--venv" if name == "bash" else "-Venv", environment]
        if python is not None:
            args.extend(["--python" if name == "bash" else "-Python", python])
        return subprocess.run(  # noqa: S603 -- reviewed helper and synthetic local paths
            args,
            cwd=self.caller,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=90,
        )

    def test_setup_uses_selected_environment_and_hash_locked_installs(self) -> None:
        environment, log = self.virtual_environment()
        relative = environment.relative_to(ROOT).as_posix()
        for shell in self.shells:
            with self.subTest(shell=shell[0]):
                log.unlink(missing_ok=True)
                result = self.invoke(shell, "setup", relative)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertTrue(all(Path(call["cwd"]) == ROOT for call in calls))
                self.assertTrue(all(Path(call["prefix"]) == environment for call in calls))
                self.assertTrue(all(call["isolated"] for call in calls))
                installs = [
                    call["args"]
                    for call in calls
                    if call["module"] == "pip" and "install" in call["args"]
                ]
                self.assertEqual(len(installs), 2)
                self.assertIn("--require-hashes", installs[0])
                self.assertEqual(
                    Path(installs[0][installs[0].index("-r") + 1]), ROOT / "requirements-ci.lock"
                )
                self.assertIn("--no-deps", installs[1])
                self.assertIn("--no-build-isolation", installs[1])
                self.assertEqual(Path(installs[1][installs[1].index("-e") + 1]), ROOT)
                self.assertEqual(calls[-1]["module"], "cpe_access_atlas")
                self.assertEqual(calls[-1]["args"], ["validate"])

    def test_real_pip_ignores_destination_and_index_overrides(self) -> None:
        environment, log = self.virtual_environment(real_pip=True)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        site = subprocess.run(  # noqa: S603 -- freshly created test interpreter
            [str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
            env=self.environment,
        ).stdout.strip()
        # Inspect the installed pip's effective install options before its
        # installer executes. No network or installation is part of this test.
        (Path(site) / "sitecustomize.py").write_text(
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "if '-m' in sys.orig_argv and sys.orig_argv[sys.orig_argv.index('-m') + 1] == 'pip':\n"
            "    from pip._internal.commands import create_command\n"
            "    args = sys.orig_argv[sys.orig_argv.index('pip') + 1:]\n"
            "    command = create_command('install', isolated='--isolated' in args)\n"
            "    options, _ = command.parse_args([arg for arg in args if arg != 'install'])\n"
            "    result = {'target': options.target_dir, 'prefix': options.prefix_path, "
            "'root': options.root_path, 'user': options.use_user_site, "
            "'index': options.index_url, 'require_venv': options.require_venv, "
            "'isolated': sys.flags.isolated, 'config_file': os.environ.get('PIP_CONFIG_FILE')}\n"
            f"    Path({str(log)!r}).write_text(json.dumps(result), encoding='utf-8')\n"
            "    os._exit(19)\n",
            encoding="utf-8",
        )
        redirected = self.base / "redirected install"
        config_text = (
            "[global]\n"
            f"target = {redirected}\nprefix = {redirected}\nroot = {redirected}\n"
            "user = true\nindex-url = https://example.invalid/simple\n"
        )
        custom_config = self.base / "caller pip config.ini"
        custom_config.write_text(config_text, encoding="utf-8")
        site_config = environment / ("pip.ini" if os.name == "nt" else "pip.conf")
        site_config.write_text(config_text, encoding="utf-8")
        self.environment["PIP_CONFIG_FILE"] = str(custom_config)
        overrides = {
            "PIP_TARGET": str(redirected),
            "PIP_PREFIX": str(redirected),
            "PIP_ROOT": str(redirected),
            "PIP_USER": "true",
            "PIP_INDEX_URL": "https://example.invalid/simple",
        }
        for shell in self.shells:
            for variables in (False, True):
                with self.subTest(shell=shell[0], variables=variables):
                    for name, value in overrides.items():
                        if variables:
                            self.environment[name] = value
                        else:
                            self.environment.pop(name, None)
                    result = self.invoke(shell, "setup", environment.relative_to(ROOT).as_posix())
                    self.assertEqual(result.returncode, 19, result.stdout + result.stderr)
                    options = json.loads(log.read_text(encoding="utf-8"))
                    for name in ("target", "prefix", "root", "user"):
                        self.assertIsNone(options[name], name)
                    self.assertEqual(options["index"], "https://pypi.org/simple")
                    self.assertTrue(options["require_venv"])
                    self.assertTrue(options["isolated"])
                    self.assertEqual(options["config_file"], os.devnull)
                    self.assertFalse(redirected.exists())
                    self.assertEqual(custom_config.read_text(encoding="utf-8"), config_text)
                    self.assertEqual(site_config.read_text(encoding="utf-8"), config_text)

    def test_editable_backend_child_does_not_inherit_python_import_overrides(self) -> None:
        environment, log = self.virtual_environment()
        poison = self.base / "caller Python modules"
        poison.mkdir()
        (poison / "hostile_import.py").write_text("raise RuntimeError('caller import')\n")
        self.environment["PYTHONPATH"] = str(poison)
        self.environment["PYTHONHOME"] = str(self.base / "invalid Python home")
        self.environment["PYTHONPLATLIBDIR"] = "invalid-platform-library-directory"
        self.environment["CPE_ATLAS_SYNTHETIC_CHILD"] = "1"
        for shell in self.shells:
            with self.subTest(shell=shell[0]):
                log.unlink(missing_ok=True)
                result = self.invoke(shell, "setup", environment.relative_to(ROOT).as_posix())
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                children = [call["child"] for call in calls if call["module"] == "pip"]
                self.assertEqual(len(children), 3)
                for child in children:
                    # The child intentionally has no -I, as in pip's editable
                    # build hook. Its import environment must still be clean.
                    self.assertEqual(child["isolated"], 0)
                    self.assertIsNone(child["pythonpath"])
                    self.assertIsNone(child["pythonhome"])
                    self.assertIsNone(child["pythonplatlibdir"])
                    self.assertFalse(child["hostile_import"])

    def test_powershell_restores_caller_environment_after_success_and_failure(self) -> None:
        powershell = next((shell for shell in self.shells if shell[0] == "pwsh"), None)
        if powershell is None:
            self.skipTest("No permitted PowerShell runtime is available")
        environment, _ = self.virtual_environment()
        restored = self.base / "restored environment.json"

        def quote(value: str) -> str:
            return "'" + value.replace("'", "''") + "'"

        invocation = (
            f"& {quote(str(ROOT / 'scripts/dev.ps1'))} setup "
            f"-Venv {quote(environment.relative_to(ROOT).as_posix())}"
        )
        command = (
            f"try {{ {invocation} }} finally {{ "
            "$result = @{config = $env:PIP_CONFIG_FILE; path = $env:PYTHONPATH; "
            "home = $env:PYTHONHOME; platlibdir = $env:PYTHONPLATLIBDIR}; "
            f"[System.IO.File]::WriteAllText({quote(str(restored))}, "
            "($result | ConvertTo-Json -Compress)) }; exit $LASTEXITCODE"
        )
        caller_values = {
            "config": "caller pip config",
            "path": "caller Python path",
            "home": "caller home",
            "platlibdir": "caller platform library directory",
        }
        names = {
            "config": "PIP_CONFIG_FILE",
            "path": "PYTHONPATH",
            "home": "PYTHONHOME",
            "platlibdir": "PYTHONPLATLIBDIR",
        }
        for present in (False, True):
            expected = caller_values if present else dict.fromkeys(caller_values)
            for key, name in names.items():
                if present:
                    self.environment[name] = caller_values[key]
                else:
                    self.environment.pop(name, None)
            for code in (0, 37):
                with self.subTest(present=present, exit_code=code):
                    self.environment["CPE_ATLAS_SYNTHETIC_EXIT"] = str(code)
                    result = subprocess.run(  # noqa: S603 -- local helper, quoted disposable paths
                        [powershell[1][0], "-NoProfile", "-Command", command],
                        cwd=self.caller,
                        env=self.environment,
                        capture_output=True,
                        text=True,
                        timeout=90,
                    )
                    self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                    self.assertEqual(json.loads(restored.read_text(encoding="utf-8")), expected)

    def test_native_failure_returns_original_exit_and_stops(self) -> None:
        environment, log = self.virtual_environment()
        self.environment["CPE_ATLAS_SYNTHETIC_EXIT"] = "37"
        for shell in self.shells:
            for action in ("setup", "check"):
                with self.subTest(shell=shell[0], action=action):
                    log.unlink(missing_ok=True)
                    result = self.invoke(shell, action, environment.relative_to(ROOT).as_posix())
                    self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
                    calls = [json.loads(line) for line in log.read_text().splitlines()]
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0]["module"], "pip")

    def test_existing_ordinary_directory_is_preserved(self) -> None:
        existing = self.base / "ordinary directory"
        existing.mkdir()
        marker = existing / "keep.txt"
        marker.write_text("keep this", encoding="utf-8")
        for shell in self.shells:
            with self.subTest(shell=shell[0]):
                result = self.invoke(shell, "setup", existing.relative_to(ROOT).as_posix())
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(marker.read_text(), "keep this")
                self.assertEqual(list(existing.iterdir()), [marker])

    def test_environment_cannot_be_checkout_or_escape_it(self) -> None:
        for shell in self.shells:
            for value in (".", "../outside", str(self.base)):
                with self.subTest(shell=shell[0], environment=value):
                    result = self.invoke(shell, "setup", value)
                    self.assertNotEqual(result.returncode, 0)

    def test_missing_bootstrap_does_not_create_environment(self) -> None:
        target = self.base / "must not be created"
        for shell in self.shells:
            with self.subTest(shell=shell[0]):
                result = self.invoke(
                    shell,
                    "setup",
                    target.relative_to(ROOT).as_posix(),
                    python=str(self.base / "missing-python"),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
