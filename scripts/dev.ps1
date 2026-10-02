#requires -Version 7.0
# SPDX-License-Identifier: 0BSD

<#
.SYNOPSIS
Set up a dedicated repository environment or run the development checks.
.DESCRIPTION
Run with pwsh -NoProfile -File. Paths are resolved from the repository, so
activation and the caller's working directory do not affect the commands.
.PARAMETER Action
Use setup to install the hash-locked environment, or check to validate it.
.PARAMETER Python
The bootstrap Python executable, including a full path containing spaces.
.PARAMETER Venv
A relative environment directory inside the repository. Defaults to .venv.
.EXAMPLE
pwsh -NoProfile -File ./scripts/dev.ps1 setup
.EXAMPLE
pwsh -NoProfile -File ./scripts/dev.ps1 check -Venv .venv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('setup', 'check')]
    [string] $Action,

    [ValidateNotNullOrEmpty()]
    [string] $Python = 'python',

    [ValidateNotNullOrEmpty()]
    [string] $Venv = '.venv'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Native failures are checked explicitly, including PowerShell 7.3 and later.
$PSNativeCommandUseErrorActionPreference = $false

function Invoke-CheckedNative {
    param([string] $Executable, [string[]] $Arguments)

    & $Executable @Arguments
    $nativeExitCode = $LASTEXITCODE
    if ($nativeExitCode -ne 0) {
        exit $nativeExitCode
    }
}

function Set-CommandEnvironment {
    param([string] $Name, $Value)

    if ($null -eq $Value) {
        Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    } else {
        [System.Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
    }
}

function Invoke-CheckedPython {
    param([string] $Executable, [string[]] $Arguments)

    # Editable-build backends spawn child Python without -I, so these import
    # overrides must also be absent from the process environment they inherit.
    $previousPythonPath = [System.Environment]::GetEnvironmentVariable('PYTHONPATH', 'Process')
    $previousPythonHome = [System.Environment]::GetEnvironmentVariable('PYTHONHOME', 'Process')
    $previousPythonPlatlibdir = [System.Environment]::GetEnvironmentVariable('PYTHONPLATLIBDIR', 'Process')
    try {
        Set-CommandEnvironment 'PYTHONPATH' $null
        Set-CommandEnvironment 'PYTHONHOME' $null
        Set-CommandEnvironment 'PYTHONPLATLIBDIR' $null
        Invoke-CheckedNative $Executable (@('-I') + $Arguments)
    } finally {
        Set-CommandEnvironment 'PYTHONPATH' $previousPythonPath
        Set-CommandEnvironment 'PYTHONHOME' $previousPythonHome
        Set-CommandEnvironment 'PYTHONPLATLIBDIR' $previousPythonPlatlibdir
    }
}

function Invoke-CheckedPip {
    param([string[]] $Arguments)

    # Isolated pip still reads global and virtualenv configuration. Disable
    # those files only for this invocation, and restore even on native failure.
    $previousConfigFile = [System.Environment]::GetEnvironmentVariable('PIP_CONFIG_FILE', 'Process')
    try {
        Set-CommandEnvironment 'PIP_CONFIG_FILE' $pipConfigFile
        Invoke-CheckedPython $venvPython (@('-m', 'pip', '--isolated', '--require-virtualenv') + $Arguments)
    } finally {
        Set-CommandEnvironment 'PIP_CONFIG_FILE' $previousConfigFile
    }
}

$supportedRuntime = "import sys, sysconfig; supported = sys.implementation.name == 'cpython' and (3, 11) <= sys.version_info[:2] < (3, 16) and not sysconfig.get_config_var('Py_GIL_DISABLED'); sys.exit(0 if supported else 'Use standard CPython 3.11 through 3.15.') # supported-runtime"
$canonicalReference = "import sys; print('1' if sys.version_info[:2] == (3, 14) else '0') # canonical-reference"

try {
    $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    if ([System.IO.Path]::IsPathRooted($Venv) -or
        ($Venv -split '[\\/]') -contains '..') {
        throw 'Venv must be a relative directory without parent traversal.'
    }
    $venvRoot = [System.IO.Path]::GetFullPath($Venv, $repoRoot)
    $comparison = if ($IsWindows) {
        [System.StringComparison]::OrdinalIgnoreCase
    } else {
        [System.StringComparison]::Ordinal
    }
    $repoPrefix = $repoRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $venvRoot.StartsWith($repoPrefix, $comparison)) {
        throw 'Venv must name a dedicated directory inside the repository.'
    }
    # Existing links or junctions must not redirect an environment outside it.
    $candidate = $venvRoot
    while (-not $candidate.Equals($repoRoot, $comparison)) {
        $item = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'Venv and its parent directories must not be links or junctions.'
        }
        $candidate = [System.IO.Path]::GetDirectoryName($candidate)
    }
    $venvPython = Join-Path $venvRoot $(if ($IsWindows) { 'Scripts/python.exe' } else { 'bin/python' })
    $config = Join-Path $venvRoot 'pyvenv.cfg'

    Push-Location -LiteralPath $repoRoot
    try {
        if (Test-Path -LiteralPath $venvRoot) {
            if (-not (Test-Path -LiteralPath $config -PathType Leaf) -or
                -not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
                throw 'Existing Venv is not a virtual environment; choose a dedicated directory.'
            }
        } elseif ($Action -eq 'setup') {
            Write-Host 'Checking the bootstrap interpreter.'
            Invoke-CheckedPython $Python @('-c', $supportedRuntime)
            Write-Host "Creating the dedicated environment: $venvRoot"
            Invoke-CheckedPython $Python @('-m', 'venv', $venvRoot)
        } else {
            throw 'The dedicated environment is missing; run setup first.'
        }

        Invoke-CheckedPython $venvPython @('-c', $supportedRuntime)
        $pipConfigFile = Invoke-CheckedPython $venvPython @('-c', 'import os; print(os.devnull)')
        if ($Action -eq 'setup') {
            Write-Host 'Installing the hash-locked dependencies and editable project.'
            Invoke-CheckedPip @('install', '--require-hashes', '-r', (Join-Path $repoRoot 'requirements-ci.lock'))
            Invoke-CheckedPip @('install', '-e', $repoRoot, '--no-deps', '--no-build-isolation')
            Invoke-CheckedPip @('check')
            Invoke-CheckedPython $venvPython @('-m', 'cpe_access_atlas', 'validate')
            Write-Host 'Setup completed. Run check to validate the development environment.'
        } else {
            Write-Host 'Checking dependencies, formatting, types, and source compilation.'
            Invoke-CheckedPip @('check')
            Invoke-CheckedPython $venvPython @('-m', 'ruff', 'check', 'src', 'tests', 'scripts')
            Invoke-CheckedPython $venvPython @('-m', 'ruff', 'format', '--check', 'src', 'tests', 'scripts')
            Invoke-CheckedPython $venvPython @('-m', 'mypy', 'src', 'scripts')
            Invoke-CheckedPython $venvPython @('-m', 'compileall', '-q', 'src')
            $checkReference = Invoke-CheckedPython $venvPython @('-c', $canonicalReference)
            if ($checkReference -eq '1') {
                Write-Host 'Checking the canonical Python 3.14 CLI reference.'
                Invoke-CheckedPython $venvPython @('scripts/generate_cli_reference.py', '--check')
            } else {
                Write-Host 'CLI reference freshness requires Python 3.14; skipping this check.'
            }
            Write-Host 'Running the test and coverage gates, then validating the catalog.'
            Invoke-CheckedPython $venvPython @('-m', 'coverage', 'run', '-m', 'unittest', 'discover', '-s', 'tests', '-t', '.', '-v')
            Invoke-CheckedPython $venvPython @('-m', 'coverage', 'report', '-m')
            Invoke-CheckedPython $venvPython @('-m', 'cpe_access_atlas', 'validate')
            Write-Host 'Development checks passed.'
        }
    } finally {
        Pop-Location
    }
} catch {
    [Console]::Error.WriteLine("dev.ps1: $($_.Exception.Message)")
    exit 1
}
