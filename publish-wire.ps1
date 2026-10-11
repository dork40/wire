param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$Message
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Keep the displayed version, package metadata, GitHub source, and installed
# command in lockstep. Run it only after the feature work is committed. It
# refuses a dirty tree so it cannot accidentally publish unrelated files.
$dirty = git status --porcelain
if ($dirty) { throw "Commit or remove outstanding changes before publishing. Nothing was changed." }
$project = Get-Content -Raw .\pyproject.toml
$project = $project -replace 'version = "\d+\.\d+\.\d+"', "version = `"$Version`""
[IO.File]::WriteAllText((Join-Path $root 'pyproject.toml'), $project)

$versionText = Get-Content -Raw .\VERSION.txt
$versionText = $versionText -replace 'Wire v\d+\.\d+\.\d+', "Wire v$Version"
[IO.File]::WriteAllText((Join-Path $root 'VERSION.txt'), $versionText)

& .\.venv\Scripts\python.exe -m py_compile .\wire.py .\wire_webrtc.py .\wire-server.py
if ($LASTEXITCODE -ne 0) { throw 'Python validation failed.' }

git add .\pyproject.toml .\VERSION.txt
git commit -m $Message
git push origin main
if ($LASTEXITCODE -ne 0) { throw 'GitHub push failed; the local Wire install was not changed.' }

if (Get-Process wire -ErrorAction SilentlyContinue) {
    Write-Host 'GitHub updated. Close Wire, then rerun this script to replace the installed command.'
    exit 0
}

py -m pipx install --force https://github.com/dork40/wire/archive/refs/heads/main.zip
if ($LASTEXITCODE -ne 0) { throw 'GitHub is updated, but the local Wire replacement failed.' }
Write-Host "Published and installed Wire v$Version."
