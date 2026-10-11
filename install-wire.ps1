param(
    [string]$Source = 'git+https://github.com/dork40/wire.git'
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Install Python 3.11+ from python.org, then run this script again.'
}
py -m pip install --user --upgrade pipx
py -m pipx ensurepath
py -m pipx install --force $Source
Write-Host 'Wire installed. Open a new terminal and run: wire'
