param(
    [string]$Source = 'https://github.com/dork40/wire/archive/refs/heads/main.zip'
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Install Python 3.11+ from python.org, then run this script again.'
}
$servers = @(Get-CimInstance Win32_Process | Where-Object {
    $_.ExecutablePath -like '*pipx\pipx\venvs\wire-messenger*' -and
    $_.CommandLine -match 'wire-server\.py|wire-server\.exe'
})
if ($servers) {
    $servers | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
py -m pip install --user --upgrade pipx
py -m pipx ensurepath
py -m pipx install --force $Source
Write-Host 'Wire installed. Open a new terminal and run: wire'
