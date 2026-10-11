@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-RestMethod 'https://raw.githubusercontent.com/dork40/wire/main/install-wire.ps1' | Invoke-Expression"
if errorlevel 1 (
  echo Wire installation failed.
  exit /b 1
)
echo.
echo Wire installed. Close this window, open a new Command Prompt, then type: wire
