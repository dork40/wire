@echo off
setlocal
where py >nul 2>nul
if errorlevel 1 (
  echo Install Python 3.11 or newer from python.org, then run this command again.
  exit /b 1
)
py -m pip install --user --upgrade pipx
if errorlevel 1 exit /b 1
py -m pipx ensurepath
if errorlevel 1 exit /b 1
py -m pipx install --force https://github.com/dork40/wire/archive/refs/heads/main.zip
if errorlevel 1 (
  echo Wire installation failed.
  exit /b 1
)
echo.
echo Wire installed. Close this window, open a new Command Prompt, then type: wire
