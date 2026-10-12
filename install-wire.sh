#!/usr/bin/env sh
set -eu

SOURCE=${1:-'https://github.com/dork40/wire/archive/refs/heads/main.zip'}

if ! command -v python3 >/dev/null 2>&1 || ! command -v pipx >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-venv pipx libportaudio2
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3 python3-pipx portaudio
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --needed python python-pipx portaudio
  else
    printf '%s\n' 'Install Python 3.11+, pipx, and PortAudio with your distribution package manager, then run this command again.' >&2
    exit 1
  fi
fi

pipx ensurepath
pipx install --force "$SOURCE"
printf '%s\n' 'Wire installed. Open a new terminal and run: wire'
