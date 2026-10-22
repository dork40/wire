#!/usr/bin/env sh
set -eu

SOURCE=${1:-'https://github.com/dork40/wire/archive/refs/heads/main.zip'}

# Termux (Android) has no sudo, uses `pkg`/`apt` without root, and cannot
# build the native voice-call/screen-share stack (aiortc, PyAV, portaudio).
# Install Wire there as a plain encrypted texting app: chat, friends,
# do-not-disturb, and encrypted file transfer all work fully; /call and
# /share report that media packages are not installed on this device.
if [ -n "${TERMUX_VERSION:-}" ] || [ -d /data/data/com.termux/files ]; then
  pkg update -y
  pkg install -y python python-pip
  pip install --user pipx
  python -m pipx ensurepath
  python -m pipx install --force "$SOURCE"
  printf '%s\n' 'Wire installed for this phone terminal (chat/friends/files; voice calls and screen sharing are desktop-only). Open a new terminal and run: wire'
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1 || ! command -v pipx >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-venv pipx libportaudio2
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3 python3-pipx portaudio
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --needed python python-pipx portaudio
  else
    printf '%s\n' 'Install Python 3.11+, pipx, and PortAudio with your distribution package manager, then run this command again.' >&2
    exit 1
  fi
fi

pipx ensurepath
pipx install --force "wire-messenger[media] @ $SOURCE"
printf '%s\n' 'Wire installed. Open a new terminal and run: wire'
