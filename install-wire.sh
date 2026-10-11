#!/usr/bin/env sh
set -eu
SOURCE=${1:-'git+https://github.com/dork40/wire.git'}
python3 -m pip install --user --upgrade pipx
python3 -m pipx ensurepath
python3 -m pipx install --force "$SOURCE"
printf '%s\n' 'Wire installed. Open a new terminal and run: wire'
