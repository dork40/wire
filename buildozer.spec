[app]
title = Wire
package.name = wire
package.domain = net.dork40

source.dir = .
source.include_exts = py,kv,png,jpg,ttf,atlas
source.exclude_dirs = tests,build,dist,dist-wheel,package,.venv,.git,.github,truenas-app,wire-data,wire-server-data,scripts,.ruff_cache,__pycache__,.buildozer,bin,.kivy
source.exclude_patterns = *.zip,wire-server.py,wire-web.py,wire.spec,wire-server.spec,install-wire.*,publish-wire.ps1,make-truenas-yaml.ps1,compose.yaml,Dockerfile,release-manifest.json,requirements.txt,run.ps1

version = 0.1.0
# Chat/friends/files/DND only: aiortc, PyAV, and portaudio-backed voice and
# screen-share packages are not installable here (see wire.py's MEDIA_AVAILABLE
# guard), same as on Termux. cryptography needs a Rust toolchain that does not
# cross-compile reliably for Android, so this build uses wire_crypto_android.py
# (pycryptodome-based, verified byte-for-byte against cryptography) instead -
# wire.py picks it automatically when `cryptography` is not importable.
requirements = python3,kivy==2.3.1,pillow,pycryptodome

orientation = portrait
fullscreen = 0

android.permissions = INTERNET
android.api = 34
android.minapi = 24
android.ndk = 25b
android.archs = arm64-v8a
android.allow_backup = True
android.accept_sdk_license = True

p4a.bootstrap = sdl2
# python-for-android's auto-added pure-Python dependency install step
# (certifi/chardet/filetype/idna/requests/six/urllib3 - not anything this
# app requested) dropped the --platform/--python-version flags on its real
# (non-dry-run) pip install inside a throwaway venv, so pip correctly
# refused the android-tagged wheel it had just resolved. Fixed upstream by
# kivy/python-for-android#3366 ("Remove venv creation for python package
# install stage", merged 2026-08-24) - not in any tagged release yet, so
# pin to develop instead of the last release (v2026.05.09, which predates
# the fix and still fails) until one ships.
p4a.branch = develop

[buildozer]
log_level = 2
warn_on_root = 1
