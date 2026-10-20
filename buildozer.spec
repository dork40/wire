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

[buildozer]
log_level = 2
warn_on_root = 1
