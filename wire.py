"""wire: a small direct encrypted terminal chat for Windows."""

from __future__ import annotations

import base64
import binascii
import ctypes
import multiprocessing as mp
import queue
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
import shutil
import sys
import threading
import time
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version as package_version
from pathlib import Path
from typing import Callable, Optional

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from PIL import Image, ImageSequence
try:
    import tkinter as tk
    from PIL import ImageTk
except ImportError:
    # Chat, encrypted files, and identity recovery must work on minimal Linux
    # installs even when an optional graphical screen-share viewer is absent.
    tk = None
    ImageTk = None
Image.MAX_IMAGE_PIXELS = 50_000_000
import numpy as np
from pywebrtc_audio import AudioProcessor
import mss
from wire_webrtc import WebRTCShare, configure_turn, network_diagnostics, probe_h264_hardware

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.filters import Condition
    from prompt_toolkit.layout.containers import ConditionalContainer, Window
    from prompt_toolkit.layout.controls import FormattedTextControl
    from prompt_toolkit.patch_stdout import patch_stdout
    from prompt_toolkit.utils import is_dumb_terminal
except ImportError:
    PromptSession = None
    Condition = ConditionalContainer = Window = FormattedTextControl = None
    patch_stdout = None
    is_dumb_terminal = None

try:
    import msvcrt
except ImportError:
    msvcrt = None

try:
    import sounddevice as sd
    from pynput import keyboard
except ImportError:
    sd = None
    keyboard = None

APP = "wire"
PORT = 46565
DEFAULT_DIRECTORY_HOST = "wirecmd.ddns.net"
DEFAULT_DIRECTORY_PORT = 47666
RELEASE_MANIFEST_URL = "https://api.github.com/repos/dork40/wire/contents/release-manifest.json?ref=main"
RELEASE_SIGNING_PUBLIC_KEY = "BRO0YhoJwdmaB3ezYutx7VVbaSI205xR2x0pjS+H53M="
# Account data must never live beside a versioned package/executable.  Updates,
# pipx environments and portable builds can be replaced without losing users.
if os.name == "nt":
    DATA = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "Wire"
else:
    DATA = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "wire"
USERS = DATA / "users.json"
SERVER_CONFIG = DATA / "server.json"
HISTORY_DIR = DATA / "history"
CONTACTS_DIR = DATA / "contacts"
SETTINGS_FILE = DATA / "settings.json"
DIRECTORY_KEYS_FILE = DATA / "directory-keys.json"
DOWNLOADS_DIR = Path.home() / "Downloads" / "Wire"
DIAGNOSTIC_LOG = DATA / "wire-diagnostics.log"


def parse_directory_endpoint(value: str) -> tuple[str, int]:
    """Parse a private Wire host without accepting URLs or shell-like input."""
    raw = value.strip()
    if not raw:
        raise ValueError("use: /private <server-ip-or-name>[:port]")
    if "://" in raw or any(char.isspace() for char in raw) or any(char in raw for char in "/\\@?#"):
        raise ValueError("enter only a server IP or DNS name, optionally followed by :port")
    host, port = raw, DEFAULT_DIRECTORY_PORT
    if raw.startswith("["):
        closing = raw.find("]")
        if closing < 0:
            raise ValueError("invalid IPv6 address")
        host = raw[1:closing]
        suffix = raw[closing + 1:]
        if suffix:
            if not suffix.startswith(":"):
                raise ValueError("invalid private server address")
            port = int(suffix[1:])
    elif raw.count(":") == 1:
        possible_host, possible_port = raw.rsplit(":", 1)
        if possible_port.isdigit():
            host, port = possible_host, int(possible_port)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if (len(host) > 253 or not re.fullmatch(
                r"(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?", host)):
            # The pattern above intentionally excludes spaces, underscores and
            # punctuation that cannot occur in a normal DNS hostname.
            raise ValueError("invalid private server IP or DNS name")
    if not 1 <= port <= 65535:
        raise ValueError("server port must be between 1 and 65535")
    return host.rstrip("."), port


def load_directory_config() -> dict:
    try:
        saved = json.loads(SERVER_CONFIG.read_text(encoding="utf-8"))
        host, port = str(saved["host"]), int(saved["port"])
        if not 1 <= port <= 65535:
            raise ValueError
        inferred_mode = "public" if host.lower() == DEFAULT_DIRECTORY_HOST and port == DEFAULT_DIRECTORY_PORT else "private"
        mode = saved.get("mode") if saved.get("mode") in ("public", "private") else inferred_mode
        return {"mode": mode, "host": host, "port": port}
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {"mode": "public", "host": DEFAULT_DIRECTORY_HOST, "port": DEFAULT_DIRECTORY_PORT}


def save_directory_config(mode: str, host: str, port: int) -> None:
    replace_private_bytes(SERVER_CONFIG, json.dumps({"mode": mode, "host": host, "port": port}).encode("utf-8"))
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
MAX_IMAGE_BYTES = 20 * 1024 * 1024
IMAGE_CHUNK_BYTES = 40 * 1024
MAX_FILE_BYTES = 500 * 1024 * 1024
MAX_MESSAGE_CHARS = 32_000
FILE_CHUNK_BYTES = 64 * 1024
# The directory accepts up to 1 MB frames, but small chunks avoid making text,
# voice, and control packets wait behind a huge encoded video/file packet.
RELAY_FILE_CHUNK_BYTES = 24 * 1024
# Conservative fallback for older directories that do not advertise their
# relay capacity. Newer directories negotiate a much higher safe pace.
RELAY_UPLOAD_BYTES_PER_SECOND = 4 * 1024 * 1024
RELAY_UPLOAD_EXPANSION = 1.42
VIDEO_EXTENSIONS = {".mp4", ".mkv", ".webm", ".avi", ".mov", ".m4v"}
TRANSFER_TEMP_DIR = DATA / "transfer-temp"
STREAM_RESOLUTIONS = [(640, 360), (854, 480), (1280, 720), (1600, 900), (1920, 1080), (2560, 1440), (3840, 2160)]
# The Python/aiortc path cannot honestly sustain 90/120 FPS across supported
# hardware. Keep the menu to targets it can reasonably measure and report.
STREAM_FPS = [15, 24, 30, 60]
# This is a target, not a promise: actual FPS also depends on the PC and LAN.
STREAM_BITRATES = [1, 2, 4, 8, 12, 20, 35, 50]
STREAM_PROFILES = ("auto", "low-resource", "balanced", "smooth", "gaming", "ultra")
TRANSFER_ID_RE = re.compile(r"^[0-9a-f]{32}$")
# OWASP-equivalent scrypt work factor with modest RAM use for older laptops.
CURRENT_KDF = {"name": "scrypt", "n": 2**14, "r": 8, "p": 5}
PRINT_LOCK = threading.Lock()
ACTIVE_PROMPT = "wire"
SAFE_PROMPT_ACTIVE = False
PROMPT_APPLICATION = None
PROMPT_WAITING = False
PENDING_OUTPUT: list[str] = []
PROMPT_REFRESH_LOCK = threading.Lock()
PROMPT_REFRESH_TIMER: Optional[threading.Timer] = None


def migrate_portable_data() -> None:
    """One-time migration from old project / portable locations; never overwrites data."""
    if USERS.exists():
        return
    candidates = [Path(__file__).with_name("wire-data"), Path(sys.executable).parent / "wire-data"]
    for legacy in candidates:
        if not (legacy / "users.json").exists():
            continue
        DATA.mkdir(parents=True, exist_ok=True)
        for source in legacy.iterdir():
            destination = DATA / source.name
            if destination.exists(): continue
            if source.is_dir(): shutil.copytree(source, destination)
            else: shutil.copy2(source, destination)
        break


migrate_portable_data()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def derive(password: str, salt: bytes, parameters: Optional[dict] = None) -> bytes:
    """Derive an account key; untagged accounts retain their legacy settings."""
    params = parameters if isinstance(parameters, dict) else {"n": 2**14, "r": 8, "p": 1}
    n, r, p = int(params.get("n", 2**14)), int(params.get("r", 8)), int(params.get("p", 1))
    if n not in (2**14, 2**15, 2**16, 2**17) or r != 8 or not 1 <= p <= 5:
        raise ValueError("unsupported password protection parameters")
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)


def safe_terminal_text(value: object) -> str:
    """Remove terminal commands while preserving ordinary Unicode and newlines."""
    text = str(value)
    return "".join(char for char in text if char in "\n\t" or (ord(char) >= 32 and not 127 <= ord(char) <= 159))


def valid_transfer_id(value: object) -> bool:
    return isinstance(value, str) and TRANSFER_ID_RE.fullmatch(value) is not None


def valid_share_offer(offer: object, expected_id: object = None) -> bool:
    """Reject malformed WebRTC metadata before it reaches native media code."""
    if not isinstance(offer, dict) or not valid_transfer_id(offer.get("id")):
        return False
    if expected_id is not None and offer["id"] != expected_id:
        return False
    resolution = offer.get("resolution")
    if (not isinstance(resolution, (list, tuple)) or len(resolution) != 2
            or any(isinstance(value, bool) or not isinstance(value, int) or not 240 <= value <= 8192
                   for value in resolution)):
        return False
    fps = offer.get("fps")
    if isinstance(fps, bool) or not isinstance(fps, int) or not 1 <= fps <= 240:
        return False
    codec = offer.get("codec", "auto")
    return (isinstance(offer.get("sdp"), str) and 0 < len(offer["sdp"]) <= 2_000_000
            and isinstance(offer.get("type", "offer"), str)
            and isinstance(codec, str) and len(codec) <= 16)


def protect_private_path(path: Path, directory: bool = False) -> None:
    """Use owner-only permissions where POSIX permissions are meaningful."""
    if os.name == "nt":
        return
    try:
        path.chmod(0o700 if directory else 0o600)
    except OSError:
        pass


def replace_private_bytes(target: Path, payload: bytes) -> None:
    """Atomically replace private client state so interruption cannot truncate it."""
    target.parent.mkdir(parents=True, exist_ok=True)
    protect_private_path(target.parent, directory=True)
    temporary = target.parent / f".{target.name}.{uuid.uuid4().hex}.tmp"
    try:
        temporary.write_bytes(payload)
        protect_private_path(temporary)
        temporary.replace(target)
        protect_private_path(target)
    finally:
        temporary.unlink(missing_ok=True)


def pin_directory_public(host: str, port: int, server_public: bytes) -> None:
    if len(server_public) != 32:
        raise ConnectionError("directory TLS identity is invalid")
    configured = os.environ.get("WIRE_DIRECTORY_KEY")
    if configured:
        try:
            expected = unb64(configured)
        except Exception as exc:
            raise ConnectionError("WIRE_DIRECTORY_KEY is not valid base64") from exc
        if not hmac.compare_digest(server_public, expected):
            raise ConnectionError("directory signing key does not match WIRE_DIRECTORY_KEY")
    endpoint = f"{host.lower()}:{port}"
    try:
        pins = json.loads(DIRECTORY_KEYS_FILE.read_text(encoding="utf-8"))
        if not isinstance(pins, dict):
            pins = {}
    except (OSError, json.JSONDecodeError):
        pins = {}
    encoded = b64(server_public)
    if endpoint in pins and not hmac.compare_digest(str(pins[endpoint]), encoded):
        raise ConnectionError("SAFETY WARNING: directory identity changed; connection refused")
    if endpoint not in pins:
        DATA.mkdir(parents=True, exist_ok=True)
        protect_private_path(DATA, directory=True)
        pins[endpoint] = encoded
        temporary = DIRECTORY_KEYS_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(pins, indent=2), encoding="utf-8")
        protect_private_path(temporary)
        temporary.replace(DIRECTORY_KEYS_FILE)
        protect_private_path(DIRECTORY_KEYS_FILE)
        say(f"saved directory safety identity: {fingerprint(server_public)}")


def open_directory_socket(host: str, port: int, timeout: float) -> tuple[ssl.SSLSocket, bytes]:
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        secure = context.wrap_socket(raw, server_hostname=host)
        certificate = x509.load_der_x509_certificate(secure.getpeercert(binary_form=True))
        public = certificate.public_key()
        if not isinstance(public, ed25519.Ed25519PublicKey):
            raise ConnectionError("directory TLS certificate uses an unsupported key")
        server_public = public.public_bytes_raw()
        pin_directory_public(host, port, server_public)
        return secure, server_public
    except Exception:
        raw.close()
        raise


def load_users() -> dict:
    if not USERS.exists():
        return {}
    users = json.loads(USERS.read_text(encoding="utf-8"))
    # Older releases stored the complete password-derived encryption key as a
    # password "check". Fernet authentication already verifies the password,
    # so delete that dangerous duplicate immediately, before login.
    changed = False
    for account in users.values() if isinstance(users, dict) else ():
        if isinstance(account, dict) and "check" in account:
            account.pop("check", None)
            changed = True
    if changed:
        save_users(users)
    return users


def save_users(users: dict) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    protect_private_path(DATA, directory=True)
    temp = USERS.with_suffix(".tmp")
    temp.write_text(json.dumps(users, indent=2), encoding="utf-8")
    protect_private_path(temp)
    temp.replace(USERS)
    protect_private_path(USERS)


def load_settings() -> dict:
    try:
        saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        noise = saved.get("voice_noise", 2 if saved.get("voice_effects", True) else 0)
        return {"notifications": bool(saved.get("notifications", True)), "do_not_disturb": bool(saved.get("do_not_disturb", False)), "allow_group_invites": bool(saved.get("allow_group_invites", True)), "voice_input": saved.get("voice_input"), "voice_output": saved.get("voice_output"), "voice_mode": saved.get("voice_mode", "ptt"), "voice_effects": bool(saved.get("voice_effects", True)), "voice_echo": bool(saved.get("voice_echo", saved.get("voice_effects", True))), "voice_noise": max(0, min(3, int(noise))), "voice_gain": bool(saved.get("voice_gain", True)), "stream_source": saved.get("stream_source", "monitor") if saved.get("stream_source", "monitor") in ("monitor", "window") else "monitor", "stream_window": str(saved.get("stream_window", ""))[:256], "stream_monitor": max(1, int(saved.get("stream_monitor", 1))), "stream_resolution": max(0, min(len(STREAM_RESOLUTIONS) - 1, int(saved.get("stream_resolution", 2)))), "stream_fps": max(0, min(len(STREAM_FPS) - 1, int(saved.get("stream_fps", 2)))), "stream_bitrate": max(0, min(len(STREAM_BITRATES) - 1, int(saved.get("stream_bitrate", 3)))), "stream_profile": saved.get("stream_profile", "auto") if saved.get("stream_profile", "auto") in STREAM_PROFILES else "auto", "stream_codec": saved.get("stream_codec", "auto"), "stream_hardware": bool(saved.get("stream_hardware", True)), "stream_system_audio": bool(saved.get("stream_system_audio", False)), "stream_latency": saved.get("stream_latency", "low")}
    except Exception:
        return {"notifications": True, "do_not_disturb": False, "allow_group_invites": True, "voice_input": None, "voice_output": None, "voice_mode": "ptt", "voice_effects": True, "voice_echo": True, "voice_noise": 2, "voice_gain": True, "stream_source": "monitor", "stream_window": "", "stream_monitor": 1, "stream_resolution": 2, "stream_fps": 2, "stream_bitrate": 3, "stream_profile": "auto", "stream_codec": "auto", "stream_hardware": True, "stream_system_audio": False, "stream_latency": "low"}


def save_settings(settings: dict) -> None:
    replace_private_bytes(SETTINGS_FILE, json.dumps(settings).encode("utf-8"))


def report_background_failure(area: str, exc: BaseException) -> None:
    """Keep unexpected worker failures inspectable without exposing message data."""
    try:
        DATA.mkdir(parents=True, exist_ok=True)
        with DIAGNOSTIC_LOG.open("a", encoding="utf-8") as log:
            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {area}: {type(exc).__name__}: {exc}\n")
        protect_private_path(DIAGNOSTIC_LOG)
    except OSError:
        pass
    say(f"{area} stopped unexpectedly; details saved to {DIAGNOSTIC_LOG}")


def stream_capabilities() -> dict:
    """Probe actual codec availability; never infer support from GPU model names."""
    result = {"platform": platform.system(), "codecs": [], "webrtc": False, "hardware": "software"}
    try:
        from aiortc.rtcrtpsender import RTCRtpSender
        result["webrtc"] = True
        result["codecs"] = sorted({codec.mimeType.split("/")[-1] for codec in RTCRtpSender.getCapabilities("video").codecs if codec.mimeType.startswith("video/") and codec.mimeType not in ("video/rtx", "video/red")})
        result["hardware"] = probe_h264_hardware() or "software"
    except Exception:
        pass
    # A successful encoder probe belongs in the native media backend.  Do not advertise
    # NVENC/QSV/AMF simply because a matching adapter name is present.
    return result


def apply_stream_profile(settings: dict) -> None:
    profiles = {
        "low-resource": (1, 2, 1), "balanced": (2, 2, 2), "smooth": (4, 3, 4),
        "gaming": (4, 3, 5), "ultra": (5, 3, 5),
    }
    if settings.get("stream_profile") in profiles:
        settings["stream_resolution"], settings["stream_fps"], settings["stream_bitrate"] = profiles[settings["stream_profile"]]


def wire_version() -> str:
    """Return the packaged version so people can confirm both PCs match."""
    base = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
    try:
        return (base / "VERSION.txt").read_text(encoding="utf-8").splitlines()[0]
    except (OSError, IndexError):
        # Running from a source checkout is common while developing Wire.
        # Prefer its declared version over stale editable-install metadata.
        try:
            project = (Path(__file__).parent / "pyproject.toml").read_text(encoding="utf-8")
            return "Wire v" + project.split('version = "', 1)[1].split('"', 1)[0]
        except (OSError, IndexError):
            pass
        try:
            return f"Wire v{package_version('wire-messenger')}"
        except PackageNotFoundError:
            return "Wire version unknown"


def version_parts(value: str) -> tuple[int, ...]:
    return tuple(int(piece) for piece in value.split(".") if piece.isdigit())


def verified_release_manifest() -> dict:
    """Fetch and authenticate the immutable commit selected for an update."""
    # raw.githubusercontent.com may retain the previous, still-valid manifest
    # briefly after a release. A unique query bypasses that CDN object; the
    # Ed25519 signature remains the authority, not the transport cache.
    manifest_url = f"{RELEASE_MANIFEST_URL}&wire={time.time_ns()}"
    request = urllib.request.Request(manifest_url, headers={"User-Agent": "Wire-Updater",
        "Accept": "application/vnd.github.raw+json", "Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=10) as response:
        manifest = json.loads(response.read().decode("utf-8"))
    version = manifest.get("version")
    commit = manifest.get("commit")
    signature_text = manifest.get("signature")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("release manifest has an invalid version")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("release manifest has an invalid commit")
    if not isinstance(signature_text, str):
        raise ValueError("release manifest has no signature")
    try:
        signature = base64.b64decode(signature_text, validate=True)
        public = base64.b64decode(RELEASE_SIGNING_PUBLIC_KEY, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("release manifest has invalid base64") from exc
    if len(signature) != 64 or len(public) != 32:
        raise ValueError("release manifest has an invalid signature")
    message = b"wire-update-v1\0" + commit.encode("ascii") + b"\0" + version.encode("ascii")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except Exception as exc:
        raise ValueError("release manifest signature verification failed") from exc
    return {"version": version, "commit": commit}


def check_for_update(quiet: bool = False) -> None:
    """Check the authenticated public release without delaying the prompt."""
    try:
        latest = verified_release_manifest()["version"]
        current = wire_version().removeprefix("Wire v")
        if current == "Wire version unknown":
            if not quiet:
                say(f"latest Wire version: {latest}")
        elif version_parts(latest) > version_parts(current):
            say(f"update available: {current} -> {latest}. Re-run the Wire install command.")
        elif not quiet:
            say(f"Wire is up to date ({current})")
    except Exception as exc:
        if not quiet:
            say(f"update check unavailable: {exc}")


def send_frame(sock: socket.socket, payload: dict) -> None:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("peer disconnected")
        data.extend(chunk)
    return bytes(data)


def recv_frame(sock: socket.socket) -> dict:
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    # Screen-share frames are direct, encrypted peer-to-peer JPEGs. 1080p
    # needs more than the small directory/control-packet size.
    if size > 4_000_000:
        raise ValueError("invalid packet size")
    return json.loads(recv_exact(sock, size).decode("utf-8"))


def say(text: str) -> None:
    """Print background output without damaging the active prompt buffer."""
    # `patch_stdout` wraps stdout while PromptSession is reading. It is the
    # supported prompt_toolkit mechanism for worker-thread output: it erases
    # and redraws the current input automatically, without waiting for Enter.
    if SAFE_PROMPT_ACTIVE:
        with PRINT_LOCK:
            print(text, flush=True)
        schedule_prompt_refresh()
        return
    with PRINT_LOCK:
        print(text, flush=True)


def flush_pending_output() -> None:
    with PRINT_LOCK:
        pending = PENDING_OUTPUT[:]
        PENDING_OUTPUT.clear()
    for text in pending:
        print(text, flush=True)


def redraw_prompt() -> None:
    # prompt_toolkit restores the exact unfinished input line itself.
    if SAFE_PROMPT_ACTIVE:
        return
    with PRINT_LOCK:
        print(f"{ACTIVE_PROMPT} > ", end="", flush=True)


def refresh_prompt_display() -> None:
    """Force a complete prompt redraw from its owning event-loop thread."""
    application = PROMPT_APPLICATION
    loop = getattr(application, "loop", None) if application else None
    if not application or not application.is_running or not loop:
        return

    def repaint() -> None:
        # invalidate() alone can emit nothing when prompt_toolkit believes its
        # cached screen is unchanged, even though background output moved the
        # real Windows console cursor. Reset the renderer cache first so the
        # prompt and current input buffer are physically written again.
        application.renderer.reset(_scroll=True, leave_alternate_screen=False)
        application._redraw()

    try:
        loop.call_soon_threadsafe(repaint)
    except RuntimeError:
        # Wire can be shutting down while a typing-expiry timer fires.
        pass


def schedule_prompt_refresh(delay: float = 0.3) -> None:
    """Repaint once background output has finished flushing.

    prompt_toolkit moves worker-thread output above the current input line, but
    its Windows stdout proxy flushes on a separate thread. A burst such as
    room-open plus chat history can finish after the proxy's first repaint and
    leave the live prompt visually blank until Enter is pressed. Debounce one
    final invalidate after the proxy's 0.2 second flush window so the prompt
    and any unfinished input are always visible.
    """
    if not SAFE_PROMPT_ACTIVE:
        return
    global PROMPT_REFRESH_TIMER

    def refresh() -> None:
        global PROMPT_REFRESH_TIMER
        with PROMPT_REFRESH_LOCK:
            PROMPT_REFRESH_TIMER = None
        refresh_prompt_display()

    with PROMPT_REFRESH_LOCK:
        if PROMPT_REFRESH_TIMER is not None:
            PROMPT_REFRESH_TIMER.cancel()
        PROMPT_REFRESH_TIMER = threading.Timer(delay, refresh)
        PROMPT_REFRESH_TIMER.daemon = True
        PROMPT_REFRESH_TIMER.start()


def restart_blank_prompt_after_background_output(delay: float = 0.5) -> None:
    """Finish an empty hidden prompt after a background operation.

    This is the safe equivalent of pressing Enter once: it never submits or
    clears text the user has started typing. Ending the empty prompt makes the
    main loop create a new prompt below the completed history block.
    """
    def request_restart() -> None:
        application = PROMPT_APPLICATION
        loop = getattr(application, "loop", None) if application else None
        if not application or not application.is_running or not loop:
            return

        def restart_or_repaint() -> None:
            buffer = application.current_buffer
            if not buffer.text:
                # Safely complete only an empty read. The main loop immediately
                # opens a fresh prompt below the background output, exactly as
                # if Enter had been pressed, without ever submitting user text.
                application.exit(result="")
            else:
                application.renderer.reset(_scroll=True, leave_alternate_screen=False)
                application._redraw()

        try:
            loop.call_soon_threadsafe(restart_or_repaint)
        except RuntimeError:
            pass

    # The stdout bridge writes history asynchronously. Restarting immediately
    # would let that pending history erase the freshly created prompt again.
    timer = threading.Timer(delay, request_restart)
    timer.daemon = True
    timer.start()


def read_menu_key() -> str:
    """Read one settings-menu key on Windows or a POSIX terminal."""
    if msvcrt is not None:
        key = msvcrt.getwch()
        if key in ("\x00", "\xe0"):
            return {"H": "up", "P": "down", "K": "left", "M": "right"}.get(msvcrt.getwch(), "")
        return {"\r": "enter", "\x1b": "escape"}.get(key, key)
    if not sys.stdin.isatty():
        return "escape"
    # Linux/macOS send ANSI sequences such as ESC [ A for the arrow keys.
    # Switch only this small menu to raw mode, restoring the terminal before
    # each redraw so an exception cannot leave the shell unusable.
    import select
    import termios
    import tty
    descriptor = sys.stdin.fileno()
    original = termios.tcgetattr(descriptor)
    try:
        tty.setraw(descriptor)
        key = sys.stdin.read(1)
        if key == "\x1b" and select.select([sys.stdin], [], [], 0.05)[0]:
            if sys.stdin.read(1) == "[":
                return {"A": "up", "B": "down", "C": "right", "D": "left"}.get(sys.stdin.read(1), "")
        return {"\r": "enter", "\n": "enter", "\x1b": "escape"}.get(key, key)
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, original)


def screen_viewer_process(frames: object, title: str, stop: object) -> None:
    """Render in an isolated process so the terminal remains responsive."""
    if os.name == "nt":
        try:
            os.environ["PYGAME_HIDE_SUPPORT_PROMPT"] = "1"
            import pygame
            from pygame._sdl2.video import Renderer, Texture, Window, get_drivers
            pygame.init()
            window = Window(title, size=(960, 540), resizable=True, allow_high_dpi=True)
            drivers = list(get_drivers())
            direct3d11 = next((index for index, driver in enumerate(drivers) if driver.name == "direct3d11"), -1)
            try:
                renderer = Renderer(window, index=direct3d11, accelerated=1, vsync=True)
            except pygame.error:
                renderer = Renderer(window, accelerated=-1, vsync=True)
            renderer.draw_color = (0, 0, 0, 255)
            texture = None
            fullscreen = False
            while not stop.is_set():
                for event in pygame.event.get():
                    if event.type == pygame.QUIT:
                        stop.set()
                    elif event.type == pygame.KEYDOWN and (event.key == pygame.K_F11 or
                            event.key == pygame.K_RETURN and event.mod & pygame.KMOD_ALT):
                        fullscreen = not fullscreen
                        window.set_fullscreen(desktop=True) if fullscreen else window.set_windowed()
                newest = None
                try:
                    while True:
                        newest = frames.get_nowait()
                except queue.Empty:
                    pass
                if newest is not None:
                    height, width = newest.shape[:2]
                    surface = pygame.image.frombuffer(newest, (width, height), "RGB")
                    if texture is None or texture.width != width or texture.height != height:
                        texture = Texture(renderer, (width, height), streaming=True, scale_quality=1)
                    texture.update(surface)
                    window_width, window_height = window.size
                    scale = min(window_width / width, window_height / height)
                    shown_width, shown_height = round(width * scale), round(height * scale)
                    destination = pygame.Rect((window_width - shown_width) // 2,
                                              (window_height - shown_height) // 2,
                                              shown_width, shown_height)
                    renderer.clear()
                    texture.draw(dstrect=destination)
                    renderer.present()
                else:
                    pygame.time.wait(5)
            window.destroy()
            pygame.quit()
            return
        except (ImportError, OSError, RuntimeError):
            # Older Windows/RDP environments may not expose a hardware SDL
            # renderer. The Tk path keeps those systems functional.
            pass
    # Tk owns its interpreter in this process; never create it on a worker thread.
    if tk is None or ImageTk is None:
        return
    root = tk.Tk(); root.title(title)
    label = tk.Label(root, text="Connecting encrypted WebRTC video...", bg="black", fg="white"); label.pack()
    closed = False
    def close() -> None:
        nonlocal closed
        closed = True; root.destroy()
    def draw() -> None:
        if closed: return
        if stop.is_set():
            close()
            return
        newest = None
        try:
            while True: newest = frames.get_nowait()
        except queue.Empty: pass
        if newest is not None:
            shown = ImageTk.PhotoImage(Image.fromarray(newest))
            label.configure(image=shown, text=""); label.image = shown
        root.after(15, draw)
    root.protocol("WM_DELETE_WINDOW", close); root.after(15, draw); root.mainloop()


def wire_console_is_foreground() -> bool:
    """True only when the Windows console hosting Wire is the active window."""
    if os.name != "nt":
        return False
    try:
        console = ctypes.windll.kernel32.GetConsoleWindow()
        return bool(console and ctypes.windll.user32.GetForegroundWindow() == console)
    except Exception:
        # If Windows Terminal does not expose a legacy console HWND, prefer a
        # notification over accidentally hiding every notification.
        return False


def toast(text: str) -> None:
    """Show a Windows notification without needing a packaged-app AUMID.

    WinRT toast notifications are silently discarded for many unpackaged console
    apps because Windows has no Start-menu registration for their app identity.
    A short-lived tray icon is reliable for a `wire` command installed by pipx.
    """
    if os.name != "nt" or wire_console_is_foreground():
        return
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    script = (
        "Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing;"
        "$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "'));"
        "$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Information;"
        "$n.Visible=$true;$n.BalloonTipTitle='Wire';$n.BalloonTipText=$t;"
        "$n.ShowBalloonTip(5000);[System.Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 5200;$n.Dispose()"
    )
    try:
        subprocess.Popen(["powershell.exe", "-NoProfile", "-STA", "-WindowStyle", "Hidden", "-Command", script],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


def start_update_after_exit() -> None:
    """Install the immutable Git commit authorized by the signed manifest."""
    if os.name != "nt":
        raise ValueError("automatic updating is currently available on Windows only")
    release = verified_release_manifest()
    current = wire_version().removeprefix("Wire v")
    if current != "Wire version unknown" and version_parts(release["version"]) <= version_parts(current):
        raise ValueError(f"Wire is already up to date ({current})")
    commit = release["commit"]
    source = f"https://github.com/dork40/wire/archive/{commit}.zip"
    script = (
        f"$wirePid = {os.getpid()}; "
        "Wait-Process -Id $wirePid -ErrorAction SilentlyContinue; "
        "$servers = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -like '*pipx\\pipx\\venvs\\wire-messenger*' -and $_.CommandLine -match 'wire-server\\.py|wire-server\\.exe' }); "
        "if ($servers) { $servers | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }; "
        f"py -m pipx install --force '{source}'; "
        "Write-Host ''; Read-Host 'Update complete. Press Enter to close this window'"
    )
    flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    subprocess.Popen(["powershell.exe", "-NoProfile", "-Command", script],
                     creationflags=flags)


def enable_terminal_color() -> None:
    """Ask classic CMD to interpret 24-bit ANSI color escapes when it supports them."""
    if os.name != "nt":
        return
    try:
        handle = ctypes.windll.kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint()
        if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def ensure_local_directory() -> None:
    """Start the bundled directory only when one is not already listening."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.2)
    try:
        probe.connect(("127.0.0.1", 47666))
        return
    except OSError:
        pass
    finally:
        probe.close()
    try:
        server_command = (
            [str(Path(sys.executable).with_name("wire-server.exe"))]
            if getattr(sys, "frozen", False)
            else [sys.executable, str(Path(__file__).with_name("wire-server.py"))]
        )
        subprocess.Popen(
            server_command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        time.sleep(0.2)
    except OSError:
        pass


def local_directory_requested() -> bool:
    """Keep the optional local directory from locking the installed updater."""
    if os.environ.get("WIRE_LOCAL_DIRECTORY") == "1":
        return True
    try:
        return load_directory_config()["host"].lower() in ("localhost", "127.0.0.1", "::1")
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return False


def fingerprint(public_key: bytes) -> str:
    digest = hashlib.sha256(public_key).hexdigest().upper()
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def login_proof_bytes(name: str, nonce: bytes) -> bytes:
    return b"wire-login-v1\0" + name.lower().encode("utf-8") + b"\0" + nonce


def directory_proof_bytes(name: str, public: bytes, sign_public: bytes, nonce: bytes) -> bytes:
    return b"wire-directory-v1\0" + name.lower().encode("utf-8") + b"\0" + public + sign_public + nonce


def directory_identity_bytes(name: str, public: bytes, sign_public: bytes) -> bytes:
    return b"wire-directory-identity-v1\0" + name.lower().encode("utf-8") + b"\0" + public + sign_public


def peer_hello_bytes(name: str, public: bytes, sign_public: bytes, nonce: bytes, timestamp: int) -> bytes:
    return (b"wire-peer-hello-v2\0" + name.lower().encode("utf-8") + b"\0" + public
            + sign_public + nonce + struct.pack("!q", timestamp))


@dataclass
class Peer:
    name: str
    sock: Optional[socket.socket]
    key: bytes
    public_key: bytes
    relay: Optional[Callable[[dict], None]] = None
    # Voice capture, acknowledgements, file workers, and the command loop can
    # all send at once.  A direct socket is a byte stream, so protect its
    # length-prefixed packets from being interleaved by those threads.
    send_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    seen_nonces: set[str] = field(default_factory=set, repr=False)
    nonce_order: list[str] = field(default_factory=list, repr=False)

    def accept_nonce(self, packet: dict) -> bool:
        encoded = packet.get("nonce")
        if not isinstance(encoded, str):
            return False
        try:
            if len(unb64(encoded)) != 12:
                return False
        except Exception:
            return False
        if encoded in self.seen_nonces:
            return False
        self.seen_nonces.add(encoded)
        self.nonce_order.append(encoded)
        if len(self.nonce_order) > 4096:
            self.seen_nonces.discard(self.nonce_order.pop(0))
        return True

    def _send_packet(self, packet: dict) -> None:
        if self.relay:
            self.relay(packet)
        elif self.sock:
            with self.send_lock:
                send_frame(self.sock, packet)
        else:
            raise ConnectionError("room is no longer connected")

    def send(self, text: str, message_id: str, reply_to: str | None = None) -> None:
        if len(text) > MAX_MESSAGE_CHARS:
            raise ValueError(f"message is too long ({MAX_MESSAGE_CHARS} character maximum)")
        nonce = os.urandom(12)
        data = AESGCM(self.key).encrypt(nonce, text.encode("utf-8"), b"wire-v1-message")
        packet = {"type": "msg", "id": message_id, "reply_to": reply_to, "nonce": b64(nonce), "data": b64(data)}
        self._send_packet(packet)

    def send_image_frame(self, frame: dict) -> None:
        nonce = os.urandom(12)
        raw = json.dumps(frame, separators=(",", ":")).encode("utf-8")
        data = AESGCM(self.key).encrypt(nonce, raw, b"wire-v1-image")
        packet = {"type": "image", "nonce": b64(nonce), "data": b64(data)}
        self._send_packet(packet)

    def send_voice_frame(self, frame: dict) -> None:
        nonce = os.urandom(12)
        data = AESGCM(self.key).encrypt(nonce, json.dumps(frame, separators=(",", ":")).encode("utf-8"), b"wire-v1-voice")
        packet = {"type": "voice", "nonce": b64(nonce), "data": b64(data)}
        self._send_packet(packet)

    def send_control(self, frame: dict) -> None:
        """Small encrypted control message; works through every deployed relay."""
        nonce = os.urandom(12)
        data = AESGCM(self.key).encrypt(nonce, json.dumps(frame, separators=(",", ":")).encode("utf-8"), b"wire-v1-control")
        packet = {"type": "control", "nonce": b64(nonce), "data": b64(data)}
        self._send_packet(packet)

    def send_audio(self, audio: bytes) -> None:
        nonce = os.urandom(12)
        data = AESGCM(self.key).encrypt(nonce, audio, b"wire-v1-audio")
        packet = {"type": "audio", "nonce": b64(nonce), "data": b64(data)}
        self._send_packet(packet)

    def send_file_frame(self, frame: dict) -> None:
        """Send one encrypted attachment frame through the existing relay."""
        nonce = os.urandom(12)
        raw = json.dumps(frame, separators=(",", ":")).encode("utf-8")
        data = AESGCM(self.key).encrypt(nonce, raw, b"wire-v1-file-relay")
        packet = {"type": "file_relay", "nonce": b64(nonce), "data": b64(data)}
        self._send_packet(packet)


class VoiceCall:
    """One encrypted, push-to-talk audio stream. Hold F12 to transmit."""
    def __init__(self, peer: Peer, settings: dict) -> None:
        if sd is None or keyboard is None:
            raise ValueError("voice support is not installed; restart Wire after updating")
        self.peer = peer
        self.settings = settings
        self.processor_lock = threading.Lock()
        self.processor = self.make_processor()
        self.far_audio = np.zeros(960, dtype=np.int16)
        self.audio_lock = threading.Lock()
        self.error_reported: set[str] = set()
        self.sent_frames = 0
        self.received_frames = 0
        self.talking = threading.Event()
        self.output = sd.RawOutputStream(samplerate=48000, channels=1, dtype="int16", blocksize=960, device=settings.get("voice_output"))
        self.input = sd.RawInputStream(samplerate=48000, channels=1, dtype="int16", blocksize=960, device=settings.get("voice_input"), callback=self.capture)
        self.listener = keyboard.Listener(on_press=self.press, on_release=self.release)
        self.output.start()
        self.input.start()
        self.listener.start()

    def make_processor(self) -> AudioProcessor:
        noise_level = int(self.settings.get("voice_noise", 2))
        return AudioProcessor(sample_rate=48000, num_channels=1,
                              echo_cancellation=bool(self.settings.get("voice_echo", True)),
                              noise_suppression=noise_level > 0,
                              high_pass_filter=True,
                              auto_gain_control=bool(self.settings.get("voice_gain", True)),
                              ns_level=noise_level, stream_delay_ms=40)

    def apply_settings(self) -> None:
        """Apply activation and audio-cleanup changes to an already live call."""
        with self.processor_lock:
            self.processor = self.make_processor()

    def press(self, key) -> None:
        if key == keyboard.Key.f12:
            self.talking.set()

    def release(self, key) -> None:
        if key == keyboard.Key.f12:
            self.talking.clear()

    def capture(self, indata, frames, timing, status) -> None:
        if self.talking.is_set() or self.settings.get("voice_mode") == "open":
            try:
                near = np.frombuffer(bytes(indata), dtype=np.int16)
                with self.audio_lock:
                    far = self.far_audio.copy()
                with self.processor_lock:
                    processor = self.processor
                clean = processor.process(near, far)
                self.peer.send_audio(np.asarray(clean, dtype=np.int16).tobytes())
                self.sent_frames += 1
            except Exception as exc:
                self.talking.clear()
                self.report_error("microphone", exc)

    def play(self, audio: bytes) -> None:
        try:
            samples = np.frombuffer(audio, dtype=np.int16)
            with self.audio_lock:
                self.far_audio = samples.copy()
            self.output.write(audio)
            self.received_frames += 1
        except Exception as exc:
            self.report_error("speaker", exc)

    def report_error(self, device: str, exc: Exception) -> None:
        """Show the first real device error instead of silently losing audio."""
        if device not in self.error_reported:
            self.error_reported.add(device)
            say(f"voice {device} error: {exc}")

    def close(self) -> None:
        self.talking.clear()
        for item in (self.input, self.output, self.listener):
            try:
                item.stop()
                item.close()
            except Exception:
                pass


class Wire:
    def __init__(self) -> None:
        self.name: Optional[str] = None
        self.private: Optional[x25519.X25519PrivateKey] = None
        self.public: Optional[bytes] = None
        self.sign_private: Optional[ed25519.Ed25519PrivateKey] = None
        self.sign_public: Optional[bytes] = None
        self.history_key: Optional[bytes] = None
        self.account_secret: Optional[bytes] = None
        self.directory_public: Optional[bytes] = None
        self.turn_configured = False
        self.history_lock = threading.Lock()
        self.peers: dict[str, Peer] = {}
        self.room: Optional[str] = None
        self.listener: Optional[socket.socket] = None
        self.server: Optional[socket.socket] = None
        self.server_lock = threading.Lock()
        # One paced budget is shared by every attachment worker.  The relay
        # limits a user, not an individual file, so separate workers must not
        # each assume they own the full bandwidth allowance.
        self.relay_upload_lock = threading.Lock()
        self.relay_next_send_at = 0.0
        self.relay_upload_bytes_per_second = RELAY_UPLOAD_BYTES_PER_SECOND
        self.requests: dict[str, str] = {}
        self.incoming_images: dict[str, dict] = {}
        self.pending_images: dict[str, dict] = {}
        self.outgoing_images: dict[str, dict] = {}
        self.calls: dict[str, VoiceCall] = {}
        self.call_requests: set[str] = set()
        self.pending_pings: dict[str, float] = {}
        self.pending_files: dict[str, dict] = {}
        self.paused_files: dict[str, dict] = {}
        self.outgoing_files: dict[str, dict] = {}
        self.incoming_files: dict[str, dict] = {}
        self.pending_shares: dict[str, dict] = {}
        self.webrtc_shares: dict[str, WebRTCShare] = {}
        self.share_peers: dict[str, str] = {}
        self.share_viewers: dict[str, mp.Process] = {}
        self.share_viewer_stops: dict[str, object] = {}
        self.groups: dict[str, dict] = {}
        self.group_invites: dict[str, str] = {}
        self.typing_until: dict[str, float] = {}
        self.typing_timers: dict[str, threading.Timer] = {}
        self.last_typing_sent = 0.0
        self.typing_notifier: Optional[Callable[[], None]] = None
        self.group_room: Optional[str] = None
        self.settings = load_settings()
        self.closing = threading.Event()
        self.background_threads: set[threading.Thread] = set()
        self.background_threads_lock = threading.Lock()
        self.direct_handshake_slots = threading.BoundedSemaphore(16)
        self.pending_sockets: set[socket.socket] = set()
        self.pending_sockets_lock = threading.Lock()

    def start_worker(self, target: Callable, *args: object) -> threading.Thread:
        """Track workers so shutdown can drain them before Python finalizes stdout."""
        def run() -> None:
            try:
                target(*args)
            finally:
                with self.background_threads_lock:
                    self.background_threads.discard(threading.current_thread())
        worker = threading.Thread(target=run, daemon=True)
        with self.background_threads_lock:
            self.background_threads.add(worker)
        worker.start()
        return worker

    def signup(self, name: str) -> None:
        if not name.isalnum() or not 3 <= len(name) <= 24:
            raise ValueError("username must be 3-24 letters/numbers")
        users = load_users()
        if name.lower() in users:
            raise ValueError("that username already exists on this PC")
        first = getpass.getpass("password: ")
        second = getpass.getpass("again: ")
        if first != second:
            raise ValueError("passwords do not match")
        salt = os.urandom(16)
        secret = derive(first, salt, CURRENT_KDF)
        private = x25519.X25519PrivateKey.generate()
        sign_private = ed25519.Ed25519PrivateKey.generate()
        raw_private = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        raw_sign_private = sign_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        sign_public = sign_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        users[name.lower()] = {"name": name, "salt": b64(salt), "kdf": dict(CURRENT_KDF),
                               "private": Fernet(base64.urlsafe_b64encode(secret)).encrypt(raw_private).decode("ascii"),
                               "public": b64(public),
                               "sign_private": Fernet(base64.urlsafe_b64encode(secret)).encrypt(raw_sign_private).decode("ascii"),
                               "sign_public": b64(sign_public)}
        save_users(users)
        say(f"made user {name}")

    def login(self, name: str) -> None:
        users = load_users()
        account = users.get(name.lower())
        password = getpass.getpass("password: ")
        if not account:
            account = self.restore_identity(name, password)
            users = load_users()
        secret = derive(password, unb64(account["salt"]), account.get("kdf"))
        try:
            raw = Fernet(base64.urlsafe_b64encode(secret)).decrypt(account["private"].encode("ascii"))
        except Exception as exc:
            raise ValueError("wrong password or damaged identity") from exc
        self.name = account["name"]
        self.private = x25519.X25519PrivateKey.from_private_bytes(raw)
        self.public = unb64(account["public"])
        if "sign_private" not in account or "sign_public" not in account:
            sign_private = ed25519.Ed25519PrivateKey.generate()
            raw_sign_private = sign_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            account["sign_private"] = Fernet(base64.urlsafe_b64encode(secret)).encrypt(raw_sign_private).decode("ascii")
            account["sign_public"] = b64(sign_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            save_users(users)
        self.sign_private = ed25519.Ed25519PrivateKey.from_private_bytes(
            Fernet(base64.urlsafe_b64encode(secret)).decrypt(account["sign_private"].encode("ascii"))
        )
        self.sign_public = unb64(account["sign_public"])
        self.history_key = base64.urlsafe_b64encode(secret)
        self.account_secret = secret
        say(f"signed in as {self.name}")
        try:
            self.connect_server()
        except (OSError, ConnectionError, ValueError) as exc:
            say(f"directory offline ({exc})")

    def restore_identity(self, name: str, password: str) -> dict:
        """Recover an identity only after proving knowledge of its password."""
        try:
            configured = load_directory_config()
            host, port = configured["host"], configured["port"]
            sock, _ = open_directory_socket(str(host), int(port), timeout=10)
            send_frame(sock, {"type": "identity_fetch", "name": name})
            reply = recv_frame(sock)
            if reply.get("type") != "identity_recovery_challenge" or not isinstance(reply.get("salt"), str):
                raise ValueError("identity recovery is unavailable")
            challenge_salt = reply["salt"]
            secret = derive(password, unb64(challenge_salt), reply.get("kdf"))
            verifier = hmac.new(secret, b"wire-v2-identity-recovery", hashlib.sha256).digest()
            challenge = reply.get("challenge")
            if isinstance(challenge, str):
                proof = hmac.new(verifier, unb64(challenge), hashlib.sha256).hexdigest()
            else:
                # One-time compatibility with an older server. A new backup
                # replaces this reusable proof as soon as login completes.
                proof = hmac.new(secret, b"wire-v1-identity-recovery", hashlib.sha256).hexdigest()
            send_frame(sock, {"type": "identity_fetch_prove", "proof": proof})
            reply = recv_frame(sock); sock.close()
            backup = reply.get("backup") if reply.get("type") == "identity_backup" else None
            if not isinstance(backup, dict): raise ValueError("no encrypted backup found")
            if not isinstance(backup.get("salt"), str) or not hmac.compare_digest(backup["salt"], challenge_salt):
                raise ValueError("backup salt did not match recovery challenge")
            account = json.loads(Fernet(base64.urlsafe_b64encode(secret)).decrypt(backup["ciphertext"].encode("ascii")).decode("utf-8"))
            if not isinstance(account, dict) or str(account.get("name", "")).lower() != name.lower(): raise ValueError("backup does not match that username")
            users = load_users(); users[name.lower()] = account; save_users(users)
            say("encrypted identity restored to this computer")
            return account
        except Exception as exc:
            raise ValueError("no local user with that name; encrypted restore was unavailable") from exc

    def backup_identity(self) -> None:
        if not self.name or not self.account_secret: return
        account = load_users().get(self.name.lower())
        if not account: return
        encrypted = Fernet(base64.urlsafe_b64encode(self.account_secret)).encrypt(json.dumps(account, separators=(",", ":")).encode("utf-8")).decode("ascii")
        recovery = hmac.new(self.account_secret, b"wire-v2-identity-recovery", hashlib.sha256).hexdigest()
        # v1.4.22's save validator still requires the legacy field, while its
        # recovery path correctly prefers the one-time challenge verifier.
        # Sending both avoids login warnings during a rolling server upgrade;
        # the reusable value is never accepted when the verifier is present.
        legacy = hmac.new(self.account_secret, b"wire-v1-identity-recovery", hashlib.sha256).hexdigest()
        self.server_send({"type": "identity_backup", "backup": {"salt": account["salt"], "kdf": account.get("kdf"),
                          "ciphertext": encrypted, "recovery_verifier": recovery, "recovery_proof": legacy}})

    def show_share_stats(self) -> None:
        if not self.webrtc_shares:
            say("no active screen share")
            return
        for share_id, media in self.webrtc_shares.items():
            stats = media.snapshot()
            bitrate = (stats.get("bitrate_bytes", 0) * 8 / max(1, stats["seconds"]) / 1_000_000)
            backend = media.capture.backend if media.capture else "waiting"
            line = (f"share {share_id[:6]}: {stats['state']}; "
                    f"{backend}; codec {media.codec_used}/{media.encoder_used}; target {media.target_bitrate / 1_000_000:.1f} Mbps; "
                    f"capture {stats['capture_fps']:.1f} fps ({stats['capture_ms']:.1f} ms); "
                    f"encode {stats['send_fps']:.1f} fps ({stats['encode_ms']:.1f} ms); "
                    f"receive {stats['receive_fps']:.1f} fps; {bitrate:.2f} Mbps")
            if stats.get("route"):
                line += f"; route {stats['route']} ({stats.get('candidate_types', 'unknown')})"
            if stats.get("adaptation") and stats["adaptation"] != "none":
                line += f"; auto {stats['adaptation']}"
            if "packets_lost" in stats:
                line += f"; lost {stats['packets_lost']}"
            if "rtt_ms" in stats:
                line += f"; RTT {stats['rtt_ms']} ms"
            say(line)

    def pause_screen_share(self, paused: bool) -> None:
        senders = [media for media in self.webrtc_shares.values() if media.capture]
        if not senders:
            raise ValueError("you are not sharing a screen")
        for media in senders:
            media.set_paused(paused)
        say("screen share paused" if paused else "screen share resumed")

    def diagnose(self, network: bool = False) -> None:
        """Report local capability checks without exposing account secrets."""
        caps = stream_capabilities()
        try:
            audio = f"{len(self.voice_devices('input'))} microphone(s), {len(self.voice_devices('output'))} speaker device(s)"
        except Exception as exc:
            audio = f"unavailable ({type(exc).__name__})"
        say("WIRE DIAGNOSTICS")
        say(f"client: {wire_version()}; {platform.system()} build {platform.version()}; Python {platform.python_version()}")
        say(f"directory: {'connected and authenticated' if self.server and self.directory_public else 'not connected'}")
        say(f"media: WebRTC {'ready' if caps['webrtc'] else 'unavailable'}; codecs {', '.join(caps['codecs']) or 'none'}")
        say(f"encoder: {caps['hardware']}; displays: {self.monitor_count()}; viewer: {'ready' if tk and ImageTk else 'unavailable'}")
        turn_ready = self.turn_configured or bool(os.environ.get("WIRE_TURN_URL", "").strip())
        say(f"audio: {audio}; TURN relay: {'configured' if turn_ready else 'not configured (direct/STUN only)'}")
        say(f"data: {DATA}; diagnostics: {DIAGNOSTIC_LOG}")
        if self.webrtc_shares:
            self.show_share_stats()
        if network:
            say("testing ICE/STUN/TURN; this can take several seconds...")
            try:
                result = network_diagnostics()
                kinds = ", ".join(result["candidate_types"]) or "none"
                say(f"network candidates: {kinds}; TURN: " +
                    ("reachable" if result["turn_reachable"] else
                     "configured but unreachable" if result["turn_configured"] else "not configured"))
            except Exception as exc:
                say(f"network test failed: {type(exc).__name__}: {exc}")

    def require_login(self) -> None:
        if not self.private or not self.public or not self.sign_private or not self.sign_public or not self.name:
            raise ValueError("sign in first")

    def verify_directory_identity(self, host: str, port: int, reply: dict, nonce: bytes) -> None:
        """Authenticate and TOFU-pin the directory's persistent signing key."""
        server_public = unb64(str(reply.get("server_sign_public", "")))
        signature = unb64(str(reply.get("server_signature", "")))
        if len(server_public) != 32 or len(signature) != 64:
            raise ConnectionError("directory does not support authenticated connections; update the server")
        ed25519.Ed25519PublicKey.from_public_bytes(server_public).verify(
            signature, directory_proof_bytes(self.name, self.public, self.sign_public, nonce)
        )
        if self.directory_public and not hmac.compare_digest(self.directory_public, server_public):
            raise ConnectionError("directory TLS and signing identities do not match")
        self.directory_public = server_public
        pin_directory_public(host, port, server_public)

    def verify_directory_peer(self, name: str, public: str, sign_public_value: str, identity_signature: str) -> tuple[bytes, bytes]:
        if not self.directory_public:
            raise ConnectionError("directory identity is not authenticated")
        peer_public, peer_sign_public = unb64(public), unb64(sign_public_value)
        signature = unb64(identity_signature)
        if len(peer_public) != 32 or len(peer_sign_public) != 32 or len(signature) != 64:
            raise ValueError("directory sent an invalid peer identity")
        ed25519.Ed25519PublicKey.from_public_bytes(self.directory_public).verify(
            signature, directory_identity_bytes(name, peer_public, peer_sign_public)
        )
        self.verify_peer_identity(name, peer_public, peer_sign_public)
        return peer_public, peer_sign_public

    def make_peer(self, sock: socket.socket, hello: dict, expected: Optional[str] = None) -> Peer:
        self.require_login()
        if hello.get("type") != "hello" or not isinstance(hello.get("name"), str) or not isinstance(hello.get("public"), str):
            raise ValueError("bad handshake")
        peer_name = hello["name"]
        if expected and peer_name.lower() != expected.lower():
            raise ValueError(f"connected peer is {peer_name}, not {expected}")
        peer_public = unb64(hello["public"])
        if len(peer_public) != 32:
            raise ValueError("bad peer key")
        sign_public = unb64(str(hello.get("sign_public", "")))
        nonce = unb64(str(hello.get("nonce", "")))
        signature = unb64(str(hello.get("signature", "")))
        timestamp = hello.get("timestamp")
        if len(sign_public) != 32 or len(nonce) != 16 or not isinstance(timestamp, int) or abs(time.time() - timestamp) > 120:
            raise ValueError("bad signed peer handshake")
        ed25519.Ed25519PublicKey.from_public_bytes(sign_public).verify(
            signature, peer_hello_bytes(peer_name, peer_public, sign_public, nonce, timestamp)
        )
        self.verify_peer_identity(peer_name, peer_public, sign_public)
        shared = self.private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"wire-v1").derive(shared)
        return Peer(peer_name, sock, key, peer_public)

    def hello(self) -> dict:
        self.require_login()
        nonce, timestamp = os.urandom(16), int(time.time())
        signature = self.sign_private.sign(peer_hello_bytes(self.name, self.public, self.sign_public, nonce, timestamp))
        return {"type": "hello", "name": self.name, "public": b64(self.public), "sign_public": b64(self.sign_public),
                "nonce": b64(nonce), "timestamp": timestamp, "signature": b64(signature)}

    def history_path(self, peer_name: str) -> Path:
        self.require_login()
        return HISTORY_DIR / f"{self.name.lower()}--{peer_name.lower()}.wire"

    def contacts_path(self) -> Path:
        self.require_login()
        return CONTACTS_DIR / f"{self.name.lower()}.wire"

    def contacts(self) -> dict:
        """Return the signed-in user's encrypted local friend and block lists."""
        empty = {"friends": [], "blocked": [], "identities": {}}
        if not self.history_key:
            return empty
        path = self.contacts_path()
        if not path.exists():
            return empty
        try:
            payload = Fernet(self.history_key).decrypt(path.read_bytes())
            contacts = json.loads(payload.decode("utf-8"))
            if not isinstance(contacts, dict):
                return empty
            return {
                "friends": [name for name in contacts.get("friends", []) if isinstance(name, str)],
                "blocked": [name for name in contacts.get("blocked", []) if isinstance(name, str)],
                "identities": contacts.get("identities", {}) if isinstance(contacts.get("identities"), dict) else {},
            }
        except Exception:
            return empty

    def save_contacts(self, contacts: dict) -> None:
        self.require_login()
        if not self.history_key:
            raise ValueError("sign in first")
        payload = json.dumps(contacts, separators=(",", ":")).encode("utf-8")
        replace_private_bytes(self.contacts_path(), Fernet(self.history_key).encrypt(payload))

    def verify_peer_identity(self, name: str, public: bytes, sign_public: bytes) -> None:
        """Trust a peer on first use and reject silent identity-key changes."""
        contacts = self.contacts()
        identities = contacts.setdefault("identities", {})
        key = name.lower()
        current = identities.get(key)
        proposed = {"public": b64(public), "sign_public": b64(sign_public)}
        if isinstance(current, dict):
            if current.get("public") != proposed["public"] or current.get("sign_public") != proposed["sign_public"]:
                raise ValueError(f"SAFETY WARNING: {name}'s identity key changed; connection refused")
            return
        identities[key] = proposed
        self.save_contacts(contacts)
        say(f"saved safety identity for {name}")

    def edit_contact(self, list_name: str, username: str, add: bool) -> None:
        self.require_login()
        username = username.strip()
        if not username.isalnum() or not 3 <= len(username) <= 24:
            raise ValueError("username must be 3-24 letters/numbers")
        if username.lower() == self.name.lower():
            raise ValueError("you cannot add yourself")
        contacts = self.contacts()
        other_name = "blocked" if list_name == "friends" else "friends"
        target = contacts[list_name]
        if add:
            contacts[other_name] = [item for item in contacts[other_name] if item.lower() != username.lower()]
            if not any(item.lower() == username.lower() for item in target):
                target.append(username)
            if list_name == "blocked":
                peer = self.peers.pop(username.lower(), None)
                if peer and self.room == username.lower():
                    self.room = None
        else:
            contacts[list_name] = [item for item in target if item.lower() != username.lower()]
        self.save_contacts(contacts)

    def is_blocked(self, username: str) -> bool:
        return any(item.lower() == username.lower() for item in self.contacts()["blocked"])

    def show_friends(self) -> None:
        self.server_send({"type": "friends_list"})

    def show_settings(self) -> None:
        say("WIRE SETTINGS")
        say("Use /settings on Windows for the arrow-key menu. Changes save automatically.")
        say(f"notifications: {'on' if self.settings['notifications'] else 'off'}")
        say(f"do not disturb: {'on' if self.settings['do_not_disturb'] else 'off'}")
        say(f"allow group invites: {'on' if self.settings['allow_group_invites'] else 'off'}")
        say(f"voice activation: {'always on' if self.settings['voice_mode'] == 'open' else 'hold F12 to talk'}")
        say(f"echo cancellation: {'on' if self.settings['voice_echo'] else 'off'}")
        say(f"noise removal: {('off', 'light', 'normal', 'strong')[self.settings['voice_noise']]}")
        say(f"auto volume: {'on' if self.settings['voice_gain'] else 'off'}")
        say("voice quality: high (48 kHz)")
        width, height = STREAM_RESOLUTIONS[self.settings["stream_resolution"]]
        caps = stream_capabilities()
        source = (f"window {self.settings['stream_window']}" if self.settings.get("stream_source") == "window"
                  else f"monitor {self.settings['stream_monitor']}")
        say(f"screen share: {source}; {self.settings['stream_profile']}; {width}x{height} at {STREAM_FPS[self.settings['stream_fps']]} FPS, {STREAM_BITRATES[self.settings['stream_bitrate']]} Mbps target")
        say(f"screen codec: {self.settings['stream_codec']}; hardware acceleration: {'on' if self.settings['stream_hardware'] else 'off'}; system audio: {'on' if self.settings['stream_system_audio'] else 'off'}; latency: {self.settings['stream_latency']}")
        say(f"WebRTC: {'available' if caps['webrtc'] else 'not installed'}; available codecs: {', '.join(caps['codecs']) or 'none'}")
        say("images: ask before download")

    def sync_preferences(self) -> None:
        """Tell the authenticated directory only the two server-enforced preferences."""
        if self.server:
            self.server_send({"type": "preferences", "dnd": self.settings["do_not_disturb"],
                              "allow_group_invites": self.settings["allow_group_invites"]})

    def sync_settings(self) -> None:
        if not self.server or not self.history_key:
            return
        payload = json.dumps({"updated": time.time_ns(), "settings": self.settings}, separators=(",", ":")).encode("utf-8")
        blob = Fernet(self.history_key).encrypt(payload).decode("ascii")
        try:
            self.server_send({"type": "sync_put_settings", "blob": blob})
        except (OSError, ConnectionError):
            pass

    def sync_record(self, peer_name: str, record: dict) -> None:
        if not self.server or not self.history_key or not valid_transfer_id(record.get("id")):
            return
        if not re.fullmatch(r"(?:group-)?[A-Za-z0-9_-]{3,40}", peer_name):
            return
        payload = json.dumps({"peer": peer_name, "record": record}, separators=(",", ":")).encode("utf-8")
        blob = Fernet(self.history_key).encrypt(payload).decode("ascii")
        try:
            self.server_send({"type": "sync_put_message", "id": record["id"], "blob": blob})
        except (OSError, ConnectionError):
            pass

    def apply_sync_state(self, packet: dict) -> None:
        if not self.history_key:
            return
        setting_blob = packet.get("settings")
        if isinstance(setting_blob, str):
            try:
                value = json.loads(Fernet(self.history_key).decrypt(setting_blob.encode("ascii")))
                remote = value.get("settings") if isinstance(value, dict) else None
                if isinstance(remote, dict):
                    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
                    replace_private_bytes(SETTINGS_FILE, json.dumps(remote).encode("utf-8"))
                    self.settings = load_settings()
            except (ValueError, InvalidTag, InvalidToken, json.JSONDecodeError):
                pass
        elif packet.get("done") and not packet.get("messages"):
            self.sync_settings()
        for item in packet.get("messages", []):
            try:
                message_id, blob = item
                value = json.loads(Fernet(self.history_key).decrypt(blob.encode("ascii")))
                peer_name, record = value["peer"], value["record"]
                if (not re.fullmatch(r"(?:group-)?[A-Za-z0-9_-]{3,40}", peer_name)
                        or not isinstance(record, dict) or record.get("id") != message_id
                        or not valid_transfer_id(message_id)
                        or not isinstance(record.get("from"), str)
                        or not isinstance(record.get("text", ""), str)
                        or len(record.get("text", "")) > MAX_MESSAGE_CHARS):
                    continue
                with self.history_lock:
                    records = self.read_history(peer_name)
                    existing = next((index for index, saved in enumerate(records) if saved.get("id") == message_id), None)
                    if existing is None:
                        records.append(record)
                    else:
                        records[existing] = record
                    encrypted = Fernet(self.history_key).encrypt(json.dumps(records[-500:], separators=(",", ":")).encode("utf-8"))
                    replace_private_bytes(self.history_path(peer_name), encrypted)
            except (ValueError, TypeError, KeyError, InvalidTag, InvalidToken, json.JSONDecodeError):
                continue

    def notifications_allowed(self) -> bool:
        return bool(self.settings["notifications"] and not self.settings["do_not_disturb"])

    def apply_voice_settings(self) -> None:
        for call in list(self.calls.values()):
            call.apply_settings()

    def voice_devices(self, direction: str) -> list[tuple[int, str]]:
        if sd is None:
            return []
        channel_key = "max_input_channels" if direction == "input" else "max_output_channels"
        return [(index, str(device["name"])) for index, device in enumerate(sd.query_devices()) if device[channel_key]]

    def monitor_count(self) -> int:
        try:
            with mss.mss() as capture:
                return max(1, len(capture.monitors) - 1)
        except Exception:
            return 1

    def share_window_handles(self) -> dict[str, int]:
        """Return visible top-level Windows titles and their current HWNDs."""
        if os.name != "nt":
            return {}
        windows = {}
        callback_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        def collect(hwnd, _param):
            if not ctypes.windll.user32.IsWindowVisible(hwnd):
                return True
            length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
            if not 0 < length <= 1024:
                return True
            buffer = ctypes.create_unicode_buffer(length + 1)
            ctypes.windll.user32.GetWindowTextW(hwnd, buffer, length + 1)
            title = safe_terminal_text(buffer.value).strip()
            if title and title not in windows and not title.startswith("Wire screen share -"):
                windows[title] = int(hwnd)
            return True
        ctypes.windll.user32.EnumWindows(callback_type(collect), 0)
        return windows

    def share_windows(self) -> list[str]:
        return list(self.share_window_handles())

    def settings_menu(self) -> None:
        """Small keyboard-only menu for Windows, Linux, and macOS terminals."""
        selected = 0
        while True:
            inputs, outputs = self.voice_devices("input"), self.voice_devices("output")
            windows = self.share_windows()
            input_id, output_id = self.settings.get("voice_input"), self.settings.get("voice_output")
            input_name = next((name for index, name in inputs if index == input_id), "Windows default")
            output_name = next((name for index, name in outputs if index == output_id), "Windows default")
            rows = [
                ("Notifications", "On" if self.settings["notifications"] else "Off"),
                ("Do Not Disturb", "On" if self.settings["do_not_disturb"] else "Off"),
                ("Allow group invites", "On" if self.settings["allow_group_invites"] else "Off"),
                ("Voice activation", "Always on" if self.settings["voice_mode"] == "open" else "Push-to-talk (F12)"),
                ("Echo cancellation", "On" if self.settings["voice_echo"] else "Off"),
                ("Noise removal", ("Off", "Light", "Normal", "Strong")[self.settings["voice_noise"]]),
                ("Auto volume", "On" if self.settings["voice_gain"] else "Off"),
                ("Microphone (next call)", input_name),
                ("Speakers (next call)", output_name),
                ("Share source", "Application window" if self.settings["stream_source"] == "window" else "Monitor"),
                ("Share window", self.settings["stream_window"] or "Choose with arrows"),
                ("Share monitor", str(min(self.settings["stream_monitor"], self.monitor_count()))),
                ("Share resolution", f"{STREAM_RESOLUTIONS[self.settings['stream_resolution']][0]}x{STREAM_RESOLUTIONS[self.settings['stream_resolution']][1]}"),
                ("Share FPS target", str(STREAM_FPS[self.settings["stream_fps"]]) + " (max 60)"),
                ("Share bitrate", f"{STREAM_BITRATES[self.settings['stream_bitrate']]} Mbps" + (" (20 max)" if STREAM_BITRATES[self.settings['stream_bitrate']] > 20 else "")),
                ("Share profile", self.settings["stream_profile"]),
                ("Share codec", self.settings["stream_codec"]),
                ("Hardware acceleration", "On" if self.settings["stream_hardware"] else "Off"),
                ("System audio", "On" if self.settings["stream_system_audio"] else "Off"),
                ("Latency mode", self.settings["stream_latency"]),
                ("Back", ""),
            ]
            hints = [
                "Windows notifications appear only while Wire is not the active window.",
                "Suppresses Wire notifications and tells the directory you are unavailable.",
                "When off, the directory rejects new group invitations for you.",
                "Always on sends audio continuously; push-to-talk uses F12.",
                "Applies to your next and current voice calls.",
                "Higher noise removal can use more CPU.",
                "Keeps voice volume steady.",
                "Selects the microphone for your next call.",
                "Selects the speakers for your next call.",
                "Choose a whole monitor or one application window.",
                "Selects the application captured through Windows.Graphics.Capture.",
                "Selects which display /share captures.",
                "Higher resolutions need more encoder and network capacity.",
                "60 is the highest supported target; use /share stats to see actual capture and send FPS.",
                "A target rate; WebRTC can adapt. This encoder currently caps at 20 Mbps.",
                "Profiles choose sensible resolution, FPS, and bitrate starting points.",
                "Auto selects a compatible WebRTC codec when possible.",
                "Uses supported GPU acceleration where the active WebRTC stack provides it.",
                "Shares the default Windows speaker mix over encrypted WebRTC audio.",
                "Low minimizes buffering; balanced is more tolerant of network variation.",
                "Return to chat.",
            ]
            print("\x1b[2J\x1b[H", end="")
            print("WIRE SETTINGS  (Up/Down: select   Left/Right: change   Enter/Esc: back)")
            print("Changes save automatically.\n")
            for index, (label, value) in enumerate(rows):
                marker = ">" if index == selected else " "
                print(f"{marker} {label}: {value}" if value else f"{marker} {label}")
            print(f"\n{hints[selected]}")
            key = read_menu_key()
            if key == "up":
                selected = (selected - 1) % len(rows)
            elif key == "down":
                selected = (selected + 1) % len(rows)
            elif key in ("left", "right"):
                    direction = -1 if key == "left" else 1
                    if selected == 0:
                        self.settings["notifications"] = not self.settings["notifications"]
                    elif selected == 1:
                        self.settings["do_not_disturb"] = not self.settings["do_not_disturb"]
                    elif selected == 2:
                        self.settings["allow_group_invites"] = not self.settings["allow_group_invites"]
                    elif selected == 3:
                        self.settings["voice_mode"] = "open" if self.settings["voice_mode"] == "ptt" else "ptt"
                    elif selected == 4:
                        self.settings["voice_echo"] = not self.settings["voice_echo"]
                    elif selected == 5:
                        self.settings["voice_noise"] = (self.settings["voice_noise"] + direction) % 4
                    elif selected == 6:
                        self.settings["voice_gain"] = not self.settings["voice_gain"]
                    elif selected in (7, 8):
                        choices = inputs if selected == 7 else outputs
                        setting = "voice_input" if selected == 7 else "voice_output"
                        if choices:
                            current = self.settings.get(setting)
                            position = next((i for i, (device_id, _) in enumerate(choices) if device_id == current), -1)
                            self.settings[setting] = choices[(position + direction) % len(choices)][0]
                    elif selected == 9:
                        self.settings["stream_source"] = "window" if self.settings["stream_source"] == "monitor" else "monitor"
                    elif selected == 10:
                        if windows:
                            current = self.settings.get("stream_window", "")
                            position = windows.index(current) if current in windows else -1
                            self.settings["stream_window"] = windows[(position + direction) % len(windows)]
                            self.settings["stream_source"] = "window"
                    elif selected == 11:
                        self.settings["stream_monitor"] = ((self.settings["stream_monitor"] - 1 + direction) % self.monitor_count()) + 1
                    elif selected == 12:
                        self.settings["stream_resolution"] = (self.settings["stream_resolution"] + direction) % len(STREAM_RESOLUTIONS)
                    elif selected == 13:
                        self.settings["stream_fps"] = (self.settings["stream_fps"] + direction) % len(STREAM_FPS)
                    elif selected == 14:
                        self.settings["stream_bitrate"] = (self.settings["stream_bitrate"] + direction) % len(STREAM_BITRATES)
                    elif selected == 15:
                        options = list(STREAM_PROFILES)
                        self.settings["stream_profile"] = options[(options.index(self.settings["stream_profile"]) + direction) % len(options)]
                        apply_stream_profile(self.settings)
                    elif selected == 16:
                        options = ["auto", "H264", "VP8", "VP9", "AV1", "HEVC"]
                        self.settings["stream_codec"] = options[(options.index(self.settings["stream_codec"]) + direction) % len(options)]
                    elif selected == 17:
                        self.settings["stream_hardware"] = not self.settings["stream_hardware"]
                    elif selected == 18:
                        self.settings["stream_system_audio"] = not self.settings["stream_system_audio"]
                    elif selected == 19:
                        self.settings["stream_latency"] = "balanced" if self.settings["stream_latency"] == "low" else "low"
                    save_settings(self.settings)
                    self.sync_settings()
                    self.apply_voice_settings()
                    self.sync_preferences()
            elif key in ("enter", "escape") and selected == 20:
                print()
                return
            elif key == "escape":
                print()
                return

    def show_voice_devices(self) -> None:
        if sd is None:
            say("voice support is not installed")
            return
        say("MICROPHONES")
        for index, device in enumerate(sd.query_devices()):
            if device["max_input_channels"]:
                say(f"{index}: {device['name']}")
        say("SPEAKERS")
        for index, device in enumerate(sd.query_devices()):
            if device["max_output_channels"]:
                say(f"{index}: {device['name']}")
        say("use: settings voice input <number>")
        say("use: settings voice output <number>")

    def set_voice_device(self, direction: str, value: str) -> None:
        if sd is None or direction not in ("input", "output"):
            raise ValueError("use: settings voice input|output <number>")
        try:
            index = int(value)
            device = sd.query_devices(index)
            channels = device["max_input_channels"] if direction == "input" else device["max_output_channels"]
            if not channels:
                raise ValueError
        except Exception as exc:
            raise ValueError("that is not a valid voice device") from exc
        self.settings[f"voice_{direction}"] = index
        save_settings(self.settings)
        self.sync_settings()
        say(f"voice {direction} set to {index}: {device['name']}")

    def set_voice_mode(self, value: str) -> None:
        if value not in ("open", "ptt"):
            raise ValueError("use: settings voice mode open|ptt")
        self.settings["voice_mode"] = value
        save_settings(self.settings)
        self.sync_settings()
        self.apply_voice_settings()
        say("voice is always on" if value == "open" else "voice is push-to-talk (hold F12)")

    def set_voice_effects(self, value: str) -> None:
        if value not in ("on", "off"):
            raise ValueError("use: settings voice effects on|off")
        self.settings["voice_effects"] = value == "on"
        self.settings["voice_echo"] = value == "on"
        self.settings["voice_noise"] = 2 if value == "on" else 0
        save_settings(self.settings)
        self.sync_settings()
        self.apply_voice_settings()
        say(f"voice effects {value}")

    def set_setting(self, name: str, value: str) -> None:
        if name != "notifications" or value not in ("on", "off"):
            raise ValueError("use: settings notifications on|off")
        self.settings["notifications"] = value == "on"
        save_settings(self.settings)
        self.sync_settings()
        say(f"notifications {value}")

    def delete_account(self) -> None:
        """Remove only this PC's encrypted account material after explicit confirmation."""
        self.require_login()
        if not self.name:
            raise ValueError("sign in first")
        confirmation = input(f"Type DELETE {self.name} to permanently remove this local Wire account: ").strip()
        if confirmation != f"DELETE {self.name}":
            say("account deletion cancelled")
            return
        users = load_users()
        users.pop(self.name.lower(), None)
        save_users(users)
        for path in HISTORY_DIR.glob(f"{self.name.lower()}--*.wire"):
            path.unlink(missing_ok=True)
        self.contacts_path().unlink(missing_ok=True)
        say(f"deleted local account {self.name}; the username remains reserved on Wire")
        self.close()

    def read_history(self, peer_name: str) -> list[dict]:
        if not self.history_key:
            return []
        path = self.history_path(peer_name)
        if not path.exists():
            return []
        try:
            plaintext = Fernet(self.history_key).decrypt(path.read_bytes())
            records = json.loads(plaintext.decode("utf-8"))
            return records if isinstance(records, list) else []
        except Exception:
            return []

    def record_history(self, peer_name: str, sender: str, text: str, message_id: str | None = None, reply_to: str | None = None) -> str:
        if not self.history_key:
            return ""
        message_id = message_id or uuid.uuid4().hex
        with self.history_lock:
            records = self.read_history(peer_name)
            records.append({"id": message_id, "at": time.strftime("%Y-%m-%d %H:%M"), "from": sender, "text": text, "reply_to": reply_to, "reactions": []})
            encrypted = Fernet(self.history_key).encrypt(json.dumps(records[-500:], separators=(",", ":")).encode("utf-8"))
            replace_private_bytes(self.history_path(peer_name), encrypted)
            changed = records[-1]
        self.sync_record(peer_name, changed)
        return message_id

    def save_history(self, peer_name: str, records: list[dict], changed: dict | None = None) -> None:
        self.require_login()
        if not self.history_key:
            raise ValueError("sign in first")
        encrypted = Fernet(self.history_key).encrypt(json.dumps(records[-500:], separators=(",", ":")).encode("utf-8"))
        replace_private_bytes(self.history_path(peer_name), encrypted)
        if changed:
            self.sync_record(peer_name, changed)

    def matching_message(self, peer_name: str, prefix: str, own_only: bool = False) -> tuple[list[dict], dict]:
        records = self.read_history(peer_name)
        candidates = [record for record in records if isinstance(record.get("id"), str) and record["id"].startswith(prefix.lower())]
        if own_only:
            candidates = [record for record in candidates if record.get("from") == self.name]
        if len(candidates) != 1:
            raise ValueError("message code did not match exactly one saved message")
        return records, candidates[0]

    def render_record(self, record: dict, show_id: bool = False) -> str:
        text = "[deleted]" if record.get("deleted") else safe_terminal_text(record.get("text", ""))
        suffix = f"  ({record.get('id', '')[:6]})" if show_id and record.get("id") else ""
        if record.get("reply_to"):
            suffix += f"  reply:{str(record['reply_to'])[:6]}"
        if record.get("edited"):
            suffix += "  edited"
        if record.get("read"):
            suffix += "  read"
        elif record.get("delivered"):
            suffix += "  delivered"
        reactions = record.get("reactions", [])
        if reactions:
            suffix += "  " + " ".join(safe_terminal_text(item) for item in reactions[:12])
        return f"{safe_terminal_text(record.get('from', '?'))} > {text}{suffix}"

    def show_history(self, peer_name: str, show_ids: bool = False) -> None:
        records = self.read_history(peer_name)
        if not records:
            return
        say("-- earlier messages --")
        for record in records[-30:]:
            say(self.render_record(record, show_id=show_ids))
        say("-- end earlier messages --")

    def search_history(self, query: str) -> None:
        """Search locally decrypted history; this never contacts the directory."""
        self.require_login()
        query = query.strip().casefold()
        if not query:
            raise ValueError("use: /search <words>")
        found = 0
        for path in HISTORY_DIR.glob(f"{self.name.lower()}--*.wire"):
            peer_name = path.stem.split("--", 1)[-1]
            for record in self.read_history(peer_name):
                text = str(record.get("text", ""))
                if query in text.casefold():
                    say(f"[{peer_name}] {record.get('at', '?')} {record.get('from', '?')} > {text}")
                    found += 1
                    if found >= 100:
                        say("search stopped at 100 results")
                        return
        if not found:
            say("no saved messages match")

    def send_message(self, peer: Peer, text: str, reply_to: str | None = None) -> None:
        if not text:
            raise ValueError("message cannot be empty")
        if len(text) > MAX_MESSAGE_CHARS:
            raise ValueError(f"message is too long ({MAX_MESSAGE_CHARS} character maximum)")
        message_id = uuid.uuid4().hex
        peer.send(text, message_id, reply_to)
        self.record_history(peer.name, self.name or "me", text, message_id, reply_to)

    def send_typing(self) -> None:
        peer = self.peers.get(self.room or "")
        now = time.monotonic()
        if peer and now - self.last_typing_sent >= 2:
            peer.send_control({"kind": "typing"})
            self.last_typing_sent = now

    def typing_label(self) -> str:
        """Return the transient prompt status without adding a chat message."""
        now = time.monotonic()
        names = [name for name, expires in self.typing_until.items() if expires > now]
        return f" {names[0]} is typing..." if names else ""

    def refresh_typing_status(self) -> None:
        if self.typing_notifier:
            try:
                self.typing_notifier()
            except Exception:
                pass

    def reply_message(self, peer: Peer, prefix: str, text: str) -> None:
        _, target = self.matching_message(peer.name, prefix)
        self.send_message(peer, text, str(target["id"]))

    def edit_message(self, peer: Peer, prefix: str, text: str) -> None:
        if not text:
            raise ValueError("message cannot be empty")
        if len(text) > MAX_MESSAGE_CHARS:
            raise ValueError(f"message is too long ({MAX_MESSAGE_CHARS} character maximum)")
        records, target = self.matching_message(peer.name, prefix, own_only=True)
        if target.get("deleted"):
            raise ValueError("cannot edit a deleted message")
        target["text"], target["edited"] = text, True
        self.save_history(peer.name, records, target)
        peer.send_control({"kind": "message_edit", "id": target["id"], "text": text})
        say(f"edited message {target['id'][:6]}")

    def delete_message(self, peer: Peer, prefix: str) -> None:
        records, target = self.matching_message(peer.name, prefix, own_only=True)
        target["deleted"], target["text"] = True, ""
        self.save_history(peer.name, records, target)
        peer.send_control({"kind": "message_delete", "id": target["id"]})
        say(f"deleted message {target['id'][:6]}")

    def react_message(self, peer: Peer, prefix: str, reaction: str) -> None:
        if not reaction or len(reaction) > 24:
            raise ValueError("reaction must be 1-24 characters")
        records, target = self.matching_message(peer.name, prefix)
        token = f"{self.name}:{reaction}"
        reactions = [item for item in target.get("reactions", []) if not str(item).startswith(f"{self.name}:")]
        reactions.append(token); target["reactions"] = reactions
        self.save_history(peer.name, records, target)
        peer.send_control({"kind": "message_react", "id": target["id"], "reaction": reaction})

    @staticmethod
    def file_digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def transfer_status(label: str, name: str, completed: int, total: int, started: float) -> None:
        elapsed = max(time.monotonic() - started, 0.001)
        rate = completed / elapsed
        percent = (completed / total * 100) if total else 100
        remaining = max(total - completed, 0)
        eta = int(remaining / rate) if rate else 0
        minutes, seconds = divmod(eta, 60)
        say(f"{label} {name}: {percent:5.1f}%  {completed / 1024 / 1024:.1f}/{total / 1024 / 1024:.1f} MB  {rate / 1024 / 1024:.1f} MB/s  ETA {minutes}:{seconds:02d}")

    @staticmethod
    def zip_contents(path: Path) -> list[str]:
        """Return a display-only ZIP listing; never extract or run its contents."""
        if path.suffix.lower() != ".zip":
            return []
        try:
            with zipfile.ZipFile(path) as archive:
                names = [entry.filename for entry in archive.infolist() if not entry.is_dir()]
            return names[:50]
        except (OSError, zipfile.BadZipFile):
            return ["[Could not read ZIP contents]"]

    @staticmethod
    def package_folder(folder: Path) -> Path:
        """Create one temporary ZIP so a folder can travel as a single verified file."""
        TRANSFER_TEMP_DIR.mkdir(parents=True, exist_ok=True)
        archive = TRANSFER_TEMP_DIR / f"{folder.name}-{uuid.uuid4().hex[:8]}.zip"
        try:
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as output:
                for root, directories, files in os.walk(folder, followlinks=False):
                    root_path = Path(root)
                    directories[:] = [item for item in directories if not (root_path / item).is_symlink()]
                    for filename in files:
                        source = root_path / filename
                        if source.is_symlink():
                            continue
                        output.write(source, Path(folder.name) / source.relative_to(folder))
        except Exception:
            archive.unlink(missing_ok=True)
            raise
        return archive

    @staticmethod
    def direct_packet(key: bytes, frame: dict) -> dict:
        nonce = os.urandom(12)
        raw = json.dumps(frame, separators=(",", ":")).encode("utf-8")
        data = AESGCM(key).encrypt(nonce, raw, b"wire-v1-direct-file")
        return {"type": "file", "nonce": b64(nonce), "data": b64(data)}

    @staticmethod
    def read_direct_packet(sock: socket.socket, key: bytes) -> dict:
        packet = recv_frame(sock)
        if packet.get("type") != "file":
            raise ValueError("invalid direct file connection")
        raw = AESGCM(key).decrypt(unb64(packet["nonce"]), unb64(packet["data"]), b"wire-v1-direct-file")
        frame = json.loads(raw.decode("utf-8"))
        if not isinstance(frame, dict):
            raise ValueError("invalid direct file frame")
        return frame

    def send_direct_packet(self, sock: socket.socket, key: bytes, frame: dict) -> None:
        send_frame(sock, self.direct_packet(key, frame))

    def send_file(self, peer: Peer, value: str) -> None:
        path = Path(value.strip().strip('"')).expanduser()
        cleanup = False
        if path.is_dir():
            original = path
            path = self.package_folder(path)
            cleanup = True
            say(f"packing folder: {original.name}")
        if not path.is_file():
            raise ValueError("choose a file to send")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            if cleanup:
                path.unlink(missing_ok=True)
            raise ValueError("files must be 500 MB or smaller")
        file_id = uuid.uuid4().hex
        token = os.urandom(32).hex()
        offer = {
            "id": file_id, "token": token, "name": path.name, "size": size,
            "sha256": self.file_digest(path), "contents": self.zip_contents(path),
        }
        self.outgoing_files[file_id] = {"path": path, "offer": offer, "peer": peer, "cleanup": cleanup}
        try:
            # The existing directory's offer route is only used for signalling.
            # Bytes stay encrypted with the peer key and travel over the already
            # connected directory relay, so this also works through NAT/firewalls.
            self.server_send({"type": "direct_offer", "to": peer.name, "port": 1, "offer": offer})
        except Exception:
            self.outgoing_files.pop(file_id, None)
            if cleanup:
                path.unlink(missing_ok=True)
            raise
        say(f"file offer sent: {path.name} (waiting for them to accept)")

    def relay_send_file_worker(self, file_id: str) -> None:
        state = self.outgoing_files.get(file_id)
        if not state:
            return
        peer, offer, path = state["peer"], state["offer"], state["path"]
        try:
            peer.send_file_frame({"kind": "start", "id": file_id, "name": offer["name"], "size": offer["size"], "sha256": offer["sha256"]})
            sent, started, last_status = 0, time.monotonic(), 0.0
            with path.open("rb") as handle:
                while chunk := handle.read(RELAY_FILE_CHUNK_BYTES):
                    self.pace_relay_upload(len(chunk))
                    peer.send_file_frame({"kind": "chunk", "id": file_id, "data": b64(chunk)})
                    sent += len(chunk)
                    if time.monotonic() - last_status >= 0.5:
                        self.transfer_status("uploading", path.name, sent, offer["size"], started)
                        last_status = time.monotonic()
            peer.send_file_frame({"kind": "end", "id": file_id, "size": sent})
        except Exception as exc:
            # Tell the receiver to discard the partial file when possible;
            # otherwise it would wait forever for a checksum that cannot pass.
            try:
                self.pace_relay_upload(256)
                peer.send_control({"kind": "file_relay_abort", "id": file_id})
            except (OSError, ConnectionError):
                pass
            say(f"file transfer stopped: {exc}")
            self.outgoing_files.pop(file_id, None)
            if state.get("cleanup"):
                path.unlink(missing_ok=True)

    def direct_send_worker(self, file_id: str) -> None:
        state = self.outgoing_files.get(file_id)
        if not state:
            return
        listener, peer, offer, path = state["listener"], state["peer"], state["offer"], state["path"]
        connection: Optional[socket.socket] = None
        completed = False
        deadline = time.monotonic() + 600
        try:
            while time.monotonic() < deadline and not completed:
                listener.settimeout(max(1, deadline - time.monotonic()))
                try:
                    connection, _address = listener.accept()
                    connection.settimeout(30)
                    hello = self.read_direct_packet(connection, peer.key)
                    offset = hello.get("offset", 0)
                    if hello.get("kind") != "hello" or hello.get("id") != file_id or not hmac.compare_digest(str(hello.get("token", "")), offer["token"]) or not isinstance(offset, int) or not 0 <= offset <= offer["size"]:
                        raise ValueError("file receiver could not be verified")
                    self.send_direct_packet(connection, peer.key, {"kind": "start", "id": file_id, "offset": offset})
                    with path.open("rb") as handle:
                        handle.seek(offset)
                        sent = offset
                        started, last_status = time.monotonic(), 0.0
                        while chunk := handle.read(FILE_CHUNK_BYTES):
                            self.send_direct_packet(connection, peer.key, {"kind": "chunk", "id": file_id, "data": b64(chunk)})
                            sent += len(chunk)
                            if time.monotonic() - last_status >= 0.5:
                                self.transfer_status("uploading", path.name, sent, offer["size"], started)
                                last_status = time.monotonic()
                    self.send_direct_packet(connection, peer.key, {"kind": "end", "id": file_id, "size": sent})
                    receipt = self.read_direct_packet(connection, peer.key)
                    if receipt.get("kind") != "complete" or receipt.get("id") != file_id:
                        raise ConnectionError("receiver did not verify the file")
                    completed = True
                    say(f"sent file directly: {path.name}")
                    restart_blank_prompt_after_background_output()
                except socket.timeout:
                    break
                except (ConnectionError, OSError):
                    say(f"upload interrupted; waiting for {peer.name} to resume {path.name}")
                finally:
                    if connection:
                        try: connection.close()
                        except OSError: pass
                        connection = None
            if not completed:
                say(f"file offer expired: {path.name}")
        except Exception as exc:
            say(f"file transfer stopped: {exc}")
        finally:
            self.outgoing_files.pop(file_id, None)
            if state.get("cleanup"):
                path.unlink(missing_ok=True)
            try:
                listener.close()
            except OSError:
                pass

    def answer_file_offer(self, code: str, accept: bool) -> None:
        matches = [key for key in self.pending_files if key.startswith(code.lower())]
        if len(matches) != 1:
            raise ValueError("no pending file with that code")
        file_id = matches[0]
        if not valid_transfer_id(file_id):
            raise ValueError("invalid file transfer code")
        state = self.pending_files.pop(file_id)
        sender, offer = state.get("from"), state.get("offer")
        peer = self.peers.get(str(sender).lower())
        if not peer or not isinstance(offer, dict):
            raise ValueError("open a room with that person before accepting their file")
        if not accept:
            peer.send_control({"kind": "file_relay_decline", "id": file_id})
            say("file declined; nothing was downloaded")
            return
        name, size, expected_hash = Path(str(offer.get("name", ""))).name, offer.get("size"), offer.get("sha256")
        if not name or not valid_transfer_id(file_id) or not isinstance(size, int) or not 0 <= size <= MAX_FILE_BYTES or not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            raise ValueError("invalid file offer")
        files_dir = DOWNLOADS_DIR / "Files"
        files_dir.mkdir(parents=True, exist_ok=True)
        target = files_dir / name
        stem, suffix, number = target.stem, target.suffix, 2
        while target.exists():
            target = files_dir / f"{stem} ({number}){suffix}"
            number += 1
        temp = files_dir / f".{name}.{file_id}.part"
        temp.unlink(missing_ok=True)
        self.incoming_files[file_id] = {"peer": peer, "offer": offer, "path": target, "temp": temp, "written": 0, "hasher": hashlib.sha256(), "started": time.monotonic(), "last_status": 0.0}
        peer.send_control({"kind": "file_relay_accept", "id": file_id})
        say("accepting encrypted file transfer...")

    def handle_file_relay(self, peer: Peer, packet: dict) -> None:
        """Receive a bounded, end-to-end encrypted file stream via the relay."""
        frame = json.loads(AESGCM(peer.key).decrypt(unb64(packet["nonce"]), unb64(packet["data"]), b"wire-v1-file-relay").decode("utf-8"))
        file_id, kind = frame.get("id"), frame.get("kind")
        state = self.incoming_files.get(file_id) if isinstance(file_id, str) else None
        if not state or state["peer"] is not peer:
            return
        offer = state["offer"]
        try:
            if kind == "start":
                if frame.get("name") != offer["name"] or frame.get("size") != offer["size"] or frame.get("sha256") != offer["sha256"]:
                    raise ValueError("sender changed the file offer")
                state["temp"].write_bytes(b"")
            elif kind == "chunk":
                chunk = unb64(frame.get("data", ""))
                if not chunk or len(chunk) > RELAY_FILE_CHUNK_BYTES or state["written"] + len(chunk) > offer["size"]:
                    raise ValueError("invalid file chunk")
                with state["temp"].open("ab") as handle:
                    handle.write(chunk)
                state["hasher"].update(chunk)
                state["written"] += len(chunk)
                if time.monotonic() - state["last_status"] >= 0.5:
                    self.transfer_status("downloading", offer["name"], state["written"], offer["size"], state["started"])
                    state["last_status"] = time.monotonic()
            elif kind == "end":
                if frame.get("size") != state["written"] or state["written"] != offer["size"] or not hmac.compare_digest(state["hasher"].hexdigest(), offer["sha256"]):
                    raise ValueError("file failed verification")
                state["temp"].replace(state["path"])
                self.incoming_files.pop(file_id, None)
                peer.send_control({"kind": "file_relay_complete", "id": file_id})
                say(f"\nfile received and verified: {state['path']}")
                toast(f"file received from {peer.name}: {offer['name']}")
                if state["path"].suffix.lower() in VIDEO_EXTENSIONS:
                    say(f"video received. Type /preview \"{state['path']}\" to watch its first 5 seconds.")
                restart_blank_prompt_after_background_output()
        except Exception as exc:
            self.incoming_files.pop(file_id, None)
            state["temp"].unlink(missing_ok=True)
            say(f"file transfer failed: {exc}")

    def stop_incoming_file(self, peer: Peer, file_id: str) -> None:
        """Discard an explicitly aborted partial relay file."""
        state = self.incoming_files.get(file_id)
        if not state or state.get("peer") is not peer:
            return
        self.incoming_files.pop(file_id, None)
        state["temp"].unlink(missing_ok=True)
        say(f"file transfer stopped by {peer.name}")

    def resume_file(self, code: str) -> None:
        matches = [key for key in self.paused_files if key.startswith(code.lower())]
        if len(matches) != 1:
            raise ValueError("no paused transfer with that code")
        state = self.paused_files[matches[0]]
        self.start_worker(self.direct_receive_worker, state["peer"], state["host"], state["port"], state["offer"], state["target"])
        say("resuming encrypted file transfer...")

    def direct_receive_worker(self, peer: Peer, host: str, port: int, offer: dict, target_override: Optional[Path] = None) -> None:
        name = Path(str(offer.get("name", "file"))).name
        size, file_id, token, expected_hash = offer.get("size"), offer.get("id"), offer.get("token"), offer.get("sha256")
        if not name or not isinstance(size, int) or not 0 <= size <= MAX_FILE_BYTES or not valid_transfer_id(file_id) or not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token) or not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
            say("file transfer rejected: invalid offer")
            return
        FILES_DIR = DOWNLOADS_DIR / "Files"
        FILES_DIR.mkdir(parents=True, exist_ok=True)
        target = target_override or FILES_DIR / name
        if not target_override:
            stem, suffix, number = target.stem, target.suffix, 2
            while target.exists():
                target = FILES_DIR / f"{stem} ({number}){suffix}"
                number += 1
        # The transfer ID makes the partial filename stable across reconnects.
        temp = FILES_DIR / f".{name}.{file_id}.part"
        connection: Optional[socket.socket] = None
        try:
            verified = False
            # A short retry loop resumes transient disconnects without needing a
            # new offer or another accept command.
            for attempt in range(4):
                written = temp.stat().st_size if temp.exists() else 0
                if written > size:
                    raise ValueError("saved partial file is larger than the offer")
                digest = hashlib.sha256()
                if written:
                    with temp.open("rb") as previous:
                        while chunk := previous.read(1024 * 1024): digest.update(chunk)
                try:
                    connection = socket.create_connection((host, port), timeout=15)
                    connection.settimeout(30)
                    self.send_direct_packet(connection, peer.key, {"kind": "hello", "id": file_id, "token": token, "offset": written})
                    start = self.read_direct_packet(connection, peer.key)
                    if start.get("kind") != "start" or start.get("id") != file_id or start.get("offset") != written:
                        raise ValueError("sender did not verify the resume offset")
                    started, last_status = time.monotonic(), 0.0
                    with temp.open("ab") as handle:
                        while True:
                            frame = self.read_direct_packet(connection, peer.key)
                            if frame.get("id") != file_id:
                                raise ValueError("wrong file transfer")
                            if frame.get("kind") == "end":
                                if frame.get("size") != written:
                                    raise ValueError("file size did not match")
                                if written != size or not hmac.compare_digest(digest.hexdigest(), expected_hash):
                                    raise ValueError("file failed verification")
                                self.send_direct_packet(connection, peer.key, {"kind": "complete", "id": file_id})
                                verified = True
                                break
                            if frame.get("kind") != "chunk" or not isinstance(frame.get("data"), str):
                                raise ValueError("invalid file data")
                            chunk = unb64(frame["data"])
                            if not chunk or len(chunk) > FILE_CHUNK_BYTES or written + len(chunk) > size:
                                raise ValueError("invalid file chunk")
                            handle.write(chunk)
                            digest.update(chunk)
                            written += len(chunk)
                            if time.monotonic() - last_status >= 0.5:
                                self.transfer_status("downloading", name, written, size, started)
                                last_status = time.monotonic()
                    break
                except (ConnectionError, OSError, socket.timeout) as exc:
                    if attempt == 3:
                        raise
                    say(f"download interrupted at {written / 1024 / 1024:.1f} MB; resuming...")
                    time.sleep(1)
                finally:
                    if connection:
                        try: connection.close()
                        except OSError: pass
                        connection = None
            if not verified:
                raise ValueError("file failed verification")
            temp.replace(target)
            self.paused_files.pop(file_id, None)
            say(f"\nfile received and verified: {target}")
            toast(f"file received from {peer.name}: {name}")
            if target.suffix.lower() in VIDEO_EXTENSIONS:
                say(f"video received. Type /preview \"{target}\" to watch its first 5 seconds.")
            restart_blank_prompt_after_background_output()
        except Exception as exc:
            self.paused_files[file_id] = {"peer": peer, "host": host, "port": port, "offer": offer, "target": target}
            say(f"file transfer paused: {exc}; type /file resume {file_id[:6]} within 10 minutes")
        finally:
            if connection:
                try:
                    connection.close()
                except OSError:
                    pass

    def preview_video(self, value: str) -> None:
        path = Path(value.strip().strip('"')).expanduser()
        if not path.is_file() or path.suffix.lower() not in VIDEO_EXTENSIONS:
            raise ValueError("choose an MP4, MKV, WEBM, AVI, MOV, or M4V video")
        player = shutil.which("ffplay.exe") or shutil.which("ffplay")
        if not player:
            raise ValueError("video preview needs FFmpeg; install FFmpeg and restart Wire")
        subprocess.Popen([player, "-t", "5", "-autoexit", "-window_title", f"Wire preview - {path.name}", str(path)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        say(f"playing the first 5 seconds of {path.name}")

    def start_share(self, peer: Peer) -> None:
        if os.name != "nt" and os.environ.get("XDG_SESSION_TYPE", "").lower() == "wayland":
            raise ValueError("Linux Wayland screen sharing needs the future PipeWire portal backend; chat and files are supported now")
        if self.webrtc_shares:
            raise ValueError("you are already sharing a screen")
        share_id = uuid.uuid4().hex
        resolution = STREAM_RESOLUTIONS[self.settings["stream_resolution"]]
        fps = STREAM_FPS[self.settings["stream_fps"]]
        window_name = self.settings.get("stream_window") if self.settings.get("stream_source") == "window" else None
        window_hwnd = self.share_window_handles().get(window_name) if window_name else None
        if window_name and window_hwnd is None:
            raise ValueError("the selected share window is no longer open; choose another in /setting")
        if self.settings.get("stream_source") == "window" and not window_name:
            raise ValueError("choose an application window in /setting before sharing")
        media = WebRTCShare(lambda _: None, lambda _: None, lambda state: say(f"screen share: {state}"), *resolution, fps, self.settings["stream_monitor"], self.settings["stream_codec"], STREAM_BITRATES[self.settings["stream_bitrate"]] * 1_000_000, self.settings["stream_hardware"], self.settings["stream_profile"] == "auto", self.settings["stream_system_audio"], window_name, window_hwnd)
        self.webrtc_shares[share_id] = media
        self.share_peers[share_id] = peer.name
        try:
            offer = media.call(media.offer()).result(timeout=35); offer["id"] = share_id
            # SDP and ICE candidates stay inside the existing end-to-end
            # encrypted room instead of being readable by the directory.
            peer.send_control({"kind": "webrtc_offer", "id": share_id, "offer": offer})
        except Exception:
            self.webrtc_shares.pop(share_id, None); self.share_peers.pop(share_id, None); media.close()
            raise
        say(f"WebRTC screen-share offer sent to {peer.name}; waiting for them to accept")

    def stop_screen_share(self) -> None:
        """Cancel an unanswered offer or end an active share immediately."""
        had_webrtc = bool(self.webrtc_shares)
        for share_id, media in list(self.webrtc_shares.items()):
            peer_name = self.share_peers.get(share_id)
            peer = self.peers.get(str(peer_name).lower()) if peer_name else None
            if peer:
                try: peer.send_control({"kind": "webrtc_stop", "id": share_id})
                except (OSError, ConnectionError): pass
            media.close()
        self.webrtc_shares.clear()
        self.share_peers.clear()
        for stop in list(self.share_viewer_stops.values()):
            stop.set()
        for viewer in list(self.share_viewers.values()):
            if viewer.is_alive(): viewer.join(timeout=3)
            if viewer.is_alive(): viewer.terminate()
        self.share_viewers.clear()
        self.share_viewer_stops.clear()
        if not had_webrtc:
            say("no screen share is active")
            return
        say("screen share stopped")

    def answer_share_offer(self, code: str, accept: bool) -> None:
        matches = [key for key in self.pending_shares if key.startswith(code.lower())]
        if len(matches) != 1:
            raise ValueError("no pending screen share with that code")
        share_id = matches[0]
        state = self.pending_shares.pop(share_id)
        if not accept:
            peer = self.peers.get(str(state["from"]).lower())
            if peer:
                try: peer.send_control({"kind": "webrtc_decline", "id": share_id})
                except (OSError, ConnectionError): pass
            say("screen share declined")
            return
        peer = self.peers.get(str(state["from"]).lower())
        if not peer:
            raise ValueError("open a room with that person before accepting their screen share")
        self.start_worker(self.webrtc_viewer, peer, state)
        say("opening encrypted screen-share viewer...")

    def webrtc_viewer(self, peer: Peer, state: dict) -> None:
        offer, share_id = state["offer"], state["offer"]["id"]
        frames = mp.Queue(maxsize=1)
        def on_frame(frame: np.ndarray) -> None:
            try:
                while frames.full(): frames.get_nowait()
                frames.put_nowait(frame)
            except (queue.Empty, ValueError): pass
        stream_ended = threading.Event()
        def on_state(status: str) -> None:
            say(f"screen share: {status}")
            if status in ("closed", "failed", "stream ended"): stream_ended.set()
        media = WebRTCShare(lambda _: None, on_frame, on_state, *(offer.get("resolution") or [1280, 720]), int(offer.get("fps", 30)), codec=offer.get("codec", "auto"))
        self.webrtc_shares[share_id] = media
        self.share_peers[share_id] = peer.name
        try:
            answer = media.call(media.answer(offer)).result(timeout=35)
            # Relay the answer end-to-end so the deployed directory never sees SDP
            # and older directories do not need a protocol upgrade.
            peer.send_control({"kind": "webrtc_answer", "id": share_id, "answer": answer})
            viewer_stop = mp.Event()
            viewer = mp.Process(target=screen_viewer_process, args=(frames, f"Wire screen share - {peer.name}", viewer_stop), daemon=True)
            self.share_viewers[share_id] = viewer
            self.share_viewer_stops[share_id] = viewer_stop
            viewer.start()
            while viewer.is_alive() and not stream_ended.wait(0.2): pass
            viewer_stop.set()
            if viewer.is_alive(): viewer.join(timeout=3)
            if viewer.is_alive(): viewer.terminate()
        except Exception as exc:
            say(f"screen share failed: {exc}")
            report_background_failure("screen share", exc)
        finally:
            self.share_viewers.pop(share_id, None)
            self.share_viewer_stops.pop(share_id, None)
            self.share_peers.pop(share_id, None)
            self.webrtc_shares.pop(share_id, media).close()

    def stop_share_id(self, share_id: str, remote: bool = False) -> None:
        media = self.webrtc_shares.pop(share_id, None)
        self.share_peers.pop(share_id, None)
        viewer = self.share_viewers.pop(share_id, None)
        viewer_stop = self.share_viewer_stops.pop(share_id, None)
        if viewer_stop:
            viewer_stop.set()
        if viewer and viewer.is_alive():
            viewer.join(timeout=3)
        if viewer and viewer.is_alive():
            viewer.terminate(); viewer.join(timeout=2)
        if media:
            media.close()
        if remote:
            say("screen share ended by the other person")

    def preview_image(self, path: Path) -> None:
        try:
            with Image.open(path) as probe:
                if probe.format not in {"PNG", "JPEG", "GIF", "BMP", "WEBP"}:
                    raise ValueError("unsupported image contents")
                probe.verify()
            if path.suffix.lower() == ".gif":
                say(f"GIF received: {path.name}")
                # GIFs arrive through the normal /send image flow. Play one
                # compact loop without asking the recipient for another
                # command or opening an external image window.
                self.start_worker(self.preview_gif, str(path))
                return
            # CMD's ANSI/color support is inconsistent and the old text card
            # could become mojibake or a wall of # characters. On Windows use
            # the user's normal image viewer, which keeps the chat readable.
            if os.name == "nt":
                os.startfile(path)
                say(f"opened image: {path.name}")
                return
            with Image.open(path) as image:
                image = image.convert("RGB")
                if os.environ.get("WT_SESSION"):
                    self.preview_sixel(image)
                    return
                # This stays a chat-sized card instead of taking over the terminal.
                # Two characters per pixel preserve normal image proportions in CMD.
                max_width, max_height = 48, 36
                image.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
                pixels = image.load()
                card_width = image.width * 2
                say("  ┌" + "─" * card_width + "┐")
                for y in range(0, image.height, 2):
                    row = []
                    for x in range(image.width):
                        top = pixels[x, y]
                        bottom = pixels[x, min(y + 1, image.height - 1)]
                        row.append(f"\x1b[38;2;{top[0]};{top[1]};{top[2]}m\x1b[48;2;{bottom[0]};{bottom[1]};{bottom[2]}m##")
                    say("  │" + "".join(row) + "\x1b[0m│")
                say("  └" + "─" * card_width + "┘")
        except Exception:
            say("[image preview unavailable]")

    @staticmethod
    def gif_frame_text(image: Image.Image, name: str) -> tuple[str, int]:
        """Compact true-colour terminal frame; standard consoles lack GIF image APIs."""
        image = image.convert("RGB")
        image.thumbnail((36, 18), Image.Resampling.LANCZOS)
        pixels = image.load()
        lines = [f"GIF: {name}  (one loop; Ctrl+C stops)"]
        for y in range(0, image.height, 2):
            row = []
            for x in range(image.width):
                top = pixels[x, y]
                bottom = pixels[x, min(y + 1, image.height - 1)]
                row.append(f"\x1b[38;2;{top[0]};{top[1]};{top[2]}m\x1b[48;2;{bottom[0]};{bottom[1]};{bottom[2]}m▀")
            lines.append("".join(row) + "\x1b[0m")
        return "\n".join(lines), len(lines)

    def preview_gif(self, value: str) -> None:
        path = Path(value.strip().strip('"')).expanduser()
        if not path.is_file() or path.suffix.lower() != ".gif":
            raise ValueError("choose a GIF file")
        try:
            with Image.open(path) as source:
                if not getattr(source, "is_animated", False):
                    raise ValueError("that GIF has only one frame")
                previous_lines = 0
                print("\x1b[?25l", end="", flush=True)
                try:
                    for index, frame in enumerate(ImageSequence.Iterator(source)):
                        if index >= 60:
                            break
                        text, line_count = self.gif_frame_text(frame.copy(), path.name)
                        if previous_lines:
                            print(f"\x1b[{previous_lines}F", end="")
                        print(text, flush=True)
                        previous_lines = line_count
                        time.sleep(min(0.15, max(0.04, frame.info.get("duration", 100) / 1000)))
                finally:
                    print("\x1b[0m\x1b[?25h", flush=True)
        except (OSError, ValueError) as exc:
            raise ValueError(f"could not play GIF: {exc}") from exc

    @staticmethod
    def sixel_rle(values: str) -> str:
        """Compress repeated SIXEL pixels so photos do not flood the terminal stream."""
        if not values:
            return ""
        result, start = [], 0
        while start < len(values):
            end = start + 1
            while end < len(values) and values[end] == values[start]:
                end += 1
            count = end - start
            result.append((f"!{count}" if count > 3 else "" ) + values[start] * (1 if count > 3 else count))
            start = end
        return "".join(result)

    def preview_sixel(self, image: Image.Image) -> None:
        """Render a real bitmap in modern Windows Terminal, limited to a chat card."""
        image.thumbnail((480, 360), Image.Resampling.LANCZOS)
        indexed = image.convert("P", palette=Image.Palette.ADAPTIVE, colors=128)
        width, height = indexed.size
        palette = indexed.getpalette() or []
        pixels = list(indexed.getdata())
        used = sorted(set(pixels))
        output = [f"\x1bPq\"1;1;{width};{height}"]
        for color in used:
            base = color * 3
            red, green, blue = palette[base:base + 3]
            output.append(f"#{color};2;{round(red * 100 / 255)};{round(green * 100 / 255)};{round(blue * 100 / 255)}")
        for top in range(0, height, 6):
            colors = sorted({pixels[y * width + x] for y in range(top, min(top + 6, height)) for x in range(width)})
            for color in colors:
                band = []
                for x in range(width):
                    value = 0
                    for bit in range(6):
                        y = top + bit
                        if y < height and pixels[y * width + x] == color:
                            value |= 1 << bit
                    band.append(chr(63 + value))
                output.append(f"#{color}" + self.sixel_rle("".join(band)))
            if top + 6 < height:
                output.append("-")
        output.append("\x1b\\")
        say("".join(output))

    def send_image(self, peer: Peer, value: str) -> None:
        path = Path(value.strip().strip('"')).expanduser()
        if not path.is_file() or path.suffix.lower() not in IMAGE_EXTENSIONS:
            raise ValueError("choose a PNG, JPG, GIF, BMP, or WEBP image")
        size = path.stat().st_size
        if size > MAX_IMAGE_BYTES:
            raise ValueError("images must be 20 MB or smaller")
        image_id = uuid.uuid4().hex
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.outgoing_images[image_id] = {"path": path, "name": path.name, "size": size, "sha256": digest}
        peer.send_image_frame({"kind": "offer", "id": image_id, "name": path.name, "size": size, "sha256": digest})
        say(f"image offer sent: {path.name} (waiting for them to accept)")

    def send_attachment(self, peer: Peer, value: str) -> None:
        """Use one send command: image flow for images, file flow for everything else."""
        path = Path(value.strip().strip('"')).expanduser()
        if not path.exists():
            raise ValueError(f"file or folder not found: {path}")
        if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS:
            self.send_image(peer, value)
        else:
            self.send_file(peer, value)

    def transfer_image(self, peer: Peer, image_id: str) -> None:
        state = self.outgoing_images.pop(image_id, None)
        if not state:
            return
        path = state["path"]
        try:
            peer.send_image_frame({"kind": "start", "id": image_id, "name": state["name"], "size": state["size"], "sha256": state["sha256"]})
            with path.open("rb") as handle:
                index = 0
                while chunk := handle.read(IMAGE_CHUNK_BYTES):
                    self.pace_relay_upload(len(chunk))
                    peer.send_image_frame({"kind": "chunk", "id": image_id, "index": index, "data": b64(chunk)})
                    index += 1
            peer.send_image_frame({"kind": "end", "id": image_id})
            say(f"sent image: {path.name}")
            # The recipient previews the received image. Do not open another
            # copy on the sender, especially when both Wire accounts happen
            # to be running on the same computer.
        except Exception as exc:
            try:
                self.pace_relay_upload(256)
                peer.send_control({"kind": "image_abort", "id": image_id})
            except (OSError, ConnectionError):
                pass
            say(f"image transfer stopped: {exc}")

    def answer_image_offer(self, peer: Peer, image_id: str, accept: bool) -> None:
        matches = [key for key in self.pending_images if key.startswith(image_id.lower())]
        if len(matches) != 1:
            raise ValueError("no pending image with that code")
        image_id = matches[0]
        offer = self.pending_images.get(image_id)
        if not offer:
            raise ValueError("no pending image with that code")
        peer.send_image_frame({"kind": "accept" if accept else "decline", "id": image_id})
        if not accept:
            self.pending_images.pop(image_id, None)
        say("image accepted" if accept else "image declined")

    def handle_image(self, peer: Peer, packet: dict) -> None:
        raw = AESGCM(peer.key).decrypt(unb64(packet["nonce"]), unb64(packet["data"]), b"wire-v1-image")
        frame = json.loads(raw.decode("utf-8"))
        image_id = frame.get("id", "")
        if not valid_transfer_id(image_id):
            return
        kind = frame.get("kind")
        if kind == "offer":
            name = Path(str(frame.get("name", "image"))).name
            size = frame.get("size")
            digest = frame.get("sha256")
            if (Path(name).suffix.lower() not in IMAGE_EXTENSIONS or not isinstance(size, int)
                    or not 0 <= size <= MAX_IMAGE_BYTES or not isinstance(digest, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                return
            self.pending_images[image_id] = {"name": name, "size": size, "sha256": digest}
            say(f"\n{peer.name} wants to send {name} ({size // 1024} KB). Type /image accept {image_id[:6]} or /image decline {image_id[:6]}")
        elif kind == "accept":
            self.start_worker(self.transfer_image, peer, image_id)
        elif kind == "decline":
            self.outgoing_images.pop(image_id, None)
            say("image offer declined")
        elif kind == "start":
            offer = self.pending_images.pop(image_id, None)
            if not offer:
                return
            name = Path(str(frame.get("name", "image"))).name
            size = frame.get("size")
            if name != offer["name"] or size != offer["size"] or frame.get("sha256") != offer["sha256"]:
                return
            DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
            target = DOWNLOADS_DIR / name
            stem, suffix, number = target.stem, target.suffix, 2
            while target.exists():
                target = DOWNLOADS_DIR / f"{stem} ({number}){suffix}"
                number += 1
            temp = target.parent / f".{target.name}.{image_id}.part"
            temp.unlink(missing_ok=True)
            self.incoming_images[image_id] = {"path": target, "temp": temp, "size": size, "sha256": frame.get("sha256"), "written": 0, "index": 0}
            say(f"\n{peer.name} is sending image: {name}")
        elif kind == "chunk" and image_id in self.incoming_images:
            state = self.incoming_images[image_id]
            if frame.get("index") != state["index"]:
                return
            chunk = unb64(frame.get("data", ""))
            if state["written"] + len(chunk) > state["size"]:
                return
            with state["temp"].open("ab") as handle:
                handle.write(chunk)
            state["written"] += len(chunk)
            state["index"] += 1
        elif kind == "end" and image_id in self.incoming_images:
            state = self.incoming_images.pop(image_id)
            if state["written"] != state["size"] or hashlib.sha256(state["temp"].read_bytes()).hexdigest() != state["sha256"]:
                state["temp"].unlink(missing_ok=True)
                say("image transfer failed verification")
                return
            state["temp"].replace(state["path"])
            say(f"\nimage received: {state['path'].name}")
            self.preview_image(state["path"])
            toast(f"image received from {peer.name}")

    def stop_incoming_image(self, peer: Peer, image_id: str) -> None:
        state = self.incoming_images.get(image_id)
        if not state:
            return
        self.incoming_images.pop(image_id, None)
        state["temp"].unlink(missing_ok=True)
        say(f"image transfer stopped by {peer.name}")

    def start_call(self, peer: Peer) -> None:
        if peer.name.lower() in self.calls:
            return
        self.calls[peer.name.lower()] = VoiceCall(peer, self.settings)
        activation = "always on" if self.settings.get("voice_mode") == "open" else "hold F12 to talk"
        say(f"voice call connected with {peer.name}; {activation}, /hangup to end")

    def show_call_stats(self) -> None:
        if not self.calls:
            say("no active voice call")
            return
        for name, call in self.calls.items():
            say(f"voice {name}: sent {call.sent_frames} frames, received {call.received_frames} frames")

    def request_call(self, peer: Peer) -> None:
        peer.send_voice_frame({"kind": "offer"})
        say(f"calling {peer.name}; waiting for them to accept")

    def accept_call(self, peer: Peer) -> None:
        if peer.name.lower() not in self.call_requests:
            raise ValueError("no voice call request from that person")
        self.call_requests.discard(peer.name.lower())
        self.start_call(peer)
        peer.send_voice_frame({"kind": "accept"})

    def end_call(self, peer: Peer, tell_peer: bool = True) -> None:
        call = self.calls.pop(peer.name.lower(), None)
        if call:
            call.close()
        if tell_peer:
            peer.send_voice_frame({"kind": "end"})
        say("voice call ended")

    def handle_voice(self, peer: Peer, packet: dict) -> None:
        frame = json.loads(AESGCM(peer.key).decrypt(unb64(packet["nonce"]), unb64(packet["data"]), b"wire-v1-voice").decode("utf-8"))
        kind = frame.get("kind")
        if kind == "offer":
            self.call_requests.add(peer.name.lower())
            say(f"\n{peer.name} wants a voice call. Type /acceptcall {peer.name} or /declinecall {peer.name}")
        elif kind == "accept":
            self.start_call(peer)
        elif kind == "end":
            self.end_call(peer, tell_peer=False)

    def handle_audio(self, peer: Peer, packet: dict) -> None:
        call = self.calls.get(peer.name.lower())
        if call:
            call.play(AESGCM(peer.key).decrypt(unb64(packet["nonce"]), unb64(packet["data"]), b"wire-v1-audio"))

    def attach(self, peer: Peer) -> None:
        old = self.peers.get(peer.name.lower())
        if old and old.sock:
            old.sock.close()
        self.peers[peer.name.lower()] = peer
        if self.room is None:
            self.room = peer.name.lower()
        say(f"connected: {peer.name}  fingerprint: {fingerprint(peer.public_key)}")
        say(f"room open: {peer.name} (type normally; /help for commands)")
        self.show_history(peer.name)
        restart_blank_prompt_after_background_output()
        redraw_prompt()
        if peer.sock:
            self.start_worker(self.receive_loop, peer)

    def handle_message(self, peer: Peer, packet: dict) -> None:
        if packet.get("type") in {"control", "image", "voice", "audio", "file_relay", "msg"} and not peer.accept_nonce(packet):
            return
        try:
            self.handle_authenticated_message(peer, packet)
        except (InvalidTag, KeyError, TypeError, ValueError, UnicodeError):
            # A corrupt authenticated media frame is untrusted network input.
            # Drop only that frame; do not let it tear down the whole room.
            return

    def handle_authenticated_message(self, peer: Peer, packet: dict) -> None:
        if packet.get("type") == "control":
            try:
                control = json.loads(AESGCM(peer.key).decrypt(unb64(packet["nonce"]), unb64(packet["data"]), b"wire-v1-control").decode("utf-8"))
                if control.get("kind") == "webrtc_answer" and isinstance(control.get("answer"), dict):
                    media = self.webrtc_shares.get(str(control.get("id", "")))
                    if media: media.call(media.remote(control["answer"]))
                elif control.get("kind") == "webrtc_offer" and isinstance(control.get("offer"), dict):
                    offer = control["offer"]
                    share_id = control.get("id")
                    if valid_transfer_id(share_id) and valid_share_offer(offer, share_id):
                        resolution = offer["resolution"]
                        self.pending_shares[share_id] = {"from": peer.name, "offer": offer}
                        say(f"\n{peer.name} wants to share their screen ({resolution[0]}x{resolution[1]}).")
                        say(f"Type /share accept {share_id[:6]} or /share decline {share_id[:6]}")
                        redraw_prompt()
                elif control.get("kind") == "webrtc_stop" and valid_transfer_id(control.get("id")):
                    self.pending_shares.pop(control["id"], None)
                    self.stop_share_id(control["id"], remote=True)
                elif control.get("kind") == "webrtc_decline" and valid_transfer_id(control.get("id")):
                    share_id = control["id"]
                    media = self.webrtc_shares.pop(share_id, None)
                    self.share_peers.pop(share_id, None)
                    if media: media.close()
                    say("screen share declined by the other person")
                elif control.get("kind") in ("message_react", "message_edit", "message_delete", "message_delivered", "message_read"):
                    self.apply_message_control(peer, control)
                elif control.get("kind") == "file_relay_accept":
                    file_id = control.get("id")
                    state = self.outgoing_files.get(file_id) if isinstance(file_id, str) else None
                    if state and state["peer"] is peer:
                        self.start_worker(self.relay_send_file_worker, file_id)
                elif control.get("kind") == "file_relay_decline":
                    file_id = control.get("id")
                    state = self.outgoing_files.pop(file_id, None) if isinstance(file_id, str) else None
                    if state:
                        if state.get("cleanup"): state["path"].unlink(missing_ok=True)
                        say("file offer declined")
                elif control.get("kind") == "file_relay_complete":
                    file_id = control.get("id")
                    state = self.outgoing_files.pop(file_id, None) if isinstance(file_id, str) else None
                    if state:
                        if state.get("cleanup"): state["path"].unlink(missing_ok=True)
                        say(f"file sent and verified: {state['path'].name}")
                        restart_blank_prompt_after_background_output()
                elif control.get("kind") == "file_relay_abort":
                    file_id = control.get("id")
                    if isinstance(file_id, str):
                        self.stop_incoming_file(peer, file_id)
                elif control.get("kind") == "image_abort":
                    image_id = control.get("id")
                    if isinstance(image_id, str):
                        self.stop_incoming_image(peer, image_id)
                elif control.get("kind") == "typing":
                    now = time.monotonic()
                    name = peer.name.lower()
                    was_typing = self.typing_until.get(name, 0) > now
                    expires = now + 5
                    self.typing_until[name] = expires
                    # Redraw only at the beginning and end of a typing run.
                    # Repainting the prompt for every typing packet disrupts text entry.
                    if not was_typing:
                        self.refresh_typing_status()
                    def refresh_when_expired() -> None:
                        if self.typing_until.get(name, 0) <= expires:
                            self.typing_until.pop(name, None)
                            self.typing_timers.pop(name, None)
                            self.refresh_typing_status()
                    previous_timer = self.typing_timers.pop(name, None)
                    if previous_timer:
                        previous_timer.cancel()
                    expiry_refresh = threading.Timer(5.05, refresh_when_expired)
                    expiry_refresh.daemon = True
                    self.typing_timers[name] = expiry_refresh
                    expiry_refresh.start()
            except Exception: pass
            return
        if packet.get("type") == "image":
            self.handle_image(peer, packet)
            return
        if packet.get("type") == "voice":
            self.handle_voice(peer, packet)
            return
        if packet.get("type") == "audio":
            self.handle_audio(peer, packet)
            return
        if packet.get("type") == "file_relay":
            self.handle_file_relay(peer, packet)
            return
        if packet.get("type") != "msg":
            return
        nonce, data = unb64(packet["nonce"]), unb64(packet["data"])
        text = AESGCM(peer.key).decrypt(nonce, data, b"wire-v1-message").decode("utf-8")
        if len(text) > MAX_MESSAGE_CHARS:
            return
        message_id = packet.get("id") if valid_transfer_id(packet.get("id")) else uuid.uuid4().hex
        reply_to = packet.get("reply_to") if valid_transfer_id(packet.get("reply_to")) else None
        self.record_history(peer.name, peer.name, text, message_id, reply_to)
        peer.send_control({"kind": "message_delivered", "id": message_id})
        # Wire renders incoming room messages immediately, so that is the
        # honest moment to acknowledge them as read.
        peer.send_control({"kind": "message_read", "id": message_id})
        say(f"\n{self.render_record({'id': message_id, 'from': peer.name, 'text': text, 'reply_to': reply_to})}")
        redraw_prompt()
        if self.notifications_allowed():
            toast(f"new message from {peer.name}")

    def apply_message_control(self, peer: Peer, control: dict) -> None:
        message_id = control.get("id")
        if not isinstance(message_id, str):
            return
        records = self.read_history(peer.name)
        target = next((record for record in records if record.get("id") == message_id), None)
        if not target:
            return
        kind = control["kind"]
        if kind in ("message_delivered", "message_read"):
            if target.get("from") != self.name:
                return
            target["delivered"] = True
            if kind == "message_read": target["read"] = True
            self.save_history(peer.name, records, target)
            return
        if kind == "message_react" and isinstance(control.get("reaction"), str) and 0 < len(control["reaction"]) <= 24:
            reaction = control["reaction"]
            token = f"{peer.name}:{reaction}"
            target["reactions"] = [item for item in target.get("reactions", []) if not str(item).startswith(f"{peer.name}:")] + [token]
            say(f"\n{peer.name} reacted {reaction} to {message_id[:6]}")
        elif kind == "message_edit" and target.get("from") == peer.name and isinstance(control.get("text"), str) and len(control["text"]) <= MAX_MESSAGE_CHARS:
            target["text"], target["edited"] = control["text"], True
            say(f"\n{peer.name} edited message {message_id[:6]}")
        elif kind == "message_delete" and target.get("from") == peer.name:
            target["deleted"], target["text"] = True, ""
            say(f"\n{peer.name} deleted message {message_id[:6]}")
        else:
            return
        self.save_history(peer.name, records, target)
        redraw_prompt()

    def receive_loop(self, peer: Peer) -> None:
        try:
            while not self.closing.is_set():
                packet = recv_frame(peer.sock)
                self.handle_message(peer, packet)
        except Exception as exc:
            if not isinstance(exc, (ConnectionError, OSError)):
                report_background_failure(f"room connection with {peer.name}", exc)
        finally:
            self.peers.pop(peer.name.lower(), None)
            if self.room == peer.name.lower():
                self.room = None
            try:
                peer.sock.close()
            except OSError:
                pass
            if not self.closing.is_set():
                say(f"\n{peer.name} disconnected")

    def connect_server(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        self.require_login()
        if host is None:
            configured = load_directory_config()
            host, port = configured["host"], configured["port"]
        port = port or DEFAULT_DIRECTORY_PORT
        if self.server:
            self.server.close()
            self.server = None
        sock, tls_public = open_directory_socket(str(host), int(port), timeout=8)
        self.directory_public = tls_public
        try:
            send_frame(sock, {"type": "hello", "name": self.name, "public": b64(self.public),
                              "sign_public": b64(self.sign_public)})
            reply = recv_frame(sock)
            if reply.get("type") != "challenge":
                raise ConnectionError(reply.get("message", "directory rejected login"))
            nonce = unb64(reply["nonce"])
            self.verify_directory_identity(str(host), int(port), reply, nonce)
            signature = self.sign_private.sign(login_proof_bytes(self.name, nonce))
            send_frame(sock, {"type": "prove", "signature": b64(signature)})
            reply = recv_frame(sock)
            if reply.get("type") != "ready":
                raise ConnectionError(reply.get("message", "directory rejected login"))
            self.turn_configured = configure_turn(reply.get("turn"))
            sock.settimeout(None)
            self.server = sock
            # New directories advertise their wire-byte relay allowance. Keep
            # headroom for encryption/base64 expansion and normal chat/voice
            # packets. This is fast on a LAN without exceeding the server's
            # anti-flood budget; old servers retain the safe fallback.
            advertised_rate = reply.get("relay_rate")
            if isinstance(advertised_rate, int) and 1 * 1024 * 1024 <= advertised_rate <= 64 * 1024 * 1024:
                self.relay_upload_bytes_per_second = max(
                    RELAY_UPLOAD_BYTES_PER_SECOND,
                    int(advertised_rate / RELAY_UPLOAD_EXPANSION * 0.85),
                )
            self.start_worker(self.server_loop, sock)
            self.server_send({"type": "sync_fetch"})
            self.sync_preferences()
            self.backup_identity()
            version = reply.get("version")
            say(f"username directory online{f' (server {version})' if isinstance(version, str) else ' (old server)' }")
        except Exception:
            sock.close()
            raise

    def switch_directory(self, mode: str, host: str, port: int) -> None:
        """Persist a directory choice and reconnect without mixing private realms."""
        if self.peers:
            raise ValueError("close the active chat with /exit before switching servers")
        old = load_directory_config()
        save_directory_config(mode, host, port)
        if not self.name:
            say(f"{mode} server saved: {host}:{port}; log in to connect")
            return
        try:
            self.connect_server(host, port)
        except Exception:
            save_directory_config(str(old["mode"]), str(old["host"]), int(old["port"]))
            try:
                self.connect_server(str(old["host"]), int(old["port"]))
            except Exception:
                pass
            raise
        say(f"using {mode} server: {host}:{port}")

    def server_send(self, packet: dict) -> None:
        if not self.server:
            raise ConnectionError("username directory is offline")
        with self.server_lock:
            send_frame(self.server, packet)

    def pace_relay_upload(self, raw_bytes: int) -> None:
        """Reserve relay bandwidth before sending an encrypted attachment frame."""
        expanded = max(1, int(raw_bytes * RELAY_UPLOAD_EXPANSION) + 256)
        duration = expanded / self.relay_upload_bytes_per_second
        with self.relay_upload_lock:
            now = time.monotonic()
            scheduled = max(now, self.relay_next_send_at)
            self.relay_next_send_at = scheduled + duration
        delay = scheduled - now
        if delay > 0:
            time.sleep(delay)

    def relay_send(self, username: str, packet: dict) -> None:
        self.server_send({"type": "relay", "to": username, "packet": packet})

    def relay_peer(self, name: str, public: str, sign_public_value: str, identity_signature: str) -> Peer:
        self.require_login()
        peer_public, _ = self.verify_directory_peer(name, public, sign_public_value, identity_signature)
        shared = self.private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"wire-v1").derive(shared)
        return Peer(name, None, key, peer_public, lambda packet: self.relay_send(name, packet))

    def attach_relay_peer(self, name: str, public: str, sign_public_value: str, identity_signature: str) -> None:
        self.require_login()
        if self.is_blocked(name):
            say(f"ignored room from blocked user {name}")
            return
        self.attach(self.relay_peer(name, public, sign_public_value, identity_signature))

    def update_groups(self, entries: object) -> None:
        if not isinstance(entries, list):
            return
        for group in entries:
            if isinstance(group, dict) and isinstance(group.get("name"), str) and isinstance(group.get("members"), list):
                self.groups[group["name"].lower()] = group

    def show_groups(self) -> None:
        if not self.groups:
            self.server_send({"type": "group_list"})
            return
        say("\nGROUPS")
        for group in self.groups.values():
            online = sum(1 for member in group.get("members", []) if member.get("online"))
            mine = next((member.get("role", "member") for member in group.get("members", []) if member.get("name", "").lower() == self.name.lower()), "member")
            say(f"{group['name']}  [{online}/{len(group.get('members', []))} online]  {mine}")

    def show_group_members(self, group: dict) -> None:
        """Show the people in a group when it is opened, without a new UI."""
        members = []
        for member in group.get("members", []):
            name = str(member.get("name", "?"))
            status = "online" if member.get("online") else "offline"
            role = " admin" if member.get("role") == "admin" else ""
            you = " (you)" if self.name and name.lower() == self.name.lower() else ""
            members.append(f"{name}{you} [{status}{role}]")
        width = shutil.get_terminal_size(fallback=(100, 24)).columns
        heading = f"GROUP {group['name']}"
        say("\n" + heading + " " * max(1, width - len(heading) - len("MEMBERS")) + "MEMBERS")
        say(" | ".join(members) or "no members")

    def send_group_message(self, group_name: str, text: str) -> None:
        if len(text) > MAX_MESSAGE_CHARS:
            raise ValueError(f"message is too long ({MAX_MESSAGE_CHARS} character maximum)")
        group = self.groups.get(group_name.lower())
        if not group:
            raise ValueError("unknown group; use group list first")
        packets: dict[str, dict] = {}
        message_id = uuid.uuid4().hex
        for member in group.get("members", []):
            name, public, sign_public_value, identity_signature = member.get("name"), member.get("public"), member.get("sign_public"), member.get("identity_signature")
            if not isinstance(name, str) or not isinstance(public, str) or not isinstance(sign_public_value, str) or not isinstance(identity_signature, str) or name.lower() == self.name.lower():
                continue
            peer = self.relay_peer(name, public, sign_public_value, identity_signature)
            nonce = os.urandom(12)
            data = AESGCM(peer.key).encrypt(nonce, text.encode("utf-8"), b"wire-v1-message")
            packets[name.lower()] = {"type": "msg", "id": message_id, "nonce": b64(nonce), "data": b64(data)}
        self.server_send({"type": "group_send", "group": group["name"], "packets": packets})
        self.record_history(f"group-{group['name']}", self.name or "me", text, message_id)

    def handle_group_message(self, packet: dict) -> None:
        group, sender, public, sign_public_value, identity_signature, encrypted = packet.get("group"), packet.get("from"), packet.get("public"), packet.get("sign_public"), packet.get("identity_signature"), packet.get("packet")
        if not isinstance(group, str) or not isinstance(sender, str) or not isinstance(public, str) or not isinstance(sign_public_value, str) or not isinstance(identity_signature, str) or not isinstance(encrypted, dict) or self.is_blocked(sender):
            return
        try:
            peer = self.relay_peer(sender, public, sign_public_value, identity_signature)
            if encrypted.get("type") != "msg":
                return
            text = AESGCM(peer.key).decrypt(unb64(encrypted["nonce"]), unb64(encrypted["data"]), b"wire-v1-message").decode("utf-8")
            if len(text) > MAX_MESSAGE_CHARS:
                return
        except Exception:
            return
        message_id = encrypted.get("id") if isinstance(encrypted.get("id"), str) else uuid.uuid4().hex
        self.record_history(f"group-{group}", sender, text, message_id)
        say(f"\n[{safe_terminal_text(group)}] {safe_terminal_text(sender)} > {safe_terminal_text(text)}")
        redraw_prompt()
        if self.notifications_allowed():
            toast(f"new group message in {group} from {sender}")

    def group_pin(self, group_name: str, prefix: str, remove: bool = False) -> None:
        group = self.groups.get(group_name.lower())
        if not group:
            raise ValueError("unknown group; use /group list first")
        records, target = self.matching_message(f"group-{group['name']}", prefix)
        self.server_send({"type": "group_unpin" if remove else "group_pin", "group": group["name"], "id": target["id"]})

    def show_group_pins(self, group_name: str) -> None:
        group = self.groups.get(group_name.lower())
        if not group:
            raise ValueError("unknown group; use /group list first")
        records = self.read_history(f"group-{group['name']}")
        by_id = {record.get("id"): record for record in records}
        pins = group.get("pins", [])
        if not pins:
            say("no pinned messages")
            return
        say(f"PINS — {group['name']}")
        for message_id in pins:
            record = by_id.get(message_id)
            say(self.render_record(record, show_id=True) if record else f"({str(message_id)[:6]}) message is not in local history")

    def jump_group_message(self, group_name: str, prefix: str) -> None:
        group = self.groups.get(group_name.lower())
        if not group:
            raise ValueError("unknown group; use /group list first")
        _, record = self.matching_message(f"group-{group['name']}", prefix)
        say(self.render_record(record, show_id=True))

    def server_loop(self, sock: socket.socket) -> None:
        try:
            while not self.closing.is_set():
                packet = recv_frame(sock)
                kind = packet.get("type")
                if kind == "request":
                    name, public, sign_public_value, identity_signature = packet["from"], packet["public"], packet.get("sign_public"), packet.get("identity_signature")
                    if not isinstance(sign_public_value, str) or not isinstance(identity_signature, str):
                        raise ValueError("directory sent an unsigned identity")
                    self.verify_directory_peer(name, public, sign_public_value, identity_signature)
                    if self.is_blocked(name):
                        say(f"\nignored room request from blocked user {name}")
                        continue
                    self.requests[name.lower()] = json.dumps({"public": public, "sign_public": sign_public_value})
                    say(f"\n{name} wants to open a room. Type: accept {name}")
                    redraw_prompt()
                elif kind == "waiting":
                    say(f"waiting for {packet['to']} to accept")
                elif kind == "discover":
                    users = packet.get("users", [])
                    say("\nDISCOVER")
                    if not users:
                        say("no usernames found")
                    for user in users:
                        marker = "online" if user.get("online") else "offline"
                        say(f"{user.get('name', '?')}  [{marker}]")
                elif kind == "status":
                    users = packet.get("users", [])
                    say("\nFRIENDS")
                    for user in users:
                        marker = "online" if user.get("online") else "offline"
                        say(f"{user.get('name', '?')}  [{marker}]")
                elif kind == "friends":
                    users = packet.get("users", [])
                    requests = packet.get("requests", [])
                    say("\nFRIENDS")
                    if not users:
                        say("no friends yet; use /friend add <username>")
                    for user in users:
                        marker = "online" if user.get("online") else "offline"
                        dnd = "; do not disturb" if user.get("dnd") else ""
                        say(f"{user.get('name', '?')}  [{marker}{dnd}]")
                    for requester in requests:
                        say(f"friend request from {requester}: /friend accept {requester} or /friend decline {requester}")
                elif kind == "friend_request":
                    requester = packet.get("from")
                    if isinstance(requester, str):
                        say(f"\nfriend request from {requester}: /friend accept {requester} or /friend decline {requester}")
                        redraw_prompt()
                elif kind == "friend_request_sent":
                    say(f"friend request sent to {packet.get('to', '?')}")
                elif kind == "friend_added":
                    say(f"friends with {packet.get('name', '?')}")
                elif kind == "friend_declined":
                    say(f"friend request declined by {packet.get('name', '?')}")
                elif kind == "friend_removed":
                    say(f"removed friend: {packet.get('name', '?')}")
                elif kind == "group_list":
                    self.update_groups(packet.get("groups"))
                    self.show_groups()
                elif kind == "group_left":
                    group_name = str(packet.get("group", "")).lower()
                    self.groups.pop(group_name, None)
                    if self.group_room == group_name:
                        self.group_room = None
                    say("left group")
                elif kind == "group_kicked":
                    group_name = str(packet.get("group", "")).lower()
                    self.groups.pop(group_name, None)
                    if self.group_room == group_name: self.group_room = None
                    say("you were removed from that group")
                elif kind == "group_invite":
                    group_name, inviter = packet.get("group"), packet.get("from")
                    if isinstance(group_name, str) and isinstance(inviter, str):
                        self.group_invites[group_name.lower()] = group_name
                        say(f"\n{inviter} invited you to group {group_name}. Type /group accept {group_name}")
                        redraw_prompt()
                elif kind == "group_message":
                    self.handle_group_message(packet)
                elif kind == "pong":
                    ping_id = packet.get("id", "")
                    started = self.pending_pings.pop(ping_id, None)
                    if started is not None:
                        say(f"ping: {round((time.monotonic() - started) * 1000)} ms")
                elif kind == "direct_offer":
                    offer = packet.get("offer", {})
                    code = offer.get("id", "")
                    if valid_transfer_id(code) and isinstance(offer.get("name"), str) and isinstance(offer.get("size"), int):
                        self.pending_files[code] = {"from": packet.get("from"), "host": packet.get("host"), "port": packet.get("port"), "offer": offer}
                        say(f"\n{safe_terminal_text(packet.get('from'))} wants to send {safe_terminal_text(offer['name'])} ({offer['size'] // 1024 // 1024} MB)")
                        for item in offer.get("contents", [])[:20]: say(f"  {safe_terminal_text(item)}")
                        say(f"Type /file accept {code[:6]} or /file decline {code[:6]}")
                        redraw_prompt()
                elif kind == "share_offer":
                    offer = packet.get("offer", {})
                    code = offer.get("id", "") if isinstance(offer, dict) else ""
                    if valid_share_offer(offer, code):
                        self.pending_shares[code] = {"from": packet.get("from"), "offer": offer}
                        resolution = offer["resolution"]
                        say(f"\n{safe_terminal_text(packet.get('from'))} wants to share their screen ({resolution[0]}x{resolution[1]}).")
                        say(f"Type /share accept {code[:6]} or /share decline {code[:6]}")
                        redraw_prompt()
                elif kind == "share_answer":
                    # Match the answer to its exact offer. A person can be viewing
                    # one share while offering another, so insertion order is not
                    # a safe way to choose a WebRTC connection.
                    share_id, answer = packet.get("id"), packet.get("answer")
                    media = self.webrtc_shares.get(share_id) if isinstance(share_id, str) else None
                    if media and isinstance(answer, dict):
                        media.call(media.remote(answer))
                elif kind == "share_stop":
                    share_id = packet.get("id", "")
                    if isinstance(share_id, str):
                        self.stop_share_id(share_id, remote=True)
                elif kind == "identity_backup_saved":
                    # Routine login backup succeeded. Avoid an async startup
                    # line here; it can arrive exactly as the first prompt opens.
                    pass
                elif kind == "sync_state":
                    self.apply_sync_state(packet)
                elif kind == "sync_saved":
                    pass
                elif kind == "server_stats":
                    uptime = int(packet.get("uptime", 0))
                    say("\nWIRE SERVER STATUS")
                    say(f"version {packet.get('version', '?')}; uptime {uptime // 86400}d {(uptime % 86400) // 3600}h")
                    say(f"online {packet.get('online', 0)}; accounts {packet.get('accounts', 0)}; groups {packet.get('groups', 0)}")
                    say(f"queued packets {packet.get('queued_packets', 0)}; TURN {'enabled' if packet.get('turn') else 'disabled'}")
                elif kind == "accepted":
                    self.attach_relay_peer(packet["name"], packet["public"], packet["sign_public"], packet["identity_signature"])
                elif kind == "relay":
                    sender = packet.get("from", "")
                    if self.is_blocked(sender):
                        continue
                    peer = self.peers.get(sender.lower())
                    if peer:
                        self.handle_message(peer, packet["packet"])
                elif kind == "error":
                    message = str(packet.get("message", "error"))
                    if packet.get("code") == "relay_rate_limited" or message.startswith("relay rate limit reached"):
                        # Attachment workers pace themselves below the relay
                        # allowance. Never turn a stale server/client mismatch
                        # into noisy terminal output.
                        pass
                    else:
                        say(f"directory: {safe_terminal_text(message)}")
        except Exception as exc:
            if self.server is sock:
                self.server = None
                if not isinstance(exc, (ConnectionError, OSError)):
                    report_background_failure("username directory connection", exc)
                if not self.closing.is_set():
                    say("\ndirectory disconnected")

    def listen(self, port: int) -> None:
        self.require_login()
        if self.listener:
            raise ValueError("already listening")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen()
        self.listener = listener
        self.start_worker(self.accept_loop)
        say(f"listening on TCP {port}")

    def accept_loop(self) -> None:
        if not self.listener:
            return
        while not self.closing.is_set():
            try:
                sock, address = self.listener.accept()
                if not self.direct_handshake_slots.acquire(blocking=False):
                    sock.close()
                    continue
                with self.pending_sockets_lock:
                    self.pending_sockets.add(sock)
                self.start_worker(self.accept_incoming_peer, sock, address)
            except OSError:
                return

    def accept_incoming_peer(self, sock: socket.socket, address: tuple[str, int]) -> None:
        try:
            sock.settimeout(15)
            hello = recv_frame(sock)
            send_frame(sock, self.hello())
            peer = self.make_peer(sock, hello)
            sock.settimeout(None)
            say(f"incoming connection from {address[0]}")
            self.attach(peer)
        except Exception as exc:
            try:
                sock.close()
            except OSError:
                pass
            if not self.closing.is_set():
                say(f"connection refused: {safe_terminal_text(exc)}")
        finally:
            with self.pending_sockets_lock:
                self.pending_sockets.discard(sock)
            self.direct_handshake_slots.release()

    def connect(self, expected: str, host: str, port: int) -> None:
        self.require_login()
        sock = socket.create_connection((host, port), timeout=12)
        try:
            send_frame(sock, self.hello())
            peer = self.make_peer(sock, recv_frame(sock), expected)
            # create_connection sets a timeout. Chat sockets must stay open while idle.
            sock.settimeout(None)
            self.attach(peer)
        except Exception:
            sock.close()
            raise

    def close(self) -> None:
        self.closing.set()
        for timer in self.typing_timers.values():
            timer.cancel()
        self.typing_timers.clear()
        for state in list(self.incoming_images.values()) + list(self.incoming_files.values()):
            temp = state.get("temp")
            if isinstance(temp, Path):
                temp.unlink(missing_ok=True)
        for state in self.outgoing_files.values():
            if state.get("cleanup") and isinstance(state.get("path"), Path):
                state["path"].unlink(missing_ok=True)
        self.incoming_images.clear()
        self.incoming_files.clear()
        self.outgoing_files.clear()
        # Do this before sockets and the interpreter disappear; aiortc owns
        # background ICE / DTLS / RTP tasks that must be drained first.
        for media in list(self.webrtc_shares.values()):
            media.close()
        self.webrtc_shares.clear()
        self.share_peers.clear()
        for stop in list(self.share_viewer_stops.values()):
            stop.set()
        for viewer in list(self.share_viewers.values()):
            if viewer.is_alive(): viewer.join(timeout=3)
            if viewer.is_alive(): viewer.terminate()
        self.share_viewers.clear()
        self.share_viewer_stops.clear()
        with self.pending_sockets_lock:
            pending_sockets = list(self.pending_sockets)
        sockets = [self.listener, self.server] + [peer.sock for peer in self.peers.values()] + pending_sockets
        for connection in sockets:
            if not connection:
                continue
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        self.listener = None
        self.server = None
        for peer in list(self.peers.values()):
            call = self.calls.pop(peer.name.lower(), None)
            if call:
                call.close()
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            with self.background_threads_lock:
                workers = [item for item in self.background_threads if item is not threading.current_thread()]
            if not workers:
                break
            for worker in workers:
                worker.join(timeout=min(0.25, max(0, deadline - time.monotonic())))

    def close_active_chat(self) -> None:
        """Close the current room while leaving Wire and the directory online."""
        if self.group_room:
            self.group_room = None
            say("group chat closed")
            return
        room_name = self.room
        if not room_name:
            say("no chat is open")
            return
        self.room = None
        peer = self.peers.pop(room_name, None)
        if peer and peer.sock:
            try:
                peer.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            peer.sock.close()
        say("chat closed")


HELP = """WIRE HELP

ACCOUNT AND PEOPLE
  signup [name] / login [name]       Create or sign in to an account.
  /private <server-ip-or-name>       Use a self-hosted Wire server (port 47666 by default).
  /public                            Return to Wire's public directory server.
  discover [name]                    Find a Wire username.
  open <name> / accept <name>        Open or accept a private chat.
  friends                             Show friends, online state, and pending requests.
  friend add|accept|decline|remove <name>
                                      Send, answer, or remove a friend request.
  block|unblock <name> / blocked     Manage blocked people.

CHAT
  Type normally in an open room to send a message.
  /history <name>                    Show saved messages without cluttering chat with IDs.
  /history <name> ids                Show saved messages with message codes for reply/edit/react.
  /search <words>                    Search your saved messages locally.
  /reply <code> <text>               Reply to a saved message.
  /react <code> <emoji>              Add or replace your reaction.
  /edit <code> <text> / /delete <code>
                                      Change or delete one of your messages.
  /room <name> / /leave              Switch or close the current room.
  /peers                             Show connected people.

FILES AND MEDIA
  /send <path>                       Send an image, video, file, or folder.
                                      Images use the image flow; everything else uses file transfer.
  /image accept|decline <code>       Answer an image offer.
  /sendfile <path>                   Older alias for /send.
  /file accept|decline <code>        Answer an encrypted file transfer.
  /preview <video path>              Play the first five seconds locally.
  /call / /call stats / /acceptcall <name> / /declinecall <name> / /hangup
  /share                             Start sharing your selected monitor.
  /share accept|decline <code>       Answer a screen-share request.
  /share pause|resume               Temporarily pause or resume outgoing capture.
  /share stop|close / /share stats   Stop sharing or show live share statistics.

GROUPS
  /group list / create <name> <people...> / open|members <name>
  /group invite|accept|kick <group> <person>
  /group admin|member <group> <person>
  /group pin|unpin <group> <message-code> / pins <group>
  /group jump <group> <message-code> / leave <group>

SETTINGS AND UTILITIES
  /settings                          Open the one arrow-key settings menu; changes save automatically.
                                      Includes Do Not Disturb and Allow group invites.
  /settings delete                   Delete this PC's local account data.
  /identity / /fingerprint <name>    Show safety fingerprints.
  /ping / /testnotify / /diagnose   Connection, notification, and capability checks.
  /diagnose network                 Test real ICE, STUN, and TURN candidates.
  /update                            Close Wire and install the newest version.
  /checkupdate                       Check whether a newer version exists.
  /exit                              Close the active chat but keep Wire open.
  /quit                              Close Wire.
  /server stats                      Show privacy-safe directory health totals.

Typing indicators clear automatically five seconds after typing stops."""


def main() -> None:
    enable_terminal_color()
    if local_directory_requested():
        ensure_local_directory()
    app = Wire()
    print(f"wire  {wire_version()}\ntype help")
    # Do not make startup depend on GitHub being reachable. The background
    # check reports only a newer version; use /update for its full result.
    threading.Thread(target=check_for_update, kwargs={"quiet": True}, daemon=True).start()
    # Some Windows launchers provide stdin/stdout but not a full console
    # screen buffer.  prompt_toolkit cannot attach there, so use normal
    # input() rather than crashing before Wire can start.
    try:
        typing_toolbar = ConditionalContainer(
            Window(content=FormattedTextControl(text=app.typing_label), height=1),
            filter=Condition(lambda: bool(app.room and app.typing_label())),
        )
        session = PromptSession(top_toolbar=typing_toolbar) if PromptSession else None
    except Exception:
        session = None
    global SAFE_PROMPT_ACTIVE, PROMPT_APPLICATION, PROMPT_WAITING, PROMPT_REFRESH_TIMER
    dumb_prompt = bool(session and is_dumb_terminal and is_dumb_terminal())
    SAFE_PROMPT_ACTIVE = session is not None and not dumb_prompt
    if SAFE_PROMPT_ACTIVE:
        PROMPT_APPLICATION = session.app
        # Typing packets and their expiry timers run on worker threads. Never
        # mutate prompt_toolkit's renderer from those threads directly.
        app.typing_notifier = refresh_prompt_display
        def announce_typing(_buffer: object) -> None:
            try:
                app.send_typing()
            except (OSError, ConnectionError):
                pass
        session.default_buffer.on_text_changed += announce_typing
    stdout_context = patch_stdout(raw=True) if SAFE_PROMPT_ACTIVE and patch_stdout else None
    if stdout_context:
        stdout_context.__enter__()
    try:
        while True:
            try:
                room_peer = app.peers.get(app.room or "")
                prompt = app.name or "wire"
                global ACTIVE_PROMPT
                ACTIVE_PROMPT = prompt
                flush_pending_output()
                if session:
                    # Incoming messages print above the prompt, then this redraws
                    # whatever the person was already typing without losing it.
                    PROMPT_WAITING = True
                    try:
                        line = session.prompt(f"{prompt} > ").strip()
                    finally:
                        PROMPT_WAITING = False
                else:
                    line = input(f"{prompt} > ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            # A room is normal chat: plain text goes straight to the active person.
            # Prefix commands with / while inside a room, for example /leave.
            room_peer = app.peers.get(app.room or "")
            if app.group_room and not line.startswith("/"):
                try:
                    app.send_group_message(app.group_room, line)
                except (OSError, ConnectionError, ValueError) as exc:
                    print(f"error: {exc}")
                continue
            if room_peer and not line.startswith("/"):
                try:
                    app.send_message(room_peer, line)
                except (OSError, ConnectionError, ValueError) as exc:
                    print(f"error: {exc}")
                continue
            if line.startswith("/"):
                line = line[1:]
            # An asynchronous status update can coincide with a bare slash.
            # Do not let that turn into an empty command and crash Wire.
            if not line.strip():
                continue
            command, *rest = line.split(maxsplit=1)
            argument = rest[0] if rest else ""
            try:
                if command == "help":
                    print(HELP)
                elif command == "settings":
                    pieces = argument.split()
                    if not pieces:
                        app.settings_menu()
                    elif pieces == ["delete"]:
                        app.delete_account()
                        break
                    else:
                        raise ValueError("use: /settings (use the arrow-key menu); /settings delete deletes your local account")
                elif command == "signup":
                    app.signup(argument or input("username: ").strip())
                elif command == "login":
                    app.login(argument or input("username: ").strip())
                elif command == "private":
                    if not argument:
                        configured = load_directory_config()
                        if configured["mode"] == "private":
                            print(f"private server: {configured['host']}:{configured['port']}")
                        else:
                            raise ValueError("use: /private <server-ip-or-name>[:port]")
                    else:
                        host, port = parse_directory_endpoint(argument)
                        app.switch_directory("private", host, port)
                elif command == "public":
                    app.switch_directory("public", DEFAULT_DIRECTORY_HOST, DEFAULT_DIRECTORY_PORT)
                elif command == "discover":
                    app.server_send({"type": "discover", "query": argument})
                elif command == "friends":
                    app.show_friends()
                elif command == "friend":
                    friend_parts = argument.split(maxsplit=1)
                    if len(friend_parts) != 2:
                        raise ValueError("use: /friend add|accept|decline|remove <username>")
                    action, username = friend_parts
                    if action == "add":
                        app.server_send({"type": "friend_request", "to": username})
                    elif action in ("accept", "decline"):
                        app.server_send({"type": f"friend_{action}", "from": username})
                    elif action == "remove":
                        app.server_send({"type": "friend_remove", "name": username})
                    else:
                        raise ValueError("use: /friend add|accept|decline|remove <username>")
                elif command == "block":
                    app.edit_contact("blocked", argument, add=True)
                    print(f"blocked: {argument}")
                elif command == "unblock":
                    app.edit_contact("blocked", argument, add=False)
                    print(f"unblocked: {argument}")
                elif command == "blocked":
                    print("\n".join(app.contacts()["blocked"]) or "no blocked users")
                elif command == "history":
                    if not argument:
                        raise ValueError("use: history <username>")
                    pieces = argument.split()
                    if len(pieces) not in (1, 2) or (len(pieces) == 2 and pieces[1] != "ids"):
                        raise ValueError("use: /history <username> [ids]")
                    app.show_history(pieces[0], show_ids=len(pieces) == 2)
                elif command == "search":
                    app.search_history(argument)
                elif command == "group":
                    pieces = argument.split()
                    if not pieces or pieces[0] == "list":
                        app.groups.clear()
                        app.server_send({"type": "group_list"})
                    elif pieces[0] == "create" and len(pieces) >= 2:
                        app.server_send({"type": "group_create", "name": pieces[1], "members": pieces[2:]})
                    elif pieces[0] == "open" and len(pieces) == 2:
                        group = app.groups.get(pieces[1].lower())
                        if not group:
                            app.server_send({"type": "group_list"})
                            raise ValueError("groups refreshed; run /group open <name> again")
                        app.group_room = group["name"].lower()
                        app.room = None
                        print(f"group open: {group['name']} (type normally; /group leave {group['name']} to leave)")
                        app.show_group_members(group)
                        app.show_history(f"group-{group['name']}")
                    elif pieces[0] == "members" and len(pieces) == 2:
                        group = app.groups.get(pieces[1].lower())
                        if not group:
                            raise ValueError("unknown group; use /group list first")
                        app.show_group_members(group)
                    elif pieces[0] in ("add", "invite") and len(pieces) == 3:
                        app.server_send({"type": "group_invite", "group": pieces[1], "member": pieces[2]})
                    elif pieces[0] == "accept" and len(pieces) == 2:
                        app.server_send({"type": "group_accept_invite", "group": pieces[1]})
                    elif pieces[0] == "kick" and len(pieces) == 3:
                        app.server_send({"type": "group_kick", "group": pieces[1], "member": pieces[2]})
                    elif pieces[0] in ("admin", "member") and len(pieces) == 3:
                        app.server_send({"type": "group_admin", "group": pieces[1], "member": pieces[2], "enabled": pieces[0] == "admin"})
                    elif pieces[0] in ("pin", "unpin") and len(pieces) == 3:
                        app.group_pin(pieces[1], pieces[2], remove=pieces[0] == "unpin")
                    elif pieces[0] == "pins" and len(pieces) == 2:
                        app.show_group_pins(pieces[1])
                    elif pieces[0] == "jump" and len(pieces) == 3:
                        app.jump_group_message(pieces[1], pieces[2])
                    elif pieces[0] == "leave" and len(pieces) == 2:
                        app.server_send({"type": "group_leave", "group": pieces[1]})
                    else:
                        raise ValueError("use: /group create <name> <people...> | list | open|members <name> | invite <name> <user> | accept <name> | kick <name> <user> | admin|member <name> <user> | pin|unpin <name> <message-code> | pins <name> | jump <name> <message-code> | leave <name>")
                elif command == "send":
                    room_peer = app.peers.get(app.room or "")
                    if not room_peer:
                        raise ValueError("open a room before sending a file")
                    if not argument:
                        raise ValueError("use: /send <file, image, video, or folder path>")
                    app.send_attachment(room_peer, argument)
                elif command == "sendfile":
                    room_peer = app.peers.get(app.room or "")
                    if not room_peer:
                        raise ValueError("open a room before sending a file")
                    if not argument:
                        raise ValueError("use: /sendfile <file path>")
                    app.send_attachment(room_peer, argument)
                elif command in ("reply", "react", "edit", "delete"):
                    room_peer = app.peers.get(app.room or "")
                    if not room_peer:
                        raise ValueError("open a room first")
                    pieces = argument.split(maxsplit=1)
                    if not pieces:
                        raise ValueError(f"use: /{command} <message-code>" + (" <text>" if command != "delete" else ""))
                    if command == "delete":
                        app.delete_message(room_peer, pieces[0])
                    elif len(pieces) != 2:
                        raise ValueError(f"use: /{command} <message-code> <text>")
                    elif command == "reply":
                        app.reply_message(room_peer, pieces[0], pieces[1])
                    elif command == "react":
                        app.react_message(room_peer, pieces[0], pieces[1])
                    else:
                        app.edit_message(room_peer, pieces[0], pieces[1])
                elif command == "file":
                    pieces = argument.split(maxsplit=1)
                    if len(pieces) != 2 or pieces[0] not in ("accept", "decline", "resume"):
                        raise ValueError("use: /file accept|decline|resume <code>")
                    if pieces[0] == "resume":
                        app.resume_file(pieces[1])
                    else:
                        app.answer_file_offer(pieces[1], accept=pieces[0] == "accept")
                elif command == "preview":
                    if not argument:
                        raise ValueError("use: /preview <video path>")
                    app.preview_video(argument)
                elif command == "share":
                    pieces = argument.split(maxsplit=1)
                    if not pieces:
                        room_peer = app.peers.get(app.room or "")
                        if not room_peer:
                            raise ValueError("open a room before sharing your screen")
                        app.start_share(room_peer)
                    elif len(pieces) == 2 and pieces[0] in ("accept", "decline"):
                        app.answer_share_offer(pieces[1], accept=pieces[0] == "accept")
                    elif pieces in (["stop"], ["close"]):
                        app.stop_screen_share()
                    elif pieces == ["stats"]:
                        app.show_share_stats()
                    elif pieces == ["pause"]:
                        app.pause_screen_share(True)
                    elif pieces == ["resume"]:
                        app.pause_screen_share(False)
                    else:
                        raise ValueError("use: /share | /share accept|decline <code> | /share pause|resume|stop|stats")
                elif command == "ping":
                    ping_id = uuid.uuid4().hex
                    app.pending_pings[ping_id] = time.monotonic()
                    app.server_send({"type": "ping", "id": ping_id})
                elif command == "diagnose":
                    if argument not in ("", "network"):
                        raise ValueError("use: /diagnose or /diagnose network")
                    app.diagnose(network=argument == "network")
                elif command == "update":
                    print("Wire will close, then install the newest version in a separate window.")
                    start_update_after_exit()
                    break
                elif command == "checkupdate":
                    check_for_update()
                elif command == "testnotify":
                    toast("Wire notifications are working.")
                    print("sent Windows notification test")
                elif command == "image":
                    room_peer = app.peers.get(app.room or "")
                    pieces = argument.split(maxsplit=1)
                    if not room_peer or len(pieces) != 2 or pieces[0] not in ("accept", "decline"):
                        raise ValueError("use: /image accept <code> or /image decline <code>")
                    app.answer_image_offer(room_peer, pieces[1], accept=pieces[0] == "accept")
                elif command == "call" and argument.strip().lower() == "stats":
                    app.show_call_stats()
                elif command == "call":
                    if argument:
                        raise ValueError("use: /call or /call stats")
                    room_peer = app.peers.get(app.room or "")
                    if not room_peer:
                        raise ValueError("open a room before calling")
                    app.request_call(room_peer)
                elif command == "acceptcall":
                    peer = app.peers.get(argument.lower())
                    if not peer:
                        raise ValueError("that person is not in a room")
                    app.accept_call(peer)
                elif command == "declinecall":
                    peer = app.peers.get(argument.lower())
                    if not peer:
                        raise ValueError("that person is not in a room")
                    app.call_requests.discard(peer.name.lower())
                    peer.send_voice_frame({"kind": "end"})
                    print("voice call declined")
                elif command == "hangup":
                    room_peer = app.peers.get(app.room or "")
                    if not room_peer:
                        raise ValueError("no active room")
                    app.end_call(room_peer)
                elif command == "server":
                    pieces = argument.split()
                    if pieces == ["stats"]:
                        app.server_send({"type": "server_stats"})
                        continue
                    raise ValueError("use /private <server-ip-or-name> or /public; /server stats shows health")
                elif command == "open":
                    if not argument:
                        raise ValueError("use: open <username>")
                    if app.is_blocked(argument):
                        raise ValueError("unblock that user before opening a room")
                    app.server_send({"type": "open", "to": argument})
                elif command == "accept":
                    if app.is_blocked(argument):
                        raise ValueError("unblock that user before accepting")
                    public = app.requests.get(argument.lower())
                    if not public:
                        raise ValueError("no pending request from that user")
                    app.server_send({"type": "accept", "from": argument})
                elif command == "listen":
                    app.listen(int(argument or PORT))
                elif command == "connect":
                    pieces = argument.split()
                    if len(pieces) not in (2, 3):
                        raise ValueError("use: connect <username> <ip-or-host> [port]")
                    app.connect(pieces[0], pieces[1], int(pieces[2]) if len(pieces) == 3 else PORT)
                elif command == "msg":
                    user, text = argument.split(maxsplit=1)
                    peer = app.peers.get(user.lower())
                    if not peer:
                        raise ValueError(f"not connected to {user}")
                    app.send_message(peer, text)
                elif command == "peers":
                    print("\n".join(peer.name for peer in app.peers.values()) or "no peers")
                elif command == "room":
                    peer = app.peers.get(argument.lower())
                    if not peer:
                        raise ValueError("not connected to that user")
                    app.room = peer.name.lower()
                    app.group_room = None
                    print(f"room open: {peer.name}")
                elif command == "leave":
                    if app.group_room:
                        app.group_room = None
                        print("group closed")
                    else:
                        app.room = None
                        print("room closed")
                elif command == "identity":
                    app.require_login()
                    print(fingerprint(app.public))
                elif command == "fingerprint":
                    peer = app.peers.get(argument.lower())
                    if not peer:
                        raise ValueError("not connected to that user")
                    print(fingerprint(peer.public_key))
                elif command == "exit":
                    app.close_active_chat()
                elif command == "quit":
                    break
                else:
                    print("unknown command; open a chat to send messages, or type help")
            except (ValueError, OSError, ConnectionError) as exc:
                print(f"error: {exc}")
    finally:
        with PROMPT_REFRESH_LOCK:
            if PROMPT_REFRESH_TIMER is not None:
                PROMPT_REFRESH_TIMER.cancel()
                PROMPT_REFRESH_TIMER = None
        app.close()
        PROMPT_APPLICATION = None
        PROMPT_WAITING = False
        if stdout_context:
            stdout_context.__exit__(*sys.exc_info())


if __name__ == "__main__":
    main()
