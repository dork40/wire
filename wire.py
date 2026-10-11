"""wire: a small direct encrypted terminal chat for Windows."""

from __future__ import annotations

import base64
import ctypes
import io
import multiprocessing as mp
import queue
import tkinter as tk
import getpass
import hashlib
import hmac
import json
import os
import platform
import socket
import struct
import subprocess
import shutil
import sys
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from PIL import Image, ImageDraw
from PIL import ImageTk
import numpy as np
from pywebrtc_audio import AudioProcessor
import mss
from wire_webrtc import WebRTCShare

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.patch_stdout import patch_stdout
except ImportError:
    PromptSession = None
    patch_stdout = None

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
DOWNLOADS_DIR = Path.home() / "Downloads" / "Wire"
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
MAX_IMAGE_BYTES = 20 * 1024 * 1024
IMAGE_CHUNK_BYTES = 40 * 1024
MAX_FILE_BYTES = 500 * 1024 * 1024
FILE_CHUNK_BYTES = 64 * 1024
VIDEO_EXTENSIONS = {".mp4", ".mkv", ".webm", ".avi", ".mov", ".m4v"}
TRANSFER_TEMP_DIR = DATA / "transfer-temp"
STREAM_RESOLUTIONS = [(640, 360), (854, 480), (1280, 720), (1600, 900), (1920, 1080), (2560, 1440), (3840, 2160)]
STREAM_FPS = [15, 24, 30, 60, 90, 120]
# This is a target, not a promise: actual FPS also depends on the PC and LAN.
STREAM_BITRATES = [1, 2, 4, 8, 12, 20, 35, 50]
STREAM_PROFILES = ("auto", "low-resource", "balanced", "smooth", "gaming", "ultra")
PRINT_LOCK = threading.Lock()
ACTIVE_PROMPT = "wire"
SAFE_PROMPT_ACTIVE = False


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


def derive(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)


def load_users() -> dict:
    if not USERS.exists():
        return {}
    return json.loads(USERS.read_text(encoding="utf-8"))


def save_users(users: dict) -> None:
    DATA.mkdir(exist_ok=True)
    temp = USERS.with_suffix(".tmp")
    temp.write_text(json.dumps(users, indent=2), encoding="utf-8")
    temp.replace(USERS)


def load_settings() -> dict:
    try:
        saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        noise = saved.get("voice_noise", 2 if saved.get("voice_effects", True) else 0)
        return {"notifications": bool(saved.get("notifications", True)), "voice_input": saved.get("voice_input"), "voice_output": saved.get("voice_output"), "voice_mode": saved.get("voice_mode", "ptt"), "voice_effects": bool(saved.get("voice_effects", True)), "voice_echo": bool(saved.get("voice_echo", saved.get("voice_effects", True))), "voice_noise": max(0, min(3, int(noise))), "voice_gain": bool(saved.get("voice_gain", True)), "stream_resolution": max(0, min(len(STREAM_RESOLUTIONS) - 1, int(saved.get("stream_resolution", 2)))), "stream_fps": max(0, min(len(STREAM_FPS) - 1, int(saved.get("stream_fps", 2)))), "stream_bitrate": max(0, min(len(STREAM_BITRATES) - 1, int(saved.get("stream_bitrate", 3)))), "stream_profile": saved.get("stream_profile", "auto") if saved.get("stream_profile", "auto") in STREAM_PROFILES else "auto", "stream_codec": saved.get("stream_codec", "auto"), "stream_hardware": bool(saved.get("stream_hardware", True)), "stream_latency": saved.get("stream_latency", "low")}
    except Exception:
        return {"notifications": True, "voice_input": None, "voice_output": None, "voice_mode": "ptt", "voice_effects": True, "voice_echo": True, "voice_noise": 2, "voice_gain": True, "stream_resolution": 2, "stream_fps": 2, "stream_bitrate": 3, "stream_profile": "auto", "stream_codec": "auto", "stream_hardware": True, "stream_latency": "low"}


def save_settings(settings: dict) -> None:
    DATA.mkdir(exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings), encoding="utf-8")


def stream_capabilities() -> dict:
    """Cheap, non-authoritative capability probe; never infer codec support from GPU names."""
    result = {"platform": platform.system(), "codecs": [], "webrtc": False, "hardware": "not verified"}
    try:
        from aiortc.rtcrtpsender import RTCRtpSender
        result["webrtc"] = True
        result["codecs"] = sorted({codec.mimeType.split("/")[-1] for codec in RTCRtpSender.getCapabilities("video").codecs if codec.mimeType.startswith("video/") and codec.mimeType not in ("video/rtx", "video/red")})
    except Exception:
        pass
    # A successful encoder probe belongs in the native media backend.  Do not advertise
    # NVENC/QSV/AMF simply because a matching adapter name is present.
    return result


def apply_stream_profile(settings: dict) -> None:
    profiles = {
        "low-resource": (1, 2, 1), "balanced": (2, 2, 2), "smooth": (4, 3, 3),
        "gaming": (4, 3, 4), "ultra": (5, 3, 5),
    }
    if settings.get("stream_profile") in profiles:
        settings["stream_resolution"], settings["stream_fps"], settings["stream_bitrate"] = profiles[settings["stream_profile"]]


def wire_version() -> str:
    """Return the packaged version so people can confirm both PCs match."""
    base = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
    try:
        return (base / "VERSION.txt").read_text(encoding="utf-8").splitlines()[0]
    except (OSError, IndexError):
        return "Wire version unknown"


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
    with PRINT_LOCK:
        print(text, flush=True)


def redraw_prompt() -> None:
    # prompt_toolkit restores the exact unfinished input line itself.
    if SAFE_PROMPT_ACTIVE:
        return
    with PRINT_LOCK:
        print(f"{ACTIVE_PROMPT} > ", end="", flush=True)


def draw_mouse_cursor(image: Image.Image, monitor: dict) -> None:
    """Draw a clear cursor into a captured desktop frame on Windows."""
    if os.name != "nt":
        return
    class Point(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
    point = Point()
    if not ctypes.windll.user32.GetCursorPos(ctypes.byref(point)):
        return
    x, y = point.x - monitor["left"], point.y - monitor["top"]
    if not (0 <= x < image.width and 0 <= y < image.height):
        return
    draw = ImageDraw.Draw(image)
    arrow = [(x, y), (x, y + 20), (x + 5, y + 15), (x + 10, y + 25),
             (x + 14, y + 23), (x + 9, y + 13), (x + 18, y + 13)]
    draw.line(arrow + [arrow[0]], fill="black", width=4, joint="curve")
    draw.polygon(arrow, fill="white")


def screen_viewer_process(frames: object, title: str) -> None:
    """Tk owns its interpreter in this process; never create it on a worker thread."""
    root = tk.Tk(); root.title(title)
    label = tk.Label(root, text="Connecting encrypted WebRTC video…", bg="black", fg="white"); label.pack()
    closed = False
    def close() -> None:
        nonlocal closed
        closed = True; root.destroy()
    def draw() -> None:
        if closed: return
        newest = None
        try:
            while True: newest = frames.get_nowait()
        except queue.Empty: pass
        if newest is not None:
            shown = ImageTk.PhotoImage(Image.fromarray(newest))
            label.configure(image=shown, text=""); label.image = shown
        root.after(15, draw)
    root.protocol("WM_DELETE_WINDOW", close); root.after(15, draw); root.mainloop()


def toast(text: str) -> None:
    # PowerShell uses the Windows toast API. Failure is harmless: the terminal still shows the message.
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    script = (
        "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] > $null;"
        "$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "'));"
        "$t=[Security.SecurityElement]::Escape($t);"
        "$x=New-Object Windows.Data.Xml.Dom.XmlDocument;"
        "$x.LoadXml(\"<toast><visual><binding template='ToastGeneric'><text>wire</text><text>$t</text></binding></visual></toast>\");"
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('wire').Show((New-Object Windows.UI.Notifications.ToastNotification $x))"
    )
    try:
        subprocess.run(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", script],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        pass


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


def fingerprint(public_key: bytes) -> str:
    digest = hashlib.sha256(public_key).hexdigest().upper()
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def login_proof_bytes(name: str, nonce: bytes) -> bytes:
    return b"wire-login-v1\0" + name.lower().encode("utf-8") + b"\0" + nonce


@dataclass
class Peer:
    name: str
    sock: Optional[socket.socket]
    key: bytes
    public_key: bytes
    relay: Optional[Callable[[dict], None]] = None

    def send(self, text: str) -> None:
        nonce = os.urandom(12)
        data = AESGCM(self.key).encrypt(nonce, text.encode("utf-8"), b"wire-v1-message")
        packet = {"type": "msg", "nonce": b64(nonce), "data": b64(data)}
        if self.relay:
            self.relay(packet)
        elif self.sock:
            send_frame(self.sock, packet)
        else:
            raise ConnectionError("room is no longer connected")

    def send_image_frame(self, frame: dict) -> None:
        nonce = os.urandom(12)
        raw = json.dumps(frame, separators=(",", ":")).encode("utf-8")
        data = AESGCM(self.key).encrypt(nonce, raw, b"wire-v1-image")
        packet = {"type": "image", "nonce": b64(nonce), "data": b64(data)}
        if self.relay:
            self.relay(packet)
        elif self.sock:
            send_frame(self.sock, packet)
        else:
            raise ConnectionError("room is no longer connected")

    def send_voice_frame(self, frame: dict) -> None:
        nonce = os.urandom(12)
        data = AESGCM(self.key).encrypt(nonce, json.dumps(frame, separators=(",", ":")).encode("utf-8"), b"wire-v1-voice")
        packet = {"type": "voice", "nonce": b64(nonce), "data": b64(data)}
        if self.relay:
            self.relay(packet)
        elif self.sock:
            send_frame(self.sock, packet)
        else:
            raise ConnectionError("room is no longer connected")

    def send_control(self, frame: dict) -> None:
        """Small encrypted control message; works through every deployed relay."""
        nonce = os.urandom(12)
        data = AESGCM(self.key).encrypt(nonce, json.dumps(frame, separators=(",", ":")).encode("utf-8"), b"wire-v1-control")
        packet = {"type": "control", "nonce": b64(nonce), "data": b64(data)}
        if self.relay: self.relay(packet)
        elif self.sock: send_frame(self.sock, packet)
        else: raise ConnectionError("room is no longer connected")

    def send_audio(self, audio: bytes) -> None:
        nonce = os.urandom(12)
        data = AESGCM(self.key).encrypt(nonce, audio, b"wire-v1-audio")
        packet = {"type": "audio", "nonce": b64(nonce), "data": b64(data)}
        if self.relay:
            self.relay(packet)
        elif self.sock:
            send_frame(self.sock, packet)
        else:
            raise ConnectionError("room is no longer connected")


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
            except Exception:
                self.talking.clear()

    def play(self, audio: bytes) -> None:
        try:
            samples = np.frombuffer(audio, dtype=np.int16)
            with self.audio_lock:
                self.far_audio = samples.copy()
            self.output.write(audio)
        except Exception:
            pass

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
        self.history_lock = threading.Lock()
        self.peers: dict[str, Peer] = {}
        self.room: Optional[str] = None
        self.listener: Optional[socket.socket] = None
        self.server: Optional[socket.socket] = None
        self.server_lock = threading.Lock()
        self.requests: dict[str, str] = {}
        self.incoming_images: dict[str, dict] = {}
        self.pending_images: dict[str, dict] = {}
        self.outgoing_images: dict[str, dict] = {}
        self.calls: dict[str, VoiceCall] = {}
        self.call_requests: set[str] = set()
        self.pending_pings: dict[str, float] = {}
        self.pending_files: dict[str, dict] = {}
        self.outgoing_files: dict[str, dict] = {}
        self.pending_shares: dict[str, dict] = {}
        self.outgoing_shares: dict[str, dict] = {}
        self.webrtc_shares: dict[str, WebRTCShare] = {}
        self.share_viewers: dict[str, mp.Process] = {}
        self.groups: dict[str, dict] = {}
        self.group_room: Optional[str] = None
        self.settings = load_settings()

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
        secret = derive(first, salt)
        private = x25519.X25519PrivateKey.generate()
        sign_private = ed25519.Ed25519PrivateKey.generate()
        raw_private = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        raw_sign_private = sign_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        sign_public = sign_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        users[name.lower()] = {"name": name, "salt": b64(salt), "check": b64(secret),
                               "private": Fernet(base64.urlsafe_b64encode(secret)).encrypt(raw_private).decode("ascii"),
                               "public": b64(public),
                               "sign_private": Fernet(base64.urlsafe_b64encode(secret)).encrypt(raw_sign_private).decode("ascii"),
                               "sign_public": b64(sign_public)}
        save_users(users)
        say(f"made user {name}")

    def login(self, name: str) -> None:
        users = load_users()
        account = users.get(name.lower())
        if not account:
            raise ValueError("no local user with that name")
        password = getpass.getpass("password: ")
        secret = derive(password, unb64(account["salt"]))
        if not hmac.compare_digest(secret, unb64(account["check"])):
            raise ValueError("wrong password")
        try:
            raw = Fernet(base64.urlsafe_b64encode(secret)).decrypt(account["private"].encode("ascii"))
        except Exception as exc:
            raise ValueError("could not unlock identity") from exc
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
        say(f"signed in as {self.name}")
        try:
            self.connect_server()
        except (OSError, ConnectionError, ValueError) as exc:
            say(f"directory offline ({exc})")

    def require_login(self) -> None:
        if not self.private or not self.public or not self.sign_private or not self.sign_public or not self.name:
            raise ValueError("sign in first")

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
        shared = self.private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"wire-v1").derive(shared)
        return Peer(peer_name, sock, key, peer_public)

    def hello(self) -> dict:
        self.require_login()
        return {"type": "hello", "name": self.name, "public": b64(self.public)}

    def history_path(self, peer_name: str) -> Path:
        self.require_login()
        return HISTORY_DIR / f"{self.name.lower()}--{peer_name.lower()}.wire"

    def contacts_path(self) -> Path:
        self.require_login()
        return CONTACTS_DIR / f"{self.name.lower()}.wire"

    def contacts(self) -> dict[str, list[str]]:
        """Return the signed-in user's encrypted local friend and block lists."""
        empty = {"friends": [], "blocked": []}
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
            }
        except Exception:
            return empty

    def save_contacts(self, contacts: dict[str, list[str]]) -> None:
        self.require_login()
        assert self.history_key
        CONTACTS_DIR.mkdir(exist_ok=True)
        payload = json.dumps(contacts, separators=(",", ":")).encode("utf-8")
        self.contacts_path().write_bytes(Fernet(self.history_key).encrypt(payload))

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
        friends = self.contacts()["friends"]
        if not friends:
            say("no friends yet; use friend add <username>")
            return
        self.server_send({"type": "status", "users": friends})

    def show_settings(self) -> None:
        say("SETTINGS")
        say(f"notifications: {'on' if self.settings['notifications'] else 'off'}")
        say(f"voice activation: {'always on' if self.settings['voice_mode'] == 'open' else 'hold F12 to talk'}")
        say(f"echo cancellation: {'on' if self.settings['voice_echo'] else 'off'}")
        say(f"noise removal: {('off', 'light', 'normal', 'strong')[self.settings['voice_noise']]}")
        say(f"auto volume: {'on' if self.settings['voice_gain'] else 'off'}")
        say("voice quality: high (48 kHz)")
        width, height = STREAM_RESOLUTIONS[self.settings["stream_resolution"]]
        caps = stream_capabilities()
        say(f"screen share: {self.settings['stream_profile']}; {width}x{height} at {STREAM_FPS[self.settings['stream_fps']]} FPS, {STREAM_BITRATES[self.settings['stream_bitrate']]} Mbps target")
        say(f"screen codec: {self.settings['stream_codec']}; WebRTC: {'available' if caps['webrtc'] else 'not installed'}; codecs: {', '.join(caps['codecs']) or 'none'}")
        say("images: ask before download")

    def apply_voice_settings(self) -> None:
        for call in list(self.calls.values()):
            call.apply_settings()

    def voice_devices(self, direction: str) -> list[tuple[int, str]]:
        if sd is None:
            return []
        channel_key = "max_input_channels" if direction == "input" else "max_output_channels"
        return [(index, str(device["name"])) for index, device in enumerate(sd.query_devices()) if device[channel_key]]

    def settings_menu(self) -> None:
        """Small keyboard-only menu for Command Prompt and Windows Terminal."""
        if msvcrt is None:
            self.show_settings()
            return
        selected = 0
        while True:
            inputs, outputs = self.voice_devices("input"), self.voice_devices("output")
            input_id, output_id = self.settings.get("voice_input"), self.settings.get("voice_output")
            input_name = next((name for index, name in inputs if index == input_id), "Windows default")
            output_name = next((name for index, name in outputs if index == output_id), "Windows default")
            rows = [
                ("Notifications", "On" if self.settings["notifications"] else "Off"),
                ("Voice activation", "Always on" if self.settings["voice_mode"] == "open" else "Push-to-talk (F12)"),
                ("Echo cancellation", "On" if self.settings["voice_echo"] else "Off"),
                ("Noise removal", ("Off", "Light", "Normal", "Strong")[self.settings["voice_noise"]]),
                ("Auto volume", "On" if self.settings["voice_gain"] else "Off"),
                ("Microphone (next call)", input_name),
                ("Speakers (next call)", output_name),
                ("Share resolution", f"{STREAM_RESOLUTIONS[self.settings['stream_resolution']][0]}x{STREAM_RESOLUTIONS[self.settings['stream_resolution']][1]}"),
                ("Share FPS", str(STREAM_FPS[self.settings["stream_fps"]])),
                ("Share bitrate", f"{STREAM_BITRATES[self.settings['stream_bitrate']]} Mbps"),
                ("Share profile", self.settings["stream_profile"]),
                ("Share codec", self.settings["stream_codec"]),
                ("Hardware acceleration", "On" if self.settings["stream_hardware"] else "Off"),
                ("Latency mode", self.settings["stream_latency"]),
                ("Back", ""),
            ]
            print("\x1b[2J\x1b[H", end="")
            print("WIRE SETTINGS  (Up/Down: select   Left/Right: change   Enter/Esc: back)\n")
            for index, (label, value) in enumerate(rows):
                marker = ">" if index == selected else " "
                print(f"{marker} {label}: {value}" if value else f"{marker} {label}")
            key = msvcrt.getwch()
            if key in ("\x00", "\xe0"):
                key = msvcrt.getwch()
                if key == "H":
                    selected = (selected - 1) % len(rows)
                elif key == "P":
                    selected = (selected + 1) % len(rows)
                elif key in ("K", "M"):
                    direction = -1 if key == "K" else 1
                    if selected == 0:
                        self.settings["notifications"] = not self.settings["notifications"]
                    elif selected == 1:
                        self.settings["voice_mode"] = "open" if self.settings["voice_mode"] == "ptt" else "ptt"
                    elif selected == 2:
                        self.settings["voice_echo"] = not self.settings["voice_echo"]
                    elif selected == 3:
                        self.settings["voice_noise"] = (self.settings["voice_noise"] + direction) % 4
                    elif selected == 4:
                        self.settings["voice_gain"] = not self.settings["voice_gain"]
                    elif selected in (5, 6):
                        choices = inputs if selected == 5 else outputs
                        setting = "voice_input" if selected == 5 else "voice_output"
                        if choices:
                            current = self.settings.get(setting)
                            position = next((i for i, (device_id, _) in enumerate(choices) if device_id == current), -1)
                            self.settings[setting] = choices[(position + direction) % len(choices)][0]
                    elif selected == 7:
                        self.settings["stream_resolution"] = (self.settings["stream_resolution"] + direction) % len(STREAM_RESOLUTIONS)
                    elif selected == 8:
                        self.settings["stream_fps"] = (self.settings["stream_fps"] + direction) % len(STREAM_FPS)
                    elif selected == 9:
                        self.settings["stream_bitrate"] = (self.settings["stream_bitrate"] + direction) % len(STREAM_BITRATES)
                    elif selected == 10:
                        options = list(STREAM_PROFILES)
                        self.settings["stream_profile"] = options[(options.index(self.settings["stream_profile"]) + direction) % len(options)]
                        apply_stream_profile(self.settings)
                    elif selected == 11:
                        options = ["auto", "H264", "VP8", "VP9", "AV1", "HEVC"]
                        self.settings["stream_codec"] = options[(options.index(self.settings["stream_codec"]) + direction) % len(options)]
                    elif selected == 12:
                        self.settings["stream_hardware"] = not self.settings["stream_hardware"]
                    elif selected == 13:
                        self.settings["stream_latency"] = "balanced" if self.settings["stream_latency"] == "low" else "low"
                    save_settings(self.settings)
                    self.apply_voice_settings()
            elif key in ("\r", "\x1b") and selected == 14:
                print()
                return
            elif key == "\x1b":
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
        say(f"voice {direction} set to {index}: {device['name']}")

    def set_voice_mode(self, value: str) -> None:
        if value not in ("open", "ptt"):
            raise ValueError("use: settings voice mode open|ptt")
        self.settings["voice_mode"] = value
        save_settings(self.settings)
        self.apply_voice_settings()
        say("voice is always on" if value == "open" else "voice is push-to-talk (hold F12)")

    def set_voice_effects(self, value: str) -> None:
        if value not in ("on", "off"):
            raise ValueError("use: settings voice effects on|off")
        self.settings["voice_effects"] = value == "on"
        self.settings["voice_echo"] = value == "on"
        self.settings["voice_noise"] = 2 if value == "on" else 0
        save_settings(self.settings)
        self.apply_voice_settings()
        say(f"voice effects {value}")

    def set_setting(self, name: str, value: str) -> None:
        if name != "notifications" or value not in ("on", "off"):
            raise ValueError("use: settings notifications on|off")
        self.settings["notifications"] = value == "on"
        save_settings(self.settings)
        say(f"notifications {value}")

    def delete_account(self) -> None:
        """Remove only this PC's encrypted account material after explicit confirmation."""
        self.require_login()
        assert self.name
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

    def record_history(self, peer_name: str, sender: str, text: str) -> None:
        if not self.history_key:
            return
        with self.history_lock:
            records = self.read_history(peer_name)
            records.append({"at": time.strftime("%Y-%m-%d %H:%M"), "from": sender, "text": text})
            HISTORY_DIR.mkdir(exist_ok=True)
            encrypted = Fernet(self.history_key).encrypt(json.dumps(records[-500:], separators=(",", ":")).encode("utf-8"))
            self.history_path(peer_name).write_bytes(encrypted)

    def show_history(self, peer_name: str) -> None:
        records = self.read_history(peer_name)
        if not records:
            return
        say("-- earlier messages --")
        for record in records[-30:]:
            say(f"{record.get('from', '?')} > {record.get('text', '')}")
        say("-- end earlier messages --")

    def send_message(self, peer: Peer, text: str) -> None:
        peer.send(text)
        self.record_history(peer.name, self.name or "me", text)

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
        token = b64(os.urandom(24))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", 0))
        listener.listen(1)
        listener.settimeout(180)
        offer = {
            "id": file_id, "token": token, "name": path.name, "size": size,
            "sha256": self.file_digest(path), "contents": self.zip_contents(path),
        }
        self.outgoing_files[file_id] = {"path": path, "listener": listener, "offer": offer, "peer": peer, "cleanup": cleanup}
        try:
            self.server_send({"type": "direct_offer", "to": peer.name, "port": listener.getsockname()[1], "offer": offer})
        except Exception:
            self.outgoing_files.pop(file_id, None)
            if cleanup:
                path.unlink(missing_ok=True)
            listener.close()
            raise
        threading.Thread(target=self.direct_send_worker, args=(file_id,), daemon=True).start()
        say(f"file offer sent: {path.name} (waiting for them to accept)")

    def direct_send_worker(self, file_id: str) -> None:
        state = self.outgoing_files.get(file_id)
        if not state:
            return
        listener, peer, offer, path = state["listener"], state["peer"], state["offer"], state["path"]
        connection: Optional[socket.socket] = None
        try:
            connection, _address = listener.accept()
            connection.settimeout(30)
            hello = self.read_direct_packet(connection, peer.key)
            if hello.get("kind") != "hello" or hello.get("id") != file_id or not hmac.compare_digest(str(hello.get("token", "")), offer["token"]):
                raise ValueError("file receiver could not be verified")
            self.send_direct_packet(connection, peer.key, {"kind": "start", "id": file_id})
            with path.open("rb") as handle:
                sent = 0
                started, last_status = time.monotonic(), 0.0
                while chunk := handle.read(FILE_CHUNK_BYTES):
                    self.send_direct_packet(connection, peer.key, {"kind": "chunk", "id": file_id, "data": b64(chunk)})
                    sent += len(chunk)
                    if time.monotonic() - last_status >= 0.5:
                        self.transfer_status("uploading", path.name, sent, offer["size"], started)
                        last_status = time.monotonic()
            self.send_direct_packet(connection, peer.key, {"kind": "end", "id": file_id, "size": sent})
            say(f"sent file directly: {path.name}")
        except socket.timeout:
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
            if connection:
                try:
                    connection.close()
                except OSError:
                    pass

    def answer_file_offer(self, code: str, accept: bool) -> None:
        matches = [key for key in self.pending_files if key.startswith(code.lower())]
        if len(matches) != 1:
            raise ValueError("no pending file with that code")
        file_id = matches[0]
        state = self.pending_files.pop(file_id)
        if not accept:
            say("file declined; nothing was downloaded")
            return
        sender, host, port, offer = state.get("from"), state.get("host"), state.get("port"), state.get("offer")
        peer = self.peers.get(str(sender).lower())
        if not peer:
            raise ValueError("open a room with that person before accepting their file")
        if not isinstance(host, str) or not isinstance(port, int) or not isinstance(offer, dict):
            raise ValueError("invalid file offer")
        threading.Thread(target=self.direct_receive_worker, args=(peer, host, port, offer), daemon=True).start()
        say("accepting direct encrypted file transfer...")

    def direct_receive_worker(self, peer: Peer, host: str, port: int, offer: dict) -> None:
        name = Path(str(offer.get("name", "file"))).name
        size, file_id, token, expected_hash = offer.get("size"), offer.get("id"), offer.get("token"), offer.get("sha256")
        if not name or not isinstance(size, int) or not 0 <= size <= MAX_FILE_BYTES or not isinstance(file_id, str) or not isinstance(token, str) or not isinstance(expected_hash, str):
            say("file transfer rejected: invalid offer")
            return
        FILES_DIR = DOWNLOADS_DIR / "Files"
        FILES_DIR.mkdir(parents=True, exist_ok=True)
        target = FILES_DIR / name
        stem, suffix, number = target.stem, target.suffix, 2
        while target.exists():
            target = FILES_DIR / f"{stem} ({number}){suffix}"
            number += 1
        temp = target.with_suffix(target.suffix + ".part")
        connection: Optional[socket.socket] = None
        try:
            connection = socket.create_connection((host, port), timeout=15)
            connection.settimeout(30)
            self.send_direct_packet(connection, peer.key, {"kind": "hello", "id": file_id, "token": token})
            start = self.read_direct_packet(connection, peer.key)
            if start.get("kind") != "start" or start.get("id") != file_id:
                raise ValueError("sender did not verify the transfer")
            digest, written = hashlib.sha256(), 0
            started, last_status = time.monotonic(), 0.0
            with temp.open("wb") as handle:
                while True:
                    frame = self.read_direct_packet(connection, peer.key)
                    if frame.get("id") != file_id:
                        raise ValueError("wrong file transfer")
                    if frame.get("kind") == "end":
                        if frame.get("size") != written:
                            raise ValueError("file size did not match")
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
            if written != size or not hmac.compare_digest(digest.hexdigest(), expected_hash):
                raise ValueError("file failed verification")
            temp.replace(target)
            say(f"\nfile received and verified: {target}")
            toast(f"file received from {peer.name}: {name}")
            if target.suffix.lower() in VIDEO_EXTENSIONS:
                say(f"video received. Type /preview \"{target}\" to watch its first 5 seconds.")
        except Exception as exc:
            temp.unlink(missing_ok=True)
            say(f"file transfer failed: {exc}")
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
        if self.webrtc_shares:
            raise ValueError("you are already sharing a screen")
        share_id = uuid.uuid4().hex
        resolution = STREAM_RESOLUTIONS[self.settings["stream_resolution"]]
        fps = STREAM_FPS[self.settings["stream_fps"]]
        media = WebRTCShare(lambda _: None, lambda _: None, lambda state: say(f"screen share: {state}"), *resolution, fps)
        self.webrtc_shares[share_id] = media
        try:
            offer = media.call(media.offer()).result(timeout=35); offer["id"] = share_id
            # `port` keeps old Wire directories compatible; WebRTC ignores it.
            self.server_send({"type": "share_offer", "to": peer.name, "port": 1, "offer": offer})
        except Exception:
            self.webrtc_shares.pop(share_id, None); media.close()
            raise
        say(f"WebRTC screen-share offer sent to {peer.name}; waiting for them to accept")

    def share_sender(self, share_id: str) -> None:
        state = self.outgoing_shares.get(share_id)
        if not state:
            return
        listener, peer, offer, stop_event = state["listener"], state["peer"], state["offer"], state["stop"]
        connection: Optional[socket.socket] = None
        try:
            connection, _ = listener.accept()
            connection.settimeout(30)
            hello = self.read_direct_packet(connection, peer.key)
            if hello.get("kind") != "share_hello" or hello.get("id") != share_id or not hmac.compare_digest(str(hello.get("token", "")), offer["token"]):
                raise ValueError("screen-share viewer could not be verified")
            self.send_direct_packet(connection, peer.key, {"kind": "share_start", "id": share_id})
            width, height = offer["resolution"]
            frame_time = 1 / offer["fps"]
            # A per-frame budget keeps bandwidth stable. When the selected
            # resolution cannot fit, Wire lowers JPEG detail/size first so
            # motion remains smooth instead of building a huge send backlog.
            target_bytes = max(20_000, int(STREAM_BITRATES[self.settings["stream_bitrate"]] * 125_000 / offer["fps"]))
            with mss.mss() as capture:
                monitor = capture.monitors[1]
                say(f"screen sharing with {peer.name}; type /share stop to end")
                while not stop_event.is_set():
                    started = time.monotonic()
                    grabbed = capture.grab(monitor)
                    image = Image.frombytes("RGB", grabbed.size, grabbed.rgb)
                    draw_mouse_cursor(image, monitor)
                    image.thumbnail((width, height), Image.Resampling.LANCZOS)
                    # Avoid JPEG optimize=True here: it gives only a small
                    # size gain but is much too expensive for live video.
                    # Scale and quality adapt to the selected bitrate.
                    frame = b""
                    for scale in (1.0, 0.85, 0.70, 0.55, 0.42):
                        candidate = image if scale == 1.0 else image.resize(
                            (max(320, int(image.width * scale)), max(180, int(image.height * scale))),
                            Image.Resampling.BILINEAR,
                        )
                        for quality in (75, 65, 55, 45, 35, 25):
                            raw = io.BytesIO()
                            candidate.save(raw, format="JPEG", quality=quality)
                            frame = raw.getvalue()
                            if len(frame) <= target_bytes:
                                break
                        if len(frame) <= target_bytes:
                            break
                    if len(frame) > min(target_bytes, 2_400_000):
                        # A very busy desktop can still be too large. Skip it
                        # rather than delaying every following frame.
                        continue
                    self.send_direct_packet(connection, peer.key, {"kind": "share_frame", "id": share_id, "jpeg": b64(frame)})
                    time.sleep(max(0, frame_time - (time.monotonic() - started)))
        except socket.timeout:
            if not stop_event.is_set():
                say("screen-share offer expired")
        except Exception as exc:
            # Closing the listener is how /share stop cancels a waiting
            # offer. Windows reports that as an OSError; it is not a failure.
            if not stop_event.is_set():
                say(f"screen share stopped: {exc}")
        finally:
            self.outgoing_shares.pop(share_id, None)
            try:
                listener.close()
            except OSError:
                pass
            if connection:
                try:
                    connection.close()
                except OSError:
                    pass

    def stop_screen_share(self) -> None:
        """Cancel an unanswered offer or end an active share immediately."""
        had_webrtc = bool(self.webrtc_shares)
        for media in list(self.webrtc_shares.values()): media.close()
        self.webrtc_shares.clear()
        for viewer in list(self.share_viewers.values()):
            if viewer.is_alive(): viewer.terminate()
        self.share_viewers.clear()
        states = list(self.outgoing_shares.values())
        if not states and not had_webrtc:
            say("no screen share is active")
            return
        self.outgoing_shares.clear()
        for state in states:
            state["stop"].set()
            try:
                state["listener"].close()
            except OSError:
                pass
        say("screen share stopped")

    def answer_share_offer(self, code: str, accept: bool) -> None:
        matches = [key for key in self.pending_shares if key.startswith(code.lower())]
        if len(matches) != 1:
            raise ValueError("no pending screen share with that code")
        share_id = matches[0]
        state = self.pending_shares.pop(share_id)
        if not accept:
            say("screen share declined")
            return
        peer = self.peers.get(str(state["from"]).lower())
        if not peer:
            raise ValueError("open a room with that person before accepting their screen share")
        threading.Thread(target=self.webrtc_viewer, args=(peer, state), daemon=True).start()
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
        media = WebRTCShare(lambda _: None, on_frame, on_state, *(offer.get("resolution") or [1280, 720]), int(offer.get("fps", 30)))
        self.webrtc_shares[share_id] = media
        try:
            answer = media.call(media.answer(offer)).result(timeout=35)
            # Relay the answer end-to-end so the deployed directory never sees SDP
            # and older directories do not need a protocol upgrade.
            peer.send_control({"kind": "webrtc_answer", "id": share_id, "answer": answer})
            viewer = mp.Process(target=screen_viewer_process, args=(frames, f"Wire screen share — {peer.name}"), daemon=True)
            self.share_viewers[share_id] = viewer; viewer.start()
            while viewer.is_alive() and not stream_ended.wait(0.2): pass
            if viewer.is_alive(): viewer.terminate()
        except Exception as exc:
            say(f"screen share failed: {exc}")
        finally:
            self.share_viewers.pop(share_id, None)
            self.webrtc_shares.pop(share_id, media).close()

    def share_viewer(self, peer: Peer, state: dict) -> None:
        offer, share_id = state["offer"], state["offer"]["id"]
        connection: Optional[socket.socket] = None
        frames: queue.Queue[bytes] = queue.Queue(maxsize=2)
        closed = threading.Event()
        try:
            connection = socket.create_connection((state["host"], state["port"]), timeout=15)
            connection.settimeout(30)
            self.send_direct_packet(connection, peer.key, {"kind": "share_hello", "id": share_id, "token": offer["token"]})
            if self.read_direct_packet(connection, peer.key).get("kind") != "share_start":
                raise ValueError("screen-share sender did not verify")
            def receive_frames() -> None:
                try:
                    while not closed.is_set():
                        frame = self.read_direct_packet(connection, peer.key)
                        if frame.get("kind") != "share_frame" or frame.get("id") != share_id:
                            return
                        jpeg = unb64(frame.get("jpeg", ""))
                        if len(jpeg) > 2_700_000:
                            return
                        while frames.full():
                            frames.get_nowait()
                        frames.put_nowait(jpeg)
                except Exception:
                    pass
                finally:
                    closed.set()
            threading.Thread(target=receive_frames, daemon=True).start()
            root = tk.Tk()
            root.title(f"Wire screen share — {peer.name}")
            label = tk.Label(root, text="Waiting for encrypted screen frames…", bg="black", fg="white")
            label.pack()
            def close_viewer() -> None:
                closed.set()
                root.destroy()
            root.protocol("WM_DELETE_WINDOW", close_viewer)
            def draw() -> None:
                if closed.is_set():
                    close_viewer()
                    return
                latest = None
                while not frames.empty():
                    latest = frames.get_nowait()
                if latest:
                    image = Image.open(io.BytesIO(latest))
                    shown = ImageTk.PhotoImage(image)
                    label.configure(image=shown, text="")
                    label.image = shown
                root.after(15, draw)
            root.after(15, draw)
            root.mainloop()
        except Exception as exc:
            say(f"screen share failed: {exc}")
        finally:
            if connection:
                try:
                    connection.close()
                except OSError:
                    pass
            say("screen-share viewer closed")

    def preview_image(self, path: Path) -> None:
        try:
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

    def transfer_image(self, peer: Peer, image_id: str) -> None:
        state = self.outgoing_images.pop(image_id, None)
        if not state:
            return
        path = state["path"]
        peer.send_image_frame({"kind": "start", "id": image_id, "name": state["name"], "size": state["size"], "sha256": state["sha256"]})
        with path.open("rb") as handle:
            index = 0
            while chunk := handle.read(IMAGE_CHUNK_BYTES):
                peer.send_image_frame({"kind": "chunk", "id": image_id, "index": index, "data": b64(chunk)})
                index += 1
        peer.send_image_frame({"kind": "end", "id": image_id})
        say(f"sent image: {path.name}")
        self.preview_image(path)

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
        if not isinstance(image_id, str) or not image_id:
            return
        kind = frame.get("kind")
        if kind == "offer":
            name = Path(str(frame.get("name", "image"))).name
            size = frame.get("size")
            if Path(name).suffix.lower() not in IMAGE_EXTENSIONS or not isinstance(size, int) or not 0 <= size <= MAX_IMAGE_BYTES:
                return
            self.pending_images[image_id] = {"name": name, "size": size, "sha256": frame.get("sha256")}
            say(f"\n{peer.name} wants to send {name} ({size // 1024} KB). Type /image accept {image_id[:6]} or /image decline {image_id[:6]}")
        elif kind == "accept":
            threading.Thread(target=self.transfer_image, args=(peer, image_id), daemon=True).start()
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
            temp = target.with_suffix(target.suffix + ".part")
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

    def start_call(self, peer: Peer) -> None:
        if peer.name.lower() in self.calls:
            return
        self.calls[peer.name.lower()] = VoiceCall(peer, self.settings)
        say(f"voice call connected with {peer.name}; hold F12 to talk, /hangup to end")

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
        if peer.sock:
            threading.Thread(target=self.receive_loop, args=(peer,), daemon=True).start()

    def handle_message(self, peer: Peer, packet: dict) -> None:
        if packet.get("type") == "control":
            try:
                control = json.loads(AESGCM(peer.key).decrypt(unb64(packet["nonce"]), unb64(packet["data"]), b"wire-v1-control").decode("utf-8"))
                if control.get("kind") == "webrtc_answer" and isinstance(control.get("answer"), dict):
                    media = self.webrtc_shares.get(str(control.get("id", "")))
                    if media: media.call(media.remote(control["answer"]))
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
        if packet.get("type") != "msg":
            return
        nonce, data = unb64(packet["nonce"]), unb64(packet["data"])
        text = AESGCM(peer.key).decrypt(nonce, data, b"wire-v1-message").decode("utf-8")
        self.record_history(peer.name, peer.name, text)
        say(f"\n{peer.name} > {text}")
        redraw_prompt()
        if self.settings["notifications"]:
            toast(f"new message from {peer.name}")

    def receive_loop(self, peer: Peer) -> None:
        try:
            while True:
                packet = recv_frame(peer.sock)
                self.handle_message(peer, packet)
        except Exception:
            pass
        finally:
            self.peers.pop(peer.name.lower(), None)
            if self.room == peer.name.lower():
                self.room = None
            try:
                peer.sock.close()
            except OSError:
                pass
            say(f"\n{peer.name} disconnected")

    def connect_server(self, host: Optional[str] = None, port: Optional[int] = None) -> None:
        self.require_login()
        if host is None:
            try:
                saved = json.loads(SERVER_CONFIG.read_text(encoding="utf-8"))
                host, port = saved["host"], int(saved["port"])
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                host, port = "127.0.0.1", 47666
        port = port or 47666
        if self.server:
            self.server.close()
            self.server = None
        sock = socket.create_connection((host, port), timeout=8)
        try:
            send_frame(sock, {"type": "hello", "name": self.name, "public": b64(self.public),
                              "sign_public": b64(self.sign_public)})
            reply = recv_frame(sock)
            if reply.get("type") != "challenge":
                raise ConnectionError(reply.get("message", "directory rejected login"))
            nonce = unb64(reply["nonce"])
            signature = self.sign_private.sign(login_proof_bytes(self.name, nonce))
            send_frame(sock, {"type": "prove", "signature": b64(signature)})
            reply = recv_frame(sock)
            if reply.get("type") != "ready":
                raise ConnectionError(reply.get("message", "directory rejected login"))
            sock.settimeout(None)
            self.server = sock
            DATA.mkdir(exist_ok=True)
            SERVER_CONFIG.write_text(json.dumps({"host": host, "port": port}), encoding="utf-8")
            threading.Thread(target=self.server_loop, args=(sock,), daemon=True).start()
            version = reply.get("version")
            say(f"username directory online{f' (server {version})' if isinstance(version, str) else ' (old server)' }")
        except Exception:
            sock.close()
            raise

    def server_send(self, packet: dict) -> None:
        if not self.server:
            raise ConnectionError("username directory is offline")
        with self.server_lock:
            send_frame(self.server, packet)

    def relay_send(self, username: str, packet: dict) -> None:
        self.server_send({"type": "relay", "to": username, "packet": packet})

    def relay_peer(self, name: str, public: str) -> Peer:
        self.require_login()
        peer_public = unb64(public)
        if len(peer_public) != 32:
            raise ValueError("bad peer key")
        shared = self.private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"wire-v1").derive(shared)
        return Peer(name, None, key, peer_public, lambda packet: self.relay_send(name, packet))

    def attach_relay_peer(self, name: str, public: str) -> None:
        self.require_login()
        if self.is_blocked(name):
            say(f"ignored room from blocked user {name}")
            return
        self.attach(self.relay_peer(name, public))

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
            say(f"{group['name']}  [{online}/{len(group.get('members', []))} online]")

    def send_group_message(self, group_name: str, text: str) -> None:
        group = self.groups.get(group_name.lower())
        if not group:
            raise ValueError("unknown group; use group list first")
        packets: dict[str, dict] = {}
        for member in group.get("members", []):
            name, public = member.get("name"), member.get("public")
            if not isinstance(name, str) or not isinstance(public, str) or name.lower() == self.name.lower():
                continue
            peer = self.relay_peer(name, public)
            nonce = os.urandom(12)
            data = AESGCM(peer.key).encrypt(nonce, text.encode("utf-8"), b"wire-v1-message")
            packets[name.lower()] = {"type": "msg", "nonce": b64(nonce), "data": b64(data)}
        self.server_send({"type": "group_send", "group": group["name"], "packets": packets})
        self.record_history(f"group-{group['name']}", self.name or "me", text)

    def handle_group_message(self, packet: dict) -> None:
        group, sender, public, encrypted = packet.get("group"), packet.get("from"), packet.get("public"), packet.get("packet")
        if not isinstance(group, str) or not isinstance(sender, str) or not isinstance(public, str) or not isinstance(encrypted, dict) or self.is_blocked(sender):
            return
        try:
            peer = self.relay_peer(sender, public)
            if encrypted.get("type") != "msg":
                return
            text = AESGCM(peer.key).decrypt(unb64(encrypted["nonce"]), unb64(encrypted["data"]), b"wire-v1-message").decode("utf-8")
        except Exception:
            return
        self.record_history(f"group-{group}", sender, text)
        say(f"\n[{group}] {sender} > {text}")
        redraw_prompt()
        if self.settings["notifications"]:
            toast(f"new group message in {group} from {sender}")

    def server_loop(self, sock: socket.socket) -> None:
        try:
            while True:
                packet = recv_frame(sock)
                kind = packet.get("type")
                if kind == "request":
                    name, public = packet["from"], packet["public"]
                    if self.is_blocked(name):
                        say(f"\nignored room request from blocked user {name}")
                        continue
                    self.requests[name.lower()] = public
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
                elif kind == "group_list":
                    self.update_groups(packet.get("groups"))
                    self.show_groups()
                elif kind == "group_left":
                    group_name = str(packet.get("group", "")).lower()
                    self.groups.pop(group_name, None)
                    if self.group_room == group_name:
                        self.group_room = None
                    say("left group")
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
                    if isinstance(code, str) and isinstance(offer.get("name"), str) and isinstance(offer.get("size"), int):
                        self.pending_files[code] = {"from": packet.get("from"), "host": packet.get("host"), "port": packet.get("port"), "offer": offer}
                        say(f"\n{packet.get('from')} wants to send {offer['name']} ({offer['size'] // 1024 // 1024} MB)")
                        say("Warning: Wire does not scan files and is not responsible for malware.")
                        for item in offer.get("contents", [])[:20]: say(f"  {item}")
                        say(f"Type /file accept {code[:6]} or /file decline {code[:6]}")
                        redraw_prompt()
                elif kind == "share_offer":
                    offer = packet.get("offer", {})
                    code = offer.get("id", "") if isinstance(offer, dict) else ""
                    if isinstance(offer, dict) and isinstance(code, str) and isinstance(offer.get("sdp"), str):
                        self.pending_shares[code] = {"from": packet.get("from"), "offer": offer}
                        resolution = offer.get("resolution", ["?", "?"])
                        say(f"\n{packet.get('from')} wants to share their screen ({resolution[0]}x{resolution[1]}).")
                        say(f"Type /share accept {code[:6]} or /share decline {code[:6]}")
                        redraw_prompt()
                elif kind == "share_answer":
                    # Sender owns the offer identified by its only active WebRTC share.
                    if self.webrtc_shares and isinstance(packet.get("answer"), dict):
                        media = next(iter(self.webrtc_shares.values()))
                        media.call(media.remote(packet["answer"]))
                elif kind == "accepted":
                    self.attach_relay_peer(packet["name"], packet["public"])
                elif kind == "relay":
                    sender = packet.get("from", "")
                    if self.is_blocked(sender):
                        continue
                    peer = self.peers.get(sender.lower())
                    if peer:
                        self.handle_message(peer, packet["packet"])
                elif kind == "error":
                    say(f"directory: {packet.get('message', 'error')}")
        except Exception:
            if self.server is sock:
                self.server = None
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
        threading.Thread(target=self.accept_loop, daemon=True).start()
        say(f"listening on TCP {port}")

    def accept_loop(self) -> None:
        assert self.listener
        while True:
            try:
                sock, address = self.listener.accept()
                hello = recv_frame(sock)
                send_frame(sock, self.hello())
                peer = self.make_peer(sock, hello)
                say(f"incoming connection from {address[0]}")
                self.attach(peer)
            except OSError:
                return
            except Exception as exc:
                say(f"connection refused: {exc}")

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
        # Do this before sockets and the interpreter disappear; aiortc owns
        # background ICE / DTLS / RTP tasks that must be drained first.
        for media in list(self.webrtc_shares.values()):
            media.close()
        self.webrtc_shares.clear()
        for viewer in list(self.share_viewers.values()):
            if viewer.is_alive(): viewer.terminate()
        self.share_viewers.clear()
        if self.listener:
            self.listener.close()
        if self.server:
            self.server.close()
        for peer in list(self.peers.values()):
            if peer.sock:
                peer.sock.close()


HELP = """WIRE HELP

  signup [username]
      Make a new Wire username. If you leave the name blank, Wire asks for it.

  login [username]
      Sign into a username you already made on this PC.

  discover [name]
      Show usernames in Wire. Add a name to search for one person.

  friends
      Show your saved friends and whether each is online.

  friend add <username>
      Save someone to your friend list.

  friend remove <username>
      Remove someone from your friend list.

  block <username>
      Block a person from opening rooms or sending you room messages.

  unblock <username>
      Remove a block.

  blocked
      Show everyone you have blocked.

  open <username>
      Ask someone to open a private room with you.

  accept <username>
      Accept a room request that person sent you.

  history <username>
      Show saved messages with that person without opening a room.

  peers
      Show the people you are currently connected to.

  room <username>
      Switch to a room with someone you are already connected to.

  leave
      Leave the current room. It does not delete chat history.

  identity
      Show your safety fingerprint. Share it only to verify your identity.

  fingerprint <username>
      Show the connected person's safety fingerprint.

  help
      Show this help screen.

  settings [notifications on|off|voice|delete]
      Show settings, change notifications, choose voice devices, or delete this local account.

  exit
      Close Wire.

IN A ROOM
  Type normally and press Enter to send a message.
  Use /send <image path> to offer an encrypted image.
  Use /image accept <code> or /image decline <code> for image offers.
  Use /call, /acceptcall <name>, /declinecall <name>, and /hangup for voice.
  Use /help, /leave, or /exit for commands while chatting."""


HELP = """WIRE
signup/login [name]  discover [name]  open/accept [name]
friends  friend add/remove [name]  block/unblock [name]  blocked
history [name]  peers  room [name]  group  leave  settings  identity  exit

IN A ROOM: type normally.
/send <image>  /image accept|decline <code>
/sendfile <file-or-folder>  /file accept|decline <code>
/preview <video> = play first 5 seconds
/share  /share accept|decline <code>  /share stop
/group create <name> <people...>  /group list|open|add|leave
/call  /acceptcall <name>  /declinecall <name>  /hangup
/settings = settings list; arrows change options
/ping  /help  /leave  /exit"""


def main() -> None:
    enable_terminal_color()
    ensure_local_directory()
    app = Wire()
    print(f"wire  {wire_version()}\ntype help")
    # Some Windows launchers provide stdin/stdout but not a full console
    # screen buffer.  prompt_toolkit cannot attach there, so use normal
    # input() rather than crashing before Wire can start.
    try:
        session = PromptSession() if PromptSession else None
    except Exception:
        session = None
    global SAFE_PROMPT_ACTIVE
    SAFE_PROMPT_ACTIVE = session is not None
    try:
        while True:
            try:
                room_peer = app.peers.get(app.room or "")
                prompt = app.name or "wire"
                global ACTIVE_PROMPT
                ACTIVE_PROMPT = prompt
                if session and patch_stdout:
                    # Incoming messages print above the prompt, then this redraws
                    # whatever the person was already typing without losing it.
                    with patch_stdout(raw=True):
                        line = session.prompt(f"{prompt} > ").strip()
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
                except (OSError, ConnectionError) as exc:
                    print(f"error: {exc}")
                continue
            if line.startswith("/"):
                line = line[1:]
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
                elif command == "discover":
                    app.server_send({"type": "discover", "query": argument})
                elif command == "friends":
                    app.show_friends()
                elif command == "friend":
                    action, username = argument.split(maxsplit=1)
                    if action not in ("add", "remove"):
                        raise ValueError("use: friend add <username> or friend remove <username>")
                    app.edit_contact("friends", username, add=action == "add")
                    print(f"friend {'added' if action == 'add' else 'removed'}: {username}")
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
                    app.show_history(argument)
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
                        app.show_history(f"group-{group['name']}")
                    elif pieces[0] == "add" and len(pieces) == 3:
                        app.server_send({"type": "group_add", "group": pieces[1], "member": pieces[2]})
                    elif pieces[0] == "leave" and len(pieces) == 2:
                        app.server_send({"type": "group_leave", "group": pieces[1]})
                    else:
                        raise ValueError("use: /group create <name> <people...> | list | open <name> | add <name> <user> | leave <name>")
                elif command == "send":
                    room_peer = app.peers.get(app.room or "")
                    if not room_peer:
                        raise ValueError("open a room before sending an image")
                    if not argument:
                        raise ValueError("use: /send <image path>")
                    app.send_image(room_peer, argument)
                elif command == "sendfile":
                    room_peer = app.peers.get(app.room or "")
                    if not room_peer:
                        raise ValueError("open a room before sending a file")
                    if not argument:
                        raise ValueError("use: /sendfile <file path>")
                    app.send_file(room_peer, argument)
                elif command == "file":
                    pieces = argument.split(maxsplit=1)
                    if len(pieces) != 2 or pieces[0] not in ("accept", "decline"):
                        raise ValueError("use: /file accept <code> or /file decline <code>")
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
                    else:
                        raise ValueError("use: /share | /share accept <code> | /share decline <code> | /share stop")
                elif command == "ping":
                    ping_id = uuid.uuid4().hex
                    app.pending_pings[ping_id] = time.monotonic()
                    app.server_send({"type": "ping", "id": ping_id})
                elif command == "image":
                    room_peer = app.peers.get(app.room or "")
                    pieces = argument.split(maxsplit=1)
                    if not room_peer or len(pieces) != 2 or pieces[0] not in ("accept", "decline"):
                        raise ValueError("use: /image accept <code> or /image decline <code>")
                    app.answer_image_offer(room_peer, pieces[1], accept=pieces[0] == "accept")
                elif command == "call":
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
                    if len(pieces) > 2:
                        raise ValueError("use: server [host] [port]")
                    app.connect_server(pieces[0] if pieces else "127.0.0.1",
                                       int(pieces[1]) if len(pieces) == 2 else 47666)
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
                elif command in ("exit", "quit"):
                    break
                else:
                    if len(app.peers) == 1:
                        next(iter(app.peers.values())).send(line)
                    else:
                        print("unknown command; type help")
            except (ValueError, OSError, ConnectionError) as exc:
                print(f"error: {exc}")
    finally:
        app.close()


if __name__ == "__main__":
    main()
