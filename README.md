# wire

## Install (no Windows executable)

Wire can be installed as the `wire` terminal command using Python's isolated
package runner. On Windows, from this folder, run:

```powershell
irm https://raw.githubusercontent.com/dork40/wire/main/install-wire.ps1 | iex
```

From ordinary Command Prompt (`cmd.exe`), use this Windows-built-in command
instead:

```cmd
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/dork40/wire/main/install-wire.ps1 | iex"
```

On Linux (Ubuntu, Fedora, or Arch), use:

```sh
curl -fsSL https://raw.githubusercontent.com/dork40/wire/main/install-wire.sh | sh
```

The installer adds Wire as the `wire` terminal command and installs its normal
chat/voice/file dependencies. Chat, encrypted file transfers, groups, friends,
and encrypted identity recovery are supported on Linux. X11 screen capture may
work through MSS; Wayland screen capture is deliberately unavailable until a
PipeWire/XDG Desktop Portal backend is implemented and tested.

`wire` is a command-line encrypted chat with usernames and rooms.
New installs automatically connect to the Wire username directory at
`wirecmd.ddns.net`; no IP address or server command is needed for normal use.

## What's new in server 1.4.32

- Added an Account page to the TrueNAS Web UI with identity-backup status,
  do-not-disturb status, group-invite preference, and privacy boundaries.
- Added the same safety fingerprint shown by the Wire terminal so an account's
  public identity can be compared through another trusted channel.
- Limited active Web UI sessions and automatically removes expired sessions.
- Hardened backup inspection against oversized or malformed archive entries.
- Prevented malformed group data from crashing the Groups dashboard.
- Kept the dashboard privacy-safe: it does not display message contents,
  passwords, or private identity keys.

## What's new in server 1.4.33

- Added a visible mobile sign-out control and changed sign-out to a POST action.
- Prevented malformed account, friend, and group records from crashing pages.
- Made backup inventory resilient when files change during a dashboard refresh.
- Restricted Web login KDF parameters to Wire's exact safe client whitelist,
  preventing malicious backups from triggering excessive memory or CPU use.
- Added regression coverage for damaged state, safe logout, and unsafe KDF data.

## What's new in server 1.4.34

- Streams backup checksums in bounded chunks instead of loading large state
  files into Web UI memory.
- Rejects oversized backup manifests and avoids duplicate verification work on
  Overview and Server page refreshes.
- Hardens generated TrueNAS containers with read-only roots, dropped Linux
  capabilities, no-new-privileges, bounded temporary storage, and graceful
  shutdown periods.

## What's new in server 1.4.35

- Completes the encrypted message-sync request with an explicit success reply,
  preventing clients and diagnostics from waiting indefinitely after storage.
- Reports a clear error when the encrypted server-side sync quota is full.
- Adds a real two-device regression test covering authenticated upload,
  disconnect, reconnect, encrypted download, and local history merge.

## What's new in Wire 1.4.69

- Isolates Windows.Graphics.Capture in a bounded shared-memory worker so a
  native WinRT wait cannot freeze chat or settings.
- Falls back to a DXGI crop of the selected application window when WGC is
  unavailable, never to a full-monitor capture.
- Preserves cursor position in the DXGI window fallback and reports backend
  startup failures instead of leaving a black share running.

## What's new in Wire 1.4.70

- Fixes application-window sharing when the selected window is static at
  startup by requesting a paced first frame from the DXGI fallback.
- Keeps full-monitor capture change-driven, avoiding needless capture and
  encoding work when the desktop is idle.
- Verifies system audio and video together through a real local DTLS-SRTP
  WebRTC session, including clean shutdown of every media thread.

## Private self-hosted server

The `truenas-app` folder is a TrueNAS Community Apps catalog definition with
local-only defaults, persistent state, backups, and a clickable status web UI.
Its install form can also enable a hardened authenticated Coturn relay without
copying a permanent TURN secret into the client.
After installing it, point each Wire client at the NAS:

```text
/private 192.168.1.50
```

Use the NAS Tailscale IP or MagicDNS name instead for private remote access.
Nothing is automatically opened on the router. `/public` switches the client
back to Wire's public directory. Private servers use a separate username and
recovery namespace, and Wire pins each server identity independently.

In-app updates verify an Ed25519-signed release manifest before installing the
exact authorized Git commit. A changed version, commit, or signature is rejected;
the release signing key is kept outside the repository.

## Start

Open Command Prompt and run:

```cmd
wire
```

Wire connects to the shared Wire directory at `wirecmd.ddns.net` by default.
Create an account with `signup kai`, then sign in using `login kai`. A local
directory is only started for development when `WIRE_LOCAL_DIRECTORY=1` is set.
It checks for a newer release in the background at startup; use `/update` to
show the result manually.

Every version tag publishes a GitHub release automatically. Client tags use
`vX.Y.Z`, directory-server tags use `server-vX.Y.Z`, and TrueNAS package tags
use `truenas-vX.Y.Z`. The release job refuses tags that do not match the
version stored in the corresponding source, and each release includes update
instructions plus a generated list of changes.

Wire v1.4.70 requires directory server v1.4.22 or newer for authenticated TLS;
server v1.4.35 is recommended for encrypted multi-device sync, server status,
automatic verified state backups, and the hardened TrueNAS containers. The
authenticated web dashboard verifies the newest backup checksum and probes the
local TURN listener instead of merely reporting that those services were configured.
Keep the server state volume because it contains the pinned server key.

## Commands

```text
open <username>                   ask that user to open a room
accept <username>                 accept their room request
```

When the other person accepts, a room opens automatically. Type normally; every line is sent as a message. Use `/help`, `/leave`, and `/exit` while in a room.

File transfers use end-to-end encryption, bounded relay chunks, and SHA-256
verification. The recipient must be online while a transfer is active.

During a screen share, `/share stats` shows measured capture, encode, receive,
bitrate, packet-loss, and RTT data. `/share stop` tells the other Wire client to
close the viewer as well. Wire uses STUN to discover public candidates for direct
internet sharing while keeping media encrypted with DTLS-SRTP. Hosts can configure
their own TURN relay with `WIRE_TURN_URL`, `WIRE_TURN_USERNAME`, and
`WIRE_TURN_CREDENTIAL` when direct UDP cannot connect.

Screen-share SDP and ICE signaling travels inside the room's end-to-end
encrypted control channel. The directory only relays ciphertext.
Windows probes and uses working H.264 NVENC, AMF, or QSV encoders when available,
then falls back to software x264. DXGI capture automatically falls back to MSS
if desktop duplication stops producing frames.

`/setting` can share either a monitor or one visible application window. Window
capture prefers isolated Windows.Graphics.Capture and safely falls back to a
DXGI crop of that window; neither path silently exposes the full monitor. The System
audio setting captures the selected default Windows output through WASAPI
loopback and sends 48 kHz stereo audio in the same DTLS-SRTP WebRTC session.
On Windows, the separate viewer process presents frames through an accelerated
Direct3D 11 streaming texture with vsync; press F11 or Alt+Enter to toggle
fullscreen. Unsupported graphics/RDP environments retain the Tk fallback.

The directory address is saved after `server <host> [port]` is used once. In a normal release, the official directory address would be built in, so chat users never need to enter an IP address.

## Security and current scope

Passwords are never stored in plaintext. They derive a local key that encrypts
the X25519 and Ed25519 private identities on disk. Wire does not store a copy of
that derived key. New accounts use scrypt with OWASP-equivalent parameters.
Messages use an X25519 shared secret, HKDF-SHA256, and AES-256-GCM.

The directory stores public identity keys and forwards encrypted packets only.
Directory traffic uses TLS with trust-on-first-use key pinning. Peer identity
records and direct handshakes are signed, and peer identities are pinned after
first contact. If Wire reports that a directory or peer identity changed, stop
and verify the fingerprints rather than bypassing the warning.
