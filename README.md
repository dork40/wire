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

Wire v1.4.53 requires directory server v1.4.22 or newer. The directory now uses
TLS and a persistent signing identity; upgrade the server before upgrading
clients. Keep the server state volume because it contains the pinned server key.

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
