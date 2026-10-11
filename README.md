# wire

## Install (no Windows executable)

Wire can be installed as the `wire` terminal command using Python's isolated
package runner. On Windows, from this folder, run:

```powershell
irm https://raw.githubusercontent.com/dork40/wire/main/install-wire.ps1 | iex
```

On Linux later, the equivalent is:

```sh
curl -fsSL https://raw.githubusercontent.com/dork40/wire/main/install-wire.sh | sh
```

The Linux package command is prepared, but Linux screen capture is not yet
implemented; it will need a PipeWire/XDG Desktop Portal backend for Wayland
and an X11 backend where applicable.

`wire` is a command-line encrypted chat with usernames and rooms.

## Start

For a local test, open one Command Prompt and run:

```cmd
wire-server
```

Then open another Command Prompt, run `wire`, create a user with `signup kai`, and sign in using `login kai`.

## Commands

```text
open <username>                   ask that user to open a room
accept <username>                 accept their room request
```

When the other person accepts, a room opens automatically. Type normally; every line is sent as a message. Use `/help`, `/leave`, and `/exit` while in a room.

The directory address is saved after `server <host> [port]` is used once. In a normal release, the official directory address would be built in, so chat users never need to enter an IP address.

## Security and current scope

Passwords are never stored in plaintext. They derive a local key that encrypts the X25519 private identity on disk. Messages use an X25519 shared secret, HKDF-SHA256, and AES-256-GCM.

The directory stores public identity keys and forwards encrypted packets only. Before trusting a new peer, compare their `identity` fingerprint with the fingerprint shown for them in your room.
