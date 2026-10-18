# Wire server on TrueNAS

Target dataset: `nvme/wire`.

This folder contains the source needed to run the encrypted-packet Wire directory on TrueNAS:

- `wire-server.py` - the server
- `Dockerfile` - container build instructions
- `compose.yaml` - container settings and persistent server data

On Windows, run this to copy a ready-to-paste Custom App YAML file to the clipboard:

```powershell
powershell -ExecutionPolicy Bypass -File .\make-truenas-yaml.ps1 | Set-Clipboard
```

In TrueNAS, go to **Apps → Discover → more menu → Install via YAML**, name the app `wire`, paste the clipboard contents, and save. The deployment keeps its server data in `/mnt/nvme/wire`.

The server writes a checksummed backup every six hours to
`/mnt/nvme/wire-backups` and retains the newest 28 archives. Backups include the
directory signing/TLS identities and all persistent service data. Protect that
dataset with a separate TrueNAS snapshot or replication task: copies on the same
pool do not protect against pool failure.

Before a restore, stop the Wire app. Verify the selected archive with
`python /app/wire-server.py --verify-backup /backups/<archive>.zip`, then run
`python /app/wire-server.py --restore-backup /backups/<archive>.zip` from a
one-shot container with the same `/data` and `/backups` mounts. Restart Wire only
after the restore completes.

The deployment runs both the Wire directory and an authenticated Coturn relay. The
directory issues one-hour TURN credentials after a signed Wire login; the permanent
TURN secret stays inside the two TrueNAS containers.

Forward these router ports to `192.168.1.199`:

- TCP 47666 for the Wire directory.
- UDP and TCP 3478 for TURN negotiation.
- UDP 49160-49200 for relayed media.

Do not expose the TrueNAS web administration interface. TURN relays encrypted
DTLS-SRTP packets and does not decrypt screen-share or call contents.
