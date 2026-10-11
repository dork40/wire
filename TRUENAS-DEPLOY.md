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

The server uses TCP port 47666. Do not expose the TrueNAS web administration interface to the internet.

Before public deployment, the Windows Wire client must be configured to use the TrueNAS hostname and the router must forward only TCP 47666 to the Wire container. The server stores public identity keys and encrypted packets; it does not store plaintext chat messages.
