$ErrorActionPreference = 'Stop'

$turnSecretBytes = New-Object byte[] 32
$turnRng = [Security.Cryptography.RandomNumberGenerator]::Create()
$turnRng.GetBytes($turnSecretBytes)
$turnRng.Dispose()
$turnSecret = [Convert]::ToBase64String($turnSecretBytes)
try {
    $publicAddress = ([Net.Dns]::GetHostAddresses('wirecmd.ddns.net') | Where-Object AddressFamily -eq InterNetwork | Select-Object -First 1).IPAddressToString
} catch {
    throw 'Could not resolve wirecmd.ddns.net; update DDNS before generating the TrueNAS YAML.'
}

@"
services:
  wire-server:
    image: ghcr.io/dork40/wire-server:latest
    pull_policy: always
    restart: unless-stopped
    environment:
      WIRE_STATE: /data
      WIRE_TURN_URLS: turn:wirecmd.ddns.net:3478?transport=udp,turn:wirecmd.ddns.net:3478?transport=tcp
      WIRE_TURN_SECRET: $turnSecret
      WIRE_BACKUP_DIR: /backups
      WIRE_BACKUP_INTERVAL: 21600
      WIRE_BACKUP_RETAIN: 28
    ports:
      - "47666:47666/tcp"
    volumes:
      - /mnt/nvme/wire:/data
      - /mnt/nvme/wire-backups:/backups
  wire-web:
    image: ghcr.io/dork40/wire-server:latest
    pull_policy: always
    restart: unless-stopped
    command: ["python", "/app/wire-web.py"]
    environment:
      WIRE_STATE: /data
      WIRE_BACKUP_DIR: /backups
      WIRE_TURN_PROBE_HOST: 192.168.1.199
      WIRE_TURN_PROBE_PORT: 3478
    ports:
      - "192.168.1.199:8097:8097/tcp"
    volumes:
      - /mnt/nvme/wire:/data:ro
      - /mnt/nvme/wire-backups:/backups:ro
  wire-turn:
    image: coturn/coturn:4.17.2-r0
    restart: unless-stopped
    network_mode: host
    command:
      - --fingerprint
      - --use-auth-secret
      - --static-auth-secret=$turnSecret
      - --realm=wirecmd.ddns.net
      - --listening-ip=192.168.1.199
      - --relay-ip=192.168.1.199
      - --external-ip=$publicAddress/192.168.1.199
      - --min-port=49160
      - --max-port=49200
      - --no-tls
      - --no-dtls
      - --no-multicast-peers
      - --stale-nonce=600
      - --user-quota=4
      - --total-quota=100
      - --max-bps=25000000
      - --denied-peer-ip=0.0.0.0-0.255.255.255
      - --denied-peer-ip=10.0.0.0-10.255.255.255
      - --denied-peer-ip=100.64.0.0-100.127.255.255
      - --denied-peer-ip=127.0.0.0-127.255.255.255
      - --denied-peer-ip=169.254.0.0-169.254.255.255
      - --denied-peer-ip=172.16.0.0-172.31.255.255
      - --denied-peer-ip=192.168.0.0-192.168.255.255
      - --denied-peer-ip=224.0.0.0-255.255.255.255
      - --log-file=stdout
x-portals:
  - host: 0.0.0.0
    name: Wire Web UI
    path: /
    port: 8097
    scheme: http
"@
