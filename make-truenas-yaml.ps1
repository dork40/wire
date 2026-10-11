$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$serverSource = [IO.File]::ReadAllBytes((Join-Path $projectRoot 'wire-server.py'))
$serverBase64 = [Convert]::ToBase64String($serverSource)

@"
services:
  wire-server:
    # Bump this whenever the embedded server protocol changes so TrueNAS
    # rebuilds the custom image instead of reusing the prior local tag.
    image: wire-server:1.4.14
    build:
      context: .
      dockerfile_inline: |
        FROM python:3.11-slim
        RUN pip install --no-cache-dir cryptography==50.0.2
        RUN mkdir -p /app && echo '$serverBase64' | base64 -d > /app/wire-server.py
        CMD ["python", "/app/wire-server.py"]
    restart: unless-stopped
    environment:
      WIRE_STATE: /data
    ports:
      - "47666:47666/tcp"
    volumes:
      - /mnt/nvme/wire:/data
"@
