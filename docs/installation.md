# Installation

## Pre-built Binaries

Download the latest release from [GitHub Releases](https://github.com/ridgelinecyberdefence/vanguard/releases).

| Platform | Binary |
|----------|--------|
| Windows (64-bit) | `vanguard-windows-amd64.exe` |
| Linux (64-bit) | `vanguard-linux-amd64` |

### Windows

1. Download `vanguard-windows-amd64.exe`
2. Verify the SHA256 checksum against `vanguard-checksums.sha256`
3. Place in your desired directory (USB drive or local folder)
4. Run as Administrator for full functionality

### Linux

1. Download `vanguard-linux-amd64`
2. Verify the SHA256 checksum: `sha256sum -c vanguard-checksums.sha256`
3. Make executable: `chmod +x vanguard-linux-amd64`
4. Run as root for full functionality: `sudo ./vanguard-linux-amd64`

## Build from Source

Requires Go 1.22+ and GCC (CGO is required for SQLite).

```bash
git clone https://github.com/ridgelinecyberdefence/vanguard.git
cd vanguard
CGO_ENABLED=1 go build -trimpath -o vanguard ./cmd/vanguard/
```

On Windows with PowerShell:
```powershell
$env:CGO_ENABLED=1; go build -trimpath -o vanguard.exe ./cmd/vanguard/
```

## USB Deployment

VanGuard is designed to run from a USB drive with no installation required. Copy the binary and the directory structure to the USB drive. All tools are downloaded at runtime via the Configuration menu.
