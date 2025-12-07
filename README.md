
<p align="center">
  <img src="./assets/logo-brutal.svg" width="100%">
    A Sudoku-based proxy protocol, ushering in the era of plaintext / low-entropy proxies
</p>

# Sudoku (ASCII)


> Sudoku protocol is now supported by [Mihomo](https://github.com/MetaCubeX/mihomo) kernel!

[![Build Status](https://img.shields.io/github/actions/workflow/status/saba-futai/sudoku/.github/workflows/release.yml?branch=main&style=for-the-badge)](https://github.com/saba-futai/sudoku/actions)
[![Latest Release](https://img.shields.io/github/v/release/saba-futai/sudoku?style=for-the-badge)](https://github.com/saba-futai/sudoku/releases)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg?style=for-the-badge)](./LICENSE)

[中文文档](https://github.com/saba-futai/sudoku/blob/main/README.zh_CN.md)


**SUDOKU** is a traffic obfuscation protocol based on the creation and solving of 4x4 Sudoku puzzles. It maps arbitrary data streams (data bytes have at most 256 possibilities, while non-isomorphic 4x4 Sudokus have 288 variants) into uniquely solvable Sudoku puzzles based on 4 Clues. Since each Puzzle has more than one setting scheme, the random selection process results in multiple combinations for the same encoded data, generating obfuscation.

The core philosophy of this project is to utilize the mathematical properties of Sudoku grids to implement byte stream encoding/decoding, while providing arbitrary padding and resistance to active probing.

## Android Client：

**[Sudodroid](https://github.com/saba-futai/sudoku-android)**

## Core Features

### Sudoku Steganography Algorithm
Unlike traditional random noise obfuscation, this protocol uses various masking schemes to map data streams into complete ASCII printable characters. To packet capture tools, it appears as completely plaintext data. Alternatively, other masking schemes can be used to ensure the data stream has sufficiently low entropy.
*   **Dynamic Padding**: Inserts non-data bytes of arbitrary length at arbitrary positions at any time, hiding protocol characteristics.
*   **Data Hiding**: The distribution characteristics of padding bytes match those of plaintext bytes (65%~100%* ASCII ratio), preventing identification of plaintext through data distribution analysis.
*   **Low Information Entropy**: The overall byte Hamming weight is approximately 3.0* (in low entropy mode), which is lower than the 3.4~4.6 range mentioned in the GFW Report that typically triggers blocking.

---

> *Note: A 100% ASCII ratio requires the `ASCII-preferred` mode; in `ENTROPY-preferred` mode, it is 65%. A Hamming weight of 3.0 requires `ENTROPY-preferred` mode; in `ASCII-preferred` mode, it is 4.0. Currently, there is no evidence indicating that either preference strategy possesses a distinct fingerprint.

### Downlink Modes
* **Pure Sudoku Downlink**: Default. Uses classic Sudoku puzzles in both directions.
* **Bandwidth-Optimized Downlink**: Set `"enable_pure_downlink": false` to pack AEAD ciphertext into 6-bit groups (01xxxxxx / 0xx0xxxx) with padding reuse. This reduces downlink overhead while keeping uplink untouched. AEAD must be enabled for this mode. Padding pools and ASCII/entropy preferences still influence the emitted byte distribution.

### Security & Encryption
Beneath the obfuscation layer, the protocol optionally employs AEAD to protect data integrity and confidentiality.
*   **Algorithm Support**: AES-128-GCM or ChaCha20-Poly1305.
*   **Anti-Replay**: The handshake phase includes timestamp validation, effectively preventing replay attacks.

### Defensive Fallback
When the server detects illegal handshake requests, timed-out connections, or malformed data packets, it does not disconnect immediately. Instead, it seamlessly forwards the connection to a specified decoy address (such as an Nginx or Apache server). Probers will only see a standard web server response.

### Drawbacks (TODO)
1.  **Packet Format**: TCP native; UDP is relayed via UoT (UDP-over-TCP) without exposing a raw UDP listener.
2.  **Bandwidth Utilization**: Obfuscation introduces overhead. Use the packed downlink mode to claw back bandwidth when downloads dominate.
3.  **Client Proxy**: Only supports SOCKS5/HTTP.
4.  **Protocol Popularity**: Currently only official and mihomo support, no compatibility with other cores.



## Quick Start

### Build

```bash
go build -o sudoku cmd/sudoku-tunnel/main.go
```

### Server Configuration (config.json)

```json
{
  "mode": "server",
  "local_port": 1080,
  "server_address": "",
  "fallback_address": "127.0.0.1:80",
  "key": "See the running steps below",
  "aead": "chacha20-poly1305",
  "suspicious_action": "fallback",
  "ascii": "prefer_entropy",
  "padding_min": 2,
  "padding_max": 7,
  "enable_pure_downlink": true,
  "disable_http_mask": false
}
```

### Client Configuration

Change `mode` to `client`, set `server_address` to the Server IP, set `local_port` to the proxy listening port, add `rule_urls` using the template in `configs/config.json`. Toggle `enable_pure_downlink` to `false` if you want the packed downlink mode.

**Note**: The Key must be generated specifically by Sudoku.

### Run

> You must generate a KeyPair first
```bash
$ ./sudoku -keygen
Available Private Key: b1ec294d5dba60a800e1ef8c3423d5a176093f0d8c432e01bc24895d6828140aac81776fc0b44c3c08e418eb702b5e0a4c0a2dd458f8284d67f0d8d2d4bfdd0e
Master Private Key: 709aab5f030c9b8c322811d5c6545497c2136ce1e43b574e231562303de8f108
Master Public Key:  6e5c05c3f7f5d45fcd2f6a5a7f4700f94ff51db376c128c581849feb71ccc58b
```
You need to enter the `Master Public Key` into the server configuration's `key` field, then copy the `Available Private Key` into the client configuration's `key` field.

If you want to generate more private keys that fits the public key, you can use the `-more` option and pass the argument with an existing private key("Master Private Key" also works):
```bash
$  ./sudoku -keygen -more 709aab5f030c9b8c322811d5c6545497c2136ce1e43b574e231562303de8f108
Split Private Key: 89acb9663cfd3bd04adf0001cc7000a8eb312903088b33a847d7e5cf102f1d0ad4c1e755e1717114bee50777d9dd3204d7e142dedcb023a6db3d7c602cb9d40e
```

Run the program specifying the `config.json` path as an argument:
```bash
./sudoku -c config.json
```

## Protocol Flow

1.  **Initialization**: Client and Server generate the same Sudoku mapping table based on the pre-shared Key.
2.  **Handshake**: Client sends encrypted timestamp and nonce.
3.  **Transmission**: Data -> AEAD Encryption -> Slicing -> Mapping to Sudoku Clues -> Adding Padding -> Sending.
4.  **Reception**: Receive Data -> Filter Padding -> Restore Sudoku Clues -> Lookup Table Decoding -> AEAD Decryption.

---


## Disclaimer
> [!NOTE]\
> This software is for educational and research purposes only. Users are responsible for complying with local network regulations.

## Acknowledgements

- [Link 1](https://gfw.report/publications/usenixsecurity23/zh/)
- [Link 2](https://github.com/enfein/mieru/issues/8)
- [Link 3](https://github.com/zhaohuabing/lightsocks)
- [Link 4](https://imciel.com/2020/08/27/create-custom-tunnel/)
- [Link 5](https://oeis.org/A109252)
- [Link 6](https://pi.math.cornell.edu/~mec/Summer2009/Mahmood/Four.html)



====================



<a name="english"></a>
## 🚀 Quick Start (English)

Run on your Linux server:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/SUDOKU-ASCII/easy-install/main/install.sh)"
```

---

## 💻 Client Configuration

After server deployment, the script outputs a **short link** and **Clash config**. Below is how to use the official Sudoku client on Windows and macOS.

### Windows Client

#### 1. Download

Download `sudoku-windows-amd64.zip` from [GitHub Releases](https://github.com/SUDOKU-ASCII/sudoku/releases) and extract `sudoku.exe`.

#### 2. Start Client

Open **Command Prompt** or **PowerShell**:

```cmd
# Start with short link (recommended)
sudoku.exe -link "sudoku://your-short-link..."

# Or use config file
sudoku.exe -c client.json
```

Client listens on `127.0.0.1:1080` (SOCKS5 + HTTP mixed proxy).

#### 3. Configure System Proxy

**Option 1: Command Line (Admin CMD)**

```cmd
:: Enable proxy
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:1080" /f

:: Disable proxy
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
```

**Option 2: PowerShell**

```powershell
# Enable proxy
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 1
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyServer -Value "127.0.0.1:1080"

# Disable proxy
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0
```

**Option 3: GUI**

1. Open **Settings** → **Network & Internet** → **Proxy**
2. Turn off "Automatically detect settings"
3. Under "Manual proxy setup", turn on the toggle
4. Enter:
   - Address: `127.0.0.1`
   - Port: `1080`
5. Click "Save"

> 💡 **Note**: Some apps (terminals, games) don't use system proxy. Use Proxifier or configure SOCKS5 directly.

---

### macOS Client

#### 1. Download

Download from [GitHub Releases](https://github.com/SUDOKU-ASCII/sudoku/releases):
- Intel Mac: `sudoku-darwin-amd64.tar.gz`
- Apple Silicon: `sudoku-darwin-arm64.tar.gz`

Extract and make executable:
```bash
chmod +x sudoku
```

#### 2. Start Client

```bash
# Start with short link (recommended)
./sudoku -link "sudoku://your-short-link..."

# Or use config file
./sudoku -c client.json
```

Client listens on `127.0.0.1:1080` (SOCKS5 + HTTP mixed proxy).

#### 3. Configure System Proxy

**Option 1: Terminal**

```bash
# List network services
networksetup -listallnetworkservices

# Set SOCKS5 proxy (using Wi-Fi as example)
sudo networksetup -setsocksfirewallproxy "Wi-Fi" 127.0.0.1 1080
sudo networksetup -setsocksfirewallproxystate "Wi-Fi" on

# Set HTTP proxy
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 1080
sudo networksetup -setwebproxystate "Wi-Fi" on

# Set HTTPS proxy
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 1080
sudo networksetup -setsecurewebproxystate "Wi-Fi" on

# Disable all proxies
sudo networksetup -setsocksfirewallproxystate "Wi-Fi" off
sudo networksetup -setwebproxystate "Wi-Fi" off
sudo networksetup -setsecurewebproxystate "Wi-Fi" off
```

**Option 2: GUI**

1. Open **System Settings** (or System Preferences)
2. Click **Network** → Select current connection (e.g., Wi-Fi)
3. Click **Details...** → **Proxies**
4. Enable and configure:
   - ✅ **Web Proxy (HTTP)**: `127.0.0.1` port `1080`
   - ✅ **Secure Web Proxy (HTTPS)**: `127.0.0.1` port `1080`
   - ✅ **SOCKS Proxy**: `127.0.0.1` port `1080`
5. Click "OK"

> 💡 **Note**: Terminal apps don't use system proxy. Set environment variables:
> ```bash
> export http_proxy=http://127.0.0.1:1080
> export https_proxy=http://127.0.0.1:1080
> export all_proxy=socks5://127.0.0.1:1080
> ```

---

### Android Client (Sudodroid)

#### 1. Download

Download the latest APK from [GitHub Releases](https://github.com/SUDOKU-ASCII/sudoku-android/releases).

#### 2. Import Short Link

Open Sudodroid and import nodes using one of these methods:

**Option 1: Quick Import**

1. Tap the **"+"** floating button (bottom right)
2. Find the **"Quick Import"** section at the top of the dialog
3. Paste the `sudoku://...` short link into the input field
4. Tap **"Import Short Link"** button
5. The node will be imported and selected automatically

**Option 2: Clipboard Paste**

1. Copy the short link from server (starts with `sudoku://`)
2. Open Sudodroid, tap **"+"** button
3. Tap the **📋 paste icon** next to the "sudoku:// link" input field
4. The link will be read from clipboard automatically
5. Tap **"Import Short Link"** to complete

**Option 3: Manual Configuration**

You can also fill in the fields manually in the "Add node" dialog:
- **Display name**: Node name (optional)
- **Server host**: Server IP/domain
- **Port**: Server port (default 10233)
- **Key**: Private key (Available Private Key)
- Configure other options as needed

#### 3. Connect VPN

1. Select a node (tap the node card)
2. Tap **"Start VPN"** button at the top
3. Grant VPN permission when prompted (first time only)
4. VPN icon appears in status bar when connected

#### 4. Other Features

| Feature | Description |
|---------|-------------|
| **Ping** | Tap 🔄 refresh icon to test latency |
| **Copy Link** | Tap 🔗 link icon to copy node's short link |
| **Edit** | Tap ✏️ edit icon to modify settings |
| **Delete** | Tap 🗑️ delete icon to remove node |
| **Switch Node** | Tap another node while VPN is running to hot-switch |

---

### Features

- ✅ Auto-detect system architecture (amd64/arm64)
- ✅ Download latest release from GitHub
- ✅ Generate keypair automatically
- ✅ Detect server public IP
- ✅ Create systemd service (auto-start)
- ✅ Configure UFW firewall (if enabled)
- ✅ Output short link and Clash node config

### Default Configuration

| Setting | Default |
|---------|---------|
| Port | `10233` |
| Mode | `prefer_entropy` (low entropy) |
| AEAD | `chacha20-poly1305` |
| Pure Sudoku Downlink | `false` (bandwidth optimized) |
| HTTP Mask | `false` |

### Customization

```bash
# Custom port
sudo SUDOKU_PORT=8443 bash -c "$(curl -fsSL ...)"

# Custom fallback
sudo SUDOKU_FALLBACK="127.0.0.1:8080" bash -c "$(curl -fsSL ...)"
```

### Uninstall

```bash
sudo bash install.sh --uninstall
```

---

## 📋 Output

After installation, the script outputs:

### 1. Short Link

```
sudoku://eyJoIjoiMS4yLjMuNCIsInAiOjEwMjMzLC...
```

Use with client:
```bash
./sudoku -link "sudoku://..."
```

### 2. Clash/Mihomo Node Config

```yaml
# sudoku
- name: sudoku
  type: sudoku
  server: 1.2.3.4
  port: 10233
  key: "your-private-key"
  aead-method: chacha20-poly1305
  padding-min: 2
  padding-max: 7
  table-type: prefer_entropy
  http-mask: false
  enable-pure-downlink: false
```

Add to the `proxies` section of your Clash config.

---

## 🌐 Platform Deployment

### VPS (Recommended)

Use the one-click script directly. Supports:
- Ubuntu / Debian
- CentOS / RHEL / AlmaLinux
- Alpine Linux

### Cloudflare Workers / Vercel

> ⚠️ **Limitation**

Sudoku uses TCP protocol. Cloudflare Workers and Vercel only support HTTP/WebSocket. **Cannot run Sudoku server directly on these platforms.**

**Alternatives:**

1. **Cloudflare Tunnel** - Run Sudoku on VPS, expose via `cloudflared`
2. **Relay** - Use Workers as traffic relay to backend Sudoku server

---

## 🔧 Service Management

```bash
sudo systemctl status sudoku    # Status
sudo systemctl restart sudoku   # Restart
sudo journalctl -u sudoku -f    # Logs
```

---

## License

GPL-3.0

