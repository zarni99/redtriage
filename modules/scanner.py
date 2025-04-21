#!/usr/bin/env python3
"""
Scanner module for RedTriage
Detects common red team artifacts and tools
"""

import os
import sys
import platform
import re
import glob
import json
import hashlib
import math
import socket
import subprocess
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

# Common red team tool names
COMMON_TOOL_NAMES = [
    # Recon and scanning tools
    "nmap", "masscan", "enum4linux", "crackmapexec", "responder", "ldapsearch", 
    "smbclient", "smbmap", "bloodhound", "nbtscan", "nikto", "dirb", "gobuster",
    
    # Lateral movement and tunneling
    "chisel", "ligolo", "plink", "socat", "ptunnel", "stunnel", "sshuttle", "netcat", "nc",
    "proxychains", "iodine", "frp", "gost", "ngrok", "pproxy", "ssf", 
    
    # Credential access and exploitation
    "mimikatz", "sekurlsa", "rubeus", "hashcat", "john", "hydra", "medusa", "crowbar",
    "lsassy", "nanodump", "pypykatz", "sprayhound", "kerberoast", "kerbrute",
    
    # Privilege escalation and post-exploitation
    "lpe", "linpeas", "winpeas", "unix-privesc-check", "wesng", "powerup", "metasploit",
    "empire", "covenant", "powersploit", "apfell", "merlin", "sliver", "havoc", "cobalt",
    "pwncat", "pupy", "starkiller", "mythic", "metasploit", "msfvenom", "shellter", "veil",
    
    # Data exfiltration and staging
    "rclone", "megasync", "scp", "rsync", "exfil", "egress", "transfer",
    
    # LOLBins/LOLBas
    "certutil", "bitsadmin", "regsvr32", "rundll32", "msiexec", "mshta", "wmic"
]

# Default scan locations by OS
DEFAULT_SCAN_LOCATIONS = {
    "Windows": [
        "%TEMP%",
        "%APPDATA%",
        "%LOCALAPPDATA%",
        "C:\\Windows\\Tasks",
        "C:\\Windows\\Temp",
        "C:\\Users\\Public",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
    ],
    "Linux": [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run/shm",
        "/var/run/shm",
        "/usr/local/bin",
        "/var/spool/cron",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
    ],
    "Darwin": [
        "/tmp",
        "/var/tmp",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "~/Library/LaunchAgents",
        "/usr/local/bin",
    ]
}

# Configuration files commonly modified during engagements
COMMON_CONFIG_FILES = {
    "Windows": [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log",
    ],
    "Linux": [
        "/etc/hosts",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config",
        "/etc/sudoers",
        "/etc/resolv.conf",
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/audit/audit.log",
        "/etc/pam.d/common-auth",
    ],
    "Darwin": [
        "/etc/hosts",
        "/etc/pam.d/sudo", 
        "/etc/ssh/sshd_config",
        "/var/log/system.log",
    ]
}

# Shell history files
SHELL_HISTORY_FILES = {
    "Windows": [
        "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
    ],
    "Linux": [
        "~/.bash_history",
        "~/.zsh_history",
        "~/.sh_history",
        "~/.history",
        "~/.python_history",
    ],
    "Darwin": [
        "~/.bash_history",
        "~/.zsh_history",
        "~/.sh_history",
        "~/.history",
        "~/.python_history",
    ]
}

class Scanner:
    def __init__(self, dry_run: bool, profile: str, target_user: Optional[str] = None):
        self.dry_run = dry_run
        self.profile = profile
        self.target_user = target_user
        self.os = platform.system()
        self.findings = {
            "suspicious_files": [],
            "suspicious_processes": [],
            "modified_configs": [],
            "shell_histories": [],
            "scheduled_tasks": [],
            "suspicious_network": [],
            "suspicious_logs": [],
            "registry_artifacts": [],
            "container_artifacts": [],
            "memory_artifacts": [],
        }
        
    def expand_path(self, path: str) -> str:
        """Expand user and environment variables in a path"""
        expanded = os.path.expanduser(path)
        expanded = os.path.expandvars(expanded)
        return expanded
        
    def is_suspicious_file(self, filepath: str) -> bool:
        """Check if a file is potentially suspicious based on name or content"""
        filename = os.path.basename(filepath).lower()
        
        # Check if filename contains common red team tool names
        for tool in COMMON_TOOL_NAMES:
            if tool.lower() in filename:
                return True
                
        # Additional checks for binary files and scripts
        suspicious_extensions = ['.exe', '.dll', '.sh', '.ps1', '.bat', '.vbs', '.py', '.rb']
        if any(filename.endswith(ext) for ext in suspicious_extensions):
            try:
                # Read part of the file to check for suspicious content
                with open(filepath, 'rb') as f:
                    content = f.read(4096)
                    
                # Check for common suspicious strings in binaries or scripts
                suspicious_strings = [
                    b'powershell -e', b'Invoke-Mimikatz', b'IEX', b'msfvenom', 
                    b'reverse shell', b'bind shell', b'privilege escalation'
                ]
                
                if any(s in content for s in suspicious_strings):
                    return True
                    
                # For paranoid profile, check file entropy (high entropy may indicate encryption/obfuscation)
                if self.profile == "paranoid" and self._calculate_entropy(content) > 7.0:
                    return True
                    
            except Exception:
                # If we can't read the file, better be safe and flag it
                if self.profile == "paranoid":
                    return True
        
        return False
        
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy -= p_x * (math.log(p_x) / math.log(2))
        
        return entropy

    def scan_files(self, locations: Optional[List[str]] = None) -> None:
        """Scan for suspicious files in specified locations"""
        if not locations:
            locations = DEFAULT_SCAN_LOCATIONS.get(self.os, [])
        
        print(f"Scanning locations: {', '.join(locations)}")
        
        for location in locations:
            location = self.expand_path(location)
            if not os.path.exists(location):
                continue
                
            try:
                if os.path.isdir(location):
                    for root, _, files in os.walk(location):
                        for file in files:
                            filepath = os.path.join(root, file)
                            self._check_file(filepath)
                else:
                    self._check_file(location)
            except (PermissionError, OSError) as e:
                print(f"Error accessing {location}: {e}")
    
    def _check_file(self, filepath: str) -> None:
        """Check individual file for suspiciousness"""
        try:
            if not os.path.exists(filepath) or not os.path.isfile(filepath):
                return
                
            # Skip if targeting specific user and file not in their directory
            if self.target_user:
                if self.os == "Windows":
                    user_dir = f"C:\\Users\\{self.target_user}"
                else:
                    user_dir = f"/home/{self.target_user}"
                    
                if not filepath.startswith(user_dir):
                    return
            
            # Check if suspicious
            if self.is_suspicious_file(filepath):
                stats = os.stat(filepath)
                self.findings["suspicious_files"].append({
                    "path": filepath,
                    "size": stats.st_size,
                    "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
                    "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                    "accessed": datetime.fromtimestamp(stats.st_atime).isoformat(),
                    "reason": "Suspicious name or content",
                })
                print(f"Found suspicious file: {filepath}")
        except Exception as e:
            print(f"Error checking file {filepath}: {e}")
    
    def scan_modified_configs(self) -> None:
        """Scan for modified config files"""
        config_files = COMMON_CONFIG_FILES.get(self.os, [])
        
        for config_file in config_files:
            config_file = self.expand_path(config_file)
            if not os.path.exists(config_file):
                continue
                
            try:
                stats = os.stat(config_file)
                # Consider recently modified config files as suspicious
                # For example, modified in the last 7 days
                current_time = datetime.now().timestamp()
                seven_days = 7 * 24 * 60 * 60  # 7 days in seconds
                
                if current_time - stats.st_mtime < seven_days:
                    self.findings["modified_configs"].append({
                        "path": config_file,
                        "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                        "accessed": datetime.fromtimestamp(stats.st_atime).isoformat(),
                    })
                    print(f"Found recently modified config: {config_file}")
            except Exception as e:
                print(f"Error checking config file {config_file}: {e}")
    
    def scan_shell_histories(self) -> None:
        """Scan for suspicious shell history entries"""
        history_files = SHELL_HISTORY_FILES.get(self.os, [])
        
        for history_file in history_files:
            history_file = self.expand_path(history_file)
            
            # If targeting specific user, adjust the path
            if self.target_user:
                if self.os == "Windows":
                    history_file = history_file.replace("%USERNAME%", self.target_user)
                else:
                    history_file = history_file.replace("~", f"/home/{self.target_user}")
            
            if not os.path.exists(history_file):
                continue
                
            try:
                stats = os.stat(history_file)
                suspicious_cmds = []
                
                with open(history_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        # Check for suspicious commands in history
                        if any(tool in line.lower() for tool in COMMON_TOOL_NAMES):
                            suspicious_cmds.append(line)
                        # Check for other common red team activities
                        suspicious_patterns = [
                            r'wget https?://', r'curl https?://', r'nc -[e]', r'bash -i',
                            r'python -c', r'perl -e', r'echo.*\|.*sh', r'curl.*\|.*sh',
                            r'download', r'upload', r'backdoor', r'reverse shell',
                            r'chmod \+x', r'chmod 777'
                        ]
                        if any(re.search(pattern, line) for pattern in suspicious_patterns):
                            suspicious_cmds.append(line)
                
                if suspicious_cmds:
                    self.findings["shell_histories"].append({
                        "path": history_file,
                        "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                        "suspicious_commands": suspicious_cmds
                    })
                    print(f"Found suspicious history entries in: {history_file}")
            except Exception as e:
                print(f"Error checking history file {history_file}: {e}")
    
    def scan_scheduled_tasks(self) -> None:
        """Scan for suspicious scheduled tasks or cron jobs"""
        if self.os == "Windows":
            # Windows scheduled tasks
            try:
                import subprocess
                result = subprocess.run(["schtasks", "/query", "/fo", "csv"], 
                                        capture_output=True, text=True, check=False)
                
                tasks = result.stdout.splitlines()[1:]  # Skip header
                for task in tasks:
                    task_parts = task.split(",")
                    if len(task_parts) < 2:
                        continue
                        
                    task_name = task_parts[0].strip('"')
                    
                    # Get more details about the task
                    task_detail = subprocess.run(
                        ["schtasks", "/query", "/tn", task_name, "/v", "/fo", "list"],
                        capture_output=True, text=True, check=False
                    )
                    
                    # Check for suspicious task details
                    detail_text = task_detail.stdout.lower()
                    if any(tool in detail_text for tool in COMMON_TOOL_NAMES):
                        self.findings["scheduled_tasks"].append({
                            "name": task_name,
                            "details": task_detail.stdout,
                            "reason": "Contains suspicious command or tool name"
                        })
                        print(f"Found suspicious scheduled task: {task_name}")
            except Exception as e:
                print(f"Error checking scheduled tasks: {e}")
                
        elif self.os == "Linux" or self.os == "Darwin":
            # Check cron jobs
            cron_locations = [
                "/etc/crontab",
                "/etc/cron.d/",
                "/var/spool/cron/",
            ]
            
            if self.target_user:
                cron_locations.append(f"/var/spool/cron/crontabs/{self.target_user}")
            
            for location in cron_locations:
                location = self.expand_path(location)
                if not os.path.exists(location):
                    continue
                    
                try:
                    if os.path.isdir(location):
                        for cron_file in os.listdir(location):
                            cron_path = os.path.join(location, cron_file)
                            self._check_cron_file(cron_path)
                    else:
                        self._check_cron_file(location)
                except Exception as e:
                    print(f"Error checking cron location {location}: {e}")
    
    def _check_cron_file(self, cron_path: str) -> None:
        """Check a cron file for suspicious entries"""
        try:
            with open(cron_path, 'r', errors='ignore') as f:
                content = f.read()
                
            suspicious = False
            reason = ""
            
            # Check for suspicious commands
            if any(tool in content.lower() for tool in COMMON_TOOL_NAMES):
                suspicious = True
                reason = "Contains suspicious tool name"
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'wget https?://', r'curl https?://', r'nc -[e]', r'bash -i',
                r'python -c', r'perl -e', r'echo.*\|.*sh', r'curl.*\|.*sh',
                r'/dev/shm', r'/tmp/.*\.sh', r'\.\.s-t-rt\.sh'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, content):
                    suspicious = True
                    reason = f"Contains suspicious pattern: {pattern}"
                    break
            
            if suspicious:
                stats = os.stat(cron_path)
                self.findings["scheduled_tasks"].append({
                    "path": cron_path,
                    "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                    "content": content,
                    "reason": reason
                })
                print(f"Found suspicious cron file: {cron_path}")
        except Exception as e:
            print(f"Error checking cron file {cron_path}: {e}")
    
    def scan_network_connections(self) -> None:
        """Scan for suspicious network connections"""
        print("\n[*] Scanning for suspicious network connections...")
        
        try:
            if self.os == "Windows":
                # Use netstat on Windows
                result = subprocess.run(
                    ["netstat", "-nao"],
                    capture_output=True, text=True, check=False
                )
                connections = self._parse_windows_netstat(result.stdout)
            else:
                # Use ss on Linux/MacOS
                result = subprocess.run(
                    ["ss", "-tulpn"],
                    capture_output=True, text=True, check=False
                )
                if result.returncode != 0:
                    # Fall back to netstat if ss is not available
                    result = subprocess.run(
                        ["netstat", "-tulpn"],
                        capture_output=True, text=True, check=False
                    )
                connections = self._parse_unix_netstat(result.stdout)
                
            # Check for suspicious connections
            self._analyze_connections(connections)
                
        except Exception as e:
            print(f"Error scanning network connections: {e}")
    
    def _parse_windows_netstat(self, netstat_output: str) -> List[Dict[str, Any]]:
        """Parse Windows netstat output"""
        connections = []
        lines = netstat_output.splitlines()
        
        # Skip header lines
        for line in lines[4:]:
            parts = line.strip().split()
            if len(parts) >= 5:
                try:
                    proto = parts[0]
                    local_addr = parts[1]
                    remote_addr = parts[2]
                    state = parts[3] if parts[3] != "LISTENING" else "LISTEN"
                    pid = parts[-1]
                    
                    connections.append({
                        "protocol": proto,
                        "local_address": local_addr,
                        "remote_address": remote_addr,
                        "state": state,
                        "pid": pid
                    })
                except Exception:
                    continue
                    
        return connections
    
    def _parse_unix_netstat(self, netstat_output: str) -> List[Dict[str, Any]]:
        """Parse Linux/MacOS netstat/ss output"""
        connections = []
        lines = netstat_output.splitlines()
        
        # Skip header line
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 5:
                try:
                    proto = parts[0]
                    local_addr = parts[3]
                    remote_addr = parts[4]
                    state = parts[1] if len(parts) > 5 else "LISTEN"
                    pid = "unknown"
                    
                    # Try to extract PID from the last column
                    pid_match = re.search(r'pid=(\d+)', line)
                    if pid_match:
                        pid = pid_match.group(1)
                    
                    connections.append({
                        "protocol": proto,
                        "local_address": local_addr,
                        "remote_address": remote_addr,
                        "state": state,
                        "pid": pid
                    })
                except Exception:
                    continue
                    
        return connections
    
    def _is_suspicious_port(self, port: int) -> bool:
        """Check if a port is commonly used for C2 or tunneling"""
        suspicious_ports = [
            4444,  # Metasploit default
            1080,  # SOCKS proxy
            8080,  # Common HTTP proxy
            8443,  # Common HTTPS proxy
            31337, # Elite (leet)
            1337,  # Leet
            6666,  # Common backdoor
            6000,  # Common X11 forwarding
            1090,  # Java RMI
        ]
        
        return port in suspicious_ports
    
    def _extract_port(self, address: str) -> Optional[int]:
        """Extract port number from address string"""
        try:
            if ":" in address:
                port_str = address.split(":")[-1]
                return int(port_str)
        except Exception:
            pass
        return None
    
    def _get_process_name(self, pid: str) -> str:
        """Get process name from PID"""
        if pid == "unknown" or pid == "0":
            return "Unknown"
            
        try:
            if self.os == "Windows":
                result = subprocess.run(
                    ["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0 and result.stdout.strip():
                    parts = result.stdout.strip().split(",")
                    if len(parts) >= 2:
                        return parts[0].strip('"')
            else:
                result = subprocess.run(
                    ["ps", "-p", pid, "-o", "comm="],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()
        except Exception:
            pass
            
        return "Unknown"
    
    def _analyze_connections(self, connections: List[Dict[str, Any]]) -> None:
        """Analyze network connections for suspicious activity"""
        for conn in connections:
            is_suspicious = False
            reason = []
            
            # Check local port
            local_port = self._extract_port(conn["local_address"])
            if local_port and self._is_suspicious_port(local_port):
                is_suspicious = True
                reason.append(f"Suspicious local port: {local_port}")
            
            # Check remote port
            remote_port = self._extract_port(conn["remote_address"])
            if remote_port and self._is_suspicious_port(remote_port):
                is_suspicious = True
                reason.append(f"Suspicious remote port: {remote_port}")
            
            # Check remote IP for non-local listening connections
            if conn["state"] == "ESTABLISHED":
                remote_ip = conn["remote_address"].split(":")[0]
                if not self._is_private_ip(remote_ip) and remote_ip != "0.0.0.0" and remote_ip != "::":
                    # Get process name
                    process_name = self._get_process_name(conn["pid"])
                    
                    # Check if process name is in the red team tools list
                    if any(tool.lower() in process_name.lower() for tool in COMMON_TOOL_NAMES):
                        is_suspicious = True
                        reason.append(f"Process name matches known red team tool: {process_name}")
            
            # Paranoid profile: Any non-standard outbound connection is suspicious
            if self.profile == "paranoid" and conn["state"] == "ESTABLISHED":
                standard_ports = [80, 443, 22, 53]
                if remote_port and remote_port not in standard_ports:
                    if not is_suspicious:  # Only add if not already suspicious
                        is_suspicious = True
                        reason.append(f"Non-standard outbound port in paranoid mode: {remote_port}")
            
            # Add to findings if suspicious
            if is_suspicious:
                process_name = self._get_process_name(conn["pid"])
                self.findings["suspicious_network"].append({
                    "protocol": conn["protocol"],
                    "local_address": conn["local_address"],
                    "remote_address": conn["remote_address"],
                    "state": conn["state"],
                    "pid": conn["pid"],
                    "process": process_name,
                    "reason": ", ".join(reason)
                })
                print(f"Found suspicious connection: {conn['protocol']} {conn['local_address']} -> {conn['remote_address']} ({process_name})")
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private/internal"""
        try:
            # Handle IPv6 addresses
            if ":" in ip:
                return ip.startswith("fe80:") or ip.startswith("fd")
                
            # IPv4 address checks
            ip_parts = ip.split(".")
            if len(ip_parts) != 4:
                return False
                
            first_octet = int(ip_parts[0])
            second_octet = int(ip_parts[1])
            
            # 10.0.0.0/8
            if first_octet == 10:
                return True
                
            # 172.16.0.0/12
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
                
            # 192.168.0.0/16
            if first_octet == 192 and second_octet == 168:
                return True
                
            # 127.0.0.0/8 (localhost)
            if first_octet == 127:
                return True
                
            return False
        except Exception:
            return False
            
    def scan_windows_registry(self) -> None:
        """Scan Windows registry for suspicious entries"""
        if self.os != "Windows":
            return
            
        print("\n[*] Scanning Windows registry for suspicious entries...")
        
        # Common registry locations used by attackers
        suspicious_registry_keys = [
            # Run keys for persistence
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            
            # Startup folders
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            
            # Service control keys
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            
            # Known COM hijacking locations
            r"HKCU\Software\Classes\CLSID",
            r"HKLM\SOFTWARE\Classes\CLSID",
            
            # WinLogon keys
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            
            # AppInit DLLs for code injection
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
            
            # Image File Execution Options (debugger redirection)
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        ]
        
        for reg_key in suspicious_registry_keys:
            try:
                # Call reg.exe to query registry keys
                root, key = reg_key.split("\\", 1)
                result = subprocess.run(
                    ["reg", "query", reg_key],
                    capture_output=True, text=True, check=False
                )
                
                if result.returncode == 0:
                    self._analyze_registry_output(reg_key, result.stdout)
            except Exception as e:
                print(f"Error scanning registry key {reg_key}: {e}")
    
    def _analyze_registry_output(self, registry_key: str, output: str) -> None:
        """Analyze registry output for suspicious entries"""
        lines = output.splitlines()
        
        for line in lines:
            line = line.strip()
            if not line or "REG_" not in line:
                continue
                
            try:
                # Parse registry value
                parts = line.split("REG_")
                if len(parts) != 2:
                    continue
                    
                value_name = parts[0].strip()
                reg_type = "REG_" + parts[1].split()[0]
                value_data = parts[1].split(None, 1)[1] if len(parts[1].split()) > 1 else ""
                
                # Check for suspicious values
                is_suspicious = False
                reason = []
                
                # Check for suspicious paths in value data
                if any(path in value_data.lower() for path in ["%temp%", "%appdata%", "\\users\\public\\", "powershell", "wscript", "cmd /c"]):
                    is_suspicious = True
                    reason.append(f"Contains suspicious path: {value_data}")
                
                # Check for obfuscated commands
                if "-e " in value_data.lower() or "-enc" in value_data.lower() or "iex" in value_data.lower():
                    is_suspicious = True
                    reason.append("Contains potentially obfuscated PowerShell command")
                
                # Check for suspicious extensions
                for ext in [".ps1", ".vbs", ".bat", ".tmp", ".dmp", ".exe"]:
                    if ext in value_data.lower():
                        is_suspicious = True
                        reason.append(f"References {ext} file")
                        break
                
                # Check for common red team tools
                for tool in COMMON_TOOL_NAMES:
                    if tool.lower() in value_data.lower():
                        is_suspicious = True
                        reason.append(f"Contains reference to known tool: {tool}")
                        break
                
                # High entropy in value data might indicate encoding/obfuscation
                if len(value_data) > 100 and "==" in value_data:
                    is_suspicious = True
                    reason.append("Contains possible Base64 encoded data")
                
                # Special checks for RunOnce and Services keys
                if "RunOnce" in registry_key or "\\Services\\" in registry_key:
                    # For paranoid mode, treat any non-Microsoft paths as suspicious
                    if self.profile == "paranoid" and "\\windows\\" not in value_data.lower() and "\\program files\\" not in value_data.lower():
                        is_suspicious = True
                        reason.append("Non-standard path in sensitive registry key")
                
                # Add to findings if suspicious
                if is_suspicious:
                    self.findings["registry_artifacts"].append({
                        "key": registry_key,
                        "value_name": value_name,
                        "value_type": reg_type,
                        "value_data": value_data,
                        "reason": ", ".join(reason)
                    })
                    print(f"Found suspicious registry entry: {registry_key}\\{value_name}")
            except Exception as e:
                # Skip this line if parsing fails
                continue
    
    def scan_containers(self) -> None:
        """Scan for suspicious container artifacts (Docker, LXC, etc.)"""
        print("\n[*] Scanning for container artifacts...")
        
        # Check if Docker is installed
        docker_installed = False
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True, text=True, check=False
            )
            docker_installed = result.returncode == 0
        except Exception:
            docker_installed = False
        
        if docker_installed:
            self._scan_docker_containers()
        
        # Also check for container files regardless of whether containers are installed
        container_paths = []
        
        if self.os == "Linux":
            container_paths = [
                "/var/lib/docker",
                "/var/run/docker.sock",
                "/etc/docker",
                "/var/lib/lxc",
                "/var/lib/containerd",
                "~/.docker",
            ]
        elif self.os == "Darwin":
            container_paths = [
                "~/Library/Containers/com.docker.docker",
                "~/.docker",
            ]
        elif self.os == "Windows":
            container_paths = [
                "%PROGRAMDATA%\\Docker",
                "%USERPROFILE%\\.docker",
            ]
        
        for path in container_paths:
            path = self.expand_path(path)
            if os.path.exists(path):
                print(f"Found container path: {path}")
                
                # Scan for suspicious files in container paths
                if os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            filepath = os.path.join(root, file)
                            self._check_container_file(filepath)
    
    def _scan_docker_containers(self) -> None:
        """Scan Docker containers for suspicious configurations"""
        try:
            # List running containers
            result = subprocess.run(
                ["docker", "ps", "-a", "--format", "{{.ID}}\t{{.Image}}\t{{.Command}}\t{{.Names}}\t{{.Ports}}"],
                capture_output=True, text=True, check=False
            )
            
            if result.returncode != 0:
                print("Error running docker ps command")
                return
                
            containers = result.stdout.strip().splitlines()
            
            for container in containers:
                parts = container.split("\t")
                if len(parts) < 5:
                    continue
                    
                container_id = parts[0]
                image = parts[1]
                command = parts[2]
                name = parts[3]
                ports = parts[4]
                
                is_suspicious = False
                reason = []
                
                # Check for suspicious container configurations
                
                # Check suspicious ports
                if any(str(port) in ports for port in [4444, 8080, 6666, 1080, 1337, 31337]):
                    is_suspicious = True
                    reason.append(f"Container exposes suspicious port(s): {ports}")
                
                # Check suspicious images
                suspicious_images = ["kalilinux", "parrotsec", "metasploit", "pentestkit", "blackarch"]
                if any(img in image.lower() for img in suspicious_images):
                    is_suspicious = True
                    reason.append(f"Container uses potentially malicious image: {image}")
                
                # Check privileged container inspect
                if is_suspicious or self.profile == "paranoid":
                    # Get detailed container info
                    inspect_result = subprocess.run(
                        ["docker", "inspect", container_id],
                        capture_output=True, text=True, check=False
                    )
                    
                    if inspect_result.returncode == 0:
                        inspect_data = json.loads(inspect_result.stdout)
                        
                        if inspect_data and len(inspect_data) > 0:
                            # Check for privileged mode
                            if inspect_data[0].get("HostConfig", {}).get("Privileged", False):
                                is_suspicious = True
                                reason.append("Container running in privileged mode")
                            
                            # Check for dangerous mounts
                            mounts = inspect_data[0].get("Mounts", [])
                            for mount in mounts:
                                source = mount.get("Source", "")
                                if source in ["/", "/etc", "/var/run/docker.sock"]:
                                    is_suspicious = True
                                    reason.append(f"Container has sensitive host path mounted: {source}")
                
                # Add to findings if suspicious
                if is_suspicious:
                    self.findings["container_artifacts"].append({
                        "container_id": container_id,
                        "image": image,
                        "command": command,
                        "name": name,
                        "ports": ports,
                        "reason": ", ".join(reason)
                    })
                    print(f"Found suspicious container: {name} ({container_id})")
                    
        except Exception as e:
            print(f"Error scanning Docker containers: {e}")
    
    def _check_container_file(self, filepath: str) -> None:
        """Check container-related files for suspicious content"""
        filename = os.path.basename(filepath).lower()
        
        # Check common container files
        suspicious_container_files = [
            "dockerfile", "docker-compose.yml", "docker-compose.yaml", 
            ".dockerignore", "docker-entrypoint.sh"
        ]
        
        if filename in suspicious_container_files:
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read()
                    
                is_suspicious = False
                reason = []
                
                # Check for suspicious commands or configurations
                suspicious_patterns = [
                    r'FROM\s+kali', r'FROM\s+parrot', r'FROM\s+blackarch',
                    r'RUN.*apt-get.*nmap', r'RUN.*apt-get.*metasploit',
                    r'RUN.*curl\s+.*\|\s*sh', r'wget\s+.*\|\s*bash',
                    r'privileged:\s*true', r'cap_add:\s*SYS_ADMIN',
                    r'volume:.*docker\.sock', r'volume:.*:/etc',
                    r'expose:.*4444', r'expose:.*31337', r'expose:.*6666'
                ]
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        is_suspicious = True
                        reason.append(f"Matches suspicious pattern: {pattern}")
                
                # Add to findings if suspicious
                if is_suspicious:
                    self.findings["container_artifacts"].append({
                        "path": filepath,
                        "type": "config_file",
                        "reason": ", ".join(reason)
                    })
                    print(f"Found suspicious container configuration file: {filepath}")
            except Exception as e:
                print(f"Error checking container file {filepath}: {e}")
    
    def scan_memory_artifacts(self) -> None:
        """Scan for memory artifacts and suspicious processes"""
        print("\n[*] Scanning for memory artifacts and suspicious processes...")
        
        try:
            if self.os == "Windows":
                self._scan_windows_processes()
            else:
                self._scan_unix_processes()
        except Exception as e:
            print(f"Error scanning memory artifacts: {e}")
    
    def _scan_windows_processes(self) -> None:
        """Scan Windows processes for suspicious characteristics"""
        try:
            # Use wmic to list processes with command line
            result = subprocess.run(
                ["wmic", "process", "get", "Caption,ProcessId,CommandLine", "/format:csv"],
                capture_output=True, text=True, check=False
            )
            
            if result.returncode != 0:
                print("Error running wmic command")
                return
                
            lines = result.stdout.strip().splitlines()
            
            # Skip header line
            for line in lines[1:]:
                if not line.strip():
                    continue
                    
                parts = line.split(",")
                if len(parts) < 3:
                    continue
                    
                node = parts[0]
                process_name = parts[1]
                pid = parts[2]
                cmdline = parts[3] if len(parts) > 3 else ""
                
                self._check_suspicious_process(process_name, pid, cmdline)
        except Exception as e:
            print(f"Error scanning Windows processes: {e}")
    
    def _scan_unix_processes(self) -> None:
        """Scan Unix/Linux processes for suspicious characteristics"""
        try:
            # Use ps to list processes with command line
            result = subprocess.run(
                ["ps", "-eo", "pid,comm,args"],
                capture_output=True, text=True, check=False
            )
            
            if result.returncode != 0:
                print("Error running ps command")
                return
                
            lines = result.stdout.strip().splitlines()
            
            # Skip header line
            for line in lines[1:]:
                if not line.strip():
                    continue
                    
                parts = line.strip().split(None, 2)
                if len(parts) < 3:
                    continue
                    
                pid = parts[0]
                process_name = parts[1]
                cmdline = parts[2]
                
                self._check_suspicious_process(process_name, pid, cmdline)
        except Exception as e:
            print(f"Error scanning Unix processes: {e}")
    
    def _check_suspicious_process(self, process_name: str, pid: str, cmdline: str) -> None:
        """Check if a process is suspicious based on name and command line"""
        is_suspicious = False
        reason = []
        
        # Check if process name matches known red team tools
        if any(tool.lower() in process_name.lower() for tool in COMMON_TOOL_NAMES):
            is_suspicious = True
            matching_tools = [tool for tool in COMMON_TOOL_NAMES if tool.lower() in process_name.lower()]
            reason.append(f"Process name matches known red team tool: {', '.join(matching_tools)}")
        
        # Check for suspicious command line arguments
        suspicious_cmd_patterns = [
            r"-e\s+[A-Za-z0-9+/=]{10,}",  # Encoded PowerShell
            r"-enc\s+[A-Za-z0-9+/=]{10,}",  # Encoded PowerShell
            r"-exec\s+bypass",  # PowerShell execution policy bypass
            r"IEX\s*\(",  # PowerShell Invoke-Expression
            r"curl\s+.*\|\s*sh",  # Pipe curl to shell
            r"wget\s+.*\|\s*bash",  # Pipe wget to bash
            r"nc\s+-e",  # Netcat with -e flag
            r"chmod\s+.*\+x",  # Making files executable
            r"socat\s+.*exec",  # Socat with exec
            r"bash\s+-i",  # Interactive bash shell
            r"python\s+-c.*socket",  # Python one-liner socket
            r"/dev/tcp/",  # Bash TCP sockets
            r"base64\s+-d",  # Base64 decode
        ]
        
        for pattern in suspicious_cmd_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                is_suspicious = True
                reason.append(f"Command line contains suspicious pattern: {pattern}")
        
        # Check for processes running from suspicious locations
        suspicious_paths = ["/tmp/", "/dev/shm/", "%TEMP%", "%APPDATA%", "\\Users\\Public\\"]
        if any(path.lower() in cmdline.lower() for path in suspicious_paths):
            is_suspicious = True
            reason.append("Process running from suspicious location")
        
        # In paranoid mode, check for any processes with encoded arguments
        if self.profile == "paranoid":
            if re.search(r"[A-Za-z0-9+/=]{20,}", cmdline):
                is_suspicious = True
                reason.append("Command line contains possible encoded data (paranoid mode)")
        
        # Add to findings if suspicious
        if is_suspicious:
            # Get memory info for the process
            memory_info = self._get_process_memory_info(pid)
            
            self.findings["memory_artifacts"].append({
                "pid": pid,
                "process_name": process_name,
                "command_line": cmdline,
                "memory_info": memory_info,
                "reason": ", ".join(reason)
            })
            print(f"Found suspicious process: {process_name} (PID: {pid})")
    
    def _get_process_memory_info(self, pid: str) -> Dict[str, Any]:
        """Get memory information for a process"""
        memory_info = {"memory_usage": "Unknown"}
        
        try:
            if self.os == "Windows":
                result = subprocess.run(
                    ["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0 and result.stdout.strip():
                    parts = result.stdout.strip().split(",")
                    if len(parts) >= 5:
                        memory_usage = parts[4].strip('"')
                        memory_info["memory_usage"] = memory_usage
            else:
                # Get memory info using ps
                result = subprocess.run(
                    ["ps", "-p", pid, "-o", "vsz,rss"],
                    capture_output=True, text=True, check=False
                )
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().splitlines()
                    if len(lines) > 1:
                        parts = lines[1].strip().split()
                        if len(parts) >= 2:
                            memory_info["vsz"] = f"{int(parts[0]):,} KB"
                            memory_info["rss"] = f"{int(parts[1]):,} KB"
        except Exception:
            pass
            
        return memory_info
    
    def scan_system(self) -> Dict[str, Any]:
        """Run a comprehensive system scan"""
        print(f"Starting RedTriage scan (profile: {self.profile})")
        
        # Scan for suspicious files
        self.scan_files()
        
        # Scan for modified config files
        self.scan_modified_configs()
        
        # Scan for suspicious shell history entries
        self.scan_shell_histories()
        
        # Scan for suspicious scheduled tasks
        self.scan_scheduled_tasks()
        
        # Scan for suspicious network connections
        self.scan_network_connections()
        
        # Scan Windows registry for suspicious entries
        if self.os == "Windows":
            self.scan_windows_registry()
            
        # Scan for container artifacts
        self.scan_containers()
        
        # Scan for memory artifacts and suspicious processes
        self.scan_memory_artifacts()
        
        # Add scan metadata
        self.findings["metadata"] = {
            "timestamp": datetime.now().isoformat(),
            "os": self.os,
            "hostname": platform.node(),
            "profile": self.profile,
            "target_user": self.target_user,
            "dry_run": self.dry_run
        }
        
        return self.findings

def scan_artifacts(dry_run: bool, profile: str, target_user: Optional[str] = None, 
                  locations: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run the scan functionality"""
    scanner = Scanner(dry_run, profile, target_user)
    
    if locations:
        scanner.scan_files(locations)
    else:
        findings = scanner.scan_system()
    
    # Save findings to a file
    output_file = f"redtriage_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(scanner.findings, f, indent=2)
    
    print(f"\nScan complete! Results saved to {output_file}")
    
    # Print summary
    print("\n=== Scan Summary ===")
    print(f"Suspicious files: {len(scanner.findings['suspicious_files'])}")
    print(f"Modified configs: {len(scanner.findings['modified_configs'])}")
    print(f"Shell histories with suspicious commands: {len(scanner.findings['shell_histories'])}")
    print(f"Suspicious scheduled tasks: {len(scanner.findings['scheduled_tasks'])}")
    
    return scanner.findings 