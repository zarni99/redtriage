"""
Scanner module for RedTriage
Detects common red team artifacts and tools
Created by: Zarni (Neo)
Copyright (c) 2025 Zarni (Neo)
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

from modules.network_scanner import scan_network_artifacts

COMMON_TOOL_NAMES = [
    
    "nmap", "masscan", "enum4linux", "crackmapexec", "responder", "ldapsearch", 
    "smbclient", "smbmap", "bloodhound", "nbtscan", "nikto", "dirb", "gobuster",
    
    
    "chisel", "ligolo", "plink", "socat", "ptunnel", "stunnel", "sshuttle", "netcat", "nc",
    "proxychains", "iodine", "frp", "gost", "ngrok", "pproxy", "ssf", 
    
    
    "mimikatz", "sekurlsa", "rubeus", "hashcat", "john", "hydra", "medusa", "crowbar",
    "lsassy", "nanodump", "pypykatz", "sprayhound", "kerberoast", "kerbrute",
    
    
    "lpe", "linpeas", "winpeas", "unix-privesc-check", "wesng", "powerup", "metasploit",
    "empire", "covenant", "powersploit", "apfell", "merlin", "sliver", "havoc", "cobalt",
    "pwncat", "pupy", "starkiller", "mythic", "metasploit", "msfvenom", "shellter", "veil",
    
    
    "rclone", "megasync", "scp", "rsync", "exfil", "egress", "transfer",
    
    
    "certutil", "bitsadmin", "regsvr32", "rundll32", "msiexec", "mshta", "wmic"
]

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
    def __init__(self, dry_run: bool, profile: str, target_user: Optional[str] = None, date_filter: Optional[Dict[str, datetime]] = None):
        self.dry_run = dry_run
        self.profile = profile
        self.target_user = target_user
        self.os = platform.system()
        self.date_filter = date_filter or {}
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
        
        
        for tool in COMMON_TOOL_NAMES:
            if tool.lower() in filename:
                return True
                
        
        suspicious_extensions = ['.exe', '.dll', '.sh', '.ps1', '.bat', '.vbs', '.py', '.rb']
        if any(filename.endswith(ext) for ext in suspicious_extensions):
            try:
                
                with open(filepath, 'rb') as f:
                    content = f.read(4096)
                    
                
                suspicious_strings = [
                    b'powershell -e', b'Invoke-Mimikatz', b'IEX', b'msfvenom', 
                    b'reverse shell', b'bind shell', b'privilege escalation'
                ]
                
                if any(s in content for s in suspicious_strings):
                    return True
                    
                
                if self.profile == "paranoid" and self._calculate_entropy(content) > 7.0:
                    return True
                    
            except Exception:
                
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
        """Check if a file is suspicious and add it to findings"""
        try:
            if not os.path.isfile(filepath):
                return

            # Get file stats
            stats = os.stat(filepath)
            mtime = stats.st_mtime
            mod_time = datetime.fromtimestamp(mtime)
            
            # Apply date filters
            if 'after' in self.date_filter and mod_time < self.date_filter['after']:
                return
            if 'before' in self.date_filter and mod_time > self.date_filter['before']:
                return
            
            file_info = {
                "path": filepath,
                "size": stats.st_size,
                "mtime": mtime,
                "mod_time_str": mod_time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            if self.target_user:
                if self.os == "Windows":
                    user_dir = f"C:\\Users\\{self.target_user}"
                else:
                    user_dir = f"/home/{self.target_user}"
                    
                if not filepath.startswith(user_dir):
                    return
            
            
            if self.is_suspicious_file(filepath):
                self.findings["suspicious_files"].append(file_info)
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
                
                
                current_time = datetime.now().timestamp()
                seven_days = 7 * 24 * 60 * 60  
                
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
                        
                        if any(tool in line.lower() for tool in COMMON_TOOL_NAMES):
                            suspicious_cmds.append(line)
                        
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
            
            try:
                import subprocess
                result = subprocess.run(["schtasks", "/query", "/fo", "csv"], 
                                        capture_output=True, text=True, check=False)
                
                tasks = result.stdout.splitlines()[1:]  
                for task in tasks:
                    task_parts = task.split(",")
                    if len(task_parts) < 2:
                        continue
                        
                    task_name = task_parts[0].strip('"')
                    
                    
                    task_detail = subprocess.run(
                        ["schtasks", "/query", "/tn", task_name, "/v", "/fo", "list"],
                        capture_output=True, text=True, check=False
                    )
                    
                    
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
            
            cron_locations = [
                "/etc/crontab",
                "/etc/cron.d/",
                "/etc/cron.daily/",
                "/etc/cron.hourly/",
                "/etc/cron.monthly/",
                "/etc/cron.weekly/",
                "/var/spool/cron/",
            ]
            
            
            crontabs_dir = "/var/spool/cron/crontabs"
            
            
            for location in cron_locations:
                location = self.expand_path(location)
                if not os.path.exists(location):
                    continue
                    
                try:
                    if os.path.isdir(location):
                        for cron_file in os.listdir(location):
                            cron_path = os.path.join(location, cron_file)
                            if os.path.isfile(cron_path):
                                self._check_cron_file(cron_path)
                    else:
                        self._check_cron_file(location)
                except Exception as e:
                    print(f"Error checking cron location {location}: {e}")
            
            
            if os.path.exists(crontabs_dir) and os.path.isdir(crontabs_dir):
                try:
                    
                    if self.target_user:
                        user_crontab = os.path.join(crontabs_dir, self.target_user)
                        if os.path.exists(user_crontab) and os.path.isfile(user_crontab):
                            self._check_cron_file(user_crontab)
                    else:
                        
                        for user_file in os.listdir(crontabs_dir):
                            user_crontab = os.path.join(crontabs_dir, user_file)
                            if os.path.isfile(user_crontab):
                                self._check_cron_file(user_crontab)
                except Exception as e:
                    print(f"Error checking user crontabs in {crontabs_dir}: {e}")
    
    def _check_cron_file(self, cron_path: str) -> None:
        """Check a cron file for suspicious entries"""
        try:
            with open(cron_path, 'r', errors='ignore') as f:
                content = f.read()
                
            suspicious = False
            reason = ""
            
            
            if any(tool in content.lower() for tool in COMMON_TOOL_NAMES):
                suspicious = True
                reason = "Contains suspicious tool name"
            
            
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
                # Windows netstat
                result = subprocess.run(
                    ["netstat", "-nao"],
                    capture_output=True, text=True, check=False
                )
                connections = self._parse_windows_netstat(result.stdout)
            elif self.os == "Darwin":  # macOS
                # Use netstat on macOS
                result = subprocess.run(
                    ["netstat", "-na"],
                    capture_output=True, text=True, check=False
                )
                connections = self._parse_macos_netstat(result.stdout)
            else:  # Linux
                # Try ss first, fallback to netstat
                try:
                    result = subprocess.run(
                        ["ss", "-tulpn"],
                        capture_output=True, text=True, check=False
                    )
                    if result.returncode == 0:
                        connections = self._parse_unix_netstat(result.stdout)
                    else:
                        # Fallback to netstat
                        result = subprocess.run(
                            ["netstat", "-tulpn"],
                            capture_output=True, text=True, check=False
                        )
                        connections = self._parse_unix_netstat(result.stdout)
                except FileNotFoundError:
                    # If ss is not found, try netstat
                    result = subprocess.run(
                        ["netstat", "-tulpn"],
                        capture_output=True, text=True, check=False
                    )
                    connections = self._parse_unix_netstat(result.stdout)
                
            # Analyze the connections
            self._analyze_connections(connections)
                
        except Exception as e:
            print(f"Error scanning network connections: {e}")
    
    def _parse_windows_netstat(self, netstat_output: str) -> List[Dict[str, Any]]:
        """Parse Windows netstat output"""
        connections = []
        lines = netstat_output.splitlines()
        
        
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
        
        
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) >= 5:
                try:
                    proto = parts[0]
                    local_addr = parts[3]
                    remote_addr = parts[4]
                    state = parts[1] if len(parts) > 5 else "LISTEN"
                    pid = "unknown"
                    
                    
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
    
    def _parse_macos_netstat(self, netstat_output: str) -> List[Dict[str, Any]]:
        """Parse macOS netstat output"""
        connections = []
        lines = netstat_output.splitlines()
        
        for line in lines[1:]:  # Skip the header
            parts = line.strip().split()
            if len(parts) >= 4:
                try:
                    proto = parts[0]
                    local_addr = parts[3]
                    remote_addr = parts[4] if len(parts) > 4 else "*.*"
                    state = parts[5] if len(parts) > 5 else "LISTEN"
                    pid = "unknown"  # macOS netstat doesn't show PIDs by default
                    
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
            4444,  
            1080,  
            8080,  
            8443,  
            31337, 
            1337,  
            6666,  
            6000,  
            1090,  
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
            
            
            local_port = self._extract_port(conn["local_address"])
            if local_port and self._is_suspicious_port(local_port):
                is_suspicious = True
                reason.append(f"Suspicious local port: {local_port}")
            
            
            remote_port = self._extract_port(conn["remote_address"])
            if remote_port and self._is_suspicious_port(remote_port):
                is_suspicious = True
                reason.append(f"Suspicious remote port: {remote_port}")
            
            
            if conn["state"] == "ESTABLISHED":
                remote_ip = conn["remote_address"].split(":")[0]
                if not self._is_private_ip(remote_ip) and remote_ip != "0.0.0.0" and remote_ip != "::":
                    
                    process_name = self._get_process_name(conn["pid"])
                    
                    
                    if any(tool.lower() in process_name.lower() for tool in COMMON_TOOL_NAMES):
                        is_suspicious = True
                        reason.append(f"Process name matches known red team tool: {process_name}")
            
            
            if self.profile == "paranoid" and conn["state"] == "ESTABLISHED":
                standard_ports = [80, 443, 22, 53]
                if remote_port and remote_port not in standard_ports:
                    if not is_suspicious:  
                        is_suspicious = True
                        reason.append(f"Non-standard outbound port in paranoid mode: {remote_port}")
            
            
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
            
            if ":" in ip:
                return ip.startswith("fe80:") or ip.startswith("fd")
                
            
            ip_parts = ip.split(".")
            if len(ip_parts) != 4:
                return False
                
            first_octet = int(ip_parts[0])
            second_octet = int(ip_parts[1])
            
            
            if first_octet == 10:
                return True
                
            
            if first_octet == 172 and 16 <= second_octet <= 31:
                return True
                
            
            if first_octet == 192 and second_octet == 168:
                return True
                
            
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
        
        
        suspicious_registry_keys = [
            
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            
            
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            
            
            r"HKLM\SYSTEM\CurrentControlSet\Services",
            
            
            r"HKCU\Software\Classes\CLSID",
            r"HKLM\SOFTWARE\Classes\CLSID",
            
            
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            
            
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
            
            
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        ]
        
        for reg_key in suspicious_registry_keys:
            try:
                
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
                
                parts = line.split("REG_")
                if len(parts) != 2:
                    continue
                    
                value_name = parts[0].strip()
                reg_type = "REG_" + parts[1].split()[0]
                value_data = parts[1].split(None, 1)[1] if len(parts[1].split()) > 1 else ""
                
                
                is_suspicious = False
                reason = []
                
                
                if any(path in value_data.lower() for path in ["%temp%", "%appdata%", "\\users\\public\\", "powershell", "wscript", "cmd /c"]):
                    is_suspicious = True
                    reason.append(f"Contains suspicious path: {value_data}")
                
                
                if "-e " in value_data.lower() or "-enc" in value_data.lower() or "iex" in value_data.lower():
                    is_suspicious = True
                    reason.append("Contains potentially obfuscated PowerShell command")
                
                
                for ext in [".ps1", ".vbs", ".bat", ".tmp", ".dmp", ".exe"]:
                    if ext in value_data.lower():
                        is_suspicious = True
                        reason.append(f"References {ext} file")
                        break
                
                
                for tool in COMMON_TOOL_NAMES:
                    if tool.lower() in value_data.lower():
                        is_suspicious = True
                        reason.append(f"Contains reference to known tool: {tool}")
                        break
                
                
                if len(value_data) > 100 and "==" in value_data:
                    is_suspicious = True
                    reason.append("Contains possible Base64 encoded data")
                
                
                if "RunOnce" in registry_key or "\\Services\\" in registry_key:
                    
                    if self.profile == "paranoid" and "\\windows\\" not in value_data.lower() and "\\program files\\" not in value_data.lower():
                        is_suspicious = True
                        reason.append("Non-standard path in sensitive registry key")
                
                
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
                
                continue
    
    def scan_containers(self) -> None:
        """Scan for suspicious container artifacts (Docker, LXC, etc.)"""
        print("\n[*] Scanning for container artifacts...")
        
        
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
                
                
                if os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            filepath = os.path.join(root, file)
                            self._check_container_file(filepath)
    
    def _scan_docker_containers(self) -> None:
        """Scan Docker containers for suspicious configurations"""
        try:
            
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
                
                
                
                
                if any(str(port) in ports for port in [4444, 8080, 6666, 1080, 1337, 31337]):
                    is_suspicious = True
                    reason.append(f"Container exposes suspicious port(s): {ports}")
                
                
                suspicious_images = ["kalilinux", "parrotsec", "metasploit", "pentestkit", "blackarch"]
                if any(img in image.lower() for img in suspicious_images):
                    is_suspicious = True
                    reason.append(f"Container uses potentially malicious image: {image}")
                
                
                if is_suspicious or self.profile == "paranoid":
                    
                    inspect_result = subprocess.run(
                        ["docker", "inspect", container_id],
                        capture_output=True, text=True, check=False
                    )
                    
                    if inspect_result.returncode == 0:
                        inspect_data = json.loads(inspect_result.stdout)
                        
                        if inspect_data and len(inspect_data) > 0:
                            
                            if inspect_data[0].get("HostConfig", {}).get("Privileged", False):
                                is_suspicious = True
                                reason.append("Container running in privileged mode")
                            
                            
                            mounts = inspect_data[0].get("Mounts", [])
                            for mount in mounts:
                                source = mount.get("Source", "")
                                if source in ["/", "/etc", "/var/run/docker.sock"]:
                                    is_suspicious = True
                                    reason.append(f"Container has sensitive host path mounted: {source}")
                
                
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
            
            result = subprocess.run(
                ["wmic", "process", "get", "Caption,ProcessId,CommandLine", "/format:csv"],
                capture_output=True, text=True, check=False
            )
            
            if result.returncode != 0:
                print("Error running wmic command")
                return
                
            lines = result.stdout.strip().splitlines()
            
            
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
            
            result = subprocess.run(
                ["ps", "-eo", "pid,comm,args"],
                capture_output=True, text=True, check=False
            )
            
            if result.returncode != 0:
                print("Error running ps command")
                return
                
            lines = result.stdout.strip().splitlines()
            
            
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
        
        
        if any(tool.lower() in process_name.lower() for tool in COMMON_TOOL_NAMES):
            is_suspicious = True
            matching_tools = [tool for tool in COMMON_TOOL_NAMES if tool.lower() in process_name.lower()]
            reason.append(f"Process name matches known red team tool: {', '.join(matching_tools)}")
        
        
        suspicious_cmd_patterns = [
            r"-e\s+[A-Za-z0-9+/=]{10,}",  
            r"-enc\s+[A-Za-z0-9+/=]{10,}",  
            r"-exec\s+bypass",  
            r"IEX\s*\(",  
            r"curl\s+.*\|\s*sh",  
            r"wget\s+.*\|\s*bash",  
            r"nc\s+-e",  
            r"chmod\s+.*\+x",  
            r"socat\s+.*exec",  
            r"bash\s+-i",  
            r"python\s+-c.*socket",  
            r"/dev/tcp/",  
            r"base64\s+-d",  
        ]
        
        for pattern in suspicious_cmd_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                is_suspicious = True
                reason.append(f"Command line contains suspicious pattern: {pattern}")
        
        
        suspicious_paths = ["/tmp/", "/dev/shm/", "%TEMP%", "%APPDATA%", "\\Users\\Public\\"]
        if any(path.lower() in cmdline.lower() for path in suspicious_paths):
            is_suspicious = True
            reason.append("Process running from suspicious location")
        
        
        if self.profile == "paranoid":
            if re.search(r"[A-Za-z0-9+/=]{20,}", cmdline):
                is_suspicious = True
                reason.append("Command line contains possible encoded data (paranoid mode)")
        
        
        if is_suspicious:
            
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
    
    def scan_system(self, locations: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run a comprehensive system scan"""
        print(f"Starting RedTriage scan (profile: {self.profile})")
        
        # Scan for suspicious files
        self.scan_files(locations)
        
        # Scan shell histories
        self.scan_shell_histories()
        
        # Scan modified configuration files
        self.scan_modified_configs()
        
        # Scan scheduled tasks
        self.scan_scheduled_tasks()
        
        # Scan network settings and connections
        self.scan_network_connections()
        
        # Get more detailed network artifacts
        network_findings = scan_network_artifacts(self.dry_run, self.profile)
        self.findings.update(network_findings)
        
        # Scan Windows registry if on Windows
        if self.os == "Windows":
            self.scan_windows_registry()
            
        # Scan for container artifacts
        self.scan_containers()
        
        # Scan processes and memory
        self.scan_memory_artifacts()
        
        # Save results
        output_file = f"redtriage_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        from rich.console import Console
        console = Console()
        
        # Print summary
        console.print("\n[bold]SCAN COMPLETE[/bold]", highlight=False)
        console.print(f"Results saved to: [cyan]{output_file}[/cyan]", highlight=False)
        
        console.print("\n" + "="*60, highlight=False)
        
        # Print findings summary
        console.print("\n[bold]SCAN SUMMARY[/bold]", highlight=False)
        
        # File system findings
        console.print("\n[bold]File System:[/bold]", highlight=False)
        console.print(f"🔍 Suspicious files: [cyan]{len(self.findings['suspicious_files'])}", highlight=False)
        console.print(f"🔍 Modified configs: [cyan]{len(self.findings['modified_configs'])}", highlight=False)
        console.print(f"🔍 Shell histories with suspicious commands: [cyan]{len(self.findings['shell_histories'])}", highlight=False)
        
        # Scheduled tasks
        console.print("\n[bold]Scheduled Tasks:[/bold]", highlight=False)
        console.print(f"🔍 Suspicious scheduled tasks: [cyan]{len(self.findings['scheduled_tasks'])}", highlight=False)
        
        # Network findings
        console.print("\n[bold]Network:[/bold]", highlight=False)
        if "suspicious_network" in self.findings:
            console.print(f"🔍 Suspicious network connections: [cyan]{len(self.findings['suspicious_network'])}", highlight=False)
        if "listening_ports" in self.findings:
            console.print(f"🔍 Unusual listening ports: [cyan]{len(self.findings['listening_ports'])}", highlight=False)
        if "firewall_modifications" in self.findings:
            console.print(f"🔍 Suspicious firewall rules: [cyan]{len(self.findings['firewall_modifications'])}", highlight=False)
        if "proxy_settings" in self.findings:
            console.print(f"🔍 Suspicious proxy settings: [cyan]{len(self.findings['proxy_settings'])}", highlight=False)
        if "vpn_connections" in self.findings:
            console.print(f"🔍 Active VPN connections: [cyan]{len(self.findings['vpn_connections'])}", highlight=False)
        if "ssh_connections" in self.findings:
            console.print(f"🔍 Suspicious SSH connections: [cyan]{len(self.findings['ssh_connections'])}", highlight=False)
        
        # Other artifacts
        console.print("\n[bold]Other Artifacts:[/bold]", highlight=False)
        if "container_artifacts" in self.findings:
            console.print(f"🔍 Suspicious container artifacts: [cyan]{len(self.findings['container_artifacts'])}", highlight=False)
        if "memory_artifacts" in self.findings:
            console.print(f"🔍 Suspicious processes: [cyan]{len(self.findings['memory_artifacts'])}", highlight=False)
        
        # Windows-specific findings
        if self.os == "Windows" and "registry_artifacts" in self.findings:
            console.print("\n[bold]Windows-specific:[/bold]", highlight=False)
            console.print(f"🔍 Registry artifacts: [cyan]{len(self.findings['registry_artifacts'])}", highlight=False)
        
        console.print("\n[italic]Use 'redtriage.py clean' to clean these artifacts[/italic]", highlight=False)
        
        # Add system info to findings
        self.findings["os"] = self.os
        self.findings["scan_time"] = datetime.now().isoformat()
        self.findings["profile"] = self.profile
        
        return self.findings

def scan_artifacts(dry_run: bool, profile: str, target_user: Optional[str] = None, 
                  locations: Optional[List[str]] = None, date_filter: Optional[Dict[str, datetime]] = None) -> Dict[str, Any]:
    """
    Scan the system for common red team artifacts
    
    Args:
        dry_run: Whether to perform a dry run
        profile: Scanning profile (minimal, standard, paranoid)
        target_user: User directory to target
        locations: Specific locations to scan
        date_filter: Optional dictionary with 'after' and/or 'before' datetime objects
    
    Returns:
        Dictionary containing scan results
    """
    # Print date filter info if applicable
    if date_filter:
        date_filter_description = []
        if 'after' in date_filter:
            date_filter_description.append(f"after {date_filter['after'].strftime('%Y-%m-%d')}")
        if 'before' in date_filter:
            date_filter_description.append(f"before {date_filter['before'].strftime('%Y-%m-%d')}")
        if date_filter_description:
            print(f"Date filter: Only including files modified {' and '.join(date_filter_description)}")
    
    scanner = Scanner(dry_run, profile, target_user, date_filter)
    return scanner.scan_system(locations) 