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
from typing import List, Dict, Any, Optional
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