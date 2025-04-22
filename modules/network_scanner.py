"""
Network Scanner module for RedTriage
Detects suspicious network connections and artifacts
Created by: Zarni (Neo)
Copyright (c) 2025 Zarni (Neo)
"""

import os
import sys
import platform
import socket
import subprocess
import re
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

SUSPICIOUS_PORTS = {
    
    4444: "Metasploit default handler",
    8080: "Common HTTP alternative/proxy",
    8443: "Common HTTPS alternative",
    1337: "Common backdoor port (leet)",
    6666: "Common backdoor port",
    31337: "Common backdoor port (eleet)",
    
    
    3389: "RDP",
    5900: "VNC",
    5938: "TeamViewer",
    22: "SSH",
    
    
    1080: "SOCKS proxy",
    9050: "Tor",
    9051: "Tor control",
    
    
    6697: "IRC+SSL",
    6667: "IRC",
    5222: "XMPP/Jabber",
}

SUSPICIOUS_DOMAINS = [
    "ngrok.io",
    "serveo.net",
    "duckdns.org",
    "dynamic-ip.hinet.net",
    "ddns.net",
    "hopto.org",
    "onion.ly",
    "onion.ws",
]

SUSPICIOUS_TOOLS = [
    "nmap", "masscan", "enum4linux", "crackmapexec", "responder", 
    "chisel", "ligolo", "plink", "socat", "ptunnel", "netcat", "nc",
    "proxychains", "iodine", "ngrok", "pproxy", "ncat",
    "mimikatz", "rubeus", "hashcat", "hydra", "medusa", "crowbar",
    "metasploit", "msfconsole", "empire", "covenant", "cobalt",
]

class NetworkScanner:
    def __init__(self, dry_run: bool, profile: str):
        self.dry_run = dry_run
        self.profile = profile
        self.os = platform.system()
        self.findings = {
            "suspicious_connections": [],
            "listening_ports": [],
            "dns_queries": [],
            "proxy_settings": [],
            "vpn_connections": [],
            "ssh_connections": [],
            "firewall_modifications": [],
        }
    
    def scan_active_connections(self) -> None:
        """Scan for suspicious active network connections"""
        print("Scanning active network connections...")
        
        try:
            if self.os == "Windows":
                # Windows netstat scan
                result = subprocess.run(
                    ["netstat", "-nao"],
                    capture_output=True, text=True, check=False
                )
                if result.returncode != 0:
                    print("Error running netstat command")
                    return
                    
                self._parse_windows_connections(result.stdout)
                
            elif self.os == "Darwin":  # macOS
                # macOS netstat scan
                result = subprocess.run(
                    ["netstat", "-na"],
                    capture_output=True, text=True, check=False
                )
                if result.returncode != 0:
                    print("Error running netstat command")
                    return
                
                # On macOS we can use lsof to get process information
                self._parse_macos_connections(result.stdout)
                
            else:  # Linux
                # Try ss first, fallback to netstat
                try:
                    result = subprocess.run(
                        ["ss", "-tulpn"],
                        capture_output=True, text=True, check=False
                    )
                    if result.returncode == 0:
                        self._parse_linux_connections(result.stdout, "ss")
                    else:
                        # Fallback to netstat
                        result = subprocess.run(
                            ["netstat", "-tulpn"],
                            capture_output=True, text=True, check=False
                        )
                        if result.returncode == 0:
                            self._parse_linux_connections(result.stdout, "netstat")
                except FileNotFoundError:
                    # If ss is not found, try netstat
                    try:
                        result = subprocess.run(
                            ["netstat", "-tulpn"],
                            capture_output=True, text=True, check=False
                        )
                        if result.returncode == 0:
                            self._parse_linux_connections(result.stdout, "netstat")
                    except FileNotFoundError:
                        print("Neither ss nor netstat commands are available")
                
        except Exception as e:
            print(f"Error scanning active connections: {e}")
    
    def _parse_windows_connections(self, netstat_output: str) -> None:
        """Parse Windows network connections and identify suspicious ones"""
        for line in netstat_output.splitlines():
            if not line or line.startswith("Proto"):
                continue
                
            try:
                parts = line.strip().split()
                if len(parts) < 5:
                    continue
                    
                proto = parts[0]
                local = parts[1]
                remote = parts[2]
                state = parts[3]
                pid = parts[4]
                
                local_ip, local_port = self._parse_address(local)
                remote_ip, remote_port = self._parse_address(remote)
                
                # Get process information using tasklist
                process_name = "Unknown"
                try:
                    proc_result = subprocess.run(
                        ["tasklist", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh"],
                        capture_output=True, text=True, check=False
                    )
                    proc_parts = proc_result.stdout.split(",")
                    if len(proc_parts) >= 2:
                        process_name = proc_parts[0].strip('"')
                except Exception:
                    pass
                
                suspicious = False
                reason = ""
                
                # Check for suspicious port numbers
                if local_port in SUSPICIOUS_PORTS:
                    suspicious = True
                    reason = f"Suspicious local port: {local_port}"
                
                if remote_port in SUSPICIOUS_PORTS:
                    suspicious = True
                    reason = f"Suspicious remote port: {remote_port}"
                
                # Check for suspicious process names
                if any(tool.lower() in process_name.lower() for tool in SUSPICIOUS_TOOLS):
                    suspicious = True
                    reason = f"Suspicious process: {process_name}"
                
                # Check for unusual states
                if self.profile == "paranoid" and state not in ["ESTABLISHED", "LISTEN"]:
                    suspicious = True
                    reason = f"Unusual connection state: {state}"
                
                # Add to findings if suspicious
                if suspicious:
                    self.findings["suspicious_network"].append({
                        "protocol": proto,
                        "local_address": local,
                        "remote_address": remote,
                        "state": state,
                        "pid": pid,
                        "process": process_name,
                        "reason": reason
                    })
                
            except Exception:
                continue
    
    def _parse_macos_connections(self, netstat_output: str) -> None:
        """Parse macOS network connections and identify suspicious ones"""
        for line in netstat_output.splitlines():
            if not line or line.startswith("Proto"):
                continue
                
            try:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                    
                proto = parts[0]
                local = parts[3]
                remote = parts[4] if len(parts) > 4 else "*.*"
                state = parts[5] if len(parts) > 5 else "LISTEN"
                
                # Skip non-TCP and non-UDP
                if not (proto.startswith("tcp") or proto.startswith("udp")):
                    continue
                    
                local_ip, local_port = self._parse_address(local)
                remote_ip, remote_port = self._parse_address(remote)
                
                # Get process information using lsof
                process_name = "Unknown"
                pid = "Unknown"
                if local_port:
                    try:
                        lsof_result = subprocess.run(
                            ["lsof", "-i", f":{local_port}"],
                            capture_output=True, text=True, check=False
                        )
                        if lsof_result.returncode == 0:
                            lsof_lines = lsof_result.stdout.strip().splitlines()
                            if len(lsof_lines) > 1:  # Skip header
                                lsof_parts = lsof_lines[1].split()
                                if len(lsof_parts) > 1:
                                    process_name = lsof_parts[0]
                                    pid = lsof_parts[1]
                    except Exception:
                        pass
                
                suspicious = False
                reason = ""
                
                # Check for suspicious port numbers
                if local_port in SUSPICIOUS_PORTS:
                    suspicious = True
                    reason = f"Suspicious local port: {local_port}"
                
                if remote_port in SUSPICIOUS_PORTS:
                    suspicious = True
                    reason = f"Suspicious remote port: {remote_port}"
                
                # Check for suspicious process names
                if any(tool.lower() in process_name.lower() for tool in SUSPICIOUS_TOOLS):
                    suspicious = True
                    reason = f"Suspicious process: {process_name}"
                
                # Check for unusual states
                if self.profile == "paranoid" and state not in ["ESTABLISHED", "LISTEN"]:
                    suspicious = True
                    reason = f"Unusual connection state: {state}"
                
                # Add to findings if suspicious
                if suspicious:
                    self.findings["suspicious_network"].append({
                        "protocol": proto,
                        "local_address": local,
                        "remote_address": remote,
                        "state": state,
                        "pid": pid,
                        "process": process_name,
                        "reason": reason
                    })
                
            except Exception:
                continue
    
    def _parse_linux_connections(self, netstat_output: str, command: str) -> None:
        """Parse Linux network connections and identify suspicious ones"""
        for line in netstat_output.splitlines():
            if not line or line.startswith("Proto"):
                continue
                
            try:
                parts = line.strip().split()
                if len(parts) < 6:
                    continue
                    
                proto = parts[0]
                state = parts[5]
                local = parts[3]
                remote = parts[4]
                process_info = parts[5] if len(parts) > 5 else ""
                
                # Skip non-TCP and non-UDP
                if not (proto.startswith("tcp") or proto.startswith("udp")):
                    continue
                    
                local_ip, local_port = self._parse_address(local)
                remote_ip, remote_port = self._parse_address(remote)
                
                # Get process information using ps
                process_name = "Unknown"
                pid = "Unknown"
                if process_info:
                    pid_match = re.search(r'pid=(\d+)', process_info)
                    if pid_match:
                        pid = pid_match.group(1)
                        
                        try:
                            proc_result = subprocess.run(
                                ["ps", "-p", pid, "-o", "comm="],
                                capture_output=True, text=True, check=False
                            )
                            process_name = proc_result.stdout.strip()
                        except Exception:
                            pass
                
                suspicious = False
                reason = ""
                
                # Check for suspicious port numbers
                if local_port in SUSPICIOUS_PORTS:
                    suspicious = True
                    reason = f"Suspicious local port: {local_port}"
                
                if remote_port in SUSPICIOUS_PORTS:
                    suspicious = True
                    reason = f"Suspicious remote port: {remote_port}"
                
                # Check for suspicious process names
                if any(tool.lower() in process_name.lower() for tool in SUSPICIOUS_TOOLS):
                    suspicious = True
                    reason = f"Suspicious process: {process_name}"
                
                # Check for unusual states
                if self.profile == "paranoid" and state not in ["ESTABLISHED", "LISTEN"]:
                    suspicious = True
                    reason = f"Unusual connection state: {state}"
                
                # Add to findings if suspicious
                if suspicious:
                    self.findings["suspicious_network"].append({
                        "protocol": proto,
                        "local_address": local,
                        "remote_address": remote,
                        "state": state,
                        "pid": pid,
                        "process": process_name,
                        "reason": reason
                    })
                
            except Exception:
                continue
    
    def _parse_address(self, address: str) -> tuple:
        """Parse IP:port format to return IP and port separately"""
        try:
            if ':' in address:
                parts = address.rsplit(':', 1)
                ip = parts[0].strip('[]')  
                port = int(parts[1])
                return ip, port
        except Exception:
            pass
            
        return "Unknown", 0
    
    def _is_suspicious_connection(self, local_port: int, remote_ip: str, remote_port: int, process_name: str) -> bool:
        """Determine if a connection is suspicious"""
        
        if remote_port in SUSPICIOUS_PORTS:
            return True
            
        
        standard_services = {
            80: ["nginx", "apache2", "httpd", "iis", "w3wp"],
            443: ["nginx", "apache2", "httpd", "iis", "w3wp"],
            22: ["sshd", "ssh", "openssh"],
            21: ["ftpd", "vsftpd", "ftp"],
            25: ["smtp", "postfix", "sendmail", "exchange"],
            3306: ["mysql", "mysqld"],
            5432: ["postgres", "postgresql"]
        }
        
        if local_port in standard_services:
            process_found = False
            for valid_process in standard_services[local_port]:
                if valid_process.lower() in process_name.lower():
                    process_found = True
                    break
                    
            if not process_found and process_name != "Unknown":
                return True
        
        
        for domain in SUSPICIOUS_DOMAINS:
            if domain in remote_ip:
                return True
                
        
        if self.profile == "paranoid":
            
            if remote_port > 40000 and remote_port != 0:
                return True
                
            
            unusual_processes = ["python", "python3", "powershell", "cmd", "bash", "perl", "ruby"]
            if any(proc in process_name.lower() for proc in unusual_processes):
                return True
        
        return False
    
    def _get_suspicious_reason(self, remote_ip: str, remote_port: int) -> str:
        """Get reason why connection is flagged as suspicious"""
        reasons = []
        
        if remote_port in SUSPICIOUS_PORTS:
            reasons.append(f"Suspicious port {remote_port} ({SUSPICIOUS_PORTS[remote_port]})")
            
        for domain in SUSPICIOUS_DOMAINS:
            if domain in remote_ip:
                reasons.append(f"Suspicious domain/IP: {remote_ip}")
                break
        
        if not reasons and remote_port > 40000 and self.profile == "paranoid":
            reasons.append(f"Unusual high port: {remote_port}")
            
        return "; ".join(reasons) if reasons else "Unknown"
    
    def scan_firewall_rules(self) -> None:
        """Scan for suspicious firewall rules and modifications"""
        print("Scanning firewall rules...")
        
        try:
            if self.os == "Windows":
                
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                    capture_output=True, text=True, check=False
                )
                
                
                current_rule = {}
                for line in result.stdout.splitlines():
                    line = line.strip()
                    
                    if line.startswith("Rule Name:"):
                        
                        if current_rule and self._is_suspicious_firewall_rule(current_rule):
                            self.findings["firewall_modifications"].append(current_rule)
                            
                        
                        current_rule = {"name": line.split(":", 1)[1].strip()}
                    elif ":" in line and current_rule:
                        key, value = line.split(":", 1)
                        current_rule[key.strip().lower().replace(" ", "_")] = value.strip()
                
                
                if current_rule and self._is_suspicious_firewall_rule(current_rule):
                    self.findings["firewall_modifications"].append(current_rule)
                    
            elif self.os == "Linux":
                
                result = subprocess.run(
                    ["iptables", "-L", "-n", "-v"],
                    capture_output=True, text=True, check=False
                )
                
                
                chain = None
                for line in result.stdout.splitlines():
                    line = line.strip()
                    
                    if line.startswith("Chain"):
                        chain = line.split()[1]
                    elif line and not line.startswith("target") and chain:
                        parts = line.split()
                        if len(parts) >= 3:
                            rule = {
                                "chain": chain,
                                "target": parts[0],
                                "protocol": parts[1],
                                "source": parts[3],
                                "destination": parts[4],
                            }
                            
                            if self._is_suspicious_firewall_rule(rule):
                                self.findings["firewall_modifications"].append(rule)
            
            elif self.os == "Darwin":
                
                result = subprocess.run(
                    ["pfctl", "-s", "rules"],
                    capture_output=True, text=True, check=False
                )
                
                
                for line in result.stdout.splitlines():
                    line = line.strip()
                    
                    if "pass" in line or "block" in line:
                        rule = {"rule": line}
                        
                        if self._is_suspicious_firewall_rule(rule):
                            self.findings["firewall_modifications"].append(rule)
                            
        except Exception as e:
            print(f"Error scanning firewall rules: {e}")
    
    def _is_suspicious_firewall_rule(self, rule: Dict[str, Any]) -> bool:
        """Determine if a firewall rule is suspicious"""
        
        if self.os == "Windows":
            
            if "direction" in rule and rule["direction"].lower() == "in":
                if "action" in rule and rule["action"].lower() == "allow":
                    
                    if "remote_ip" in rule and rule["remote_ip"] == "Any":
                        
                        if self.profile != "minimal":
                            suspicious_terms = ["remote", "access", "backdoor", "admin", "shell", "cmd", "powershell"]
                            if any(term in rule.get("name", "").lower() for term in suspicious_terms):
                                return True
                        
                        
                        if self.profile == "paranoid":
                            return True
                            
                    
                    if "local_port" in rule:
                        ports = rule["local_port"].split(",")
                        for port in ports:
                            try:
                                port_num = int(port.strip())
                                if port_num in SUSPICIOUS_PORTS:
                                    return True
                            except ValueError:
                                pass
        
        
        elif self.os == "Linux":
            
            if "target" in rule and rule["target"] == "ACCEPT":
                if "source" in rule and rule["source"] == "0.0.0.0/0":
                    if "destination" in rule and rule["destination"] == "0.0.0.0/0":
                        return True
        
        
        elif self.os == "Darwin":
            
            if "rule" in rule:
                rule_text = rule["rule"].lower()
                if "pass" in rule_text and "all" in rule_text and "from any to any" in rule_text:
                    return True
        
        return False
    
    def scan_proxy_settings(self) -> None:
        """Scan for suspicious proxy settings"""
        print("Scanning proxy settings...")
        
        try:
            if self.os == "Windows":
                
                reg_result = subprocess.run(
                    ["reg", "query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"],
                    capture_output=True, text=True, check=False
                )
                
                proxy_enabled = False
                proxy_server = ""
                
                for line in reg_result.stdout.splitlines():
                    if "ProxyEnable" in line:
                        parts = re.split(r'\s+', line.strip())
                        if len(parts) >= 3 and parts[2] == "0x1":
                            proxy_enabled = True
                    
                    if "ProxyServer" in line:
                        parts = re.split(r'\s+', line.strip(), maxsplit=2)
                        if len(parts) >= 3:
                            proxy_server = parts[2]
                
                if proxy_enabled and proxy_server:
                    self.findings["proxy_settings"].append({
                        "type": "Windows Internet Settings",
                        "proxy": proxy_server,
                        "enabled": True,
                        "suspicious": self._is_suspicious_proxy(proxy_server)
                    })
            
            elif self.os == "Linux" or self.os == "Darwin":
                
                for var in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
                    if var in os.environ:
                        proxy_value = os.environ[var]
                        self.findings["proxy_settings"].append({
                            "type": f"Environment variable ({var})",
                            "proxy": proxy_value,
                            "enabled": True,
                            "suspicious": self._is_suspicious_proxy(proxy_value)
                        })
                
                
                if self.os == "Darwin":
                    
                    result = subprocess.run(
                        ["networksetup", "-getwebproxy", "Wi-Fi"],
                        capture_output=True, text=True, check=False
                    )
                    
                    proxy_enabled = False
                    proxy_server = ""
                    proxy_port = ""
                    
                    for line in result.stdout.splitlines():
                        if "Enabled:" in line and "Yes" in line:
                            proxy_enabled = True
                        
                        if "Server:" in line:
                            proxy_server = line.split(":", 1)[1].strip()
                            
                        if "Port:" in line:
                            proxy_port = line.split(":", 1)[1].strip()
                    
                    if proxy_enabled and proxy_server:
                        full_proxy = f"{proxy_server}:{proxy_port}"
                        self.findings["proxy_settings"].append({
                            "type": "macOS Web Proxy",
                            "proxy": full_proxy,
                            "enabled": True,
                            "suspicious": self._is_suspicious_proxy(full_proxy)
                        })
                        
        except Exception as e:
            print(f"Error scanning proxy settings: {e}")
    
    def _is_suspicious_proxy(self, proxy: str) -> bool:
        """Determine if a proxy is suspicious"""
        
        if "127.0.0.1" in proxy or "localhost" in proxy:
            
            suspicious_ports = [1080, 8080, 3128, 9050, 9051, 8118]
            for port in suspicious_ports:
                if f":{port}" in proxy:
                    return True
            
            
            if self.profile == "paranoid":
                return True
                
        
        for domain in SUSPICIOUS_DOMAINS:
            if domain in proxy:
                return True
                
        
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.search(ip_pattern, proxy) and self.profile != "minimal":
            return True
            
        return False
    
    def scan_vpn_connections(self) -> None:
        """Scan for active VPN connections"""
        print("Scanning for VPN connections...")
        
        try:
            vpn_processes = {
                "Windows": ["openvpn.exe", "nordvpn.exe", "expressvpn.exe", "ivpn.exe", "protonvpn.exe", "wireguard.exe", "wg.exe"],
                "Linux": ["openvpn", "nordvpn", "expressvpn", "wireguard", "wg"],
                "Darwin": ["openvpn", "nordvpn", "expressvpn", "wireguard", "wg"]
            }
            
            if self.os == "Windows":
                
                result = subprocess.run(
                    ["tasklist", "/fo", "csv", "/nh"],
                    capture_output=True, text=True, check=False
                )
                
                for line in result.stdout.splitlines():
                    parts = line.strip('"').split('","')
                    if parts and parts[0] in vpn_processes["Windows"]:
                        self.findings["vpn_connections"].append({
                            "type": "VPN Process",
                            "process": parts[0],
                            "pid": parts[1] if len(parts) > 1 else "Unknown"
                        })
                
                
                ipconfig = subprocess.run(
                    ["ipconfig", "/all"],
                    capture_output=True, text=True, check=False
                )
                
                vpn_adapters = ["tap", "tun", "vpn", "wireguard", "nordvpn", "expressvpn", "ipsec"]
                current_adapter = ""
                
                for line in ipconfig.stdout.splitlines():
                    line = line.strip()
                    
                    if "adapter" in line.lower():
                        current_adapter = line
                    
                    if current_adapter and any(adapter in current_adapter.lower() for adapter in vpn_adapters):
                        if "IPv4 Address" in line or "IPv6 Address" in line:
                            self.findings["vpn_connections"].append({
                                "type": "VPN Network Interface",
                                "interface": current_adapter,
                                "details": line
                            })
            
            elif self.os == "Linux" or self.os == "Darwin":
                
                ps_cmd = "ps aux" if self.os == "Linux" else "ps -ax"
                result = subprocess.run(
                    ps_cmd, shell=True, capture_output=True, text=True, check=False
                )
                
                vpn_procs = vpn_processes["Linux"] if self.os == "Linux" else vpn_processes["Darwin"]
                for line in result.stdout.splitlines():
                    if any(proc in line for proc in vpn_procs):
                        self.findings["vpn_connections"].append({
                            "type": "VPN Process",
                            "details": line.strip()
                        })
                
                
                ifconfig = subprocess.run(
                    ["ifconfig"] if self.os == "Linux" else ["/sbin/ifconfig"],
                    capture_output=True, text=True, check=False
                )
                
                vpn_interfaces = ["tun", "tap", "ppp", "wg"]
                current_interface = ""
                
                for line in ifconfig.stdout.splitlines():
                    line = line.strip()
                    
                    if line and not line.startswith(" "):
                        current_interface = line.split(":")[0]
                    
                    if current_interface and any(iface in current_interface for iface in vpn_interfaces):
                        if "inet " in line:
                            self.findings["vpn_connections"].append({
                                "type": "VPN Network Interface",
                                "interface": current_interface,
                                "details": line
                            })
                        
        except Exception as e:
            print(f"Error scanning VPN connections: {e}")
    
    def scan_network(self) -> Dict[str, Any]:
        """Run a comprehensive network scan"""
        print("Starting RedTriage network scan...")
        
        
        self.scan_active_connections()
        
        
        self.scan_proxy_settings()
        
        
        self.scan_vpn_connections()
        
        
        self.scan_firewall_rules()
        
        
        self.findings["metadata"] = {
            "timestamp": datetime.now().isoformat(),
            "os": self.os,
            "hostname": socket.gethostname(),
            "profile": self.profile,
            "dry_run": self.dry_run
        }
        
        return self.findings


def scan_network_artifacts(dry_run: bool, profile: str) -> Dict[str, Any]:
    """Run the network scan functionality"""
    try:
        network_scanner = NetworkScanner(dry_run, profile)
        findings = network_scanner.scan_network()
        return findings
    except Exception as e:
        print(f"Error in network scanning: {e}")
        # Return empty findings in case of error to avoid breaking the main flow
        return {
            "listening_ports": [],
            "suspicious_network": [],
            "firewall_modifications": [],
            "proxy_settings": [],
            "vpn_connections": [],
            "ssh_connections": []
        } 