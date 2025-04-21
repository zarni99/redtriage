#!/usr/bin/env python3
"""
Network Scanner module for RedTriage
Detects suspicious network connections and artifacts
Created by: Zarni (Neo)
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

# Common suspicious ports used by malware and C2 channels
SUSPICIOUS_PORTS = {
    # Common C2 ports
    4444: "Metasploit default handler",
    8080: "Common HTTP alternative/proxy",
    8443: "Common HTTPS alternative",
    1337: "Common backdoor port (leet)",
    6666: "Common backdoor port",
    31337: "Common backdoor port (eleet)",
    
    # Remote access tools
    3389: "RDP",
    5900: "VNC",
    5938: "TeamViewer",
    22: "SSH",
    
    # Tunneling/proxying
    1080: "SOCKS proxy",
    9050: "Tor",
    9051: "Tor control",
    
    # Less common but suspicious when unexpected
    6697: "IRC+SSL",
    6667: "IRC",
    5222: "XMPP/Jabber",
}

# Common C2 domains and IPs (examples - would need regular updates)
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
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True, text=True, check=False
                )
                
                # Parse output
                for line in result.stdout.splitlines():
                    if "ESTABLISHED" in line or "LISTENING" in line:
                        parts = re.split(r'\s+', line.strip())
                        if len(parts) >= 5:
                            proto = parts[0]
                            local = parts[1]
                            remote = parts[2]
                            state = parts[3]
                            pid = parts[4]
                            
                            local_ip, local_port = self._parse_address(local)
                            remote_ip, remote_port = self._parse_address(remote)
                            
                            # Get process name from PID
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
                            
                            connection_info = {
                                "protocol": proto,
                                "local_address": local,
                                "remote_address": remote,
                                "state": state,
                                "pid": pid,
                                "process": process_name,
                                "suspicious": False,
                                "reason": ""
                            }
                            
                            # Check if suspicious
                            if self._is_suspicious_connection(local_port, remote_ip, remote_port, process_name):
                                connection_info["suspicious"] = True
                                connection_info["reason"] = self._get_suspicious_reason(remote_ip, remote_port)
                                self.findings["suspicious_connections"].append(connection_info)
                            
                            # Always add listening ports
                            if state == "LISTENING":
                                self.findings["listening_ports"].append(connection_info)
                
            elif self.os == "Linux" or self.os == "Darwin":
                # For Linux/Mac, use ss or netstat
                ss_exists = subprocess.run(["which", "ss"], capture_output=True, text=True).returncode == 0
                
                if ss_exists:
                    cmd = ["ss", "-tupn"]
                else:
                    cmd = ["netstat", "-tupn"]
                
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                # Parse output
                for line in result.stdout.splitlines():
                    if "ESTAB" in line or "LISTEN" in line:
                        parts = re.split(r'\s+', line.strip())
                        if len(parts) >= 6:
                            # Format depends on whether ss or netstat is used
                            if "ss" in cmd[0]:
                                # Adjust indexes for ss output
                                proto = parts[0]
                                state = parts[1]
                                local = parts[3]
                                remote = parts[4]
                                process_info = parts[5] if len(parts) > 5 else ""
                            else:
                                # Adjust indexes for netstat output
                                proto = parts[0]
                                local = parts[3]
                                remote = parts[4]
                                state = parts[5]
                                process_info = parts[6] if len(parts) > 6 else ""
                            
                            local_ip, local_port = self._parse_address(local)
                            remote_ip, remote_port = self._parse_address(remote)
                            
                            # Extract PID and process name
                            pid = "Unknown"
                            process_name = "Unknown"
                            if process_info:
                                pid_match = re.search(r'pid=(\d+)', process_info)
                                if pid_match:
                                    pid = pid_match.group(1)
                                    
                                    # Try to get process name from PID
                                    try:
                                        proc_result = subprocess.run(
                                            ["ps", "-p", pid, "-o", "comm="],
                                            capture_output=True, text=True, check=False
                                        )
                                        process_name = proc_result.stdout.strip()
                                    except Exception:
                                        pass
                            
                            connection_info = {
                                "protocol": proto,
                                "local_address": local,
                                "remote_address": remote,
                                "state": state,
                                "pid": pid,
                                "process": process_name,
                                "suspicious": False,
                                "reason": ""
                            }
                            
                            # Check if suspicious
                            if self._is_suspicious_connection(local_port, remote_ip, remote_port, process_name):
                                connection_info["suspicious"] = True
                                connection_info["reason"] = self._get_suspicious_reason(remote_ip, remote_port)
                                self.findings["suspicious_connections"].append(connection_info)
                            
                            # Always add listening ports
                            if state == "LISTEN":
                                self.findings["listening_ports"].append(connection_info)
                
        except Exception as e:
            print(f"Error scanning network connections: {e}")
    
    def _parse_address(self, address: str) -> tuple:
        """Parse IP:port format to return IP and port separately"""
        try:
            if ':' in address:
                parts = address.rsplit(':', 1)
                ip = parts[0].strip('[]')  # Handle IPv6 addresses
                port = int(parts[1])
                return ip, port
        except Exception:
            pass
            
        return "Unknown", 0
    
    def _is_suspicious_connection(self, local_port: int, remote_ip: str, remote_port: int, process_name: str) -> bool:
        """Determine if a connection is suspicious"""
        # Check if connecting to a suspicious port
        if remote_port in SUSPICIOUS_PORTS:
            return True
            
        # Check if using a well-known local port with an unusual process
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
        
        # Check for suspicious domain/IP patterns
        for domain in SUSPICIOUS_DOMAINS:
            if domain in remote_ip:
                return True
                
        # Paranoid profile - be more aggressive
        if self.profile == "paranoid":
            # Unusual high ports with established connections
            if remote_port > 40000 and remote_port != 0:
                return True
                
            # Check for non-standard processes with network connections
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
                # Use netsh to get firewall rules
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                    capture_output=True, text=True, check=False
                )
                
                # Parse output to find suspicious rules
                current_rule = {}
                for line in result.stdout.splitlines():
                    line = line.strip()
                    
                    if line.startswith("Rule Name:"):
                        # Save previous rule if it exists and is suspicious
                        if current_rule and self._is_suspicious_firewall_rule(current_rule):
                            self.findings["firewall_modifications"].append(current_rule)
                            
                        # Start new rule
                        current_rule = {"name": line.split(":", 1)[1].strip()}
                    elif ":" in line and current_rule:
                        key, value = line.split(":", 1)
                        current_rule[key.strip().lower().replace(" ", "_")] = value.strip()
                
                # Check the last rule
                if current_rule and self._is_suspicious_firewall_rule(current_rule):
                    self.findings["firewall_modifications"].append(current_rule)
                    
            elif self.os == "Linux":
                # Use iptables
                result = subprocess.run(
                    ["iptables", "-L", "-n", "-v"],
                    capture_output=True, text=True, check=False
                )
                
                # Parse output
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
                # For macOS, use pfctl
                result = subprocess.run(
                    ["pfctl", "-s", "rules"],
                    capture_output=True, text=True, check=False
                )
                
                # Parse output
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
        # Windows-specific checks
        if self.os == "Windows":
            # Check for rules allowing all inbound traffic
            if "direction" in rule and rule["direction"].lower() == "in":
                if "action" in rule and rule["action"].lower() == "allow":
                    # Check if it allows remote addresses
                    if "remote_ip" in rule and rule["remote_ip"] == "Any":
                        # Standard profiles only flag rules with suspicious names
                        if self.profile != "minimal":
                            suspicious_terms = ["remote", "access", "backdoor", "admin", "shell", "cmd", "powershell"]
                            if any(term in rule.get("name", "").lower() for term in suspicious_terms):
                                return True
                        
                        # Paranoid profile flags all open inbound rules
                        if self.profile == "paranoid":
                            return True
                            
                    # Check for rules allowing specific suspicious ports
                    if "local_port" in rule:
                        ports = rule["local_port"].split(",")
                        for port in ports:
                            try:
                                port_num = int(port.strip())
                                if port_num in SUSPICIOUS_PORTS:
                                    return True
                            except ValueError:
                                pass
        
        # Linux-specific checks
        elif self.os == "Linux":
            # Check for rules allowing all traffic
            if "target" in rule and rule["target"] == "ACCEPT":
                if "source" in rule and rule["source"] == "0.0.0.0/0":
                    if "destination" in rule and rule["destination"] == "0.0.0.0/0":
                        return True
        
        # macOS-specific checks
        elif self.os == "Darwin":
            # Check for rules allowing all traffic
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
                # Check Windows proxy settings using registry
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
                # Check environment variables
                for var in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]:
                    if var in os.environ:
                        proxy_value = os.environ[var]
                        self.findings["proxy_settings"].append({
                            "type": f"Environment variable ({var})",
                            "proxy": proxy_value,
                            "enabled": True,
                            "suspicious": self._is_suspicious_proxy(proxy_value)
                        })
                
                # Check system proxy settings
                if self.os == "Darwin":
                    # macOS network settings
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
        # Check for localhost proxies (potential SSH tunnels or SOCKS)
        if "127.0.0.1" in proxy or "localhost" in proxy:
            # Check for common proxy ports
            suspicious_ports = [1080, 8080, 3128, 9050, 9051, 8118]
            for port in suspicious_ports:
                if f":{port}" in proxy:
                    return True
            
            # In paranoid mode, any localhost proxy is suspicious
            if self.profile == "paranoid":
                return True
                
        # Check for suspicious domains
        for domain in SUSPICIOUS_DOMAINS:
            if domain in proxy:
                return True
                
        # Check for direct IP addresses with no domain (suspicious in some contexts)
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
                # Check for running VPN processes
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
                
                # Check network interfaces that may be VPN-related
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
                # Check for running VPN processes
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
                
                # Check network interfaces
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
        
        # Scan for active network connections
        self.scan_active_connections()
        
        # Scan for proxy settings
        self.scan_proxy_settings()
        
        # Scan for VPN connections
        self.scan_vpn_connections()
        
        # Scan for suspicious firewall rules
        self.scan_firewall_rules()
        
        # Add scan metadata
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
    network_scanner = NetworkScanner(dry_run, profile)
    findings = network_scanner.scan_network()
    
    return findings 