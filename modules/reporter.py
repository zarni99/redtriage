#!/usr/bin/env python3
"""
Reporter module for RedTriage
Generates reports of findings and cleanup actions
"""

import os
import json
import platform
import logging
from typing import Dict, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Reportlab imports are handled in the generate_pdf_report method to make it optional

class Reporter:
    def __init__(self, output_format: str, output_file: Optional[str] = None):
        self.output_format = output_format
        self.output_file = output_file
        self.os = platform.system()
    
    def generate_txt_report(self, data: Dict[str, Any]) -> str:
        """Generate a text report from the data"""
        report = []
        
        # Add header
        report.append("=" * 50)
        report.append("RedTriage Report")
        report.append("=" * 50)
        
        # Add metadata
        if "metadata" in data:
            report.append("\nMetadata:")
            report.append("-" * 50)
            metadata = data["metadata"]
            report.append(f"Timestamp: {metadata.get('timestamp', 'Unknown')}")
            report.append(f"Operating System: {metadata.get('os', 'Unknown')}")
            report.append(f"Hostname: {metadata.get('hostname', 'Unknown')}")
            report.append(f"Profile: {metadata.get('profile', 'Unknown')}")
            report.append(f"Target User: {metadata.get('target_user', 'None')}")
            report.append(f"Dry Run: {metadata.get('dry_run', False)}")
            if "force" in metadata:
                report.append(f"Force: {metadata.get('force', False)}")
        
        # Add suspicious files
        if "suspicious_files" in data and data["suspicious_files"]:
            report.append("\nSuspicious Files:")
            report.append("-" * 50)
            for i, file_info in enumerate(data["suspicious_files"], 1):
                report.append(f"{i}. Path: {file_info.get('path', 'Unknown')}")
                report.append(f"   Size: {file_info.get('size', 'Unknown')} bytes")
                report.append(f"   Created: {file_info.get('created', 'Unknown')}")
                report.append(f"   Modified: {file_info.get('modified', 'Unknown')}")
                report.append(f"   Reason: {file_info.get('reason', 'Unknown')}")
                report.append("")
        
        # Add modified configs
        if "modified_configs" in data and data["modified_configs"]:
            report.append("\nModified Configuration Files:")
            report.append("-" * 50)
            for i, config_info in enumerate(data["modified_configs"], 1):
                report.append(f"{i}. Path: {config_info.get('path', 'Unknown')}")
                report.append(f"   Modified: {config_info.get('modified', 'Unknown')}")
                report.append("")
        
        # Add shell histories with suspicious commands
        if "shell_histories" in data and data["shell_histories"]:
            report.append("\nShell Histories with Suspicious Commands:")
            report.append("-" * 50)
            for i, history_info in enumerate(data["shell_histories"], 1):
                report.append(f"{i}. Path: {history_info.get('path', 'Unknown')}")
                report.append(f"   Modified: {history_info.get('modified', 'Unknown')}")
                if "suspicious_commands" in history_info:
                    report.append("   Suspicious Commands:")
                    for j, cmd in enumerate(history_info["suspicious_commands"], 1):
                        report.append(f"     {j}. {cmd}")
                report.append("")
        
        # Add suspicious scheduled tasks
        if "scheduled_tasks" in data and data["scheduled_tasks"]:
            report.append("\nSuspicious Scheduled Tasks/Cron Jobs:")
            report.append("-" * 50)
            for i, task_info in enumerate(data["scheduled_tasks"], 1):
                if "name" in task_info:
                    report.append(f"{i}. Name: {task_info['name']}")
                elif "path" in task_info:
                    report.append(f"{i}. Path: {task_info['path']}")
                    
                if "reason" in task_info:
                    report.append(f"   Reason: {task_info['reason']}")
                    
                if "modified" in task_info:
                    report.append(f"   Modified: {task_info['modified']}")
                    
                # For cron jobs, include content
                if "content" in task_info:
                    content = task_info["content"]
                    if len(content) > 500:
                        content = content[:500] + "... (truncated)"
                    report.append(f"   Content: {content}")
                    
                report.append("")
        
        # Add suspicious network connections
        if "suspicious_network" in data and data["suspicious_network"]:
            report.append("\nSuspicious Network Connections:")
            report.append("-" * 50)
            for i, net_info in enumerate(data["suspicious_network"], 1):
                report.append(f"{i}. Protocol: {net_info.get('protocol', 'Unknown')}")
                report.append(f"   Local: {net_info.get('local_address', 'Unknown')}")
                report.append(f"   Remote: {net_info.get('remote_address', 'Unknown')}")
                report.append(f"   State: {net_info.get('state', 'Unknown')}")
                report.append(f"   PID: {net_info.get('pid', 'Unknown')}")
                report.append(f"   Process: {net_info.get('process', 'Unknown')}")
                report.append(f"   Reason: {net_info.get('reason', 'Unknown')}")
                report.append("")
        
        # Add registry artifacts
        if "registry_artifacts" in data and data["registry_artifacts"]:
            report.append("\nSuspicious Registry Entries:")
            report.append("-" * 50)
            for i, reg_info in enumerate(data["registry_artifacts"], 1):
                report.append(f"{i}. Key: {reg_info.get('key', 'Unknown')}")
                report.append(f"   Value: {reg_info.get('value_name', 'Unknown')}")
                report.append(f"   Data: {reg_info.get('value_data', 'Unknown')}")
                report.append(f"   Reason: {reg_info.get('reason', 'Unknown')}")
                report.append("")
        
        # Add container artifacts
        if "container_artifacts" in data and data["container_artifacts"]:
            report.append("\nSuspicious Container Artifacts:")
            report.append("-" * 50)
            for i, container_info in enumerate(data["container_artifacts"], 1):
                if "container_id" in container_info:
                    report.append(f"{i}. Container: {container_info.get('name', 'Unknown')}")
                    report.append(f"   ID: {container_info.get('container_id', 'Unknown')}")
                    report.append(f"   Image: {container_info.get('image', 'Unknown')}")
                    report.append(f"   Ports: {container_info.get('ports', 'Unknown')}")
                else:
                    report.append(f"{i}. Container Config: {container_info.get('path', 'Unknown')}")
                    report.append(f"   Type: {container_info.get('type', 'Unknown')}")
                report.append(f"   Reason: {container_info.get('reason', 'Unknown')}")
                report.append("")
        
        # Add memory artifacts
        if "memory_artifacts" in data and data["memory_artifacts"]:
            report.append("\nSuspicious Processes:")
            report.append("-" * 50)
            for i, proc_info in enumerate(data["memory_artifacts"], 1):
                report.append(f"{i}. Process: {proc_info.get('process_name', 'Unknown')}")
                report.append(f"   PID: {proc_info.get('pid', 'Unknown')}")
                report.append(f"   Command: {proc_info.get('command_line', 'Unknown')}")
                
                memory_info = proc_info.get("memory_info", {})
                if memory_info:
                    if "memory_usage" in memory_info:
                        report.append(f"   Memory Usage: {memory_info['memory_usage']}")
                    if "vsz" in memory_info:
                        report.append(f"   Virtual Size: {memory_info['vsz']}")
                    if "rss" in memory_info:
                        report.append(f"   Resident Size: {memory_info['rss']}")
                        
                report.append(f"   Reason: {proc_info.get('reason', 'Unknown')}")
                report.append("")
        
        # Add cleaned items if available
        if "files" in data:
            report.append("\nCleaned Files:")
            report.append("-" * 50)
            if data["files"]:
                for i, file_info in enumerate(data["files"], 1):
                    report.append(f"{i}. Path: {file_info.get('path', 'Unknown')}")
            else:
                report.append("None")
                
        if "histories" in data:
            report.append("\nCleaned Shell Histories:")
            report.append("-" * 50)
            if data["histories"]:
                for i, history_info in enumerate(data["histories"], 1):
                    report.append(f"{i}. Path: {history_info.get('path', 'Unknown')}")
            else:
                report.append("None")
                
        if "tasks" in data:
            report.append("\nRemoved Scheduled Tasks/Cron Jobs:")
            report.append("-" * 50)
            if data["tasks"]:
                for i, task_info in enumerate(data["tasks"], 1):
                    if "name" in task_info:
                        report.append(f"{i}. Name: {task_info['name']}")
                    elif "path" in task_info:
                        report.append(f"{i}. Path: {task_info['path']}")
            else:
                report.append("None")
                
        if "configs" in data:
            report.append("\nRestored Configuration Files:")
            report.append("-" * 50)
            if data["configs"]:
                for i, config_info in enumerate(data["configs"], 1):
                    report.append(f"{i}. Path: {config_info.get('path', 'Unknown')}")
            else:
                report.append("None")
        
        if "network" in data:
            report.append("\nCleaned Network Connections:")
            report.append("-" * 50)
            if data["network"]:
                for i, net_info in enumerate(data["network"], 1):
                    report.append(f"{i}. Protocol: {net_info.get('protocol', 'Unknown')}")
                    report.append(f"   Local: {net_info.get('local_address', 'Unknown')}")
                    report.append(f"   Remote: {net_info.get('remote_address', 'Unknown')}")
                    report.append(f"   Process: {net_info.get('process', 'Unknown')} (PID: {net_info.get('pid', 'Unknown')})")
                    report.append("")
            else:
                report.append("None")
        
        if "registry" in data:
            report.append("\nCleaned Registry Entries:")
            report.append("-" * 50)
            if data["registry"]:
                for i, reg_info in enumerate(data["registry"], 1):
                    report.append(f"{i}. Key: {reg_info.get('key', 'Unknown')}")
                    report.append(f"   Value: {reg_info.get('value_name', 'Unknown')}")
                    report.append("")
            else:
                report.append("None")
        
        if "containers" in data:
            report.append("\nCleaned Container Artifacts:")
            report.append("-" * 50)
            if data["containers"]:
                for i, container_info in enumerate(data["containers"], 1):
                    if "container_id" in container_info:
                        report.append(f"{i}. Container: {container_info.get('name', 'Unknown')} ({container_info.get('container_id', 'Unknown')})")
                    else:
                        report.append(f"{i}. Container Config: {container_info.get('path', 'Unknown')}")
                    report.append("")
            else:
                report.append("None")
        
        if "processes" in data:
            report.append("\nTerminated Processes:")
            report.append("-" * 50)
            if data["processes"]:
                for i, proc_info in enumerate(data["processes"], 1):
                    report.append(f"{i}. Process: {proc_info.get('process_name', 'Unknown')} (PID: {proc_info.get('pid', 'Unknown')})")
                    report.append("")
            else:
                report.append("None")
        
        # Add summary
        report.append("\nSummary:")
        report.append("-" * 50)
        
        if "suspicious_files" in data:
            report.append(f"Suspicious Files: {len(data['suspicious_files'])}")
        if "modified_configs" in data:
            report.append(f"Modified Configs: {len(data['modified_configs'])}")
        if "shell_histories" in data:
            report.append(f"Shell Histories with Suspicious Commands: {len(data['shell_histories'])}")
        if "scheduled_tasks" in data:
            report.append(f"Suspicious Scheduled Tasks: {len(data['scheduled_tasks'])}")
        if "suspicious_network" in data:
            report.append(f"Suspicious Network Connections: {len(data['suspicious_network'])}")
        if "registry_artifacts" in data:
            report.append(f"Suspicious Registry Entries: {len(data['registry_artifacts'])}")
        if "container_artifacts" in data:
            report.append(f"Suspicious Container Artifacts: {len(data['container_artifacts'])}")
        if "memory_artifacts" in data:
            report.append(f"Suspicious Processes: {len(data['memory_artifacts'])}")
            
        if "files" in data:
            report.append(f"Cleaned Files: {len(data['files'])}")
        if "histories" in data:
            report.append(f"Cleaned Histories: {len(data['histories'])}")
        if "tasks" in data:
            report.append(f"Cleaned Tasks: {len(data['tasks'])}")
        if "configs" in data:
            report.append(f"Restored Configs: {len(data['configs'])}")
        if "network" in data:
            report.append(f"Terminated Network Connections: {len(data['network'])}")
        if "registry" in data:
            report.append(f"Cleaned Registry Entries: {len(data['registry'])}")
        if "containers" in data:
            report.append(f"Cleaned Container Artifacts: {len(data['containers'])}")
        if "processes" in data:
            report.append(f"Terminated Processes: {len(data['processes'])}")
        
        return "\n".join(report)
    
    def generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate an HTML report from the data"""
        html = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "    <title>RedTriage Report</title>",
            "    <style>",
            "        body { font-family: Arial, sans-serif; margin: 20px; }",
            "        .container { max-width: 1200px; margin: 0 auto; }",
            "        h1, h2, h3 { color: #d9534f; }",
            "        .section { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }",
            "        .item { margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px dotted #eee; }",
            "        .item:last-child { border-bottom: none; }",
            "        .header { background-color: #f8f9fa; padding: 10px; }",
            "        .footer { background-color: #f8f9fa; padding: 10px; font-size: 12px; text-align: center; }",
            "        .summary { display: flex; flex-wrap: wrap; }",
            "        .summary-item { flex: 0 0 50%; margin-bottom: 10px; }",
            "        table { width: 100%; border-collapse: collapse; }",
            "        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }",
            "        th { background-color: #f2f2f2; }",
            "        .high { color: #d9534f; }",
            "        .medium { color: #f0ad4e; }",
            "        .low { color: #5bc0de; }",
            "    </style>",
            "</head>",
            "<body>",
            "    <div class='container'>",
            "        <div class='header'>",
            f"            <h1>RedTriage Scan Report</h1>",
            f"            <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            f"            <p>System: {platform.node()} - {platform.system()} {platform.release()}</p>",
            "        </div>",
        ]
        
        # Metadata
        if "metadata" in data:
            html.append("        <div class='section'>")
            html.append("            <h2>Metadata</h2>")
            html.append("            <table>")
            html.append("                <tr><th>Property</th><th>Value</th></tr>")
            metadata = data["metadata"]
            html.append(f"                <tr><td>Timestamp</td><td>{metadata.get('timestamp', 'Unknown')}</td></tr>")
            html.append(f"                <tr><td>Operating System</td><td>{metadata.get('os', 'Unknown')}</td></tr>")
            html.append(f"                <tr><td>Hostname</td><td>{metadata.get('hostname', 'Unknown')}</td></tr>")
            html.append(f"                <tr><td>Profile</td><td>{metadata.get('profile', 'Unknown')}</td></tr>")
            html.append(f"                <tr><td>Target User</td><td>{metadata.get('target_user', 'None')}</td></tr>")
            html.append(f"                <tr><td>Dry Run</td><td>{metadata.get('dry_run', False)}</td></tr>")
            if "force" in metadata:
                html.append(f"                <tr><td>Force</td><td>{metadata.get('force', False)}</td></tr>")
            html.append("            </table>")
            html.append("        </div>")
        
        # Suspicious Files
        if "suspicious_files" in data and data["suspicious_files"]:
            html.append("        <div class='section'>")
            html.append("            <h2 class='suspicious'>Suspicious Files</h2>")
            html.append("            <table>")
            html.append("                <tr><th>Path</th><th>Size</th><th>Created</th><th>Modified</th><th>Reason</th></tr>")
            
            for file_info in data["suspicious_files"]:
                html.append("                <tr>")
                html.append(f"                    <td>{file_info.get('path', 'Unknown')}</td>")
                html.append(f"                    <td>{file_info.get('size', 'Unknown')} bytes</td>")
                html.append(f"                    <td>{file_info.get('created', 'Unknown')}</td>")
                html.append(f"                    <td>{file_info.get('modified', 'Unknown')}</td>")
                html.append(f"                    <td>{file_info.get('reason', 'Unknown')}</td>")
                html.append("                </tr>")
                
            html.append("            </table>")
            html.append("        </div>")
        
        # Modified Configs
        if "modified_configs" in data and data["modified_configs"]:
            html.append("        <div class='section'>")
            html.append("            <h2 class='suspicious'>Modified Configuration Files</h2>")
            html.append("            <table>")
            html.append("                <tr><th>Path</th><th>Modified</th></tr>")
            
            for config_info in data["modified_configs"]:
                html.append("                <tr>")
                html.append(f"                    <td>{config_info.get('path', 'Unknown')}</td>")
                html.append(f"                    <td>{config_info.get('modified', 'Unknown')}</td>")
                html.append("                </tr>")
                
            html.append("            </table>")
            html.append("        </div>")
            
        # Shell Histories
        if "shell_histories" in data and data["shell_histories"]:
            html.append("        <div class='section'>")
            html.append("            <h2 class='suspicious'>Shell Histories with Suspicious Commands</h2>")
            
            for i, history_info in enumerate(data["shell_histories"], 1):
                html.append(f"            <h3>{i}. {history_info.get('path', 'Unknown')}</h3>")
                html.append(f"            <p>Modified: {history_info.get('modified', 'Unknown')}</p>")
                
                if "suspicious_commands" in history_info:
                    html.append("            <table>")
                    html.append("                <tr><th>#</th><th>Command</th></tr>")
                    
                    for j, cmd in enumerate(history_info["suspicious_commands"], 1):
                        html.append("                <tr>")
                        html.append(f"                    <td>{j}</td>")
                        html.append(f"                    <td>{cmd}</td>")
                        html.append("                </tr>")
                        
                    html.append("            </table>")
                    
            html.append("        </div>")
            
        # Scheduled Tasks
        if "scheduled_tasks" in data and data["scheduled_tasks"]:
            html.append("        <div class='section'>")
            html.append("            <h2 class='suspicious'>Suspicious Scheduled Tasks/Cron Jobs</h2>")
            html.append("            <table>")
            html.append("                <tr><th>Name/Path</th><th>Reason</th><th>Details</th></tr>")
            
            for task_info in data["scheduled_tasks"]:
                html.append("                <tr>")
                
                if "name" in task_info:
                    html.append(f"                    <td>{task_info['name']}</td>")
                elif "path" in task_info:
                    html.append(f"                    <td>{task_info['path']}</td>")
                else:
                    html.append("                    <td>Unknown</td>")
                    
                html.append(f"                    <td>{task_info.get('reason', 'Unknown')}</td>")
                
                # Details
                details = "N/A"
                if "content" in task_info:
                    details = task_info["content"]
                    if len(details) > 200:
                        details = details[:200] + "... (truncated)"
                html.append(f"                    <td><pre>{details}</pre></td>")
                
                html.append("                </tr>")
                
            html.append("            </table>")
            html.append("        </div>")
            
        # Cleaned items
        if all(k in data for k in ["files", "histories", "tasks", "configs"]):
            html.append("        <div class='section'>")
            html.append("            <h2 class='cleaned'>Cleanup Actions</h2>")
            
            # Files
            html.append("            <h3>Cleaned Files</h3>")
            if data["files"]:
                html.append("            <ul>")
                for file_info in data["files"]:
                    html.append(f"                <li>{file_info.get('path', 'Unknown')}</li>")
                html.append("            </ul>")
            else:
                html.append("            <p>None</p>")
                
            # Histories
            html.append("            <h3>Cleaned Shell Histories</h3>")
            if data["histories"]:
                html.append("            <ul>")
                for history_info in data["histories"]:
                    html.append(f"                <li>{history_info.get('path', 'Unknown')}</li>")
                html.append("            </ul>")
            else:
                html.append("            <p>None</p>")
                
            # Tasks
            html.append("            <h3>Removed Scheduled Tasks/Cron Jobs</h3>")
            if data["tasks"]:
                html.append("            <ul>")
                for task_info in data["tasks"]:
                    if "name" in task_info:
                        html.append(f"                <li>{task_info['name']}</li>")
                    elif "path" in task_info:
                        html.append(f"                <li>{task_info['path']}</li>")
                html.append("            </ul>")
            else:
                html.append("            <p>None</p>")
                
            # Configs
            html.append("            <h3>Restored Configuration Files</h3>")
            if data["configs"]:
                html.append("            <ul>")
                for config_info in data["configs"]:
                    html.append(f"                <li>{config_info.get('path', 'Unknown')}</li>")
                html.append("            </ul>")
            else:
                html.append("            <p>None</p>")
                
            html.append("        </div>")
        
        # Summary
        html.append("        <div class='section'>")
        html.append("            <h2>Summary</h2>")
        html.append("            <div class='summary'>")
        
        if "suspicious_files" in data:
            html.append(f"                <div class='summary-item'>Suspicious Files: <strong>{len(data['suspicious_files'])}</strong></div>")
        if "modified_configs" in data:
            html.append(f"                <div class='summary-item'>Modified Configs: <strong>{len(data['modified_configs'])}</strong></div>")
        if "shell_histories" in data:
            html.append(f"                <div class='summary-item'>Shell Histories with Suspicious Commands: <strong>{len(data['shell_histories'])}</strong></div>")
        if "scheduled_tasks" in data:
            html.append(f"                <div class='summary-item'>Suspicious Scheduled Tasks: <strong>{len(data['scheduled_tasks'])}</strong></div>")
            
        if "files" in data:
            html.append(f"                <div class='summary-item'>Cleaned Files: <strong>{len(data['files'])}</strong></div>")
        if "histories" in data:
            html.append(f"                <div class='summary-item'>Cleaned Histories: <strong>{len(data['histories'])}</strong></div>")
        if "tasks" in data:
            html.append(f"                <div class='summary-item'>Cleaned Tasks: <strong>{len(data['tasks'])}</strong></div>")
        if "configs" in data:
            html.append(f"                <div class='summary-item'>Restored Configs: <strong>{len(data['configs'])}</strong></div>")
            
        html.append("            </div>")
        html.append("        </div>")
        
        # Footer
        html.append("        <div class='footer'>")
        html.append(f"            <p>Report generated by RedTriage on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        html.append("        </div>")
        
        # Close tags
        html.append("    </div>")
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)
    
    def generate_json_report(self, data: Dict[str, Any]) -> str:
        """Generate a JSON report from the data"""
        
        report_data = {
            "metadata": {
                "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "system_info": f"{platform.node()} - {platform.system()} {platform.release()}"
            },
            "suspicious_items": {
                "files": data.get("suspicious_files", []),
                "configs": data.get("modified_configs", []),
                "histories": data.get("shell_histories", []),
                "tasks": data.get("scheduled_tasks", []),
                "network": data.get("suspicious_network", []),
                "registry": data.get("registry_artifacts", []),
                "containers": data.get("container_artifacts", []),
                "processes": data.get("memory_artifacts", [])
            },
            "cleaned_items": {
                "files": data.get("files", []),
                "configs": data.get("configs", []),
                "histories": data.get("histories", []),
                "tasks": data.get("tasks", []),
                "network": data.get("network", []),
                "registry": data.get("registry", []),
                "containers": data.get("containers", []),
                "processes": data.get("processes", [])
            },
            "summary": {
                "suspicious_files": len(data.get("suspicious_files", [])),
                "modified_configs": len(data.get("modified_configs", [])),
                "shell_histories": len(data.get("shell_histories", [])),
                "scheduled_tasks": len(data.get("scheduled_tasks", [])),
                "suspicious_network": len(data.get("suspicious_network", [])),
                "registry_artifacts": len(data.get("registry_artifacts", [])),
                "container_artifacts": len(data.get("container_artifacts", [])),
                "memory_artifacts": len(data.get("memory_artifacts", [])),
                "cleaned_files": len(data.get("files", [])),
                "restored_configs": len(data.get("configs", [])),
                "cleaned_histories": len(data.get("histories", [])),
                "cleaned_tasks": len(data.get("tasks", [])),
                "terminated_connections": len(data.get("network", [])),
                "cleaned_registry": len(data.get("registry", [])),
                "cleaned_containers": len(data.get("containers", [])),
                "terminated_processes": len(data.get("processes", []))
            }
        }
        
        return json.dumps(report_data, indent=4)
    
    def generate_pdf_report(self, data: Dict[str, Any], output_path: str) -> None:
        """Generate a PDF report from the data and save it to the output path
        
        This requires reportlab to be installed: pip install reportlab
        """
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        except ImportError:
            logger.error("reportlab is required for PDF generation. Please install it: pip install reportlab")
            return
            
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Create custom styles
        title_style = ParagraphStyle(
            'Title',
            parent=styles['Heading1'],
            fontSize=16,
            alignment=1,
            spaceAfter=12
        )
        heading_style = ParagraphStyle(
            'Heading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=6
        )
        normal_style = styles["Normal"]
        
        # Build the document
        elements = []
        
        # Title
        elements.append(Paragraph("Incident Response Report", title_style))
        elements.append(Spacer(1, 12))
        
        # Metadata
        elements.append(Paragraph(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        elements.append(Paragraph(f"System: {platform.node()} - {platform.system()} {platform.release()}", normal_style))
        elements.append(Spacer(1, 12))
        
        # Summary section
        elements.append(Paragraph("Summary", heading_style))
        summary_data = [
            ["Category", "Suspicious", "Cleaned"]
        ]
        
        summary_data.append(["Files", len(data.get("suspicious_files", [])), len(data.get("files", []))])
        summary_data.append(["Configurations", len(data.get("modified_configs", [])), len(data.get("configs", []))])
        summary_data.append(["Shell Histories", len(data.get("shell_histories", [])), len(data.get("histories", []))])
        summary_data.append(["Scheduled Tasks", len(data.get("scheduled_tasks", [])), len(data.get("tasks", []))])
        summary_data.append(["Network", len(data.get("suspicious_network", [])), len(data.get("network", []))])
        summary_data.append(["Registry", len(data.get("registry_artifacts", [])), len(data.get("registry", []))])
        summary_data.append(["Containers", len(data.get("container_artifacts", [])), len(data.get("containers", []))])
        summary_data.append(["Processes", len(data.get("memory_artifacts", [])), len(data.get("processes", []))])
        
        summary_table = Table(summary_data, colWidths=[200, 100, 100])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 12))
        
        # Function to add a section with table data
        def add_section(title, data_list, headers):
            if not data_list:
                return
                
            elements.append(Paragraph(title, heading_style))
            table_data = [headers]
            
            for item in data_list:
                row = []
                for header in headers:
                    key = header.lower().replace(' ', '_')
                    row.append(str(item.get(key, '')))
                table_data.append(row)
                
            table = Table(table_data, colWidths=[400/len(headers)]*len(headers))
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
            elements.append(Spacer(1, 12))
        
        # Add suspicious items sections
        add_section("Suspicious Files", data.get("suspicious_files", []), ["Path", "Type", "Reason"])
        add_section("Modified Configurations", data.get("modified_configs", []), ["Path", "Type", "Modification"])
        add_section("Suspicious Shell Histories", data.get("shell_histories", []), ["User", "Command", "Timestamp"])
        add_section("Suspicious Scheduled Tasks", data.get("scheduled_tasks", []), ["Name", "Command", "Schedule"])
        add_section("Suspicious Network Connections", data.get("suspicious_network", []), ["Source", "Destination", "Port", "Process"])
        add_section("Suspicious Registry Entries", data.get("registry_artifacts", []), ["Path", "Value", "Reason"])
        add_section("Suspicious Container Artifacts", data.get("container_artifacts", []), ["Container", "Image", "Issue"])
        add_section("Suspicious Processes", data.get("memory_artifacts", []), ["PID", "Name", "Command", "User"])
        
        # Add cleaned items sections
        add_section("Cleaned Files", data.get("files", []), ["Path", "Action"])
        add_section("Restored Configurations", data.get("configs", []), ["Path", "Action"])
        add_section("Cleaned Shell Histories", data.get("histories", []), ["User", "Action"])
        add_section("Cleaned Scheduled Tasks", data.get("tasks", []), ["Name", "Action"])
        add_section("Terminated Network Connections", data.get("network", []), ["Connection", "Action"])
        add_section("Cleaned Registry Entries", data.get("registry", []), ["Path", "Action"])
        add_section("Cleaned Containers", data.get("containers", []), ["Container", "Action"])
        add_section("Terminated Processes", data.get("processes", []), ["Process", "Action"])
        
        # Build the PDF
        doc.build(elements)
        
        logger.info(f"PDF report generated and saved to {output_path}")
    
    def generate_report(self, data: Dict[str, Any]) -> None:
        """Generate a report from the data"""
        if self.output_format == "json":
            # JSON format is already handled, just pretty print
            report_content = self.generate_json_report(data)
            output_type = "JSON"
        elif self.output_format == "html":
            # Generate HTML report
            report_content = self.generate_html_report(data)
            output_type = "HTML"
        elif self.output_format == "pdf":
            # Generate PDF report
            self.generate_pdf_report(data, self.output_file)
            return
        else:
            # Default to text format
            report_content = self.generate_txt_report(data)
            output_type = "Text"
        
        # Determine output file
        if not self.output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_file = f"redtriage_report_{timestamp}.{self.output_format}"
        
        # Write to file
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
            
        print(f"\n{output_type} report saved to: {self.output_file}")


def generate_report(output_format: str, output_file: Optional[str] = None, 
                   scan_results_file: Optional[str] = None) -> None:
    """Generate a report from scan or cleanup results"""
    # Determine which file to use
    data = {}
    
    if scan_results_file:
        # Use specified file
        try:
            with open(scan_results_file, 'r') as f:
                data = json.load(f)
            print(f"Loaded data from {scan_results_file}")
        except Exception as e:
            print(f"Error loading data from {scan_results_file}: {e}")
            return
    else:
        # Try to find the most recent scan or cleanup file
        results_files = []
        
        # Look for scan and cleanup files
        for filename in os.listdir('.'):
            if (filename.startswith('redtriage_scan_') or filename.startswith('redtriage_cleanup_')) \
               and filename.endswith('.json'):
                results_files.append(filename)
        
        if not results_files:
            print("No scan or cleanup results found. Run 'scan' or 'clean' command first.")
            return
            
        # Sort by modification time (newest first)
        results_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        latest_file = results_files[0]
        
        try:
            with open(latest_file, 'r') as f:
                data = json.load(f)
            print(f"Loaded data from {latest_file}")
        except Exception as e:
            print(f"Error loading data from {latest_file}: {e}")
            return
    
    # Generate report
    reporter = Reporter(output_format, output_file)
    reporter.generate_report(data) 