#!/usr/bin/env python3
"""
Reporter module for RedTriage
Generates reports of findings and cleanup actions
"""

import os
import json
import platform
from typing import Dict, Any, Optional
from datetime import datetime

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
            
        if "files" in data:
            report.append(f"Cleaned Files: {len(data['files'])}")
        if "histories" in data:
            report.append(f"Cleaned Histories: {len(data['histories'])}")
        if "tasks" in data:
            report.append(f"Cleaned Tasks: {len(data['tasks'])}")
        if "configs" in data:
            report.append(f"Restored Configs: {len(data['configs'])}")
        
        return "\n".join(report)
    
    def generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate an HTML report from the data"""
        html = []
        
        # Start HTML document
        html.append("<!DOCTYPE html>")
        html.append("<html lang='en'>")
        html.append("<head>")
        html.append("  <meta charset='UTF-8'>")
        html.append("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append("  <title>RedTriage Report</title>")
        html.append("  <style>")
        html.append("    body { font-family: Arial, sans-serif; margin: 20px; }")
        html.append("    h1, h2 { color: #d9534f; }")
        html.append("    .container { max-width: 1200px; margin: 0 auto; }")
        html.append("    .section { margin-bottom: 30px; }")
        html.append("    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }")
        html.append("    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }")
        html.append("    th { background-color: #f2f2f2; }")
        html.append("    .summary { background-color: #f9f9f9; padding: 15px; border-radius: 5px; }")
        html.append("    .suspicious { color: #d9534f; }")
        html.append("    .cleaned { color: #5cb85c; }")
        html.append("  </style>")
        html.append("</head>")
        html.append("<body>")
        html.append("  <div class='container'>")
        
        # Header
        html.append("    <div class='section'>")
        html.append("      <h1>RedTriage Report</h1>")
        
        # Metadata
        if "metadata" in data:
            html.append("      <div class='section'>")
            html.append("        <h2>Metadata</h2>")
            html.append("        <table>")
            html.append("          <tr><th>Property</th><th>Value</th></tr>")
            metadata = data["metadata"]
            html.append(f"          <tr><td>Timestamp</td><td>{metadata.get('timestamp', 'Unknown')}</td></tr>")
            html.append(f"          <tr><td>Operating System</td><td>{metadata.get('os', 'Unknown')}</td></tr>")
            html.append(f"          <tr><td>Hostname</td><td>{metadata.get('hostname', 'Unknown')}</td></tr>")
            html.append(f"          <tr><td>Profile</td><td>{metadata.get('profile', 'Unknown')}</td></tr>")
            html.append(f"          <tr><td>Target User</td><td>{metadata.get('target_user', 'None')}</td></tr>")
            html.append(f"          <tr><td>Dry Run</td><td>{metadata.get('dry_run', False)}</td></tr>")
            if "force" in metadata:
                html.append(f"          <tr><td>Force</td><td>{metadata.get('force', False)}</td></tr>")
            html.append("        </table>")
            html.append("      </div>")
        
        # Suspicious Files
        if "suspicious_files" in data and data["suspicious_files"]:
            html.append("      <div class='section'>")
            html.append("        <h2 class='suspicious'>Suspicious Files</h2>")
            html.append("        <table>")
            html.append("          <tr><th>Path</th><th>Size</th><th>Created</th><th>Modified</th><th>Reason</th></tr>")
            
            for file_info in data["suspicious_files"]:
                html.append("          <tr>")
                html.append(f"            <td>{file_info.get('path', 'Unknown')}</td>")
                html.append(f"            <td>{file_info.get('size', 'Unknown')} bytes</td>")
                html.append(f"            <td>{file_info.get('created', 'Unknown')}</td>")
                html.append(f"            <td>{file_info.get('modified', 'Unknown')}</td>")
                html.append(f"            <td>{file_info.get('reason', 'Unknown')}</td>")
                html.append("          </tr>")
                
            html.append("        </table>")
            html.append("      </div>")
        
        # Modified Configs
        if "modified_configs" in data and data["modified_configs"]:
            html.append("      <div class='section'>")
            html.append("        <h2 class='suspicious'>Modified Configuration Files</h2>")
            html.append("        <table>")
            html.append("          <tr><th>Path</th><th>Modified</th></tr>")
            
            for config_info in data["modified_configs"]:
                html.append("          <tr>")
                html.append(f"            <td>{config_info.get('path', 'Unknown')}</td>")
                html.append(f"            <td>{config_info.get('modified', 'Unknown')}</td>")
                html.append("          </tr>")
                
            html.append("        </table>")
            html.append("      </div>")
            
        # Shell Histories
        if "shell_histories" in data and data["shell_histories"]:
            html.append("      <div class='section'>")
            html.append("        <h2 class='suspicious'>Shell Histories with Suspicious Commands</h2>")
            
            for i, history_info in enumerate(data["shell_histories"], 1):
                html.append(f"        <h3>{i}. {history_info.get('path', 'Unknown')}</h3>")
                html.append(f"        <p>Modified: {history_info.get('modified', 'Unknown')}</p>")
                
                if "suspicious_commands" in history_info:
                    html.append("        <table>")
                    html.append("          <tr><th>#</th><th>Command</th></tr>")
                    
                    for j, cmd in enumerate(history_info["suspicious_commands"], 1):
                        html.append("          <tr>")
                        html.append(f"            <td>{j}</td>")
                        html.append(f"            <td>{cmd}</td>")
                        html.append("          </tr>")
                        
                    html.append("        </table>")
                    
            html.append("      </div>")
            
        # Scheduled Tasks
        if "scheduled_tasks" in data and data["scheduled_tasks"]:
            html.append("      <div class='section'>")
            html.append("        <h2 class='suspicious'>Suspicious Scheduled Tasks/Cron Jobs</h2>")
            html.append("        <table>")
            html.append("          <tr><th>Name/Path</th><th>Reason</th><th>Details</th></tr>")
            
            for task_info in data["scheduled_tasks"]:
                html.append("          <tr>")
                
                if "name" in task_info:
                    html.append(f"            <td>{task_info['name']}</td>")
                elif "path" in task_info:
                    html.append(f"            <td>{task_info['path']}</td>")
                else:
                    html.append("            <td>Unknown</td>")
                    
                html.append(f"            <td>{task_info.get('reason', 'Unknown')}</td>")
                
                # Details
                details = "N/A"
                if "content" in task_info:
                    details = task_info["content"]
                    if len(details) > 200:
                        details = details[:200] + "... (truncated)"
                html.append(f"            <td><pre>{details}</pre></td>")
                
                html.append("          </tr>")
                
            html.append("        </table>")
            html.append("      </div>")
            
        # Cleaned items
        if all(k in data for k in ["files", "histories", "tasks", "configs"]):
            html.append("      <div class='section'>")
            html.append("        <h2 class='cleaned'>Cleanup Actions</h2>")
            
            # Files
            html.append("        <h3>Cleaned Files</h3>")
            if data["files"]:
                html.append("        <ul>")
                for file_info in data["files"]:
                    html.append(f"          <li>{file_info.get('path', 'Unknown')}</li>")
                html.append("        </ul>")
            else:
                html.append("        <p>None</p>")
                
            # Histories
            html.append("        <h3>Cleaned Shell Histories</h3>")
            if data["histories"]:
                html.append("        <ul>")
                for history_info in data["histories"]:
                    html.append(f"          <li>{history_info.get('path', 'Unknown')}</li>")
                html.append("        </ul>")
            else:
                html.append("        <p>None</p>")
                
            # Tasks
            html.append("        <h3>Removed Scheduled Tasks/Cron Jobs</h3>")
            if data["tasks"]:
                html.append("        <ul>")
                for task_info in data["tasks"]:
                    if "name" in task_info:
                        html.append(f"          <li>{task_info['name']}</li>")
                    elif "path" in task_info:
                        html.append(f"          <li>{task_info['path']}</li>")
                html.append("        </ul>")
            else:
                html.append("        <p>None</p>")
                
            # Configs
            html.append("        <h3>Restored Configuration Files</h3>")
            if data["configs"]:
                html.append("        <ul>")
                for config_info in data["configs"]:
                    html.append(f"          <li>{config_info.get('path', 'Unknown')}</li>")
                html.append("        </ul>")
            else:
                html.append("        <p>None</p>")
                
            html.append("      </div>")
        
        # Summary
        html.append("      <div class='section summary'>")
        html.append("        <h2>Summary</h2>")
        html.append("        <table>")
        html.append("          <tr><th>Category</th><th>Count</th></tr>")
        
        if "suspicious_files" in data:
            html.append(f"          <tr><td>Suspicious Files</td><td>{len(data['suspicious_files'])}</td></tr>")
        if "modified_configs" in data:
            html.append(f"          <tr><td>Modified Configs</td><td>{len(data['modified_configs'])}</td></tr>")
        if "shell_histories" in data:
            html.append(f"          <tr><td>Shell Histories with Suspicious Commands</td><td>{len(data['shell_histories'])}</td></tr>")
        if "scheduled_tasks" in data:
            html.append(f"          <tr><td>Suspicious Scheduled Tasks</td><td>{len(data['scheduled_tasks'])}</td></tr>")
            
        if "files" in data:
            html.append(f"          <tr><td>Cleaned Files</td><td>{len(data['files'])}</td></tr>")
        if "histories" in data:
            html.append(f"          <tr><td>Cleaned Histories</td><td>{len(data['histories'])}</td></tr>")
        if "tasks" in data:
            html.append(f"          <tr><td>Cleaned Tasks</td><td>{len(data['tasks'])}</td></tr>")
        if "configs" in data:
            html.append(f"          <tr><td>Restored Configs</td><td>{len(data['configs'])}</td></tr>")
            
        html.append("        </table>")
        html.append("      </div>")
        
        # Footer
        html.append("      <div class='section'>")
        html.append(f"        <p>Report generated by RedTriage on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        html.append("      </div>")
        
        # Close tags
        html.append("    </div>")
        html.append("  </div>")
        html.append("</body>")
        html.append("</html>")
        
        return "\n".join(html)
    
    def generate_report(self, data: Dict[str, Any]) -> None:
        """Generate a report from the data"""
        if self.output_format == "json":
            # JSON format is already handled, just pretty print
            report_content = json.dumps(data, indent=2)
            output_type = "JSON"
        elif self.output_format == "html":
            # Generate HTML report
            report_content = self.generate_html_report(data)
            output_type = "HTML"
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