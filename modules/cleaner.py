#!/usr/bin/env python3
"""
Cleaner module for RedTriage
Handles cleanup of detected red team artifacts
"""

import os
import sys
import shutil
import platform
import re
import json
import subprocess
import tempfile
from typing import List, Dict, Any, Optional
from datetime import datetime

# Import scanner constants to reuse them
from modules.scanner import (
    COMMON_TOOL_NAMES,
    SHELL_HISTORY_FILES,
)

class Cleaner:
    def __init__(self, dry_run: bool, force: bool, profile: str, target_user: Optional[str] = None):
        self.dry_run = dry_run
        self.force = force
        self.profile = profile
        self.target_user = target_user
        self.os = platform.system()
        self.cleaned_items = {
            "files": [],
            "histories": [],
            "tasks": [],
            "configs": [],
        }
    
    def expand_path(self, path: str) -> str:
        """Expand user and environment variables in a path"""
        expanded = os.path.expanduser(path)
        expanded = os.path.expandvars(expanded)
        return expanded
    
    def secure_delete_file(self, filepath: str) -> bool:
        """Securely delete a file by overwriting it before deletion"""
        if self.dry_run:
            print(f"[DRY RUN] Would securely delete: {filepath}")
            return True
            
        try:
            # Get file size
            file_size = os.path.getsize(filepath)
            
            # For small files, do multiple overwrites
            if file_size < 10 * 1024 * 1024:  # Less than 10MB
                # Open file for overwriting
                with open(filepath, "wb") as f:
                    # First pass: zeros
                    f.write(b'\x00' * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    # Second pass: ones
                    f.seek(0)
                    f.write(b'\xFF' * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    # Third pass: random data
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            else:
                # For larger files, do a single pass of zeros to save time
                with open(filepath, "wb") as f:
                    # Use a buffer to avoid loading the entire file into memory
                    chunk_size = 1024 * 1024  # 1MB chunks
                    for _ in range(0, file_size, chunk_size):
                        write_size = min(chunk_size, file_size - f.tell())
                        f.write(b'\x00' * write_size)
                        
            # Delete the file
            os.remove(filepath)
            print(f"Securely deleted: {filepath}")
            return True
            
        except Exception as e:
            print(f"Error securely deleting {filepath}: {e}")
            return False
    
    def clean_suspicious_file(self, file_info: Dict[str, Any]) -> bool:
        """Clean a suspicious file"""
        filepath = file_info["path"]
        
        if not os.path.exists(filepath):
            print(f"File no longer exists: {filepath}")
            return False
            
        if not self.force:
            # Prompt user if not in force mode
            prompt = f"Delete suspicious file {filepath}? [y/N] "
            response = input(prompt).strip().lower()
            if response != 'y':
                print(f"Skipping file: {filepath}")
                return False
        
        return self.secure_delete_file(filepath)
        
    def clean_all_suspicious_files(self, suspicious_files: List[Dict[str, Any]]) -> None:
        """Clean all suspicious files in the list"""
        print(f"\n[*] Cleaning {len(suspicious_files)} suspicious files...")
        
        for file_info in suspicious_files:
            if self.clean_suspicious_file(file_info):
                self.cleaned_items["files"].append(file_info)
    
    def clean_shell_histories(self) -> None:
        """Clean shell history files"""
        print("\n[*] Cleaning shell history files...")
        
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
                
            if not self.force:
                prompt = f"Clean shell history file {history_file}? [y/N] "
                response = input(prompt).strip().lower()
                if response != 'y':
                    print(f"Skipping history file: {history_file}")
                    continue
            
            if self.dry_run:
                print(f"[DRY RUN] Would clean shell history: {history_file}")
                self.cleaned_items["histories"].append({"path": history_file})
                continue
                
            try:
                # For paranoid profile, securely delete the file
                if self.profile == "paranoid":
                    if self.secure_delete_file(history_file):
                        # Create an empty file
                        with open(history_file, 'w') as f:
                            pass
                        self.cleaned_items["histories"].append({"path": history_file})
                else:
                    # For other profiles, just empty the file
                    with open(history_file, 'w') as f:
                        pass
                    
                    print(f"Cleaned shell history: {history_file}")
                    self.cleaned_items["histories"].append({"path": history_file})
                
                # If Linux/Darwin and not in dry run, also clear current shell history
                if (self.os == "Linux" or self.os == "Darwin") and not self.dry_run:
                    # Try to use the history command to clear history
                    try:
                        subprocess.run("history -c", shell=True, check=False)
                    except Exception:
                        pass
            except Exception as e:
                print(f"Error cleaning shell history {history_file}: {e}")
    
    def remove_scheduled_task(self, task_info: Dict[str, Any]) -> bool:
        """Remove a suspicious scheduled task or cron job"""
        if self.os == "Windows":
            if "name" not in task_info:
                return False
                
            task_name = task_info["name"]
            
            if self.dry_run:
                print(f"[DRY RUN] Would remove scheduled task: {task_name}")
                return True
                
            try:
                result = subprocess.run(
                    ["schtasks", "/delete", "/tn", task_name, "/f"],
                    capture_output=True, text=True, check=False
                )
                
                if "SUCCESS" in result.stdout or result.returncode == 0:
                    print(f"Removed scheduled task: {task_name}")
                    return True
                else:
                    print(f"Failed to remove scheduled task {task_name}: {result.stderr}")
                    return False
            except Exception as e:
                print(f"Error removing scheduled task {task_name}: {e}")
                return False
        
        elif self.os == "Linux" or self.os == "Darwin":
            if "path" not in task_info:
                return False
                
            cron_path = task_info["path"]
            
            if self.dry_run:
                print(f"[DRY RUN] Would remove cron job in: {cron_path}")
                return True
                
            try:
                # If it's a file in cron.d or another cron directory, delete the file
                if os.path.dirname(cron_path) in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly"]:
                    os.remove(cron_path)
                    print(f"Removed cron file: {cron_path}")
                    return True
                # If it's the main crontab file, we need to edit it
                elif cron_path in ["/etc/crontab", "/var/spool/cron/crontabs/" + self.target_user]:
                    # Read the content first
                    with open(cron_path, 'r') as f:
                        content = f.readlines()
                    
                    # Find the suspicious entry
                    suspicious_content = task_info.get("content", "")
                    suspicious_lines = suspicious_content.splitlines()
                    
                    # Create a new list without suspicious lines
                    clean_content = []
                    for line in content:
                        if not any(susp_line.strip() in line for susp_line in suspicious_lines if susp_line.strip()):
                            clean_content.append(line)
                    
                    # Write back the clean content
                    with open(cron_path, 'w') as f:
                        f.writelines(clean_content)
                    
                    print(f"Cleaned suspicious entries from cron file: {cron_path}")
                    return True
            except Exception as e:
                print(f"Error removing cron job {cron_path}: {e}")
                return False
        
        return False
    
    def clean_all_scheduled_tasks(self, tasks: List[Dict[str, Any]]) -> None:
        """Clean all suspicious scheduled tasks"""
        print(f"\n[*] Cleaning {len(tasks)} suspicious scheduled tasks...")
        
        for task_info in tasks:
            if not self.force:
                task_id = task_info.get("name", task_info.get("path", "Unknown task"))
                prompt = f"Remove scheduled task {task_id}? [y/N] "
                response = input(prompt).strip().lower()
                if response != 'y':
                    print(f"Skipping task: {task_id}")
                    continue
            
            if self.remove_scheduled_task(task_info):
                self.cleaned_items["tasks"].append(task_info)
    
    def restore_config_file(self, config_info: Dict[str, Any]) -> bool:
        """Restore a modified config file from backup or default"""
        config_path = config_info["path"]
        
        if not os.path.exists(config_path):
            print(f"Config file no longer exists: {config_path}")
            return False
            
        if not self.force:
            prompt = f"Restore config file {config_path}? [y/N] "
            response = input(prompt).strip().lower()
            if response != 'y':
                print(f"Skipping config file: {config_path}")
                return False
        
        if self.dry_run:
            print(f"[DRY RUN] Would restore config file: {config_path}")
            return True
            
        try:
            # Check for .bak version of the file
            backup_path = config_path + ".bak"
            if os.path.exists(backup_path):
                # Copy backup to original location
                shutil.copy2(backup_path, config_path)
                print(f"Restored config from backup: {config_path}")
                return True
            else:
                # For certain known config files, we could restore defaults
                # But for now, just make a backup of the suspicious version
                backup_path = config_path + f".suspicious_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(config_path, backup_path)
                print(f"Backed up suspicious config to: {backup_path}")
                print(f"Manual review required for {config_path}")
                return True
        except Exception as e:
            print(f"Error restoring config file {config_path}: {e}")
            return False
    
    def clean_all_config_files(self, configs: List[Dict[str, Any]]) -> None:
        """Clean all modified config files"""
        print(f"\n[*] Cleaning {len(configs)} modified config files...")
        
        for config_info in configs:
            if self.restore_config_file(config_info):
                self.cleaned_items["configs"].append(config_info)
    
    def clean_system(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Clean the system based on scan results"""
        print(f"Starting RedTriage cleanup (profile: {self.profile}, dry-run: {self.dry_run}, force: {self.force})")
        
        if self.dry_run:
            print("\n⚠️  DRY RUN MODE - No actual changes will be made")
        
        # Clean suspicious files
        if "suspicious_files" in scan_results and scan_results["suspicious_files"]:
            self.clean_all_suspicious_files(scan_results["suspicious_files"])
        
        # Clean shell histories
        self.clean_shell_histories()
        
        # Clean scheduled tasks
        if "scheduled_tasks" in scan_results and scan_results["scheduled_tasks"]:
            self.clean_all_scheduled_tasks(scan_results["scheduled_tasks"])
        
        # Clean modified config files
        if "modified_configs" in scan_results and scan_results["modified_configs"]:
            self.clean_all_config_files(scan_results["modified_configs"])
        
        # Add cleanup metadata
        self.cleaned_items["metadata"] = {
            "timestamp": datetime.now().isoformat(),
            "os": self.os,
            "hostname": platform.node(),
            "profile": self.profile,
            "target_user": self.target_user,
            "dry_run": self.dry_run,
            "force": self.force
        }
        
        return self.cleaned_items


def clean_artifacts(dry_run: bool, force: bool, profile: str, target_user: Optional[str] = None,
                   specific_artifacts: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run the cleanup functionality"""
    # First check if we need to load scan results
    scan_results = {}
    scan_files = [f for f in os.listdir('.') if f.startswith('redtriage_scan_') and f.endswith('.json')]
    
    # Sort by modification time (newest first)
    scan_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    
    if scan_files:
        latest_scan = scan_files[0]
        try:
            with open(latest_scan, 'r') as f:
                scan_results = json.load(f)
            print(f"Loaded scan results from {latest_scan}")
        except Exception as e:
            print(f"Error loading scan results: {e}")
            scan_results = {}
    
    # If no scan results, prompt to run a scan first
    if not scan_results:
        if not force:
            prompt = "No scan results found. Run a scan first? [Y/n] "
            response = input(prompt).strip().lower()
            if response != 'n':
                from modules.scanner import scan_artifacts
                scan_results = scan_artifacts(dry_run, profile, target_user)
        else:
            print("No scan results found and --force specified. Proceeding with minimal cleaning.")
    
    # Run the cleaner
    cleaner = Cleaner(dry_run, force, profile, target_user)
    cleaned_items = cleaner.clean_system(scan_results)
    
    # Save cleanup results to a file
    output_file = f"redtriage_cleanup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(cleaned_items, f, indent=2)
    
    print(f"\nCleanup complete! Results saved to {output_file}")
    
    # Print summary
    print("\n=== Cleanup Summary ===")
    print(f"Cleaned files: {len(cleaner.cleaned_items['files'])}")
    print(f"Cleaned histories: {len(cleaner.cleaned_items['histories'])}")
    print(f"Cleaned scheduled tasks: {len(cleaner.cleaned_items['tasks'])}")
    print(f"Restored config files: {len(cleaner.cleaned_items['configs'])}")
    
    return cleaned_items 