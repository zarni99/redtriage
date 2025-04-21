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
            "network": [],
            "registry": [],
            "containers": [],
            "processes": [],
        }
    
    def prompt_category(self, category: str, items: List[Dict[str, Any]], count: int) -> str:
        """
        First-tier prompt for a category of items.
        Returns: 'y' (yes), 'n' (no), or 's' (selective)
        """
        prompt = f"Found {count} {category}. Clean them? [y/N/s] (Yes/No/Selective) "
        while True:
            response = input(prompt).strip().lower()
            if response in ['y', 'n', 's', '']:
                return 'n' if response == '' else response
            print("Invalid response. Please enter 'y', 'n', or 's'.")
    
    def prompt_selection_mode(self, category: str) -> str:
        """
        Second-tier prompt for selection mode.
        Returns: 'a' (all), 'n' (none), 'i' (interactive), 'r' (range), or 'f' (filter)
        """
        print(f"\nSelect action for {category}:")
        print("[a]ll - Clean all items in this category")
        print("[n]one - Skip all items in this category")
        print("[i]nteractive - Individually select which items to clean")
        print("[r]ange - Specify numeric ranges to clean")
        print("[f]ilter - Filter by pattern")
        
        while True:
            response = input("Selection mode [a/n/i/r/f]: ").strip().lower()
            if response in ['a', 'n', 'i', 'r', 'f']:
                return response
            print("Invalid response. Please enter 'a', 'n', 'i', 'r', or 'f'.")
    
    def select_items_interactive(self, items: List[Dict[str, Any]], item_formatter=None) -> List[int]:
        """
        Present interactive selection interface and return indices of selected items.
        item_formatter: A function to format an item for display
        """
        # Function to format items if no custom formatter provided
        if item_formatter is None:
            def item_formatter(item, idx):
                if "path" in item:
                    return f"{idx+1}. {item['path']}"
                elif "name" in item:
                    return f"{idx+1}. {item['name']}"
                else:
                    return f"{idx+1}. Unknown item"
        
        # Initialize all items as selected
        selected = set(range(len(items)))
        
        while True:
            # Display items with selection status
            print("\nCurrent selection:")
            for i, item in enumerate(items):
                status = "[X]" if i in selected else "[ ]"
                print(f"{status} {item_formatter(item, i)}")
            
            # Display options
            print("\nToggle items using numbers (e.g., 2,4,7-9), [a]ll, [n]one, or [d]one: ")
            response = input().strip().lower()
            
            if response == 'a':
                selected = set(range(len(items)))
            elif response == 'n':
                selected = set()
            elif response == 'd':
                return sorted(list(selected))
            else:
                # Parse ranges and individual numbers
                try:
                    parts = response.split(',')
                    for part in parts:
                        part = part.strip()
                        if '-' in part:
                            start, end = map(int, part.split('-'))
                            # Convert to 0-indexed
                            start = max(0, start - 1)
                            end = min(len(items) - 1, end - 1)
                            # Toggle selection for range
                            for i in range(start, end + 1):
                                if i in selected:
                                    selected.remove(i)
                                else:
                                    selected.add(i)
                        else:
                            idx = int(part) - 1  # Convert to 0-indexed
                            if 0 <= idx < len(items):
                                if idx in selected:
                                    selected.remove(idx)
                                else:
                                    selected.add(idx)
                except ValueError:
                    print("Invalid format. Use numbers, ranges (e.g., 1-5), or commands.")
    
    def select_items_range(self, count: int) -> List[int]:
        """
        Prompt user for a range of items and return indices.
        """
        while True:
            print(f"\nEnter range of items to clean (e.g., 1-5,8,10-15) (1-{count}): ")
            response = input().strip()
            
            try:
                selected = set()
                parts = response.split(',')
                for part in parts:
                    part = part.strip()
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        # Convert to 0-indexed
                        start = max(0, start - 1)
                        end = min(count - 1, end - 1)
                        for i in range(start, end + 1):
                            selected.add(i)
                    else:
                        idx = int(part) - 1  # Convert to 0-indexed
                        if 0 <= idx < count:
                            selected.add(idx)
                
                return sorted(list(selected))
            except ValueError:
                print("Invalid format. Use numbers, ranges (e.g., 1-5), or commands.")
    
    def select_items_filter(self, items: List[Dict[str, Any]]) -> List[int]:
        """
        Filter items by pattern and return indices of matching items.
        """
        import fnmatch
        
        while True:
            print("\nEnter pattern to match (shell wildcards supported): ")
            pattern = input().strip()
            
            try:
                matched = []
                for i, item in enumerate(items):
                    if "path" in item and fnmatch.fnmatch(item["path"].lower(), pattern.lower()):
                        matched.append(i)
                    elif "name" in item and fnmatch.fnmatch(item["name"].lower(), pattern.lower()):
                        matched.append(i)
                
                if matched:
                    print(f"Selected {len(matched)} items matching '{pattern}'")
                    return matched
                else:
                    print(f"No items matched the pattern '{pattern}'. Try again.")
            except Exception as e:
                print(f"Error in pattern matching: {e}. Try again.")
    
    def get_selected_items(self, category: str, items: List[Dict[str, Any]], item_formatter=None) -> List[int]:
        """
        Handle the entire tiered selection process for a category.
        Returns indices of items to clean.
        """
        if self.force:
            # If --force is specified, clean all items
            return list(range(len(items)))
        
        # First-tier prompt: category level
        response = self.prompt_category(category, items, len(items))
        
        if response == 'y':
            # Clean all items
            return list(range(len(items)))
        elif response == 'n':
            # Skip all items
            return []
        elif response == 's':
            # Second-tier prompt: selection mode
            mode = self.prompt_selection_mode(category)
            
            if mode == 'a':
                return list(range(len(items)))
            elif mode == 'n':
                return []
            elif mode == 'i':
                return self.select_items_interactive(items, item_formatter)
            elif mode == 'r':
                return self.select_items_range(len(items))
            elif mode == 'f':
                return self.select_items_filter(items)
        
        # Default is to clean nothing
        return []
    
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
        if not suspicious_files:
            return
            
        print(f"\n[*] Found {len(suspicious_files)} suspicious files...")
        
        # Skip prompting in dry-run mode with force flag
        if self.dry_run and self.force:
            for file_info in suspicious_files:
                print(f"[DRY RUN] Would delete: {file_info.get('path', 'Unknown')}")
                self.cleaned_items["files"].append(file_info)
            return
            
        # Create a formatter function for better display
        def file_formatter(file_info, idx):
            path = file_info.get('path', 'Unknown')
            reason = file_info.get('reason', 'Unknown reason')
            size = file_info.get('size', 'Unknown size')
            return f"{idx+1}. {path} ({size} bytes) - {reason}"
            
        # Get selected items using tiered prompting
        selected_indices = self.get_selected_items("suspicious files", suspicious_files, file_formatter)
        
        if not selected_indices:
            print("No files selected for cleaning.")
            return
            
        print(f"Cleaning {len(selected_indices)} suspicious files...")
        
        # Process selected files
        for idx in selected_indices:
            file_info = suspicious_files[idx]
            if self.clean_suspicious_file(file_info):
                self.cleaned_items["files"].append(file_info)
    
    def clean_shell_histories(self) -> None:
        """Clean shell history files"""
        print("\n[*] Checking shell history files...")
        
        history_files = SHELL_HISTORY_FILES.get(self.os, [])
        existing_histories = []
        
        # First collect all existing history files
        for history_file in history_files:
            history_file = self.expand_path(history_file)
            
            # If targeting specific user, adjust the path
            if self.target_user:
                if self.os == "Windows":
                    history_file = history_file.replace("%USERNAME%", self.target_user)
                else:
                    history_file = history_file.replace("~", f"/home/{self.target_user}")
            
            if os.path.exists(history_file):
                # Get file stats for display
                stats = os.stat(history_file)
                existing_histories.append({
                    "path": history_file,
                    "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                    "size": stats.st_size
                })
        
        if not existing_histories:
            print("No shell history files found.")
            return
            
        print(f"Found {len(existing_histories)} shell history files.")
        
        # Skip prompting in dry-run mode with force flag
        if self.dry_run and self.force:
            for history_info in existing_histories:
                print(f"[DRY RUN] Would clean shell history: {history_info['path']}")
                self.cleaned_items["histories"].append(history_info)
            return
            
        # Create a formatter function for better display
        def history_formatter(history_info, idx):
            path = history_info.get('path', 'Unknown')
            modified = history_info.get('modified', 'Unknown')
            size = history_info.get('size', 0)
            return f"{idx+1}. {path} (Size: {size} bytes, Modified: {modified})"
            
        # Get selected items using tiered prompting
        selected_indices = self.get_selected_items("shell history files", existing_histories, history_formatter)
        
        if not selected_indices:
            print("No shell histories selected for cleaning.")
            return
            
        print(f"Cleaning {len(selected_indices)} shell history files...")
        
        # Process selected histories
        for idx in selected_indices:
            history_file = existing_histories[idx]["path"]
            
            if self.dry_run:
                print(f"[DRY RUN] Would clean shell history: {history_file}")
                self.cleaned_items["histories"].append(existing_histories[idx])
                continue
                
            try:
                # For paranoid profile, securely delete the file
                if self.profile == "paranoid":
                    if self.secure_delete_file(history_file):
                        # Create an empty file
                        with open(history_file, 'w') as f:
                            pass
                        self.cleaned_items["histories"].append(existing_histories[idx])
                else:
                    # For other profiles, just empty the file
                    with open(history_file, 'w') as f:
                        pass
                    
                    print(f"Cleaned shell history: {history_file}")
                    self.cleaned_items["histories"].append(existing_histories[idx])
                
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
                if os.path.dirname(cron_path) in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"]:
                    os.remove(cron_path)
                    print(f"Removed cron file: {cron_path}")
                    return True
                # If it's the main crontab file or a user crontab, we need to edit it
                elif cron_path == "/etc/crontab" or os.path.dirname(cron_path) == "/var/spool/cron/crontabs":
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
        if not tasks:
            return
            
        print(f"\n[*] Found {len(tasks)} suspicious scheduled tasks...")
        
        # Skip prompting in dry-run mode with force flag
        if self.dry_run and self.force:
            for task_info in tasks:
                task_id = task_info.get("name", task_info.get("path", "Unknown task"))
                print(f"[DRY RUN] Would remove task: {task_id}")
                self.cleaned_items["tasks"].append(task_info)
            return
            
        # Create a formatter function for better display
        def task_formatter(task_info, idx):
            if "name" in task_info:
                return f"{idx+1}. {task_info['name']} - {task_info.get('reason', 'Unknown reason')}"
            elif "path" in task_info:
                return f"{idx+1}. {task_info['path']} - {task_info.get('reason', 'Unknown reason')}"
            else:
                return f"{idx+1}. Unknown task"
                
        # Get selected items using tiered prompting
        selected_indices = self.get_selected_items("suspicious scheduled tasks", tasks, task_formatter)
        
        if not selected_indices:
            print("No scheduled tasks selected for cleaning.")
            return
            
        print(f"Cleaning {len(selected_indices)} suspicious scheduled tasks...")
        
        # Process selected tasks
        for idx in selected_indices:
            task_info = tasks[idx]
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
        if not configs:
            return
            
        print(f"\n[*] Found {len(configs)} modified configuration files...")
        
        # Skip prompting in dry-run mode with force flag
        if self.dry_run and self.force:
            for config_info in configs:
                print(f"[DRY RUN] Would restore config file: {config_info.get('path', 'Unknown')}")
                self.cleaned_items["configs"].append(config_info)
            return
            
        # Create a formatter function for better display
        def config_formatter(config_info, idx):
            path = config_info.get('path', 'Unknown')
            modified = config_info.get('modified', 'Unknown date')
            return f"{idx+1}. {path} (Modified: {modified})"
            
        # Get selected items using tiered prompting
        selected_indices = self.get_selected_items("modified configuration files", configs, config_formatter)
        
        if not selected_indices:
            print("No configuration files selected for restoration.")
            return
            
        print(f"Restoring {len(selected_indices)} modified configuration files...")
        
        # Process selected configs
        for idx in selected_indices:
            config_info = configs[idx]
            if self.restore_config_file(config_info):
                self.cleaned_items["configs"].append(config_info)
    
    def clean_suspicious_network(self, network_items: List[Dict[str, Any]]) -> None:
        """Clean suspicious network connections"""
        if not network_items:
            return
            
        print(f"\n[*] Found {len(network_items)} suspicious network connections...")
        
        # Skip prompting in dry-run mode with force flag
        if self.dry_run and self.force:
            for item in network_items:
                print(f"[DRY RUN] Would terminate process: {item.get('pid', 'Unknown')} ({item.get('process', 'Unknown')})")
                self.cleaned_items["network"].append(item)
            return
            
        # Create a formatter function for better display
        def network_formatter(item, idx):
            pid = item.get('pid', 'Unknown')
            process = item.get('process', 'Unknown')
            protocol = item.get('protocol', 'Unknown')
            local = item.get('local_address', 'Unknown')
            remote = item.get('remote_address', 'Unknown')
            reason = item.get('reason', 'Unknown reason')
            return f"{idx+1}. {process} (PID: {pid}) - {protocol} {local} → {remote} - {reason}"
            
        # Get selected items using tiered prompting
        selected_indices = self.get_selected_items("suspicious network connections", network_items, network_formatter)
        
        if not selected_indices:
            print("No network connections selected for termination.")
            return
            
        print(f"Terminating {len(selected_indices)} suspicious network connections...")
        
        # Process selected network connections
        for idx in selected_indices:
            item = network_items[idx]
            try:
                # Terminate the process
                if self.dry_run:
                    print(f"[DRY RUN] Would terminate process: {item['pid']}")
                    self.cleaned_items["network"].append(item)
                    continue
                    
                if self.os == "Windows":
                    result = subprocess.run(
                        ["taskkill", "/F", "/PID", item["pid"]],
                        capture_output=True, text=True, check=False
                    )
                else:
                    result = subprocess.run(
                        ["kill", "-9", item["pid"]],
                        capture_output=True, text=True, check=False
                    )
                
                if result.returncode == 0:
                    print(f"Terminated process: {item['pid']}")
                    self.cleaned_items["network"].append(item)
                else:
                    print(f"Failed to terminate process {item['pid']}: {result.stderr}")
            except Exception as e:
                print(f"Error terminating process {item['pid']}: {e}")
    
    def clean_registry_artifacts(self, registry_items: List[Dict[str, Any]]) -> None:
        """Clean suspicious registry entries (Windows only)"""
        if self.os != "Windows" or not registry_items:
            return
            
        print(f"\n[*] Found {len(registry_items)} suspicious registry entries...")
        
        # Skip prompting in dry-run mode with force flag
        if self.dry_run and self.force:
            for item in registry_items:
                key = item["key"]
                value_name = item["value_name"]
                print(f"[DRY RUN] Would delete registry value: {key}\\{value_name}")
                self.cleaned_items["registry"].append(item)
            return
            
        # Create a formatter function for better display
        def registry_formatter(item, idx):
            key = item.get('key', 'Unknown')
            value_name = item.get('value_name', 'Unknown')
            reason = item.get('reason', 'Unknown reason')
            return f"{idx+1}. {key}\\{value_name} - {reason}"
            
        # Get selected items using tiered prompting
        selected_indices = self.get_selected_items("suspicious registry entries", registry_items, registry_formatter)
        
        if not selected_indices:
            print("No registry entries selected for cleaning.")
            return
            
        print(f"Cleaning {len(selected_indices)} suspicious registry entries...")
        
        # Process selected registry entries
        for idx in selected_indices:
            item = registry_items[idx]
            key = item["key"]
            value_name = item["value_name"]
            
            try:
                # Delete the registry value
                if self.dry_run:
                    print(f"[DRY RUN] Would delete registry value: {key}\\{value_name}")
                    self.cleaned_items["registry"].append(item)
                    continue
                    
                result = subprocess.run(
                    ["reg", "delete", key, "/v", value_name, "/f"],
                    capture_output=True, text=True, check=False
                )
                
                if result.returncode == 0:
                    print(f"Deleted registry value: {key}\\{value_name}")
                    self.cleaned_items["registry"].append(item)
                else:
                    print(f"Failed to delete registry value {key}\\{value_name}: {result.stderr}")
            except Exception as e:
                print(f"Error deleting registry value {key}\\{value_name}: {e}")
    
    def clean_container_artifacts(self, container_items: List[Dict[str, Any]]) -> None:
        """Clean suspicious container artifacts"""
        if not container_items:
            return
            
        print(f"\n[*] Found {len(container_items)} suspicious container artifacts...")
        
        # Skip prompting in dry-run mode with force flag
        if self.dry_run and self.force:
            for item in container_items:
                if "container_id" in item:
                    name = item.get("name", "Unknown")
                    container_id = item.get("container_id", "Unknown")
                    print(f"[DRY RUN] Would stop and remove container: {name} ({container_id})")
                else:
                    print(f"[DRY RUN] Would remove container config: {item.get('path', 'Unknown')}")
                self.cleaned_items["containers"].append(item)
            return
            
        # Create a formatter function for better display
        def container_formatter(item, idx):
            if "container_id" in item:
                name = item.get("name", "Unknown")
                container_id = item.get("container_id", "Unknown")
                image = item.get("image", "Unknown")
                reason = item.get("reason", "Unknown reason")
                return f"{idx+1}. Container: {name} ({container_id}) - Image: {image} - {reason}"
            else:
                path = item.get("path", "Unknown")
                type_info = item.get("type", "Unknown type")
                reason = item.get("reason", "Unknown reason")
                return f"{idx+1}. Config: {path} - Type: {type_info} - {reason}"
            
        # Get selected items using tiered prompting
        selected_indices = self.get_selected_items("suspicious container artifacts", container_items, container_formatter)
        
        if not selected_indices:
            print("No container artifacts selected for cleaning.")
            return
            
        print(f"Cleaning {len(selected_indices)} suspicious container artifacts...")
        
        # Process selected container artifacts
        for idx in selected_indices:
            item = container_items[idx]
            if "container_id" in item:
                # This is a container
                container_id = item["container_id"]
                name = item.get("name", "Unknown")
                
                if self.dry_run:
                    print(f"[DRY RUN] Would stop and remove container: {name} ({container_id})")
                    self.cleaned_items["containers"].append(item)
                    continue
                    
                try:
                    # Stop and remove the container
                    subprocess.run(
                        ["docker", "stop", container_id],
                        capture_output=True, text=True, check=False
                    )
                    
                    result = subprocess.run(
                        ["docker", "rm", container_id],
                        capture_output=True, text=True, check=False
                    )
                    
                    if result.returncode == 0:
                        print(f"Removed container: {name} ({container_id})")
                        self.cleaned_items["containers"].append(item)
                    else:
                        print(f"Failed to remove container {name}: {result.stderr}")
                except Exception as e:
                    print(f"Error removing container {name}: {e}")
            
            elif "path" in item and "type" in item and item["type"] == "config_file":
                # This is a container configuration file
                filepath = item["path"]
                
                # Use the secure delete method from files
                if self.secure_delete_file(filepath):
                    self.cleaned_items["containers"].append(item)
    
    def clean_memory_artifacts(self, memory_items: List[Dict[str, Any]]) -> None:
        """Clean suspicious processes from memory"""
        if not memory_items:
            return
            
        print(f"\n[*] Found {len(memory_items)} suspicious processes...")
        
        # Skip prompting in dry-run mode with force flag
        if self.dry_run and self.force:
            for item in memory_items:
                pid = item["pid"]
                process_name = item["process_name"]
                print(f"[DRY RUN] Would terminate process: {process_name} (PID: {pid})")
                self.cleaned_items["processes"].append(item)
            return
            
        # Create a formatter function for better display
        def process_formatter(item, idx):
            pid = item.get('pid', 'Unknown')
            process_name = item.get('process_name', 'Unknown')
            cmdline = item.get('command_line', '')
            reason = item.get('reason', 'Unknown reason')
            
            # Truncate command line if too long
            if len(cmdline) > 50:
                cmdline = cmdline[:47] + "..."
                
            return f"{idx+1}. {process_name} (PID: {pid}) - {cmdline} - {reason}"
            
        # Get selected items using tiered prompting
        selected_indices = self.get_selected_items("suspicious processes", memory_items, process_formatter)
        
        if not selected_indices:
            print("No processes selected for termination.")
            return
            
        print(f"Terminating {len(selected_indices)} suspicious processes...")
        
        # Process selected processes
        for idx in selected_indices:
            item = memory_items[idx]
            pid = item["pid"]
            process_name = item["process_name"]
            
            try:
                # Terminate the process
                if self.dry_run:
                    print(f"[DRY RUN] Would terminate process: {process_name} (PID: {pid})")
                    self.cleaned_items["processes"].append(item)
                    continue
                    
                if self.os == "Windows":
                    result = subprocess.run(
                        ["taskkill", "/F", "/PID", pid],
                        capture_output=True, text=True, check=False
                    )
                else:
                    result = subprocess.run(
                        ["kill", "-9", pid],
                        capture_output=True, text=True, check=False
                    )
                
                if result.returncode == 0:
                    print(f"Terminated process: {process_name} (PID: {pid})")
                    self.cleaned_items["processes"].append(item)
                else:
                    print(f"Failed to terminate process {process_name}: {result.stderr}")
            except Exception as e:
                print(f"Error terminating process {process_name}: {e}")
    
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
            
        # Clean suspicious network connections
        if "suspicious_network" in scan_results and scan_results["suspicious_network"]:
            self.clean_suspicious_network(scan_results["suspicious_network"])
            
        # Clean suspicious registry entries (Windows)
        if "registry_artifacts" in scan_results and scan_results["registry_artifacts"]:
            self.clean_registry_artifacts(scan_results["registry_artifacts"])
            
        # Clean container artifacts
        if "container_artifacts" in scan_results and scan_results["container_artifacts"]:
            self.clean_container_artifacts(scan_results["container_artifacts"])
            
        # Clean memory artifacts and processes
        if "memory_artifacts" in scan_results and scan_results["memory_artifacts"]:
            self.clean_memory_artifacts(scan_results["memory_artifacts"])
        
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
    print(f"Terminated network connections: {len(cleaner.cleaned_items['network'])}")
    print(f"Cleaned registry entries: {len(cleaner.cleaned_items['registry'])}")
    print(f"Cleaned container artifacts: {len(cleaner.cleaned_items['containers'])}")
    print(f"Terminated processes: {len(cleaner.cleaned_items['processes'])}")
    
    return cleaned_items 