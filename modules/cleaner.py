"""
Cleaner module for RedTriage
Handles cleanup of detected red team artifacts
Created by: Zarni (Neo)
"""

import os
import sys
import shutil
import platform
import re
import json
import subprocess
import tempfile
import glob
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from modules.scanner import (
    COMMON_TOOL_NAMES,
    SHELL_HISTORY_FILES,
)

class Cleaner:
    def __init__(self, dry_run: bool, force: bool, profile: str, target_user: Optional[str] = None, 
                 date_filter: Optional[Dict[str, datetime]] = None, batch_size: int = 15):
        self.dry_run = dry_run
        self.force = force
        self.profile = profile
        self.target_user = target_user
        self.os = platform.system()
        self.date_filter = date_filter or {}
        self.batch_size = batch_size
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
        print("[d]ate - Filter by date")
        
        while True:
            response = input("Selection mode [a/n/i/r/f/d]: ").strip().lower()
            if response in ['a', 'n', 'i', 'r', 'f', 'd']:
                return response
            print("Invalid response. Please enter 'a', 'n', 'i', 'r', 'f', or 'd'.")
    
    def select_items_interactive(self, items: List[Dict[str, Any]], item_formatter=None) -> List[int]:
        """
        Present interactive selection interface and return indices of selected items.
        item_formatter: A function to format an item for display
        """
        
        if item_formatter is None:
            def item_formatter(item, idx):
                if "path" in item:
                    return f"{idx+1}. {item['path']}"
                elif "name" in item:
                    return f"{idx+1}. {item['name']}"
                else:
                    return f"{idx+1}. Unknown item"
        
        
        selected = set(range(len(items)))
        
        # Process items in batches
        total_items = len(items)
        current_page = 0
        pages = (total_items + self.batch_size - 1) // self.batch_size
        
        while True:
            print(f"\n--- Showing items {current_page * self.batch_size + 1}-{min((current_page + 1) * self.batch_size, total_items)} of {total_items} ---")
            
            # Display current batch
            start_idx = current_page * self.batch_size
            end_idx = min((current_page + 1) * self.batch_size, total_items)
            
            for i in range(start_idx, end_idx):
                status = "[X]" if i in selected else "[ ]"
                print(f"{status} {item_formatter(items[i], i)}")
            
            print("\nToggle items using numbers (e.g., 2,4,7-9), [a]ll, [n]one")
            print("[p]rev page, [N]ext page, [d]one: ")
            response = input().strip().lower()
            
            if response == 'a':
                selected = set(range(len(items)))
            elif response == 'n':
                selected = set()
            elif response == 'd':
                return sorted(list(selected))
            elif response == 'p':
                current_page = max(0, current_page - 1)
                continue
            elif response == '' or response == 'n' or response == 'next':
                current_page = min(pages - 1, current_page + 1)
                continue
            else:
                try:
                    parts = response.split(',')
                    for part in parts:
                        part = part.strip()
                        if '-' in part:
                            start, end = map(int, part.split('-'))
                            start = max(0, start - 1)
                            end = min(len(items) - 1, end - 1)
                            for i in range(start, end + 1):
                                if i in selected:
                                    selected.remove(i)
                                else:
                                    selected.add(i)
                        else:
                            idx = int(part) - 1
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
                        
                        start = max(0, start - 1)
                        end = min(count - 1, end - 1)
                        for i in range(start, end + 1):
                            selected.add(i)
                    else:
                        idx = int(part) - 1  
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
    
    def select_items_date(self, items: List[Dict[str, Any]]) -> List[int]:
        """
        Filter items by date and return indices of matching items.
        """
        from datetime import datetime, timedelta
        
        print("\nDate filter options:")
        print("1. Last day")
        print("2. Last 3 days")
        print("3. Last week")
        print("4. Last month")
        print("5. Custom date range")
        
        while True:
            choice = input("Enter your choice (1-5): ").strip()
            
            try:
                now = datetime.now()
                
                if choice == '1':
                    after_date = now - timedelta(days=1)
                    date_description = "the last day"
                elif choice == '2':
                    after_date = now - timedelta(days=3)
                    date_description = "the last 3 days"
                elif choice == '3':
                    after_date = now - timedelta(days=7)
                    date_description = "the last week"
                elif choice == '4':
                    after_date = now - timedelta(days=30)
                    date_description = "the last month"
                elif choice == '5':
                    # Custom date range
                    while True:
                        try:
                            date_str = input("Enter date in YYYY-MM-DD format: ").strip()
                            after_date = datetime.strptime(date_str, "%Y-%m-%d")
                            date_description = f"after {date_str}"
                            break
                        except ValueError:
                            print("Invalid date format. Please use YYYY-MM-DD.")
                else:
                    print("Invalid choice. Please enter a number between 1 and 5.")
                    continue
                
                # Find files modified after the selected date
                matched = []
                for i, item in enumerate(items):
                    if "mtime" in item:
                        file_date = datetime.fromtimestamp(item["mtime"])
                        if file_date >= after_date:
                            matched.append(i)
                    elif "timestamp" in item:
                        file_date = datetime.fromtimestamp(item["timestamp"])
                        if file_date >= after_date:
                            matched.append(i)
                
                if matched:
                    print(f"Selected {len(matched)} items from {date_description}")
                    return matched
                else:
                    print(f"No items found from {date_description}. Try a different filter.")
            except Exception as e:
                print(f"Error in date filtering: {e}")
    
    def group_similar_items(self, items: List[Dict[str, Any]]) -> Dict[str, List[int]]:
        """
        Group similar items together to simplify selection.
        Returns a dictionary of group names mapped to item indices.
        """
        groups = {}
        
        # Group files by directory
        for i, item in enumerate(items):
            if "path" in item:
                path = item["path"]
                dirname = os.path.dirname(path)
                
                # Special cases for known patterns
                if "Firefox" in path and "datareporting" in path:
                    group = "Firefox Data Reporting Files"
                elif "Firefox" in path and "extension-preferences" in path:
                    group = "Firefox Extension Preferences"
                elif "Microsoft\\Windows\\Recent" in path:
                    group = "Windows Recent Files"
                elif "Microsoft\\Windows" in path and "Installation" in path:
                    group = "Windows Installation Files"
                else:
                    group = f"Files in {dirname}"
                
                if group not in groups:
                    groups[group] = []
                groups[group].append(i)
        
        return groups
    
    def get_selected_items(self, category: str, items: List[Dict[str, Any]], item_formatter=None) -> List[int]:
        """
        Handle the entire tiered selection process for a category.
        Returns indices of items to clean.
        """
        if self.force:
            return list(range(len(items)))
        
        # Check if we need to filter by date from the command line options
        if self.date_filter and items:
            filtered_indices = []
            for i, item in enumerate(items):
                if "mtime" in item:
                    file_time = datetime.fromtimestamp(item["mtime"])
                    if 'after' in self.date_filter and file_time < self.date_filter['after']:
                        continue
                    if 'before' in self.date_filter and file_time > self.date_filter['before']:
                        continue
                    filtered_indices.append(i)
            
            if filtered_indices:
                items_desc = f"{category} (date-filtered: {len(filtered_indices)} of {len(items)})"
            else:
                print(f"No {category} match the date filter criteria.")
                return []
        else:
            filtered_indices = list(range(len(items)))
            items_desc = category
        
        # If we have a lot of items, suggest grouping them
        if len(filtered_indices) > self.batch_size:
            print(f"\nFound {len(filtered_indices)} {category}. Would you like to:")
            print("1. View all items individually")
            print("2. Group similar items together")
            print("3. Apply date filter")
            print("4. Skip all")
            
            choice = input("Enter your choice (1-4): ").strip()
            
            if choice == '2':
                # Create a subset of the items for grouping
                subset = [items[i] for i in filtered_indices]
                groups = self.group_similar_items(subset)
                
                if groups:
                    print(f"\nIdentified {len(groups)} groups of similar items:")
                    for i, (group_name, indices) in enumerate(groups.items()):
                        print(f"{i+1}. {group_name} ({len(indices)} items)")
                    
                    group_choice = input("\nEnter group numbers to clean (e.g., 1,3-5) or 'a' for all: ").strip().lower()
                    
                    if group_choice == 'a':
                        return filtered_indices
                    
                    try:
                        selected_groups = set()
                        parts = group_choice.split(',')
                        for part in parts:
                            part = part.strip()
                            if '-' in part:
                                start, end = map(int, part.split('-'))
                                for i in range(start-1, end):
                                    if i < len(groups):
                                        selected_groups.add(i)
                            else:
                                idx = int(part) - 1
                                if 0 <= idx < len(groups):
                                    selected_groups.add(idx)
                        
                        selected_indices = []
                        for i, (_, indices) in enumerate(groups.items()):
                            if i in selected_groups:
                                # Map back to original indices
                                for idx in indices:
                                    selected_indices.append(filtered_indices[idx])
                        
                        return selected_indices
                    except ValueError:
                        print("Invalid input. Proceeding with individual selection.")
                else:
                    print("Could not identify groups. Proceeding with individual selection.")
            elif choice == '3':
                subset = [items[i] for i in filtered_indices]
                date_indices = self.select_items_date(subset)
                # Map back to original indices
                return [filtered_indices[i] for i in date_indices]
            elif choice == '4':
                return []
        
        # First-tier prompt: category level
        response = self.prompt_category(items_desc, [items[i] for i in filtered_indices], len(filtered_indices))
        
        if response == 'y':
            # Clean all items
            return filtered_indices
        elif response == 'n':
            # Skip all items
            return []
        elif response == 's':
            # Second-tier prompt: selection mode
            mode = self.prompt_selection_mode(category)
            
            subset = [items[i] for i in filtered_indices]
            
            if mode == 'a':
                return filtered_indices
            elif mode == 'n':
                return []
            elif mode == 'i':
                indices = self.select_items_interactive(subset, item_formatter)
                # Map back to original indices
                return [filtered_indices[i] for i in indices]
            elif mode == 'r':
                indices = self.select_items_range(len(subset))
                # Map back to original indices
                return [filtered_indices[i] for i in indices]
            elif mode == 'f':
                indices = self.select_items_filter(subset)
                # Map back to original indices
                return [filtered_indices[i] for i in indices]
            elif mode == 'd':
                indices = self.select_items_date(subset)
                # Map back to original indices
                return [filtered_indices[i] for i in indices]
        
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
            
            file_size = os.path.getsize(filepath)
            
            
            if file_size < 10 * 1024 * 1024:  
                
                with open(filepath, "wb") as f:
                    
                    f.write(b'\x00' * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    
                    f.seek(0)
                    f.write(b'\xFF' * file_size)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            else:
                
                with open(filepath, "wb") as f:
                    
                    chunk_size = 1024 * 1024  
                    for _ in range(0, file_size, chunk_size):
                        write_size = min(chunk_size, file_size - f.tell())
                        f.write(b'\x00' * write_size)
                        
            
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
        
        
        if self.dry_run and self.force:
            for file_info in suspicious_files:
                print(f"[DRY RUN] Would delete: {file_info.get('path', 'Unknown')}")
                self.cleaned_items["files"].append(file_info)
            return
            
        
        def file_formatter(file_info, idx):
            path = file_info.get('path', 'Unknown')
            reason = file_info.get('reason', 'Unknown reason')
            size = file_info.get('size', 'Unknown size')
            return f"{idx+1}. {path} ({size} bytes) - {reason}"
            
        
        selected_indices = self.get_selected_items("suspicious files", suspicious_files, file_formatter)
        
        if not selected_indices:
            print("No files selected for cleaning.")
            return
            
        print(f"Cleaning {len(selected_indices)} suspicious files...")
        
        
        for idx in selected_indices:
            file_info = suspicious_files[idx]
            if self.clean_suspicious_file(file_info):
                self.cleaned_items["files"].append(file_info)
    
    def clean_shell_histories(self) -> None:
        """Clean shell history files"""
        print("\n[*] Checking shell history files...")
        
        history_files = SHELL_HISTORY_FILES.get(self.os, [])
        existing_histories = []
        
        
        for history_file in history_files:
            history_file = self.expand_path(history_file)
            
            
            if self.target_user:
                if self.os == "Windows":
                    history_file = history_file.replace("%USERNAME%", self.target_user)
                else:
                    history_file = history_file.replace("~", f"/home/{self.target_user}")
            
            if os.path.exists(history_file):
                
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
        
        
        if self.dry_run and self.force:
            for history_info in existing_histories:
                print(f"[DRY RUN] Would clean shell history: {history_info['path']}")
                self.cleaned_items["histories"].append(history_info)
            return
            
        
        def history_formatter(history_info, idx):
            path = history_info.get('path', 'Unknown')
            modified = history_info.get('modified', 'Unknown')
            size = history_info.get('size', 0)
            return f"{idx+1}. {path} (Size: {size} bytes, Modified: {modified})"
            
        
        selected_indices = self.get_selected_items("shell history files", existing_histories, history_formatter)
        
        if not selected_indices:
            print("No shell histories selected for cleaning.")
            return
            
        print(f"Cleaning {len(selected_indices)} shell history files...")
        
        
        for idx in selected_indices:
            history_file = existing_histories[idx]["path"]
            
            if self.dry_run:
                print(f"[DRY RUN] Would clean shell history: {history_file}")
                self.cleaned_items["histories"].append(existing_histories[idx])
                continue
                
            try:
                
                if self.profile == "paranoid":
                    if self.secure_delete_file(history_file):
                        
                        with open(history_file, 'w') as f:
                            pass
                        self.cleaned_items["histories"].append(existing_histories[idx])
                else:
                    
                    with open(history_file, 'w') as f:
                        pass
                    
                    print(f"Cleaned shell history: {history_file}")
                    self.cleaned_items["histories"].append(existing_histories[idx])
                
                
                if (self.os == "Linux" or self.os == "Darwin") and not self.dry_run:
                    
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
                
                if os.path.dirname(cron_path) in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"]:
                    os.remove(cron_path)
                    print(f"Removed cron file: {cron_path}")
                    return True
                
                elif cron_path == "/etc/crontab" or os.path.dirname(cron_path) == "/var/spool/cron/crontabs":
                    
                    with open(cron_path, 'r') as f:
                        content = f.readlines()
                    
                    
                    suspicious_content = task_info.get("content", "")
                    suspicious_lines = suspicious_content.splitlines()
                    
                    
                    clean_content = []
                    for line in content:
                        if not any(susp_line.strip() in line for susp_line in suspicious_lines if susp_line.strip()):
                            clean_content.append(line)
                    
                    
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
        
        
        if self.dry_run and self.force:
            for task_info in tasks:
                task_id = task_info.get("name", task_info.get("path", "Unknown task"))
                print(f"[DRY RUN] Would remove task: {task_id}")
                self.cleaned_items["tasks"].append(task_info)
            return
            
        
        def task_formatter(task_info, idx):
            if "name" in task_info:
                return f"{idx+1}. {task_info['name']} - {task_info.get('reason', 'Unknown reason')}"
            elif "path" in task_info:
                return f"{idx+1}. {task_info['path']} - {task_info.get('reason', 'Unknown reason')}"
            else:
                return f"{idx+1}. Unknown task"
                
        
        selected_indices = self.get_selected_items("suspicious scheduled tasks", tasks, task_formatter)
        
        if not selected_indices:
            print("No scheduled tasks selected for cleaning.")
            return
            
        print(f"Cleaning {len(selected_indices)} suspicious scheduled tasks...")
        
        
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
            
            backup_path = config_path + ".bak"
            if os.path.exists(backup_path):
                
                shutil.copy2(backup_path, config_path)
                print(f"Restored config from backup: {config_path}")
                return True
            else:
                
                
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
        
        
        if self.dry_run and self.force:
            for config_info in configs:
                print(f"[DRY RUN] Would restore config file: {config_info.get('path', 'Unknown')}")
                self.cleaned_items["configs"].append(config_info)
            return
            
        
        def config_formatter(config_info, idx):
            path = config_info.get('path', 'Unknown')
            modified = config_info.get('modified', 'Unknown date')
            return f"{idx+1}. {path} (Modified: {modified})"
            
        
        selected_indices = self.get_selected_items("modified configuration files", configs, config_formatter)
        
        if not selected_indices:
            print("No configuration files selected for restoration.")
            return
            
        print(f"Restoring {len(selected_indices)} modified configuration files...")
        
        
        for idx in selected_indices:
            config_info = configs[idx]
            if self.restore_config_file(config_info):
                self.cleaned_items["configs"].append(config_info)
    
    def clean_suspicious_network(self, network_items: List[Dict[str, Any]]) -> None:
        """Clean suspicious network connections"""
        if not network_items:
            return
            
        print(f"\n[*] Found {len(network_items)} suspicious network connections...")
        
        
        if self.dry_run and self.force:
            for item in network_items:
                print(f"[DRY RUN] Would terminate process: {item.get('pid', 'Unknown')} ({item.get('process', 'Unknown')})")
                self.cleaned_items["network"].append(item)
            return
            
        
        def network_formatter(item, idx):
            pid = item.get('pid', 'Unknown')
            process = item.get('process', 'Unknown')
            protocol = item.get('protocol', 'Unknown')
            local = item.get('local_address', 'Unknown')
            remote = item.get('remote_address', 'Unknown')
            reason = item.get('reason', 'Unknown reason')
            return f"{idx+1}. {process} (PID: {pid}) - {protocol} {local} → {remote} - {reason}"
            
        
        selected_indices = self.get_selected_items("suspicious network connections", network_items, network_formatter)
        
        if not selected_indices:
            print("No network connections selected for termination.")
            return
            
        print(f"Terminating {len(selected_indices)} suspicious network connections...")
        
        
        for idx in selected_indices:
            item = network_items[idx]
            try:
                
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
        
        
        if self.dry_run and self.force:
            for item in registry_items:
                key = item["key"]
                value_name = item["value_name"]
                print(f"[DRY RUN] Would delete registry value: {key}\\{value_name}")
                self.cleaned_items["registry"].append(item)
            return
            
        
        def registry_formatter(item, idx):
            key = item.get('key', 'Unknown')
            value_name = item.get('value_name', 'Unknown')
            reason = item.get('reason', 'Unknown reason')
            return f"{idx+1}. {key}\\{value_name} - {reason}"
            
        
        selected_indices = self.get_selected_items("suspicious registry entries", registry_items, registry_formatter)
        
        if not selected_indices:
            print("No registry entries selected for cleaning.")
            return
            
        print(f"Cleaning {len(selected_indices)} suspicious registry entries...")
        
        
        for idx in selected_indices:
            item = registry_items[idx]
            key = item["key"]
            value_name = item["value_name"]
            
            try:
                
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
            
        
        selected_indices = self.get_selected_items("suspicious container artifacts", container_items, container_formatter)
        
        if not selected_indices:
            print("No container artifacts selected for cleaning.")
            return
            
        print(f"Cleaning {len(selected_indices)} suspicious container artifacts...")
        
        
        for idx in selected_indices:
            item = container_items[idx]
            if "container_id" in item:
                
                container_id = item["container_id"]
                name = item.get("name", "Unknown")
                
                if self.dry_run:
                    print(f"[DRY RUN] Would stop and remove container: {name} ({container_id})")
                    self.cleaned_items["containers"].append(item)
                    continue
                    
                try:
                    
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
                
                filepath = item["path"]
                
                
                if self.secure_delete_file(filepath):
                    self.cleaned_items["containers"].append(item)
    
    def clean_memory_artifacts(self, memory_items: List[Dict[str, Any]]) -> None:
        """Clean suspicious processes from memory"""
        if not memory_items:
            return
            
        print(f"\n[*] Found {len(memory_items)} suspicious processes...")
        
        
        if self.dry_run and self.force:
            for item in memory_items:
                pid = item["pid"]
                process_name = item["process_name"]
                print(f"[DRY RUN] Would terminate process: {process_name} (PID: {pid})")
                self.cleaned_items["processes"].append(item)
            return
            
        
        def process_formatter(item, idx):
            pid = item.get('pid', 'Unknown')
            process_name = item.get('process_name', 'Unknown')
            cmdline = item.get('command_line', '')
            reason = item.get('reason', 'Unknown reason')
            
            
            if len(cmdline) > 50:
                cmdline = cmdline[:47] + "..."
                
            return f"{idx+1}. {process_name} (PID: {pid}) - {cmdline} - {reason}"
            
        
        selected_indices = self.get_selected_items("suspicious processes", memory_items, process_formatter)
        
        if not selected_indices:
            print("No processes selected for termination.")
            return
            
        print(f"Terminating {len(selected_indices)} suspicious processes...")
        
        
        for idx in selected_indices:
            item = memory_items[idx]
            pid = item["pid"]
            process_name = item["process_name"]
            
            try:
                
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
        
        
        if "suspicious_files" in scan_results and scan_results["suspicious_files"]:
            self.clean_all_suspicious_files(scan_results["suspicious_files"])
        
        
        self.clean_shell_histories()
        
        
        if "scheduled_tasks" in scan_results and scan_results["scheduled_tasks"]:
            self.clean_all_scheduled_tasks(scan_results["scheduled_tasks"])
        
        
        if "modified_configs" in scan_results and scan_results["modified_configs"]:
            self.clean_all_config_files(scan_results["modified_configs"])
            
        
        if "suspicious_network" in scan_results and scan_results["suspicious_network"]:
            self.clean_suspicious_network(scan_results["suspicious_network"])
            
        
        if "registry_artifacts" in scan_results and scan_results["registry_artifacts"]:
            self.clean_registry_artifacts(scan_results["registry_artifacts"])
            
        
        if "container_artifacts" in scan_results and scan_results["container_artifacts"]:
            self.clean_container_artifacts(scan_results["container_artifacts"])
            
        
        if "memory_artifacts" in scan_results and scan_results["memory_artifacts"]:
            self.clean_memory_artifacts(scan_results["memory_artifacts"])
        
        
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
                   scan_results: Optional[str] = None, date_filter: Optional[Dict[str, datetime]] = None,
                   batch_size: int = 15, specific_artifacts: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Clean up red team artifacts found during scanning
    
    Args:
        dry_run: Whether to perform a dry run
        force: Whether to force cleanup without confirmation
        profile: Scanning profile (minimal, standard, paranoid)
        target_user: User directory to target
        scan_results: Path to scan results JSON file
        date_filter: Optional dictionary with 'after' and/or 'before' datetime objects
        batch_size: Number of items to display at once during cleaning
        specific_artifacts: List of specific artifact types to clean
        
    Returns:
        Dictionary containing cleanup results
    """
    if scan_results is None:
        # Find most recent scan result if none specified
        json_files = sorted(glob.glob("redtriage_scan_*.json"), reverse=True)
        if not json_files:
            print("No scan results found. Run 'scan' first.")
            return {}
        scan_results = json_files[0]
        print(f"Using most recent scan result: {scan_results}")
    
    try:
        with open(scan_results, 'r') as f:
            scan_data = json.load(f)
    except Exception as e:
        print(f"Error loading scan results: {e}")
        return {}
    
    # Apply date filtering to scan results if specified
    if date_filter:
        date_filter_description = []
        if 'after' in date_filter:
            date_filter_description.append(f"after {date_filter['after'].strftime('%Y-%m-%d')}")
        if 'before' in date_filter:
            date_filter_description.append(f"before {date_filter['before'].strftime('%Y-%m-%d')}")
        if date_filter_description:
            print(f"Applying date filter: items modified {' and '.join(date_filter_description)}")
    
    cleaner = Cleaner(dry_run, force, profile, target_user, date_filter, batch_size)
    return cleaner.clean_system(scan_data)


def main():
    # Example usage
    dry_run = True
    force = False
    profile = "standard"
    target_user = "JohnDoe"
    scan_results = None
    date_filter = None
    batch_size = 15
    specific_artifacts = None
    
    cleaned_items = clean_artifacts(dry_run, force, profile, target_user, scan_results, date_filter, batch_size, specific_artifacts)
    
    # Save results to file
    output_file = f"redtriage_cleanup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(cleaned_items, f, indent=2)
    
    from rich.console import Console
    console = Console()
    
    console.print("\n[bold]CLEANUP COMPLETE[/bold]", highlight=False)
    console.print(f"Results saved to: [cyan]{output_file}[/cyan]", highlight=False)
    
    console.print("\n" + "="*60, highlight=False)
    
    console.print("\n[bold]CLEANUP SUMMARY[/bold]", highlight=False)
    
    console.print("\n[bold]File System:[/bold]", highlight=False)
    console.print(f"🧹 Cleaned files: [cyan]{len(cleaned_items['files'])}", highlight=False)
    console.print(f"🧹 Cleaned shell histories: [cyan]{len(cleaned_items['histories'])}", highlight=False)
    console.print(f"🧹 Restored config files: [cyan]{len(cleaned_items['configs'])}", highlight=False)
    
    console.print("\n[bold]Scheduled Tasks:[/bold]", highlight=False)
    console.print(f"🧹 Cleaned scheduled tasks: [cyan]{len(cleaned_items['tasks'])}", highlight=False)
    
    console.print("\n[bold]Network:[/bold]", highlight=False)
    console.print(f"🧹 Terminated network connections: [cyan]{len(cleaned_items['network'])}", highlight=False)
    
    console.print("\n[bold]Other Artifacts:[/bold]", highlight=False)
    console.print(f"🧹 Cleaned container artifacts: [cyan]{len(cleaned_items['containers'])}", highlight=False)
    console.print(f"🧹 Terminated processes: [cyan]{len(cleaned_items['processes'])}", highlight=False)
    
    if cleaned_items["os"] == "Windows":
        console.print("\n[bold]Windows-specific:[/bold]", highlight=False)
        console.print(f"🧹 Cleaned registry entries: [cyan]{len(cleaned_items['registry'])}", highlight=False)
    
    console.print("\n[italic]Use 'redtriage.py report' to generate a detailed report[/italic]", highlight=False)
    
    return cleaned_items


if __name__ == "__main__":
    main() 