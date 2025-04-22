# RedTriage

A CLI tool for red teamers to help clean up traces after penetration tests or red team engagements.

Created by: Zarni (Neo)

## Features

- **Scan**: Detect common red team artifacts and tools
- **Clean**: Remove suspicious files, wipe shell histories, etc.
- **Report**: Generate reports in text, JSON, HTML, or PDF format
- **Help**: Detailed information about the tool's usage and capabilities
- **Network Scanning**: Identify suspicious network connections and configurations
- **Tiered Prompting**: User-friendly interface for selecting artifacts to clean

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/RedTriage.git
cd RedTriage

# Install dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x redtriage.py
```

## Capabilities

RedTriage can detect and clean various artifacts left by red team activities:

### File System Artifacts
- Suspicious binaries and scripts
- Modified configuration files
- Shell history files with suspicious commands
- Webshells and backdoors

### Scheduled Tasks
- Suspicious scheduled tasks and cron jobs
- Persistence mechanisms

### Network Artifacts
- Suspicious active network connections
- Unusual listening ports
- Connections to known malicious domains/IPs
- Suspicious firewall rule modifications
- Unusual proxy settings
- VPN connections
- SSH connections with potential backdoor configurations

### Registry Artifacts (Windows)
- Autorun entries
- Service modifications
- Suspicious registry keys

### Container Artifacts
- Suspicious container configurations
- Potentially malicious images

### Process Artifacts
- Suspicious running processes
- Memory-resident malware indicators

## Usage

### Basic Commands

```bash
# Scan for artifacts
./redtriage.py scan

# Clean up artifacts (will prompt before deleting)
./redtriage.py clean

# Generate a report
./redtriage.py report

# Show detailed help information
./redtriage.py help
```

### Command Options

#### Scan Command

```bash
# Perform a dry run (no actual changes)
./redtriage.py scan --dry-run

# Use a specific profile level (minimal, standard, paranoid)
./redtriage.py scan --profile paranoid

# Target a specific user's home directory
./redtriage.py scan --target-user johndoe

# Scan specific locations
./redtriage.py scan --locations /tmp /var/tmp

# Only scan files modified in the last 7 days
./redtriage.py scan --days 7

# Only scan files modified after a specific date
./redtriage.py scan --after 2023-04-15

# Only scan files modified before a specific date
./redtriage.py scan --before 2023-04-30

# Combine date filters
./redtriage.py scan --after 2023-04-15 --before 2023-04-30
```

#### Clean Command

```bash
# Perform a dry run (no actual changes)
./redtriage.py clean --dry-run

# Force cleanup without prompts
./redtriage.py clean --force

# Use a specific profile level
./redtriage.py clean --profile paranoid

# Target a specific user's home directory
./redtriage.py clean --target-user johndoe

# Only clean files modified in the last 7 days
./redtriage.py clean --days 7

# Only clean files modified after a specific date
./redtriage.py clean --after 2023-04-15

# Adjust the batch size for interactive display
./redtriage.py clean --batch-size 10
```

The clean command now features a tiered prompting system for more interactive and controlled artifact cleaning. See the [Tiered Prompting](#tiered-prompting) section for details.

#### Report Command

```bash
# Generate report in specific format (txt, json, html, pdf)
./redtriage.py report --format html

# Generate PDF report
./redtriage.py report --format pdf --output report.pdf

# Specify output file
./redtriage.py report --format html --output report.html

# Use specific scan results file
./redtriage.py report --scan-results redtriage_scan_20230101_120000.json
```

#### Help Command

```bash
# Show detailed help information with formatting
./redtriage.py help
```

## Profiles

- **minimal**: Basic checks and cleanup actions
- **standard**: Default level - comprehensive but conservative
- **paranoid**: Aggressive checks and cleanup (may produce false positives)

## Tiered Prompting

RedTriage features a sophisticated tiered prompting system for handling large numbers of artifacts:

### First-Tier Prompt
When artifacts are found, you're presented with three options for each category:
- **Yes [y]**: Clean all artifacts in the category
- **No [n]**: Skip cleaning all artifacts
- **Selective [s]**: Enter the second-tier prompt for more control

Example:
```
Found 15 suspicious files. Clean them? [y/N/s] (Yes/No/Selective) s
```

### Second-Tier Prompt
If you choose "Selective" in the first tier, you can select:
- **All [a]**: Clean all items in this category
- **None [n]**: Skip all items in this category
- **Interactive [i]**: Select items individually with toggling interface
- **Range [r]**: Specify numeric ranges of items to clean
- **Filter [f]**: Filter items by pattern using shell wildcards

Example:
```
Select action for suspicious files:
[a]ll - Clean all items in this category
[n]one - Skip all items in this category
[i]nteractive - Individually select which items to clean
[r]ange - Specify numeric ranges to clean
[f]ilter - Filter by pattern
Selection mode [a/n/i/r/f]: i
```

### Selection Modes in Detail

#### Interactive Mode
Presents a checkbox-style interface where you can toggle individual items:
```
Current selection:
[X] 1. /tmp/nc
[X] 2. /tmp/mimikatz.exe
[X] 3. /home/user/.ssh/backdoor_key
[ ] 4. /var/www/html/c99.php

Toggle items using numbers (e.g., 2,4,7-9), [a]ll, [n]one, or [d]one:
```
- Toggle individual items by typing their number (e.g., `2` toggles item 2)
- Toggle ranges with hyphens (e.g., `2-4` toggles items 2, 3, and 4)
- Multiple selections with commas (e.g., `1,3,5-7`)
- Type `a` to select all, `n` to select none, or `d` when done

#### Range Mode
Specify numeric ranges of items to clean:
```
Enter range of items to clean (e.g., 1-5,8,10-15) (1-15): 1-3,7,10-12
```

#### Filter Mode
Filter items by pattern using shell wildcards:
```
Enter pattern to match (shell wildcards supported): *backdoor*
Selected 4 items matching '*backdoor*'
```
- Supports `*` (any characters) and `?` (single character)
- Case-insensitive matching
- Searches both paths and names
- Multiple attempts allowed if no matches found

### Benefits
- **Progressive Disclosure**: Only shows details when needed
- **Efficiency**: Quickly handle groups of artifacts
- **Flexibility**: Multiple methods to select specific artifacts
- **Safety**: Better visibility and control over what's being cleaned
- **Context-Aware**: Different formatters for different artifact types

### Context-Aware Formatters

RedTriage uses specialized formatters for each artifact type to provide relevant information when making selections:

- **File Formatters**: Display path, size, and modification time
- **Task Formatters**: Show task name, command, and schedule
- **Network Formatters**: Present connection details, ports, and protocols
- **Registry Formatters**: Display key path, value, and modification time
- **Container Formatters**: Show image name, ID, and creation time
- **Process Formatters**: Display process name, PID, and command line

This context-awareness ensures you have all relevant information to make informed decisions about which artifacts to clean.

Example formatter implementation:
```python
# Example of a file formatter from the code
def file_formatter(file_info, idx):
    path = file_info["path"]
    size = file_info.get("size", "Unknown size")
    mtime = file_info.get("mtime", "Unknown time")
    
    # Format size
    if isinstance(size, int):
        if size < 1024:
            size_str = f"{size} bytes"
        elif size < 1024 * 1024:
            size_str = f"{size / 1024:.1f} KB"
        else:
            size_str = f"{size / (1024 * 1024):.1f} MB"
    else:
        size_str = str(size)
    
    # Format time
    if isinstance(mtime, (int, float)):
        time_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    else:
        time_str = str(mtime)
    
    return f"{idx+1}. {path} [{size_str}, modified {time_str}]"
```

This system makes RedTriage much more practical for scenarios with numerous artifacts, allowing you to focus on critical items while maintaining control over the cleanup process.

## Detection Categories

RedTriage can detect the following categories of artifacts:

- **Suspicious Files**: Files related to common red team tools (mimikatz, nc, chisel, etc.)
- **Modified Configs**: Recently modified configuration files (sshd_config, hosts, etc.)
- **Shell Histories**: Suspicious commands in shell history files
- **Scheduled Tasks**: Suspicious scheduled tasks or cron jobs
- **Network Connections**: Suspicious network connections, unusual ports, and firewall modifications
- **Registry Entries**: Suspicious Windows registry entries for persistence or configuration
- **Container Artifacts**: Suspicious container images or configurations
- **Process Artifacts**: Unusual running processes or memory-resident tools

## Warning

This tool is designed for legitimate use by authorized red teamers during or after engagements. Improper use could result in data loss or system issues. Always use with caution and proper authorization.

## Requirements

- Python 3.6+
- typer
- colorama
- rich
- reportlab (optional, for PDF report generation)

## License

[MIT License](LICENSE)

## Date Filtering

RedTriage now includes powerful date filtering capabilities to help you focus on artifacts from specific time periods:

### Command Line Date Filters

You can use these options with both `scan` and `clean` commands:

- `--after YYYY-MM-DD`: Only include files modified after this date
- `--before YYYY-MM-DD`: Only include files modified before this date
- `--days N`: Only include files modified in the last N days

These filters help narrow down the scope to a specific timeframe, which is especially useful after a known red team engagement or incident.

### Interactive Date Filtering

When cleaning artifacts, you can also filter by date interactively:

1. Choose the `[d]ate` option in the selection mode prompt
2. Select from predefined options:
   - Last day
   - Last 3 days
   - Last week
   - Last month
   - Custom date range

This makes it easy to focus on recent artifacts while ignoring older system files.

## Batch Processing

For systems with many artifacts, RedTriage now includes batch processing features to manage large numbers of files:

### Automatic Batching

When displaying items interactively, RedTriage automatically breaks them into pages of 15 items (configurable with `--batch-size`).

### Smart Grouping

When cleaning artifacts, RedTriage can automatically group similar files:

1. Files from the same directory
2. Files of similar types (like Firefox data reporting files)
3. Windows Recent files
4. Windows Installation files

This allows you to make a single decision for an entire group of related files, dramatically speeding up the cleaning process.

### Navigation Controls

When viewing batched items, you can:
- View next/previous batch
- Select all items in current view
- Toggle individual items or ranges
- Skip to specific sections

These improvements make RedTriage much more practical for real-world scenarios where hundreds of artifacts might be detected.