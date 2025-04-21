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

RedTriage now features a sophisticated tiered prompting system for handling large numbers of artifacts:

### First-Tier Prompt
When artifacts are found, you're presented with three options for each category:
- **Yes**: Clean all artifacts in the category
- **No**: Skip cleaning all artifacts
- **Selective**: Enter the second-tier prompt for more control

### Second-Tier Prompt
If you choose "Selective" in the first tier, you can select:
- **All**: Clean all items in this category
- **None**: Skip all items in this category
- **Interactive**: Select items individually with toggling interface
- **Range**: Specify numeric ranges of items to clean
- **Filter**: Filter items by pattern using shell wildcards

### Benefits
- **Progressive Disclosure**: Only shows details when needed
- **Efficiency**: Quickly handle groups of artifacts
- **Flexibility**: Multiple methods to select specific artifacts
- **Safety**: Better visibility and control over what's being cleaned

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