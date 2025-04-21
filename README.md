# RedTriage

A CLI tool for red teamers to help clean up traces after penetration tests or red team engagements.

Created by: Zarni (Neo)

## Features

- **Scan**: Detect common red team artifacts and tools
- **Clean**: Remove suspicious files, wipe shell histories, etc.
- **Report**: Generate reports in text, JSON, or HTML format
- **Help**: Detailed information about the tool's usage and capabilities

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