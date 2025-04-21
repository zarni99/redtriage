#!/usr/bin/env python3
"""
RedTriage - A tool for red teamers to clean up artifacts
Created by: Zarni (Neo)
"""
import typer
import platform
import os
from enum import Enum
from typing import Optional, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# Display banner on import
banner_console = Console()
banner_console.print(Panel.fit(
    "[bold red]RedTriage[/bold red] - A tool for red teamers to clean up artifacts\n[bold]Created by:[/bold] Zarni (Neo)",
    title="RedTriage v1.0.0",
    border_style="red"
), highlight=False)

# Import modules
from modules.scanner import scan_artifacts
from modules.cleaner import clean_artifacts
from modules.reporter import generate_report

class Profile(str, Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    PARANOID = "paranoid"

class OutputFormat(str, Enum):
    TXT = "txt"
    JSON = "json"
    HTML = "html"
    PDF = "pdf"

# Create the app with comprehensive help formatting
app = typer.Typer(
    help="RedTriage: A tool for red teamers to clean up artifacts after engagements\nCreated by: Zarni (Neo)",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]}
)
console = Console()

# Create a callback to display comprehensive help
@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    RedTriage - A tool for red teamers to clean up artifacts after engagements.
    Created by: Zarni (Neo)
    
    Run with --help for comprehensive documentation or use specific commands.
    """
    # If no command was invoked and help wasn't requested, show help
    if ctx.invoked_subcommand is None and not ctx.help_option_used:
        show_detailed_help()

@app.command()
def scan(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done without actually doing it"),
    profile: Profile = typer.Option(Profile.STANDARD, "--profile", "-p", help="Level of scanning to perform"),
    target_user: Optional[str] = typer.Option(None, "--target-user", "-u", help="Specific user to target"),
    locations: List[str] = typer.Option(None, "--locations", "-l", help="Specific locations to scan")
):
    """
    Scan for common red team artifacts and tools.

    This command detects various artifacts left by red team activities, including:
    - Suspicious files (tools like mimikatz, netcat, etc.)
    - Modified configuration files
    - Shell history files with suspicious commands
    - Scheduled tasks and cron jobs
    - Network connections and configurations
    - Windows registry entries
    - Container and process artifacts
    """
    # Print header with creator name
    console.print("\n[bold red]RedTriage[/bold red] - Scanning", highlight=False)
    console.print("[bold]Created by:[/bold] Zarni (Neo)", highlight=False)
    console.print("[bold]Version:[/bold] 1.0.0", highlight=False)
    console.print("=" * 60, highlight=False)
    
    typer.echo(f"🔍 Scanning for artifacts (Profile: {profile.value})")
    scan_artifacts(dry_run, profile.value, target_user, locations)


@app.command()
def clean(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done without actually doing it"),
    force: bool = typer.Option(False, "--force", "-f", help="Don't prompt before cleanup actions"),
    profile: Profile = typer.Option(Profile.STANDARD, "--profile", "-p", help="Level of cleanup to perform"),
    target_user: Optional[str] = typer.Option(None, "--target-user", "-u", help="Specific user to target"),
    artifacts: List[str] = typer.Option(None, "--artifacts", "-a", help="Specific artifacts to clean")
):
    """
    Clean up red team artifacts and traces.
    
    This command removes or disables detected artifacts, including:
    - Deleting suspicious files
    - Restoring modified configuration files
    - Cleaning shell history files
    - Removing suspicious scheduled tasks
    - Terminating suspicious network connections
    - Cleaning Windows registry entries
    - Removing container artifacts
    - Terminating suspicious processes
    """
    # Print header with creator name
    console.print("\n[bold red]RedTriage[/bold red] - Cleanup", highlight=False)
    console.print("[bold]Created by:[/bold] Zarni (Neo)", highlight=False)
    console.print("[bold]Version:[/bold] 1.0.0", highlight=False)
    console.print("=" * 60, highlight=False)
    
    typer.echo(f"🧹 Cleaning artifacts (Profile: {profile.value})")
    clean_artifacts(dry_run, force, profile.value, target_user, artifacts)


@app.command()
def report(
    output_format: OutputFormat = typer.Option(OutputFormat.TXT, "--format", "-f", help="Output format"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    scan_results: Optional[str] = typer.Option(None, "--scan-results", help="Path to scan results JSON file")
):
    """
    Generate a report of findings and cleanup actions.
    
    This command creates detailed reports in various formats:
    - TXT: Simple text report
    - JSON: Structured data for further processing
    - HTML: Rich formatted report with categorized sections
    - PDF: Professional document with tables and summaries
    
    Reports include all detected artifacts, cleanup actions, and a summary.
    """
    # Print header with creator name
    console.print("\n[bold red]RedTriage[/bold red] - Reporting", highlight=False)
    console.print("[bold]Created by:[/bold] Zarni (Neo)", highlight=False)
    console.print("[bold]Version:[/bold] 1.0.0", highlight=False)
    console.print("=" * 60, highlight=False)
    
    typer.echo(f"📊 Generating report in {output_format.value} format")
    generate_report(output_format.value, output_file, scan_results)


@app.command()
def help():
    """
    Show detailed help information about RedTriage
    
    RedTriage is created by Zarni (Neo)
    """
    show_detailed_help()


def show_detailed_help():
    """Function to display detailed help information"""
    console = Console()
    
    # Title and creator
    console.print("\n[bold red]RedTriage[/bold red] - A tool for red teamers to clean up artifacts", highlight=False)
    console.print("[bold]Created by:[/bold] Zarni (Neo)", highlight=False)
    console.print("[bold]Version:[/bold] 1.0.0", highlight=False)
    console.print("\n" + "="*60, highlight=False)  # Separator
    
    # Overview
    console.print("\n[bold]OVERVIEW[/bold]", highlight=False)
    console.print("RedTriage helps red teamers clean up traces after penetration tests.", highlight=False)
    console.print("It detects and cleans artifacts left behind during engagements and", highlight=False)
    console.print("generates comprehensive reports to document findings and actions.", highlight=False)
    
    # Commands
    console.print("\n[bold]COMMANDS[/bold]", highlight=False)
    console.print("\n[cyan]scan[/cyan] - Detect artifacts and tools used during engagements", highlight=False)
    console.print("  Example: ./redtriage.py scan --profile paranoid", highlight=False)
    
    console.print("\n[cyan]clean[/cyan] - Clean up detected artifacts", highlight=False)
    console.print("  Example: ./redtriage.py clean --dry-run", highlight=False)
    
    console.print("\n[cyan]report[/cyan] - Generate a report of findings and cleanup actions", highlight=False)
    console.print("  Example: ./redtriage.py report --format html", highlight=False)
    
    console.print("\n[cyan]help[/cyan] - Show this help message", highlight=False)
    console.print("  Example: ./redtriage.py help", highlight=False)
    
    # Profiles
    console.print("\n" + "="*60, highlight=False)  # Separator
    console.print("\n[bold]PROFILES[/bold]", highlight=False)
    
    console.print("\n[cyan]minimal[/cyan] - Basic checks and cleanup actions, minimal disruption", highlight=False)
    console.print("\n[cyan]standard[/cyan] - Default level - comprehensive but conservative scans", highlight=False)
    console.print("\n[cyan]paranoid[/cyan] - Aggressive checks and cleanup (may produce false positives)", highlight=False)
    
    # Common Options
    console.print("\n" + "="*60, highlight=False)  # Separator
    console.print("\n[bold]COMMON OPTIONS[/bold]", highlight=False)
    
    console.print("\n[cyan]--dry-run[/cyan] - Show what would be done without actually doing it", highlight=False)
    console.print("\n[cyan]--profile[/cyan] - Level of scanning/cleanup (minimal, standard, paranoid)", highlight=False)
    console.print("\n[cyan]--target-user[/cyan] - Specific user to target", highlight=False)
    
    # Command-specific options
    console.print("\n" + "="*60, highlight=False)  # Separator
    console.print("\n[bold]COMMAND-SPECIFIC OPTIONS[/bold]", highlight=False)
    
    # Scan command options
    console.print("\n[bold]scan[/bold] options:", highlight=False)
    console.print("  [cyan]--locations[/cyan] - Specific locations to scan (space-separated)", highlight=False)
    
    # Clean command options
    console.print("\n[bold]clean[/bold] options:", highlight=False)
    console.print("  [cyan]--force[/cyan] - Don't prompt before cleanup actions (use with caution!)", highlight=False)
    console.print("  [cyan]--artifacts[/cyan] - Specific artifacts to clean (space-separated list)", highlight=False)
    
    # Report command options
    console.print("\n[bold]report[/bold] options:", highlight=False)
    console.print("  [cyan]--format[/cyan] - Output format: txt, json, html, or pdf", highlight=False)
    console.print("  [cyan]--output[/cyan] - Output file path (default: auto-generated filename)", highlight=False)
    console.print("  [cyan]--scan-results[/cyan] - Path to scan results JSON file", highlight=False)
    
    # What RedTriage detects
    console.print("\n" + "="*60, highlight=False)  # Separator
    console.print("\n[bold]WHAT REDTRIAGE DETECTS[/bold]", highlight=False)
    
    console.print("\n[cyan]Suspicious Files[/cyan] - Files related to common red team tools", highlight=False)
    console.print("[cyan]Modified Configs[/cyan] - Recently modified configuration files", highlight=False)
    console.print("[cyan]Shell Histories[/cyan] - Suspicious commands in shell history", highlight=False)
    console.print("[cyan]Scheduled Tasks[/cyan] - Suspicious scheduled tasks or cron jobs", highlight=False)
    console.print("[cyan]Network Connections[/cyan] - Suspicious network connections", highlight=False)
    console.print("[cyan]Firewall Rules[/cyan] - Modified firewall rules that may allow backdoor access", highlight=False)
    console.print("[cyan]Proxy Settings[/cyan] - Suspicious proxy configurations", highlight=False)
    console.print("[cyan]VPN Connections[/cyan] - Active VPN connections that might be used for exfiltration", highlight=False)
    console.print("[cyan]Registry Artifacts[/cyan] - Windows registry entries for persistence", highlight=False)
    console.print("[cyan]Container Artifacts[/cyan] - Suspicious container configurations or images", highlight=False)
    console.print("[cyan]Process Artifacts[/cyan] - Unusual running processes or memory-resident malware", highlight=False)
    
    # Warning
    console.print("\n" + "="*60, highlight=False)  # Separator
    console.print("\n[bold red]WARNING[/bold red]", highlight=False)
    console.print("This tool is designed for legitimate use by authorized red teamers.", highlight=False)
    console.print("Improper use could result in data loss or system issues.", highlight=False)
    console.print("Always use with caution and proper authorization.", highlight=False)
    console.print("Running with elevated privileges is recommended for full functionality.", highlight=False)


if __name__ == "__main__":
    # Check if running with elevated privileges
    if os.name == "posix" and os.geteuid() != 0:
        typer.echo("⚠️  Warning: RedTriage may require sudo/root privileges for complete functionality")
    elif os.name == "nt" and not os.environ.get("ADMINISTRATOR", False):
        typer.echo("⚠️  Warning: RedTriage may require Administrator privileges for complete functionality")

    typer.echo(f"🔴 RedTriage - Operating System: {platform.system()}")
    app() 