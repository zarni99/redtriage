"""
RedTriage - A tool for red teamers to clean up artifacts
Created by: Zarni (Neo)
"""
import typer
import platform
import os
import sys
from enum import Enum
from typing import Optional, List
from datetime import datetime, timedelta

# Make sure the modules directory is in the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
except ImportError:
    print("Error: Required package 'rich' not found. Install it using 'pip install rich'")
    sys.exit(1)

banner_console = Console()
banner_console.print(Panel.fit(
    "[bold red]RedTriage[/bold red] - A tool for red teamers to clean up artifacts\n"
    "[bold blue]Created by:[/bold blue] Zarni (Neo)",
    border_style="red"
), highlight=False)

# Print operating system information
os_name = platform.system()
banner_console.print(f"RedTriage - Operating System: {os_name}")
if os_name != "Windows" and os.geteuid() != 0:
    banner_console.print("Warning: RedTriage may require sudo/root privileges for complete functionality\n")

try:
    from modules.scanner import scan_artifacts
    from modules.cleaner import clean_artifacts
    from modules.reporter import generate_report
except ImportError as e:
    banner_console.print(f"[bold red]Error:[/bold red] Could not import required modules: {e}")
    banner_console.print("Make sure you are running the script from the RedTriage directory.")
    sys.exit(1)

class Profile(str, Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    PARANOID = "paranoid"

class OutputFormat(str, Enum):
    TXT = "txt"
    JSON = "json"
    HTML = "html"
    PDF = "pdf"

app = typer.Typer(
    help="RedTriage: A tool for red teamers to clean up artifacts after engagements\nCreated by: Zarni (Neo)",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]}
)
console = Console()

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    RedTriage - A tool for red teamers to clean up artifacts after engagements.
    Created by: Zarni (Neo)
    
    Run with --help for comprehensive documentation or use specific commands.
    """
    
    if ctx.invoked_subcommand is None and not ctx.help_option_used:
        show_detailed_help()

@app.command()
def scan(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done without actually doing it"),
    profile: Profile = typer.Option(Profile.STANDARD, "--profile", "-p", help="Level of scanning to perform"),
    target_user: Optional[str] = typer.Option(None, "--target-user", "-u", help="Specific user to target"),
    locations: List[str] = typer.Option(None, "--locations", "-l", help="Specific locations to scan"),
    after_date: Optional[str] = typer.Option(None, "--after", help="Only include files modified after this date (YYYY-MM-DD)"),
    before_date: Optional[str] = typer.Option(None, "--before", help="Only include files modified before this date (YYYY-MM-DD)"),
    days: Optional[int] = typer.Option(None, "--days", help="Only include files modified in the last N days")
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
    
    console.print("\n[bold red]RedTriage[/bold red] - Scanning", highlight=False)
    console.print("=" * 60, highlight=False)
    
    typer.echo(f"Scanning for artifacts (Profile: {profile.value})")
    
    # Process date filters
    date_filter = process_date_filters(after_date, before_date, days)
    
    scan_artifacts(dry_run, profile.value, target_user, locations, date_filter)


@app.command()
def clean(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done without actually doing it"),
    profile: Profile = typer.Option(Profile.STANDARD, "--profile", "-p", help="Level of cleaning to perform"),
    force: bool = typer.Option(False, "--force", "-f", help="Force cleanup without confirmation"),
    target_user: Optional[str] = typer.Option(None, "--target-user", "-u", help="Specific user to target"),
    scan_results: str = typer.Option(None, "--scan-results", "-s", help="Path to scan results JSON file"),
    after_date: Optional[str] = typer.Option(None, "--after", help="Only include files modified after this date (YYYY-MM-DD)"),
    before_date: Optional[str] = typer.Option(None, "--before", help="Only include files modified before this date (YYYY-MM-DD)"),
    days: Optional[int] = typer.Option(None, "--days", help="Only include files modified in the last N days"),
    batch_size: int = typer.Option(15, "--batch-size", "-b", help="Number of items to display at once during cleaning")
):
    """
    Clean up detected red team artifacts.

    This command removes artifacts found during scanning, including:
    - Suspicious files (tools like mimikatz, netcat, etc.)
    - Modified configuration files
    - Shell history entries with suspicious commands
    - Scheduled tasks and cron jobs
    - Network connection remnants
    - Windows registry entries
    """
    console.print("\n[bold red]RedTriage[/bold red] - Cleanup", highlight=False)
    typer.echo(f"Cleaning up artifacts (Profile: {profile.value})")
    
    # Process date filters
    date_filter = process_date_filters(after_date, before_date, days)
    
    clean_artifacts(dry_run, profile.value, force, target_user, scan_results, date_filter, batch_size)


def process_date_filters(after_date, before_date, days):
    """Process date filter options and return a dictionary with date constraints"""
    date_filter = {}
    
    if after_date:
        try:
            date_filter['after'] = datetime.strptime(after_date, "%Y-%m-%d")
        except ValueError:
            console.print("[bold red]Error:[/bold red] Invalid date format for --after. Use YYYY-MM-DD format.", highlight=False)
            raise typer.Exit(1)
    
    if before_date:
        try:
            date_filter['before'] = datetime.strptime(before_date, "%Y-%m-%d")
        except ValueError:
            console.print("[bold red]Error:[/bold red] Invalid date format for --before. Use YYYY-MM-DD format.", highlight=False)
            raise typer.Exit(1)
    
    if days:
        if days <= 0:
            console.print("[bold red]Error:[/bold red] Days must be a positive number.", highlight=False)
            raise typer.Exit(1)
        date_filter['after'] = datetime.now() - timedelta(days=days)
    
    return date_filter


@app.command()
def report(
    format: OutputFormat = typer.Option(OutputFormat.TXT, "--format", "-f", help="Report output format"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    scan_results: Optional[str] = typer.Option(None, "--scan-results", "-s", help="Path to scan results JSON file")
):
    """
    Generate a report of findings and cleanup actions.
    
    This command creates a formatted report based on scan results and any cleanup actions performed.
    The report can be generated in multiple formats including text, JSON, HTML, or PDF.
    """
    console.print("\n[bold red]RedTriage[/bold red] - Report Generation", highlight=False)
    typer.echo(f"Generating {format.value} report")
    generate_report(format.value, output, scan_results)


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
    
    
    console.print("\n[bold red]RedTriage[/bold red] - A tool for red teamers to clean up artifacts", highlight=False)
    console.print("[bold]Created by:[/bold] Zarni (Neo)", highlight=False)
    console.print("[bold]Version:[/bold] 1.0.0", highlight=False)
    console.print("\n" + "="*60, highlight=False)  
    
    
    console.print("\n[bold]OVERVIEW[/bold]", highlight=False)
    console.print("RedTriage helps red teamers clean up traces after penetration tests.", highlight=False)
    console.print("It detects and cleans artifacts left behind during engagements and", highlight=False)
    console.print("generates comprehensive reports to document findings and actions.", highlight=False)
    
    
    console.print("\n[bold]COMMANDS[/bold]", highlight=False)
    console.print("\n[cyan]scan[/cyan] - Detect artifacts and tools used during engagements", highlight=False)
    console.print("  Example: ./redtriage.py scan --profile paranoid", highlight=False)
    
    console.print("\n[cyan]clean[/cyan] - Clean up detected artifacts", highlight=False)
    console.print("  Example: ./redtriage.py clean --dry-run", highlight=False)
    
    console.print("\n[cyan]report[/cyan] - Generate a report of findings and cleanup actions", highlight=False)
    console.print("  Example: ./redtriage.py report --format html", highlight=False)
    
    console.print("\n[cyan]help[/cyan] - Show this help message", highlight=False)
    console.print("  Example: ./redtriage.py help", highlight=False)
    
    
    console.print("\n" + "="*60, highlight=False)  
    console.print("\n[bold]PROFILES[/bold]", highlight=False)
    
    console.print("\n[cyan]minimal[/cyan] - Basic checks and cleanup actions, minimal disruption", highlight=False)
    console.print("\n[cyan]standard[/cyan] - Default level - comprehensive but conservative scans", highlight=False)
    console.print("\n[cyan]paranoid[/cyan] - Aggressive checks and cleanup (may produce false positives)", highlight=False)
    
    
    console.print("\n" + "="*60, highlight=False)  
    console.print("\n[bold]COMMON OPTIONS[/bold]", highlight=False)
    
    console.print("\n[cyan]--dry-run[/cyan] - Show what would be done without actually doing it", highlight=False)
    console.print("\n[cyan]--profile[/cyan] - Level of scanning/cleanup (minimal, standard, paranoid)", highlight=False)
    console.print("\n[cyan]--target-user[/cyan] - Specific user to target", highlight=False)
    
    console.print("\n[cyan]--after[/cyan] - Only include files modified after this date (YYYY-MM-DD)", highlight=False)
    console.print("\n[cyan]--before[/cyan] - Only include files modified before this date (YYYY-MM-DD)", highlight=False)
    console.print("\n[cyan]--days[/cyan] - Only include files modified in the last N days", highlight=False)
    
    console.print("\n" + "="*60, highlight=False)  
    console.print("\n[bold]COMMAND-SPECIFIC OPTIONS[/bold]", highlight=False)
    
    
    console.print("\n[bold]scan[/bold] options:", highlight=False)
    console.print("  [cyan]--locations[/cyan] - Specific locations to scan (space-separated)", highlight=False)
    
    
    console.print("\n[bold]clean[/bold] options:", highlight=False)
    console.print("  [cyan]--force[/cyan] - Don't prompt before cleanup actions (use with caution!)", highlight=False)
    console.print("  [cyan]--scan-results[/cyan] - Path to scan results JSON file", highlight=False)
    console.print("  [cyan]--batch-size[/cyan] - Number of items to display at once (default: 15)", highlight=False)
    
    
    console.print("\n[bold]report[/bold] options:", highlight=False)
    console.print("  [cyan]--format[/cyan] - Output format: txt, json, html, or pdf", highlight=False)
    console.print("  [cyan]--output[/cyan] - Output file path (default: auto-generated filename)", highlight=False)
    console.print("  [cyan]--scan-results[/cyan] - Path to scan results JSON file", highlight=False)
    
    
    console.print("\n" + "="*60, highlight=False)  
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
    
    
    console.print("\n" + "="*60, highlight=False)  
    console.print("\n[bold red]WARNING[/bold red]", highlight=False)
    console.print("This tool is designed for legitimate use by authorized red teamers.", highlight=False)
    console.print("Improper use could result in data loss or system issues.", highlight=False)
    console.print("Always use with caution and proper authorization.", highlight=False)
    console.print("Running with elevated privileges is recommended for full functionality.", highlight=False)


if __name__ == "__main__":
    
    app() 