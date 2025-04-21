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

app = typer.Typer(help="RedTriage: A tool for red teamers to clean up artifacts after engagements")
console = Console()

@app.command()
def scan(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be done without actually doing it"),
    profile: Profile = typer.Option(Profile.STANDARD, "--profile", "-p", help="Level of scanning to perform"),
    target_user: Optional[str] = typer.Option(None, "--target-user", "-u", help="Specific user to target"),
    locations: List[str] = typer.Option(None, "--locations", "-l", help="Specific locations to scan")
):
    """
    Scan for common red team artifacts and tools
    """
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
    Clean up red team artifacts and traces
    """
    typer.echo(f"🧹 Cleaning artifacts (Profile: {profile.value})")
    clean_artifacts(dry_run, force, profile.value, target_user, artifacts)


@app.command()
def report(
    output_format: OutputFormat = typer.Option(OutputFormat.TXT, "--format", "-f", help="Output format"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
    scan_results: Optional[str] = typer.Option(None, "--scan-results", help="Path to scan results JSON file")
):
    """
    Generate a report of findings and cleanup actions
    """
    typer.echo(f"📊 Generating report in {output_format.value} format")
    generate_report(output_format.value, output_file, scan_results)


@app.command()
def help():
    """
    Show detailed help information about RedTriage
    """
    console.print(Panel.fit(
        "[bold red]RedTriage[/bold red] - A tool for red teamers to clean up artifacts after engagements",
        title="About",
        border_style="red"
    ))
    
    console.print("\n[bold]OVERVIEW[/bold]")
    console.print("""
        RedTriage helps red teamers clean up traces after a penetration test or red team engagement.
        It detects and cleans common artifacts left behind during engagements, and generates
        comprehensive reports to document findings and actions taken.
    """)
    
    # Commands Table
    console.print("\n[bold]COMMANDS[/bold]")
    commands_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    commands_table.add_column("Command", style="cyan")
    commands_table.add_column("Description")
    commands_table.add_column("Example")
    
    commands_table.add_row(
        "scan", 
        "Detect artifacts and tools used during engagements",
        "./redtriage.py scan --profile paranoid"
    )
    commands_table.add_row(
        "clean", 
        "Clean up detected artifacts",
        "./redtriage.py clean --dry-run"
    )
    commands_table.add_row(
        "report", 
        "Generate a report of findings and cleanup actions",
        "./redtriage.py report --format html"
    )
    commands_table.add_row(
        "help", 
        "Show this help message",
        "./redtriage.py help"
    )
    console.print(commands_table)
    
    # Profiles Table
    console.print("\n[bold]PROFILES[/bold]")
    profiles_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    profiles_table.add_column("Profile", style="cyan")
    profiles_table.add_column("Description")
    
    profiles_table.add_row(
        "minimal", 
        "Basic checks and cleanup actions, minimal disruption"
    )
    profiles_table.add_row(
        "standard", 
        "Default level - comprehensive but conservative scans and cleanup"
    )
    profiles_table.add_row(
        "paranoid", 
        "Aggressive checks and cleanup (may produce false positives)"
    )
    console.print(profiles_table)
    
    # Common Options
    console.print("\n[bold]COMMON OPTIONS[/bold]")
    options_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    options_table.add_column("Option", style="cyan")
    options_table.add_column("Description")
    
    options_table.add_row(
        "--dry-run", 
        "Show what would be done without actually doing it"
    )
    options_table.add_row(
        "--profile", 
        "Level of scanning/cleanup to perform: minimal, standard, or paranoid"
    )
    options_table.add_row(
        "--target-user", 
        "Specific user to target (e.g., only clean a specific user's files)"
    )
    console.print(options_table)
    
    # Command-specific options
    console.print("\n[bold]COMMAND-SPECIFIC OPTIONS[/bold]")
    
    # Scan options
    console.print("\n[cyan]scan[/cyan] options:")
    scan_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    scan_table.add_column("Option", style="cyan")
    scan_table.add_column("Description")
    
    scan_table.add_row(
        "--locations", 
        "Specific locations to scan (space-separated list of directories)"
    )
    console.print(scan_table)
    
    # Clean options
    console.print("\n[cyan]clean[/cyan] options:")
    clean_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    clean_table.add_column("Option", style="cyan")
    clean_table.add_column("Description")
    
    clean_table.add_row(
        "--force", 
        "Don't prompt before cleanup actions (use with caution!)"
    )
    clean_table.add_row(
        "--artifacts", 
        "Specific artifacts to clean (space-separated list)"
    )
    console.print(clean_table)
    
    # Report options
    console.print("\n[cyan]report[/cyan] options:")
    report_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    report_table.add_column("Option", style="cyan")
    report_table.add_column("Description")
    
    report_table.add_row(
        "--format", 
        "Output format: txt, json, or html"
    )
    report_table.add_row(
        "--output", 
        "Output file path (default: auto-generated filename)"
    )
    report_table.add_row(
        "--scan-results", 
        "Path to scan results JSON file (default: use most recent scan results)"
    )
    console.print(report_table)
    
    # What RedTriage detects
    console.print("\n[bold]WHAT REDTRIAGE DETECTS[/bold]")
    detects_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    detects_table.add_column("Category", style="cyan")
    detects_table.add_column("Description")
    
    detects_table.add_row(
        "Suspicious Files", 
        "Files related to common red team tools (mimikatz, nc, chisel, etc.)"
    )
    detects_table.add_row(
        "Modified Configs", 
        "Recently modified configuration files (sshd_config, hosts, etc.)"
    )
    detects_table.add_row(
        "Shell Histories", 
        "Suspicious commands in shell history files"
    )
    detects_table.add_row(
        "Scheduled Tasks", 
        "Suspicious scheduled tasks or cron jobs"
    )
    console.print(detects_table)
    
    # Warning
    console.print("\n[bold red]WARNING[/bold red]")
    console.print("""
        This tool is designed for legitimate use by authorized red teamers during or after engagements.
        Improper use could result in data loss or system issues. Always use with caution and proper
        authorization. Running with elevated privileges is recommended for full functionality.
    """)


if __name__ == "__main__":
    # Check if running with elevated privileges
    if os.name == "posix" and os.geteuid() != 0:
        typer.echo("⚠️  Warning: RedTriage may require sudo/root privileges for complete functionality")
    elif os.name == "nt" and not os.environ.get("ADMINISTRATOR", False):
        typer.echo("⚠️  Warning: RedTriage may require Administrator privileges for complete functionality")

    typer.echo(f"🔴 RedTriage - Operating System: {platform.system()}")
    app() 