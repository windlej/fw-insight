"""CLI output formatting helpers."""

import click

SEVERITY_COLORS = {
    "critical": "red",
    "high": "bright_red",
    "medium": "yellow",
    "low": "blue",
    "info": "white",
}


def severity_badge(severity: str) -> str:
    """Return a colored severity badge."""
    color = SEVERITY_COLORS.get(severity, "white")
    return click.style(f"[{severity.upper()}]", fg=color, bold=True)


def print_findings_summary(result, session):
    """Print analysis results to the console."""
    click.echo(f"\n{'=' * 60}")
    click.echo(f"fw-insight Analysis Report")
    click.echo(f"{'=' * 60}")
    click.echo(f"Vendor:        {session.vendor}")
    click.echo(f"Hostname:      {session.hostname or 'N/A'}")
    click.echo(f"Rules:         {session.rule_count}")
    click.echo(f"Health Score:  {result.health_score}/100")
    click.echo(f"{'=' * 60}")

    if result.finding_counts:
        click.echo("\nFinding Summary:")
        for severity, count in sorted(
            result.finding_counts.items(),
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x[0], 5),
        ):
            click.echo(f"  {severity_badge(severity)} {count}")

    if result.findings:
        click.echo(f"\nFindings ({len(result.findings)} total):")
        click.echo("-" * 60)
        for i, f in enumerate(result.findings, 1):
            click.echo(f"\n{i}. {severity_badge(f.severity.value)} {f.title}")
            click.echo(f"   Rule: {f.entity_id}")
            click.echo(f"   {f.description}")
    else:
        click.echo("\nNo findings. Configuration looks clean.")

    click.echo()
