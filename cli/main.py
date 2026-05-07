"""fw-insight CLI entry point."""

import click

from cli.commands.analyze import analyze
from cli.commands.report import report
from cli.commands.diff import diff
from cli.commands.export import export_cmd
from cli.commands.serve import serve


@click.group()
@click.version_option(version="0.1.0", prog_name="fw-insight")
def cli():
    """fw-insight - Firewall configuration visualization and analysis."""
    pass


cli.add_command(analyze)
cli.add_command(report)
cli.add_command(diff)
cli.add_command(export_cmd)
cli.add_command(serve)


if __name__ == "__main__":
    cli()
