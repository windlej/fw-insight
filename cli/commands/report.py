"""Report command."""

import click

from core.analysis.engine import AnalysisEngine
from core.normalizer import normalize
from parsers import get_parser
from report.generator import generate_pdf


@click.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--vendor", required=True, help="Vendor type (e.g., paloalto)")
@click.option("--format", "fmt", type=click.Choice(["pdf", "json"]), default="pdf")
@click.option("--output", "-o", type=click.Path(), help="Output file")
def report(file, vendor, fmt, output):
    """Generate a PDF or JSON report for a firewall config."""
    raw_content = open(file, "rb").read()

    parser = get_parser(vendor)
    ast = parser.parse(raw_content)
    session_data = parser.normalize(ast)

    session = normalize(vendor, session_data, source_filename=file, source_content=raw_content)

    engine = AnalysisEngine()
    result = engine.analyze(session)

    findings = [f.model_dump() for f in result.findings]
    session_dict = session.model_dump()
    session_dict["health_score"] = result.health_score
    session_dict["finding_counts"] = result.finding_counts

    if fmt == "pdf":
        output_path = output or "fw-insight-report.pdf"
        pdf_bytes = generate_pdf(session_dict, findings, raw_content)
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
        click.echo(f"PDF report written to {output_path}")
    else:
        output_path = output or "fw-insight-report.json"
        import json
        output_data = {
            "session": session_dict,
            "findings": findings,
            "health_score": result.health_score,
        }
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2, default=str)
        click.echo(f"JSON report written to {output_path}")
