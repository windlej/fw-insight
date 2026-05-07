"""Serve command - launches the FastAPI server."""

import click


@click.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8080, type=int, help="Port to bind to")
def serve(host, port):
    """Start the fw-insight web server."""
    import uvicorn
    click.echo(f"Starting fw-insight on http://{host}:{port}")
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=False,
    )
