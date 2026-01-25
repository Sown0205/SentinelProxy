"""CLI interface for SentinelProxy."""

import sys
from pathlib import Path
from typing import Optional

import click

from sentinelproxy import __version__
from sentinelproxy.config import ProxyConfig, parse_listen_address
from sentinelproxy.cert import print_cert_status, print_install_instructions
from sentinelproxy.logger import setup_logging, get_component_logger


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version and exit")
@click.pass_context
def main(ctx: click.Context, version: bool) -> None:
    """SentinelProxy - AI-assisted HTTPS reverse proxy & traffic analyzer.

    Use 'sentinelproxy start' to launch the proxy.
    Use 'sentinelproxy cert' for certificate management.
    """
    if version:
        click.echo(f"SentinelProxy v{__version__}")
        sys.exit(0)

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.option(
    "--listen",
    default="127.0.0.1:8080",
    help="Local bind address (host:port or just port)",
    metavar="ADDRESS",
)
@click.option(
    "--target",
    required=True,
    help="Upstream target server URL",
    metavar="URL",
)
@click.option(
    "--cert-dir",
    type=click.Path(path_type=Path),
    default=Path("certs"),
    help="Certificate storage directory",
    metavar="DIR",
)
@click.option(
    "--log-dir",
    type=click.Path(path_type=Path),
    default=Path("logs"),
    help="Session log directory",
    metavar="DIR",
)
@click.option(
    "--trace",
    is_flag=True,
    help="Enable live request tracing",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug output",
)
@click.option(
    "--stats",
    is_flag=True,
    help="Enable periodic metrics output",
)
@click.option(
    "--only-errors",
    is_flag=True,
    help="Trace only error responses (4xx/5xx)",
)
@click.option(
    "--table",
    "table_mode",
    is_flag=True,
    help="Display traces in table format",
)
@click.option(
    "--host",
    "filter_host",
    default=None,
    help="Filter traces by host",
    metavar="HOST",
)
@click.option(
    "--path",
    "filter_path",
    default=None,
    help="Filter traces by path",
    metavar="PATH",
)
@click.option(
    "--min-latency",
    type=int,
    default=None,
    help="Show only requests slower than N ms",
    metavar="MS",
)
def start(
    listen: str,
    target: str,
    cert_dir: Path,
    log_dir: Path,
    trace: bool,
    verbose: bool,
    stats: bool,
    only_errors: bool,
    table_mode: bool,
    filter_host: Optional[str],
    filter_path: Optional[str],
    min_latency: Optional[int],
) -> None:
    """Start the reverse proxy.

    Examples:

        sentinelproxy start --target https://api.example.com

        sentinelproxy start --listen 8080 --target https://api.example.com --trace

        sentinelproxy start --target https://api.example.com --trace --only-errors
    """
    # Import here to avoid circular imports and speed up --help
    from sentinelproxy.proxy import start_proxy

    # Parse listen address
    host, port = parse_listen_address(listen)

    # Build config
    config = ProxyConfig(
        listen_host=host,
        listen_port=port,
        target=target,
        cert_dir=cert_dir,
        log_dir=log_dir,
        trace=trace,
        verbose=verbose,
        stats=stats,
        only_errors=only_errors,
        table_mode=table_mode,
        filter_host=filter_host,
        filter_path=filter_path,
        min_latency=min_latency,
    )

    # Start proxy
    exit_code = start_proxy(config)
    sys.exit(exit_code)


@main.group()
def cert() -> None:
    """Certificate management commands."""
    pass


@cert.command("status")
@click.option(
    "--cert-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Certificate directory (uses default mitmproxy location if not specified)",
    metavar="DIR",
)
def cert_status(cert_dir: Optional[Path]) -> None:
    """Show certificate status.

    Displays information about the root CA certificate used for
    TLS interception.
    """
    print_cert_status(cert_dir)


@cert.command("install")
def cert_install() -> None:
    """Show certificate installation instructions.

    Prints OS-specific instructions for installing the root CA
    certificate into the system trust store.
    """
    print_install_instructions()


if __name__ == "__main__":
    main()
