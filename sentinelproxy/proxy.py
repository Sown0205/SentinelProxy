"""Proxy engine for SentinelProxy using mitmproxy."""

import asyncio
import signal
import sys
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from sentinelproxy.config import ProxyConfig
from sentinelproxy.logger import (
    TrafficLogger,
    get_component_logger,
    setup_logging,
)
from sentinelproxy.display import LiveDisplay, TraceFilter
from sentinelproxy.addon import SentinelAddon
from sentinelproxy.banner import print_banner

log = get_component_logger("proxy")
engine_log = get_component_logger("engine")


class ProxyEngine:
    """SentinelProxy engine wrapping mitmproxy."""

    def __init__(self, config: ProxyConfig):
        """Initialize the proxy engine.

        Args:
            config: Proxy configuration
        """
        self._config = config
        self._master: Optional[DumpMaster] = None
        self._traffic_logger: Optional[TrafficLogger] = None
        self._live_display: Optional[LiveDisplay] = None
        self._shutdown_event = threading.Event()

    def _setup_signal_handlers(self) -> None:
        """Set up graceful shutdown signal handlers."""
        def handle_shutdown(signum, frame):
            log.info("Received shutdown signal")
            self._shutdown_event.set()
            if self._master:
                self._master.shutdown()

        # Handle SIGINT (Ctrl+C) and SIGTERM
        signal.signal(signal.SIGINT, handle_shutdown)
        signal.signal(signal.SIGTERM, handle_shutdown)

    def run(self) -> int:
        """Run the proxy engine.

        Returns:
            Exit code (0 for success)
        """
        # Set up logging
        setup_logging(verbose=self._config.verbose)

        # Validate config
        errors = self._config.validate()
        if errors:
            for error in errors:
                log.error(error)
            return 1

        # Ensure directories exist
        self._config.ensure_directories()

        # Print banner if not in quiet mode
        if sys.stdout.isatty():
            print_banner()

        log.info("Starting SentinelProxy")

        # Determine proxy mode and parse target if needed
        if self._config.forward_mode:
            log.info("Mode: Forward proxy")
            log.info(f"Listening on {self._config.listen_address}")
            log.info("Configure your browser to use HTTP/HTTPS proxy: "
                     f"{self._config.listen_host}:{self._config.listen_port}")
            target_host = None
            target_scheme = None
        else:
            # Parse target URL for reverse proxy mode
            parsed_target = urlparse(self._config.target)
            target_host = parsed_target.netloc or parsed_target.path
            target_scheme = parsed_target.scheme or "https"
            log.info("Mode: Reverse proxy")
            log.info(f"Target: {target_scheme}://{target_host}")
            log.info(f"Listening on {self._config.listen_address}")

        # Start traffic logger
        self._traffic_logger = TrafficLogger(self._config.log_dir)
        log_file = self._traffic_logger.start()
        log.info(f"Logging to {log_file}")

        # Set up live display if tracing enabled
        if self._config.trace:
            trace_filter = TraceFilter(
                only_errors=self._config.only_errors,
                host_filter=self._config.filter_host,
                path_filter=self._config.filter_path,
                min_latency=self._config.min_latency,
            )
            self._live_display = LiveDisplay(
                verbose=self._config.verbose,
                table_mode=self._config.table_mode,
                trace_filter=trace_filter,
            )
            self._live_display.start()
            mode_str = "table mode" if self._config.table_mode else "standard mode"
            log.info(f"Live tracing enabled ({mode_str})")

        # Log CORS rewriting status
        if self._config.cors_rewrite:
            if self._config.cors_origin:
                log.info(f"CORS header rewriting enabled (origin: {self._config.cors_origin})")
            elif self._config.forward_mode:
                log.info("CORS header rewriting enabled (dynamic origin per request)")
            else:
                log.info(f"CORS header rewriting enabled (origin: {target_scheme}://{target_host})")

        # Run the proxy
        try:
            asyncio.run(self._run_proxy(target_host, target_scheme))
        except KeyboardInterrupt:
            pass
        finally:
            self._shutdown()

        return 0

    async def _run_proxy(
        self, target_host: Optional[str] = None, target_scheme: Optional[str] = None
    ) -> None:
        """Run the mitmproxy instance.

        Args:
            target_host: Target server host (None for forward proxy mode)
            target_scheme: Target server scheme (None for forward proxy mode)
        """
        # Configure mitmproxy options based on mode
        if self._config.forward_mode:
            # Forward proxy mode - regular proxy, no target specification
            opts = options.Options(
                listen_host=self._config.listen_host,
                listen_port=self._config.listen_port,
                ssl_insecure=False,
            )
        else:
            # Reverse proxy mode - specify target
            opts = options.Options(
                listen_host=self._config.listen_host,
                listen_port=self._config.listen_port,
                mode=[f"reverse:{target_scheme}://{target_host}/"],
                ssl_insecure=False,
            )

        # Set confdir if custom cert dir specified
        if self._config.cert_dir != Path("certs"):
            opts.confdir = str(self._config.cert_dir)

        # Create mitmproxy master
        self._master = DumpMaster(opts)

        # Create and register our addon
        addon = SentinelAddon(
            config=self._config,
            traffic_logger=self._traffic_logger,
            live_display=self._live_display,
            trace_enabled=self._config.trace,
        )
        self._master.addons.add(addon)

        engine_log.info("mitmproxy engine initialized (Type Ctrl + C to shutdown proxy server)")

        # Set up signal handlers
        self._setup_signal_handlers()

        # Run the proxy
        try:
            await self._master.run()
        except Exception as e:
            engine_log.error(f"Proxy error: {e}")
            raise

    def _shutdown(self) -> None:
        """Perform graceful shutdown."""
        log.info("Shutting down SentinelProxy...")

        # Stop live display
        dropped = 0
        if self._live_display:
            dropped = self._live_display.stop()
            if dropped > 0:
                log.warning(f"Dropped {dropped} display events (queue overflow)")

        # Stop traffic logger and get stats
        stats = {}
        if self._traffic_logger:
            stats = self._traffic_logger.stop()

        # Print session summary
        if stats:
            log.info("Session summary:")
            log.info(f"Requests: {stats.get('requests', 0)}")
            log.info(f"Errors:   {stats.get('errors', 0)}")
            log.info(f"Duration: {stats.get('duration', '00:00:00')}")

        log.info("Goodbye.")


def start_proxy(config: ProxyConfig) -> int:
    """Start the proxy with the given configuration.

    Args:
        config: Proxy configuration

    Returns:
        Exit code
    """
    engine = ProxyEngine(config)
    return engine.run()
