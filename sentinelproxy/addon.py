"""mitmproxy addon for SentinelProxy traffic interception."""

import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from mitmproxy import http, ctx
from mitmproxy.flow import Flow

from sentinelproxy.config import ProxyConfig
from sentinelproxy.logger import (
    TrafficEvent,
    TrafficLogger,
    ClientInfo,
    ServerInfo,
    TLSInfo,
    RequestInfo,
    ResponseInfo,
    filter_headers,
    get_component_logger,
)
from sentinelproxy.display import LiveDisplay, TraceEvent, TraceFilter

log = get_component_logger("addon")


class SentinelAddon:
    """mitmproxy addon for request/response tracking and logging."""

    def __init__(
        self,
        config: ProxyConfig,
        traffic_logger: TrafficLogger,
        live_display: Optional[LiveDisplay] = None,
        trace_enabled: bool = False,
    ):
        """Initialize the addon.

        Args:
            config: Proxy configuration
            traffic_logger: TrafficLogger instance for JSONL logging
            live_display: Optional LiveDisplay for real-time tracing
            trace_enabled: Whether live tracing is enabled
        """
        self._config = config
        self._traffic_logger = traffic_logger
        self._live_display = live_display
        self._trace_enabled = trace_enabled
        self._request_counter = 0

    def _next_request_id(self) -> str:
        """Generate next request ID."""
        self._request_counter += 1
        return str(self._request_counter)

    def request(self, flow: http.HTTPFlow) -> None:
        """Handle incoming request.

        Called when a client request has been received.
        """
        # Assign request ID and store metadata
        request_id = self._next_request_id()
        flow.metadata["sentinel_request_id"] = request_id
        flow.metadata["sentinel_start_time"] = time.time()

        # CORS Header Rewriting
        if self._config.cors_rewrite:
            self._rewrite_cors_request_headers(flow)

        log.debug(f"Request #{request_id}: {flow.request.method} {flow.request.path}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response.

        Called when a server response has been received.
        """
        # CORS Header Rewriting - Response
        if self._config.cors_rewrite:
            self._rewrite_cors_response_headers(flow)

        # Retrieve request context
        request_id = flow.metadata.get("sentinel_request_id", "unknown")
        start_time = flow.metadata.get("sentinel_start_time", time.time())

        # Calculate latency
        latency_ms = int((time.time() - start_time) * 1000)

        # Build traffic event
        event = self._build_traffic_event(flow, request_id, latency_ms)

        # Log to JSONL
        self._traffic_logger.log(event)

        # Emit to live display if enabled
        if self._trace_enabled and self._live_display:
            trace_event = self._build_trace_event(flow, request_id, latency_ms)
            self._live_display.emit(trace_event)

        log.debug(
            f"Response #{request_id}: {flow.response.status_code} ({latency_ms}ms)"
        )

    def error(self, flow: http.HTTPFlow) -> None:
        """Handle flow error.

        Called when a flow error occurs.
        """
        request_id = flow.metadata.get("sentinel_request_id", "unknown")
        error_msg = str(flow.error) if flow.error else "Unknown error"
        log.error(f"Flow #{request_id} error: {error_msg}")

    def _build_traffic_event(
        self, flow: http.HTTPFlow, request_id: str, latency_ms: int
    ) -> TrafficEvent:
        """Build a TrafficEvent from a completed flow."""
        req = flow.request
        resp = flow.response

        # Client info
        client_conn = flow.client_conn
        client = ClientInfo(
            ip=client_conn.peername[0] if client_conn.peername else "unknown",
            port=client_conn.peername[1] if client_conn.peername else 0,
        )

        # Server info
        server_conn = flow.server_conn
        server = ServerInfo(
            host=req.host,
            port=req.port,
            ip=server_conn.peername[0] if server_conn and server_conn.peername else None,
        )

        # TLS info
        tls = TLSInfo()
        if server_conn and server_conn.tls_version:
            tls.version = server_conn.tls_version
        if server_conn and hasattr(server_conn, "alpn") and server_conn.alpn:
            tls.alpn = server_conn.alpn.decode() if isinstance(server_conn.alpn, bytes) else server_conn.alpn
        if server_conn and hasattr(server_conn, "cipher") and server_conn.cipher:
            tls.cipher = server_conn.cipher[0] if server_conn.cipher else None

        # Request info - extract path without query
        path = req.path
        if "?" in path:
            path = path.split("?")[0]

        request_info = RequestInfo(
            method=req.method,
            path=path,
            http_version=req.http_version,
            headers=filter_headers(dict(req.headers)),
            size=len(req.content) if req.content else 0,
        )

        # Response info
        response_info = ResponseInfo(
            status=resp.status_code if resp else 0,
            headers=filter_headers(dict(resp.headers)) if resp else {},
            size=len(resp.content) if resp and resp.content else 0,
        )

        # Determine flags
        flags = []
        if resp:
            if resp.status_code == 401:
                flags.append("auth_failed")
            elif resp.status_code == 403:
                flags.append("forbidden")
            elif resp.status_code >= 500:
                flags.append("server_error")
            elif resp.status_code >= 400:
                flags.append("client_error")

        return TrafficEvent(
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            client=client,
            server=server,
            tls=tls,
            request=request_info,
            response=response_info,
            latency_ms=latency_ms,
            flags=flags,
        )

    def _build_trace_event(
        self, flow: http.HTTPFlow, request_id: str, latency_ms: int
    ) -> TraceEvent:
        """Build a TraceEvent for live display."""
        req = flow.request
        resp = flow.response
        server_conn = flow.server_conn
        client_conn = flow.client_conn

        # Extract path without query
        path = req.path
        if "?" in path:
            path = path.split("?")[0]

        # TLS info
        tls_version = None
        alpn = None
        if server_conn:
            tls_version = server_conn.tls_version
            if hasattr(server_conn, "alpn") and server_conn.alpn:
                alpn = server_conn.alpn.decode() if isinstance(server_conn.alpn, bytes) else server_conn.alpn

        return TraceEvent(
            request_id=request_id,
            timestamp=datetime.now(),
            client_ip=client_conn.peername[0] if client_conn.peername else "unknown",
            server_host=req.host,
            method=req.method,
            path=path,
            status=resp.status_code if resp else 0,
            latency_ms=latency_ms,
            tls_version=tls_version,
            alpn=alpn,
            request_size=len(req.content) if req.content else 0,
            response_size=len(resp.content) if resp and resp.content else 0,
        )

    # -------------------------------------------------------------------------
    # CORS Header Rewriting
    # -------------------------------------------------------------------------

    def _get_target_origin_for_request(self, flow: http.HTTPFlow) -> str:
        """Get the target origin for CORS rewriting.

        In forward mode: derived from the actual request destination
        In reverse mode: derived from config.target or config.cors_origin

        Args:
            flow: The HTTP flow to get the origin for

        Returns:
            The target origin string (e.g., "https://api.example.com")
        """
        # If custom cors_origin is set, always use it
        if self._config.cors_origin:
            return self._config.cors_origin

        # In forward mode, derive from the actual request
        if self._config.forward_mode:
            req = flow.request
            scheme = req.scheme
            host = req.host
            port = req.port

            # Include port only if non-standard
            if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
                return f"{scheme}://{host}:{port}"
            return f"{scheme}://{host}"

        # Reverse mode - use configured target
        parsed = urlparse(self._config.target)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _rewrite_referer_url(self, original_referer: str, target_origin: str) -> str:
        """Rewrite Referer URL, replacing origin but preserving path.

        Args:
            original_referer: Original Referer header value
            target_origin: Target origin to use

        Returns:
            Rewritten Referer URL
        """
        parsed = urlparse(original_referer)
        # Keep the path portion, replace the origin
        return f"{target_origin}{parsed.path}"

    def _rewrite_cors_request_headers(self, flow: http.HTTPFlow) -> None:
        """Rewrite Origin and Referer headers to match target server.

        Stores original values in flow metadata for response rewriting.
        """
        target_origin = self._get_target_origin_for_request(flow)

        # Store and rewrite Origin header
        original_origin = flow.request.headers.get("Origin")
        if original_origin:
            flow.metadata["sentinel_original_origin"] = original_origin
            flow.request.headers["Origin"] = target_origin
            log.debug(f"CORS: Rewrote Origin from {original_origin} to {target_origin}")

        # Store and rewrite Referer header
        original_referer = flow.request.headers.get("Referer")
        if original_referer:
            flow.metadata["sentinel_original_referer"] = original_referer
            new_referer = self._rewrite_referer_url(original_referer, target_origin)
            flow.request.headers["Referer"] = new_referer
            log.debug(f"CORS: Rewrote Referer from {original_referer} to {new_referer}")

    def _rewrite_cors_response_headers(self, flow: http.HTTPFlow) -> None:
        """Rewrite Access-Control-Allow-Origin to allow original origin.

        Restores the original origin in CORS response headers so the
        browser accepts the response.
        """
        original_origin = flow.metadata.get("sentinel_original_origin")
        if not original_origin:
            return  # No original origin stored, skip

        if not flow.response:
            return

        allow_origin = flow.response.headers.get("Access-Control-Allow-Origin")

        # If Access-Control-Allow-Origin exists and is not wildcard, rewrite it
        if allow_origin and allow_origin != "*":
            flow.response.headers["Access-Control-Allow-Origin"] = original_origin
            log.debug(
                f"CORS: Rewrote Access-Control-Allow-Origin from {allow_origin} to {original_origin}"
            )

        # Handle credentials case: if credentials allowed, origin must be specific
        if flow.response.headers.get("Access-Control-Allow-Credentials") == "true":
            flow.response.headers["Access-Control-Allow-Origin"] = original_origin
