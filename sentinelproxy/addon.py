"""mitmproxy addon for SentinelProxy traffic interception."""

import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from mitmproxy import http, ctx
from mitmproxy.flow import Flow

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
        traffic_logger: TrafficLogger,
        live_display: Optional[LiveDisplay] = None,
        trace_enabled: bool = False,
    ):
        """Initialize the addon.

        Args:
            traffic_logger: TrafficLogger instance for JSONL logging
            live_display: Optional LiveDisplay for real-time tracing
            trace_enabled: Whether live tracing is enabled
        """
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

        log.debug(f"Request #{request_id}: {flow.request.method} {flow.request.path}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response.

        Called when a server response has been received.
        """
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
