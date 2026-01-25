"""Live traffic display for SentinelProxy."""

import threading
from datetime import datetime
from queue import Queue, Empty
from typing import Optional, List, Any
from dataclasses import dataclass

import colorama
from colorama import Fore, Style
from tabulate import tabulate

# Initialize colorama for Windows support
colorama.init()


@dataclass
class TraceEvent:
    """Event for live trace display."""
    request_id: str
    timestamp: datetime
    client_ip: str
    server_host: str
    method: str
    path: str
    status: int
    latency_ms: int
    tls_version: Optional[str] = None
    alpn: Optional[str] = None
    request_size: Optional[int] = None
    response_size: Optional[int] = None


def get_status_color(status: int) -> str:
    """Get color code for HTTP status."""
    if 200 <= status < 300:
        return Fore.GREEN
    elif 300 <= status < 400:
        return Fore.YELLOW
    elif status >= 400:
        return Fore.RED
    return Fore.WHITE


def truncate_path(path: str, max_len: int = 40) -> str:
    """Truncate path for display."""
    if len(path) <= max_len:
        return path
    return path[:max_len - 3] + "..."


def format_size(size: Optional[int]) -> str:
    """Format size in human readable format."""
    if size is None:
        return ""
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f}MB"
    elif size >= 1024:
        return f"{size / 1024:.1f}KB"
    return f"{size}B"


def format_trace_line(event: TraceEvent, verbose: bool = False) -> str:
    """Format a trace event into a display line.

    Standard format:
    [REQ#1]    12:43:12   127.0.0.1       -> api.example.com     POST   /v1/login                  401    92ms

    Verbose format:
    [REQ#1]    12:43:12   TLSv1.3  127.0.0.1       -> api.example.com     POST   /v1/login                  401    92ms   842B
    """
    time_str = event.timestamp.strftime("%H:%M:%S")
    status_color = get_status_color(event.status)
    path_display = truncate_path(event.path)

    # Fixed-width columns for consistent alignment
    req_id = f"[REQ#{event.request_id}]"

    if verbose:
        # Verbose format with TLS info and size
        tls_info = event.tls_version or "---"
        size_str = format_size(event.response_size)

        line = (
            f"{Fore.CYAN}{req_id:<11}{Style.RESET_ALL}"
            f"{time_str}   "
            f"{tls_info:<8} "
            f"{event.client_ip:<15} -> {event.server_host:<20} "
            f"{event.method:<6} {path_display:<40} "
            f"{status_color}{event.status:<3}{Style.RESET_ALL} "
            f"{event.latency_ms:>6}ms"
        )
        if size_str:
            line += f"  {size_str:>8}"
    else:
        # Standard format with proper alignment
        line = (
            f"{Fore.CYAN}{req_id:<11}{Style.RESET_ALL}"
            f"{time_str}   "
            f"{event.client_ip:<15} -> {event.server_host:<20} "
            f"{event.method:<6} {path_display:<40} "
            f"{status_color}{event.status:<3}{Style.RESET_ALL} "
            f"{event.latency_ms:>6}ms"
        )

    return line


# Table mode constants - rounded grid style
TABLE_HEADERS = ["ID", "Time", "Client", "Server", "Method", "Path", "Status", "Latency", "Size"]
TABLE_WIDTHS = [6, 8, 15, 20, 7, 35, 6, 9, 9]

# Box drawing characters for rounded grid
BOX_TOP_LEFT = "╭"
BOX_TOP_RIGHT = "╮"
BOX_BOTTOM_LEFT = "╰"
BOX_BOTTOM_RIGHT = "╯"
BOX_HORIZONTAL = "─"
BOX_VERTICAL = "│"
BOX_TOP_TEE = "┬"
BOX_BOTTOM_TEE = "┴"
BOX_LEFT_TEE = "├"
BOX_RIGHT_TEE = "┤"
BOX_CROSS = "┼"


def _build_horizontal_line(left: str, mid: str, right: str) -> str:
    """Build a horizontal line with box drawing characters."""
    segments = [BOX_HORIZONTAL * (w + 2) for w in TABLE_WIDTHS]
    return left + mid.join(segments) + right


def _build_row(values: List[str], color_idx: Optional[int] = None, color: str = "") -> str:
    """Build a data row with proper padding and box characters."""
    cells = []
    for i, (val, width) in enumerate(zip(values, TABLE_WIDTHS)):
        # Handle color for specific column
        if i == color_idx and color:
            # Account for ANSI codes not taking visual space
            padded = f" {color}{val}{Style.RESET_ALL}".ljust(width + 2 + len(color) + len(Style.RESET_ALL))
            # Recalculate padding without ANSI codes
            visible_len = len(val)
            padding_needed = width - visible_len
            padded = f" {color}{val}{Style.RESET_ALL}" + " " * (padding_needed + 1)
        else:
            padded = f" {val:<{width}} "
        cells.append(padded)
    return BOX_VERTICAL + BOX_VERTICAL.join(cells) + BOX_VERTICAL


def get_table_header() -> str:
    """Get the table header with rounded grid style."""
    top_line = _build_horizontal_line(BOX_TOP_LEFT, BOX_TOP_TEE, BOX_TOP_RIGHT)
    header_row = _build_row(TABLE_HEADERS)
    separator = _build_horizontal_line(BOX_LEFT_TEE, BOX_CROSS, BOX_RIGHT_TEE)

    return f"{Fore.WHITE}{Style.BRIGHT}{top_line}\n{header_row}\n{separator}{Style.RESET_ALL}"


def get_table_footer() -> str:
    """Get the table footer (bottom border)."""
    return _build_horizontal_line(BOX_BOTTOM_LEFT, BOX_BOTTOM_TEE, BOX_BOTTOM_RIGHT)


def format_table_row(event: TraceEvent) -> str:
    """Format a trace event as a table row with rounded grid style."""
    time_str = event.timestamp.strftime("%H:%M:%S")
    status_color = get_status_color(event.status)
    path_display = truncate_path(event.path, TABLE_WIDTHS[5])
    size_str = format_size(event.response_size) or "-"
    latency_str = f"{event.latency_ms}ms"

    row = [
        str(event.request_id),
        time_str,
        event.client_ip,
        event.server_host,
        event.method,
        path_display,
        str(event.status),
        latency_str,
        size_str,
    ]

    return _build_row(row, color_idx=6, color=status_color)


class TraceFilter:
    """Filter for trace events."""

    def __init__(
        self,
        only_errors: bool = False,
        host_filter: Optional[str] = None,
        path_filter: Optional[str] = None,
        min_latency: Optional[int] = None,
    ):
        self.only_errors = only_errors
        self.host_filter = host_filter
        self.path_filter = path_filter
        self.min_latency = min_latency

    def matches(self, event: TraceEvent) -> bool:
        """Check if event matches filter criteria."""
        if self.only_errors and event.status < 400:
            return False

        if self.host_filter and self.host_filter not in event.server_host:
            return False

        if self.path_filter and self.path_filter not in event.path:
            return False

        if self.min_latency is not None and event.latency_ms < self.min_latency:
            return False

        return True


class LiveDisplay:
    """Non-blocking live traffic display."""

    MAX_QUEUE_SIZE = 1000  # Drop events if queue exceeds this

    def __init__(
        self,
        verbose: bool = False,
        table_mode: bool = False,
        trace_filter: Optional[TraceFilter] = None,
    ):
        self._verbose = verbose
        self._table_mode = table_mode
        self._filter = trace_filter or TraceFilter()
        self._queue: Queue[TraceEvent] = Queue(maxsize=self.MAX_QUEUE_SIZE)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._dropped_count = 0
        self._header_printed = False

    def start(self) -> None:
        """Start the display thread."""
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self) -> None:
        """Worker thread that prints trace events."""
        while self._running or not self._queue.empty():
            try:
                event = self._queue.get(timeout=0.1)
                if self._filter.matches(event):
                    if self._table_mode:
                        if not self._header_printed:
                            print(get_table_header())
                            self._header_printed = True
                        line = format_table_row(event)
                    else:
                        line = format_trace_line(event, self._verbose)
                    print(line)
                self._queue.task_done()
            except Empty:
                continue

    def emit(self, event: TraceEvent) -> None:
        """Queue a trace event for display.

        Non-blocking: drops events if queue is full.
        """
        try:
            self._queue.put_nowait(event)
        except:
            # Queue full, drop event
            self._dropped_count += 1

    def stop(self) -> int:
        """Stop the display thread.

        Returns:
            Number of dropped events
        """
        self._running = False

        if self._thread:
            self._thread.join(timeout=2.0)

        # Print table footer if we printed any rows
        if self._table_mode and self._header_printed:
            print(get_table_footer())

        return self._dropped_count
