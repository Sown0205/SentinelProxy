"""Logging system for SentinelProxy."""

import json
import logging
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue, Empty
from typing import Any, Optional
from dataclasses import dataclass, field, asdict

import colorama
from colorama import Fore, Style

# Initialize colorama for Windows support
colorama.init()


class SentinelFormatter(logging.Formatter):
    """Custom formatter for SentinelProxy console output.

    Format: [LEVEL] TIMESTAMP | COMPONENT | MESSAGE
    """

    LEVEL_COLORS = {
        logging.DEBUG: Fore.WHITE,
        logging.INFO: Fore.CYAN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record: logging.LogRecord) -> str:
        # Get component from record or default to 'main'
        component = getattr(record, "component", "main")

        # Format timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Get level color
        color = self.LEVEL_COLORS.get(record.levelno, Fore.WHITE)

        # Build formatted message
        level_str = f"[{record.levelname}]"
        formatted = f"{color}{level_str:<10}{Style.RESET_ALL} {timestamp} | {component:<7} | {record.getMessage()}"

        return formatted


class ComponentLogger:
    """Logger wrapper that adds component context."""

    def __init__(self, logger: logging.Logger, component: str):
        self._logger = logger
        self._component = component

    def _log(self, level: int, msg: str, *args, **kwargs) -> None:
        kwargs.setdefault("extra", {})["component"] = self._component
        self._logger.log(level, msg, *args, **kwargs)

    def debug(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.INFO, msg, *args, **kwargs)

    def warning(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.ERROR, msg, *args, **kwargs)

    def critical(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.CRITICAL, msg, *args, **kwargs)


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up the SentinelProxy logging system.

    Args:
        verbose: Enable DEBUG level output

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("sentinelproxy")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(SentinelFormatter())
    logger.addHandler(console_handler)

    return logger


def get_component_logger(component: str) -> ComponentLogger:
    """Get a logger for a specific component.

    Args:
        component: Component name (cli, proxy, engine, addon, tls, log, display)

    Returns:
        ComponentLogger instance
    """
    logger = logging.getLogger("sentinelproxy")
    return ComponentLogger(logger, component)


# Traffic log schema
@dataclass
class ClientInfo:
    """Client connection information."""
    ip: str
    port: int


@dataclass
class ServerInfo:
    """Server connection information."""
    host: str
    port: int
    ip: Optional[str] = None


@dataclass
class TLSInfo:
    """TLS connection details."""
    version: Optional[str] = None
    alpn: Optional[str] = None
    cipher: Optional[str] = None


@dataclass
class RequestInfo:
    """HTTP request information."""
    method: str
    path: str
    http_version: str
    headers: dict[str, str] = field(default_factory=dict)
    size: int = 0


@dataclass
class ResponseInfo:
    """HTTP response information."""
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    size: int = 0


@dataclass
class AIInfo:
    """AI analysis placeholder."""
    anomaly_score: Optional[float] = None
    notes: Optional[str] = None


@dataclass
class TrafficEvent:
    """Complete traffic event for logging."""
    request_id: str
    timestamp: str
    client: ClientInfo
    server: ServerInfo
    tls: TLSInfo
    request: RequestInfo
    response: ResponseInfo
    latency_ms: int
    flags: list[str] = field(default_factory=list)
    ai: AIInfo = field(default_factory=AIInfo)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))


class TrafficLogger:
    """Async JSON traffic logger."""

    def __init__(self, log_dir: Path):
        self._log_dir = log_dir
        self._queue: Queue[TrafficEvent] = Queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._file_handle = None
        self._event_count = 0
        self._error_count = 0
        self._start_time: Optional[datetime] = None
        self._first_event = True

    def start(self) -> Path:
        """Start the logger thread.

        Returns:
            Path to the session log file
        """
        self._log_dir.mkdir(parents=True, exist_ok=True)

        # Generate session filename
        session_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self._log_dir / f"session_{session_time}.json"

        self._file_handle = open(log_file, "w", encoding="utf-8")
        self._file_handle.write("[\n")  # Start JSON array
        self._running = True
        self._start_time = datetime.now()
        self._first_event = True
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

        return log_file

    def _worker(self) -> None:
        """Worker thread that writes events to file."""
        while self._running or not self._queue.empty():
            try:
                event = self._queue.get(timeout=0.1)
                if self._file_handle:
                    # Pretty print each event with indentation
                    event_json = json.dumps(event.to_dict(), indent=2)
                    # Indent the whole block by 2 spaces
                    indented = "\n".join("  " + line for line in event_json.split("\n"))

                    if self._first_event:
                        self._file_handle.write(indented)
                        self._first_event = False
                    else:
                        self._file_handle.write(",\n" + indented)
                    self._file_handle.flush()
                self._queue.task_done()
            except Empty:
                continue

    def log(self, event: TrafficEvent) -> None:
        """Queue a traffic event for logging.

        Args:
            event: Traffic event to log
        """
        self._event_count += 1
        if event.response.status >= 400:
            self._error_count += 1
        self._queue.put(event)

    def stop(self) -> dict[str, Any]:
        """Stop the logger and return session statistics.

        Returns:
            Session statistics dictionary
        """
        self._running = False

        if self._thread:
            self._thread.join(timeout=5.0)

        if self._file_handle:
            self._file_handle.write("\n]")  # Close JSON array
            self._file_handle.close()

        duration = datetime.now() - self._start_time if self._start_time else None
        duration_str = str(duration).split(".")[0] if duration else "00:00:00"

        return {
            "requests": self._event_count,
            "errors": self._error_count,
            "duration": duration_str,
        }


# Sensitive headers to filter out
FILTERED_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "proxy-authorization",
}


def filter_headers(headers: dict[str, str]) -> dict[str, str]:
    """Filter sensitive headers from logging.

    Args:
        headers: Original headers dict

    Returns:
        Filtered headers dict
    """
    return {
        k: v for k, v in headers.items()
        if k.lower() not in FILTERED_HEADERS
    }
