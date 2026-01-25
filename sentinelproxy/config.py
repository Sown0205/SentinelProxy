"""Configuration management for SentinelProxy."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import os


@dataclass
class ProxyConfig:
    """Proxy configuration settings."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    target: str = ""
    cert_dir: Path = field(default_factory=lambda: Path("certs"))
    log_dir: Path = field(default_factory=lambda: Path("logs"))

    # Display options
    trace: bool = False
    verbose: bool = False
    stats: bool = False
    only_errors: bool = False
    table_mode: bool = False

    # Filters
    filter_host: Optional[str] = None
    filter_path: Optional[str] = None
    min_latency: Optional[int] = None

    @property
    def listen_address(self) -> str:
        """Get full listen address."""
        return f"{self.listen_host}:{self.listen_port}"

    def validate(self) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []

        if not self.target:
            errors.append("Target URL is required")
        elif not self.target.startswith(("http://", "https://")):
            errors.append("Target must be a valid HTTP/HTTPS URL")

        if self.listen_port < 1 or self.listen_port > 65535:
            errors.append("Listen port must be between 1 and 65535")

        if self.min_latency is not None and self.min_latency < 0:
            errors.append("Minimum latency must be non-negative")

        return errors

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)


def parse_listen_address(address: str) -> tuple[str, int]:
    """Parse listen address into host and port."""
    if ":" in address:
        parts = address.rsplit(":", 1)
        return parts[0], int(parts[1])
    return "127.0.0.1", int(address)
