"""Certificate management for SentinelProxy."""

import platform
import subprocess
from pathlib import Path
from typing import Optional

from sentinelproxy.logger import get_component_logger

log = get_component_logger("tls")


# Default mitmproxy CA file names
CA_CERT_NAME = "mitmproxy-ca-cert.pem"
CA_KEY_NAME = "mitmproxy-ca.pem"


def get_default_cert_dir() -> Path:
    """Get the default mitmproxy certificate directory."""
    home = Path.home()
    return home / ".mitmproxy"


def check_ca_exists(cert_dir: Optional[Path] = None) -> bool:
    """Check if root CA certificate exists.

    Args:
        cert_dir: Certificate directory (uses default if None)

    Returns:
        True if CA exists
    """
    cert_dir = cert_dir or get_default_cert_dir()
    ca_cert = cert_dir / CA_CERT_NAME
    return ca_cert.exists()


def get_ca_cert_path(cert_dir: Optional[Path] = None) -> Path:
    """Get path to CA certificate.

    Args:
        cert_dir: Certificate directory (uses default if None)

    Returns:
        Path to CA certificate
    """
    cert_dir = cert_dir or get_default_cert_dir()
    return cert_dir / CA_CERT_NAME


def get_ca_info(cert_dir: Optional[Path] = None) -> dict:
    """Get information about the CA certificate.

    Args:
        cert_dir: Certificate directory (uses default if None)

    Returns:
        Dictionary with CA info
    """
    cert_dir = cert_dir or get_default_cert_dir()
    ca_cert = cert_dir / CA_CERT_NAME
    ca_key = cert_dir / CA_KEY_NAME

    info = {
        "cert_dir": str(cert_dir),
        "ca_cert_exists": ca_cert.exists(),
        "ca_key_exists": ca_key.exists(),
        "ca_cert_path": str(ca_cert) if ca_cert.exists() else None,
    }

    if ca_cert.exists():
        stat = ca_cert.stat()
        info["ca_cert_size"] = stat.st_size
        info["ca_cert_modified"] = stat.st_mtime

    return info


def get_install_instructions() -> str:
    """Get OS-specific certificate installation instructions.

    Returns:
        Installation instructions string
    """
    system = platform.system().lower()
    ca_path = get_ca_cert_path()

    instructions = f"""
Certificate Installation Instructions
=====================================

CA Certificate Location: {ca_path}

"""

    if system == "windows":
        instructions += """
Windows:
--------
1. Double-click the certificate file: {ca_path}
2. Click "Install Certificate..."
3. Select "Local Machine" and click Next
4. Select "Place all certificates in the following store"
5. Click Browse and select "Trusted Root Certification Authorities"
6. Click Next, then Finish
7. Restart your browser

Or via PowerShell (Admin):
    Import-Certificate -FilePath "{ca_path}" -CertStoreLocation Cert:\\LocalMachine\\Root
""".format(ca_path=ca_path)

    elif system == "darwin":
        instructions += f"""
macOS:
------
1. Open Keychain Access
2. Drag the certificate file into "System" keychain
3. Double-click the imported certificate
4. Expand "Trust" section
5. Set "When using this certificate" to "Always Trust"
6. Close and enter password when prompted

Or via Terminal:
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{ca_path}"
"""

    else:  # Linux
        instructions += f"""
Linux (Debian/Ubuntu):
----------------------
    sudo cp "{ca_path}" /usr/local/share/ca-certificates/mitmproxy-ca.crt
    sudo update-ca-certificates

Linux (Fedora/RHEL):
--------------------
    sudo cp "{ca_path}" /etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt
    sudo update-ca-trust

Linux (Arch):
-------------
    sudo trust anchor "{ca_path}"

Firefox (all platforms):
------------------------
1. Open Firefox Preferences/Settings
2. Search for "certificates"
3. Click "View Certificates"
4. Go to "Authorities" tab
5. Click "Import" and select the certificate
6. Check "Trust this CA to identify websites"
"""

    instructions += """
After Installation:
-------------------
- Restart your browser
- Verify by visiting a HTTPS site through the proxy
- The certificate should show as trusted
"""

    return instructions


def print_cert_status(cert_dir: Optional[Path] = None) -> None:
    """Print certificate status to console.

    Args:
        cert_dir: Certificate directory (uses default if None)
    """
    from colorama import Fore, Style

    info = get_ca_info(cert_dir)

    print("\nSentinelProxy Certificate Status")
    print("=" * 40)
    print(f"Certificate Directory: {info['cert_dir']}")

    if info["ca_cert_exists"]:
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Root CA certificate found")
        print(f"     Path: {info['ca_cert_path']}")
    else:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Root CA not found")
        print("     Run 'sentinelproxy start' to generate certificates")
        print("     mitmproxy will create the CA on first run")

    if info.get("ca_key_exists"):
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} CA private key found")
    else:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} CA private key not found")

    print()


def print_install_instructions() -> None:
    """Print certificate installation instructions."""
    ca_path = get_ca_cert_path()

    if not ca_path.exists():
        from colorama import Fore, Style
        print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} CA certificate not found.")
        print("    Run 'sentinelproxy start' first to generate certificates.")
        print("    mitmproxy will create the CA on first run.\n")
        return

    print(get_install_instructions())
