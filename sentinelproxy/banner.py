"""ASCII banner for SentinelProxy."""

from colorama import Fore, Style

from sentinelproxy import __version__, __author__

BANNER_ART = f"""
⠀⠀⠀⠀⣀⡀
⠀⠀⠀⠀⣿⠙⣦⠀⠀⠀⠀⠀⠀⣀⣤⡶⠛⠁
⠀⠀⠀⠀⢻⠀⠈⠳⠀⠀⣀⣴⡾⠛⠁⣠⠂⢠⠇
⠀⠀⠀⠀⠈⢀⣀⠤⢤⡶⠟⠁⢀⣴⣟⠀⠀⣾
⠀⠀⠀⠠⠞⠉⢁⠀⠉⠀⢀⣠⣾⣿⣏⠀⢠⡇
⠀⠀⡰⠋⠀⢰⠃⠀⠀⠉⠛⠿⠿⠏⠁⠀⣸⠁
⠀⠀⣄⠀⠀⠏⣤⣤⣀⡀⠀⠀⠀⠀⠀⠾⢯⣀
⠀⠀⣻⠃⠀⣰⡿⠛⠁⠀⠀⠀⢤⣀⡀⠀⠺⣿⡟⠛⠁
⠀⡠⠋⡤⠠⠋⠀⠀⢀⠐⠁⠀⠈⣙⢯⡃⠀⢈⡻⣦
⢰⣷⠇⠀⠀⠀⢀⡠⠃⠀⠀⠀⠀⠈⠻⢯⡄⠀⢻⣿⣷
⠀⠉⠲⣶⣶⢾⣉⣐⡚⠋⠀⠀⠀⠀⠀⠘⠀⠀⡎⣿⣿⡇
⠀⠀⠀⠀⠀⣸⣿⣿⣿⣷⡄⠀⠀⢠⣿⣴⠀⠀⣿⣿⣿⣧
⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⠇⠀⢠⠟⣿⠏⢀⣾⠟⢸⣿⡇
⠀⠀⢠⣿⣿⣿⣿⠟⠘⠁⢠⠜⢉⣐⡥⠞⠋⢁⣴⣿⣿⠃
⠀⠀⣾⢻⣿⣿⠃⠀⠀⡀⢀⡄⠁⠀⠀⢠⡾
⠀⠀⠃⢸⣿⡇⠀⢠⣾⡇⢸⡇⠀⠀⠀⡞
⠀⠀⠀⠈⢿⡇⡰⠋⠈⠙⠂⠙⠢
⠀⠀⠀⠀⠈⢧
"""


def get_banner(mode: str = "reverse", model: str = "None") -> str:
    """Generate the full startup banner.

    Args:
        mode: Proxy mode (reverse, forward, etc.)
        model: AI model name if configured

    Returns:
        Formatted banner string
    """
    # Info lines to display on the right
    info_lines = [
        f"{Fore.CYAN}SentinelProxy{Style.RESET_ALL} v{__version__}",
        f"{Fore.CYAN}Author:{Style.RESET_ALL} {__author__}",
        "",
        "AI-assisted HTTPS reverse proxy",
        "& traffic analyzer",
        "",
        f"{Fore.CYAN}Engine:{Style.RESET_ALL} {Fore.GREEN}mitmproxy{Style.RESET_ALL}",
        f"{Fore.CYAN}Mode:{Style.RESET_ALL}   {mode}",
        f"{Fore.CYAN}Model:{Style.RESET_ALL}  {model}",
    ]

    # Split banner art into lines (skip empty first/last lines)
    art_lines = BANNER_ART.strip().split("\n")

    # Find the max width of art lines for padding
    max_art_width = max(len(line) for line in art_lines) if art_lines else 0
    padding = 4  # Space between art and info

    # Start info lines at line 3 (0-indexed: 2) for visual balance
    start_info_line = 2

    # Build the combined banner
    result_lines = []
    for i, art_line in enumerate(art_lines):
        # Pad the art line to consistent width
        padded_art = art_line.ljust(max_art_width)

        # Get corresponding info line if available
        info_index = i - start_info_line
        if 0 <= info_index < len(info_lines):
            info_text = info_lines[info_index]
        else:
            info_text = ""

        result_lines.append(f"{padded_art}{' ' * padding}{info_text}")

    # Add separator
    separator = "-" * 100
    result_lines.append(separator)

    return "\n".join(result_lines)

def print_banner(mode: str = "reverse", model: str = "None") -> None:
    """Print the startup banner to stdout."""
    print(get_banner(mode, model))
