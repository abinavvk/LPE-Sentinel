"""
System Information Module for LPE Sentinel.

Gathers non-sensitive system environment details to identify the target host
and evaluate platform compatibility for security auditing.
"""

import getpass
import os
import platform
import socket
from typing import Any, Dict


def get_platform_category(system_name: str) -> str:
    """
    Categorize operating system into Windows, Linux, macOS, or Other.

    Args:
        system_name: OS name (e.g. from platform.system()).

    Returns:
        One of: 'Windows', 'Linux', 'macOS', 'Other'
    """
    cleaned = (system_name or "").strip().lower()
    if "windows" in cleaned:
        return "Windows"
    elif "linux" in cleaned:
        return "Linux"
    elif "darwin" in cleaned or "mac" in cleaned:
        return "macOS"
    else:
        return "Other"


def collect_system_info() -> Dict[str, Any]:
    """
    Collect basic, non-sensitive system details.

    Handles individual collection failures gracefully to prevent program termination.

    Returns:
        Dictionary containing OS name, release, hostname, username,
        Python version, architecture, and platform category.
    """
    info: Dict[str, Any] = {}

    # Operating system name
    try:
        info["os_name"] = platform.system() or "Unknown"
    except Exception:
        info["os_name"] = "Unavailable"

    # OS release / version
    try:
        info["os_release"] = platform.release() or "Unknown"
    except Exception:
        info["os_release"] = "Unavailable"

    # Hostname
    try:
        info["hostname"] = socket.gethostname() or "Unknown"
    except Exception:
        info["hostname"] = "Unavailable"

    # Current username (safely handled fallback)
    try:
        try:
            username = getpass.getuser()
        except Exception:
            username = os.environ.get("USER") or os.environ.get("USERNAME") or "Unknown"
        info["username"] = username or "Unknown"
    except Exception:
        info["username"] = "Unavailable"

    # Python version
    try:
        info["python_version"] = platform.python_version() or "Unknown"
    except Exception:
        info["python_version"] = "Unavailable"

    # Machine architecture
    try:
        info["architecture"] = platform.machine() or "Unknown"
    except Exception:
        info["architecture"] = "Unavailable"

    # Platform category
    info["platform_category"] = get_platform_category(str(info.get("os_name", "")))

    return info


def display_system_info(info: Dict[str, Any] = None) -> None:
    """
    Format and print collected system information to stdout.

    Args:
        info: Optional pre-collected system info dictionary.
    """
    if info is None:
        info = collect_system_info()

    print("\n" + "=" * 54)
    print("               SYSTEM INFORMATION")
    print("=" * 54)
    print(f" Platform Category : {info.get('platform_category', 'Unknown')}")
    print(f" Operating System  : {info.get('os_name', 'Unknown')}")
    print(f" OS Release        : {info.get('os_release', 'Unknown')}")
    print(f" Hostname          : {info.get('hostname', 'Unknown')}")
    print(f" Current Username  : {info.get('username', 'Unknown')}")
    print(f" Architecture      : {info.get('architecture', 'Unknown')}")
    print(f" Python Version    : {info.get('python_version', 'Unknown')}")
    print("=" * 54)
