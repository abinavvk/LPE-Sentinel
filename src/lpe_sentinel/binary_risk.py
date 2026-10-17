"""
Defensive SUID/SGID Binary Risk Assessment Module for LPE Sentinel.

Evaluates discovered SUID and SGID executables against a curated, locally bundled
reference catalog of standard utilities that carry elevated operational risks
or administrative review requirements when granted setuid/setgid privileges.

Strictly read-only: does not execute discovered binaries, alter permissions,
or run commands. Generates conservative findings intended for administrative review.
"""

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from lpe_sentinel.models import Finding
except ImportError:
    from models import Finding

MITRE_ATTACK_ID = "T1548.001"


@dataclass(frozen=True)
class BinaryRiskProfile:
    """
    Profile representing a standard utility that warrants security review when SUID/SGID.

    Attributes:
        basename: Normalized canonical binary name (e.g., 'find', 'bash').
        risk_level: Conservative severity level ('HIGH', 'MEDIUM', 'LOW').
        category: Functional category of the binary (e.g., 'Shell', 'File System').
        review_reason: Explanation of why SUID/SGID on this binary requires review.
        admin_recommendation: Actionable administrative guidance.
    """

    basename: str
    risk_level: str
    category: str
    review_reason: str
    admin_recommendation: str


# Curated, locally bundled reference catalog of utilities requiring review
REFERENCE_BINARY_CATALOG: Dict[str, BinaryRiskProfile] = {
    # 1. Command Shells & Scripting Interpreters (HIGH risk when SUID)
    "bash": BinaryRiskProfile(
        basename="bash",
        risk_level="HIGH",
        category="Command Shell",
        review_reason=(
            "Standard Bourne-Again Shell. When granted SUID permissions, executing this binary "
            "allows callers to launch subshells retaining owner privileges."
        ),
        admin_recommendation="Ensure shells are never configured with SUID/SGID bits.",
    ),
    "sh": BinaryRiskProfile(
        basename="sh",
        risk_level="HIGH",
        category="Command Shell",
        review_reason=(
            "Standard POSIX command interpreter. SUID permissions permit arbitrary command "
            "execution under file owner identity."
        ),
        admin_recommendation="Remove SUID permissions from standard command shells.",
    ),
    "zsh": BinaryRiskProfile(
        basename="zsh",
        risk_level="HIGH",
        category="Command Shell",
        review_reason=(
            "Z-shell command interpreter. Executing with SUID permits arbitrary command "
            "execution under the file owner's context."
        ),
        admin_recommendation="Ensure interactive shells do not have SUID/SGID enabled.",
    ),
    "dash": BinaryRiskProfile(
        basename="dash",
        risk_level="HIGH",
        category="Command Shell",
        review_reason=(
            "Debian Almquist Shell. SUID permissions allow arbitrary shell command execution."
        ),
        admin_recommendation="Remove SUID bits from system shell interpreters.",
    ),
    "python": BinaryRiskProfile(
        basename="python",
        risk_level="HIGH",
        category="Scripting Interpreter",
        review_reason=(
            "Python runtime environment. An SUID Python interpreter allows arbitrary script "
            "and system command execution with owner privileges."
        ),
        admin_recommendation="Do not set SUID/SGID bits on scripting runtimes or interpreters.",
    ),
    "python3": BinaryRiskProfile(
        basename="python3",
        risk_level="HIGH",
        category="Scripting Interpreter",
        review_reason=(
            "Python 3 runtime environment. An SUID Python interpreter allows arbitrary code "
            "execution under the binary owner identity."
        ),
        admin_recommendation="Do not set SUID/SGID bits on Python interpreters.",
    ),
    "perl": BinaryRiskProfile(
        basename="perl",
        risk_level="HIGH",
        category="Scripting Interpreter",
        review_reason=(
            "Perl language interpreter. An SUID Perl binary permits running arbitrary system "
            "commands and scripts with owner privileges."
        ),
        admin_recommendation="Ensure Perl runtimes do not possess SUID or SGID permissions.",
    ),
    "ruby": BinaryRiskProfile(
        basename="ruby",
        risk_level="HIGH",
        category="Scripting Interpreter",
        review_reason=(
            "Ruby programming language interpreter. Executing with SUID allows arbitrary "
            "code execution under the owner's credentials."
        ),
        admin_recommendation="Remove SUID/SGID permission bits from Ruby binaries.",
    ),
    "php": BinaryRiskProfile(
        basename="php",
        risk_level="HIGH",
        category="Scripting Interpreter",
        review_reason=(
            "PHP command-line interface. SUID permissions permit executing arbitrary code "
            "under file owner privileges."
        ),
        admin_recommendation="Remove SUID permissions from PHP CLI binaries.",
    ),
    "lua": BinaryRiskProfile(
        basename="lua",
        risk_level="HIGH",
        category="Scripting Interpreter",
        review_reason=(
            "Lua scripting interpreter. SUID execution permits arbitrary script invocation."
        ),
        admin_recommendation="Do not grant SUID/SGID bits to Lua interpreters.",
    ),
    "node": BinaryRiskProfile(
        basename="node",
        risk_level="HIGH",
        category="Scripting Interpreter",
        review_reason=(
            "Node.js JavaScript runtime. SUID execution permits arbitrary script execution."
        ),
        admin_recommendation="Remove SUID permissions from JavaScript runtime binaries.",
    ),

    # 2. File Modification & Permission Tools (HIGH risk when SUID)
    "chmod": BinaryRiskProfile(
        basename="chmod",
        risk_level="HIGH",
        category="Permission Management",
        review_reason=(
            "File permission modifier. SUID privileges allow callers to alter access permissions "
            "on arbitrary files across the system."
        ),
        admin_recommendation="Chmod must never possess SUID/SGID permissions.",
    ),
    "chown": BinaryRiskProfile(
        basename="chown",
        risk_level="HIGH",
        category="Permission Management",
        review_reason=(
            "File ownership modifier. SUID privileges allow callers to transfer file ownership."
        ),
        admin_recommendation="Chown must never possess SUID/SGID permissions.",
    ),
    "cp": BinaryRiskProfile(
        basename="cp",
        risk_level="HIGH",
        category="File Operations",
        review_reason=(
            "Standard file copy utility. SUID privileges allow overwriting sensitive system "
            "configuration files."
        ),
        admin_recommendation="Ensure file copy utilities do not have SUID/SGID bits set.",
    ),
    "mv": BinaryRiskProfile(
        basename="mv",
        risk_level="HIGH",
        category="File Operations",
        review_reason=(
            "Standard file move utility. SUID privileges permit replacing or renaming "
            "critical system files."
        ),
        admin_recommendation="Ensure file move utilities do not have SUID/SGID bits set.",
    ),
    "dd": BinaryRiskProfile(
        basename="dd",
        risk_level="HIGH",
        category="File Operations",
        review_reason=(
            "Low-level data duplicator. SUID privileges permit raw read and write operations "
            "on system disks, block devices, and files."
        ),
        admin_recommendation="Ensure dd does not have SUID/SGID permissions.",
    ),

    # 3. Search, Processing & Text Utilities (MEDIUM risk when SUID)
    "find": BinaryRiskProfile(
        basename="find",
        risk_level="MEDIUM",
        category="Search & Execution",
        review_reason=(
            "File tree search utility. Features execution parameters (such as -exec) that run "
            "commands during directory traversal under file owner privileges."
        ),
        admin_recommendation="Avoid setting SUID on find; use sudo rules with restricted arguments if needed.",
    ),
    "awk": BinaryRiskProfile(
        basename="awk",
        risk_level="MEDIUM",
        category="Text Processing",
        review_reason=(
            "Pattern scanning and processing language. Can invoke system commands and read "
            "restricted files during text evaluation."
        ),
        admin_recommendation="Remove SUID bits from text processing tools.",
    ),
    "gawk": BinaryRiskProfile(
        basename="gawk",
        risk_level="MEDIUM",
        category="Text Processing",
        review_reason=(
            "GNU Awk text processing utility. Supports command execution and file reading."
        ),
        admin_recommendation="Remove SUID bits from text processing tools.",
    ),
    "sed": BinaryRiskProfile(
        basename="sed",
        risk_level="MEDIUM",
        category="Text Processing",
        review_reason=(
            "Stream editor. SUID permissions allow reading and modifying file contents."
        ),
        admin_recommendation="Ensure sed does not possess SUID/SGID bits.",
    ),
    "nano": BinaryRiskProfile(
        basename="nano",
        risk_level="MEDIUM",
        category="Text Editor",
        review_reason=(
            "Terminal text editor. SUID permissions permit reading, modifying, or creating "
            "files with owner privileges."
        ),
        admin_recommendation="Text editors must not possess SUID/SGID permissions.",
    ),
    "vim": BinaryRiskProfile(
        basename="vim",
        risk_level="MEDIUM",
        category="Text Editor",
        review_reason=(
            "Vi IMproved text editor. Supports file reading/writing and internal shell escapes."
        ),
        admin_recommendation="Do not assign SUID/SGID bits to interactive text editors.",
    ),
    "vi": BinaryRiskProfile(
        basename="vi",
        risk_level="MEDIUM",
        category="Text Editor",
        review_reason=(
            "Standard visual text editor. Supports file reading/writing and command execution."
        ),
        admin_recommendation="Do not assign SUID/SGID bits to interactive text editors.",
    ),
    "ed": BinaryRiskProfile(
        basename="ed",
        risk_level="MEDIUM",
        category="Text Editor",
        review_reason=(
            "Line-oriented text editor. SUID execution permits arbitrary file modification."
        ),
        admin_recommendation="Remove SUID permissions from text editors.",
    ),
    "less": BinaryRiskProfile(
        basename="less",
        risk_level="MEDIUM",
        category="File Pager",
        review_reason=(
            "Terminal pager. Allows viewing arbitrary files and features interactive shell escapes."
        ),
        admin_recommendation="Remove SUID permissions from pagers.",
    ),
    "more": BinaryRiskProfile(
        basename="more",
        risk_level="MEDIUM",
        category="File Pager",
        review_reason=(
            "Terminal pager. SUID permissions permit viewing restricted files and executing escapes."
        ),
        admin_recommendation="Remove SUID permissions from pagers.",
    ),
    "tar": BinaryRiskProfile(
        basename="tar",
        risk_level="MEDIUM",
        category="Archiving",
        review_reason=(
            "Archive utility. SUID permissions allow arbitrary file extraction or command "
            "execution via checkpoint actions."
        ),
        admin_recommendation="Ensure archiving tools do not have SUID/SGID enabled.",
    ),
    "zip": BinaryRiskProfile(
        basename="zip",
        risk_level="MEDIUM",
        category="Archiving",
        review_reason=(
            "Archive packaging utility. Supports program execution via testing parameters."
        ),
        admin_recommendation="Ensure zip does not have SUID/SGID permissions.",
    ),
    "curl": BinaryRiskProfile(
        basename="curl",
        risk_level="MEDIUM",
        category="Network Utility",
        review_reason=(
            "URL transfer utility. SUID permissions allow writing downloaded files to arbitrary "
            "system paths."
        ),
        admin_recommendation="Network download tools should never have SUID/SGID permissions.",
    ),
    "wget": BinaryRiskProfile(
        basename="wget",
        risk_level="MEDIUM",
        category="Network Utility",
        review_reason=(
            "Non-interactive network downloader. SUID permissions permit writing downloaded "
            "files to arbitrary locations."
        ),
        admin_recommendation="Network download tools should never have SUID/SGID permissions.",
    ),
    "env": BinaryRiskProfile(
        basename="env",
        risk_level="MEDIUM",
        category="Command Execution",
        review_reason=(
            "Environment configuration runner. SUID permissions allow executing arbitrary commands."
        ),
        admin_recommendation="Env must not have SUID/SGID permissions.",
    ),
    "nmap": BinaryRiskProfile(
        basename="nmap",
        risk_level="MEDIUM",
        category="Network Scanner",
        review_reason=(
            "Network exploration tool. SUID permissions or interactive script modes allow "
            "reading files and running scripts."
        ),
        admin_recommendation="Remove SUID permissions from network scanning utilities.",
    ),
}


# Explicitly supported versioned executable families (e.g. python3.11 -> python3, ruby3.2 -> ruby)
VERSIONED_BINARY_FAMILIES: tuple[str, ...] = (
    "python",
    "ruby",
    "perl",
    "php",
    "lua",
    "node",
)


def normalize_binary_name(path: str) -> str:
    """
    Extract a clean, normalized executable basename from an arbitrary path string.

    Handles forward and backward slashes, trailing slashes, and whitespace.

    Args:
        path: Path string to normalize.

    Returns:
        Lowercase basename string, or empty string on invalid input.
    """
    if not isinstance(path, str):
        return ""

    cleaned = path.strip().replace("\\", "/")
    cleaned = cleaned.rstrip("/")
    if not cleaned:
        return ""

    basename = cleaned.split("/")[-1].strip().lower()
    return basename


def get_binary_risk_profile(path_or_name: str) -> Optional[BinaryRiskProfile]:
    """
    Look up a binary in the local reference catalog by exact or normalized name.

    Only explicitly supported versioned executable families (e.g., 'python3.11' -> 'python3',
    'ruby3.2' -> 'ruby') resolve to catalog profiles. Arbitrary custom names with trailing
    digits (e.g., 'cp1', 'dd2', 'find1') do NOT match.

    Args:
        path_or_name: Executable name or full path string.

    Returns:
        Matching BinaryRiskProfile instance, or None if not cataloged.
    """
    basename = normalize_binary_name(path_or_name)
    if not basename:
        return None

    # 1. Exact match (primary lookup for all cataloged binaries)
    if basename in REFERENCE_BINARY_CATALOG:
        return REFERENCE_BINARY_CATALOG[basename]

    # 2. Versioned executable family matching for supported runtimes
    for prefix in VERSIONED_BINARY_FAMILIES:
        if basename.startswith(prefix):
            version_suffix = basename[len(prefix):]
            # Suffix must strictly consist of digits and dots (e.g. '3', '3.11', '3.2')
            if re.fullmatch(r"[\d\.]+", version_suffix):
                # Try major-version catalog match first if defined (e.g. 'python3.11' -> 'python3')
                major_match = re.match(r"^(" + re.escape(prefix) + r"\d+)", basename)
                if major_match and major_match.group(1) in REFERENCE_BINARY_CATALOG:
                    return REFERENCE_BINARY_CATALOG[major_match.group(1)]

                # Fallback to base runtime family match (e.g. 'ruby3.2' -> 'ruby')
                if prefix in REFERENCE_BINARY_CATALOG:
                    return REFERENCE_BINARY_CATALOG[prefix]

    return None


def assess_binary_risk(
    file_path: str,
    st_mode: Optional[int] = None,
    is_suid: bool = True,
    is_sgid: bool = False,
) -> Optional[Finding]:
    """
    Evaluate whether a discovered SUID or SGID binary matches a reference risk profile.

    Generates a conservative Finding object with actionable review guidance.

    Args:
        file_path: Absolute or relative path to the binary.
        st_mode: Optional stat st_mode integer for formatting permissions evidence.
        is_suid: Whether the file has stat.S_ISUID set.
        is_sgid: Whether the file has stat.S_ISGID set.

    Returns:
        A Finding instance if the binary matches a risk profile, or None.
    """
    # Only evaluate files that possess SUID or SGID permissions
    if not is_suid and not is_sgid:
        return None

    profile = get_binary_risk_profile(file_path)
    if profile is None:
        return None

    try:
        abs_path = os.path.abspath(file_path)
    except Exception:
        abs_path = str(file_path)

    # Permission string formatting
    if st_mode is not None:
        octal_perms = oct(st_mode & 0o7777)
        symbolic_perms = stat.filemode(st_mode)
        perm_evidence = f"Permissions: {symbolic_perms} ({octal_perms})"
    else:
        perm_bits = []
        if is_suid:
            perm_bits.append("SUID")
        if is_sgid:
            perm_bits.append("SGID")
        perm_evidence = f"Special Bits: {', '.join(perm_bits)}"

    perm_type = "SUID" if is_suid else "SGID"
    finding_id = "SUID-002" if is_suid else "SGID-002"

    title = f"{perm_type} Binary Review Recommended: {profile.basename}"

    description = (
        f"The binary '{profile.basename}' has special execution permissions ({perm_type}) "
        f"and matches a known standard utility in the '{profile.category}' category. "
        f"{profile.review_reason} "
        f"Note: This finding indicates that the binary warrants security review by an administrator; "
        f"it is not proof of an active vulnerability or exploit."
    )

    evidence = (
        f"Binary: {profile.basename} | Category: {profile.category} | "
        f"File: {abs_path} | {perm_evidence}"
    )

    chmod_flag = "u-s" if is_suid else "g-s"
    recommendation = (
        f"Review whether elevated {perm_type} execution rights are strictly required for '{profile.basename}'. "
        f"If not required for operational duties, remove the special bit using: chmod {chmod_flag} '{abs_path}'. "
        f"{profile.admin_recommendation}"
    )

    return Finding(
        finding_id=finding_id,
        title=title,
        severity=profile.risk_level,
        description=description,
        evidence=evidence,
        affected_resource=abs_path,
        recommendation=recommendation,
        mitre_attack=MITRE_ATTACK_ID,
    )
