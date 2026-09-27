"""
IOC Extractor (Team 4)

Finds Indicators of Compromise (IOCs) in report text using fixed patterns
("regular expressions") instead of asking an AI model.

Why patterns instead of the AI?
- A pattern can only return something that is actually written in the text.
  It can never invent a CVE or an IP address that isn't there.
- It gives the same answer every time, costs nothing, and works offline.

What it finds:
- CVE IDs          e.g. CVE-2023-23397
- IPv4 addresses   e.g. 185.220.101.47  (also "defanged" ones like 185.220.101[.]47)
- File hashes      MD5 (32 hex chars), SHA-1 (40), SHA-256 (64)
- Domain names     e.g. secure-update-cdn.net  (also defanged: secure-update-cdn[.]net)

What it does NOT find (yet): threat-actor names and malware names.
Those have no fixed shape, so they need the AI model. They come back as empty lists.
"""

import ipaddress
import re
from typing import Dict, List

# ---------------------------------------------------------------------------
# Patterns. "[.]" and "(.)" are how analysts "defang" indicators so nobody
# clicks them by accident; we accept those as well as a normal ".".
# ---------------------------------------------------------------------------
_DOT = r"(?:\.|\[\.\]|\(\.\))"

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IPV4_PATTERN = re.compile(rf"(?<![\w.])(?:\d{{1,3}}{_DOT}){{3}}\d{{1,3}}(?!\w)(?!\.\d)")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_PATTERN = re.compile(
    rf"(?<![\w@-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?{_DOT})+[a-zA-Z]{{2,24}}(?![\w-])"
)

# Endings that look like a domain but are almost always file names ("report.pdf").
_FILE_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "json", "xml",
    "exe", "dll", "bat", "ps1", "sh", "py", "js", "zip", "rar", "gz", "tar", "iso",
    "png", "jpg", "jpeg", "gif", "log", "tmp", "bin", "md", "html", "htm",
}


def _refang(value: str) -> str:
    """Turn a defanged indicator back into its plain form, for de-duplication."""
    return value.replace("[.]", ".").replace("(.)", ".")


def _unique(values: List[str]) -> List[str]:
    """Remove duplicates (ignoring case and defanging) but keep the original order."""
    seen = set()
    result = []
    for value in values:
        key = _refang(value).lower()
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def _find_ips(text: str) -> List[str]:
    found = []
    for match in IPV4_PATTERN.findall(text):
        try:
            ipaddress.IPv4Address(_refang(match))  # drops impossible ones like 999.1.1.1
        except ValueError:
            continue
        found.append(match)
    return _unique(found)


def _find_domains(text: str) -> List[str]:
    found = []
    for match in DOMAIN_PATTERN.findall(text):
        last_part = _refang(match).rsplit(".", 1)[-1].lower()
        if last_part in _FILE_EXTENSIONS:
            continue
        found.append(match)
    return _unique(found)


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Find indicators in `text`. Returns a dict of lists; every list can be empty.

    The combined "iocs" list is what the investigator dashboard currently displays.
    """
    text = text or ""

    cves = _unique([c.upper() for c in CVE_PATTERN.findall(text)])
    ips = _find_ips(text)
    domains = _find_domains(text)
    hashes = _unique(
        SHA256_PATTERN.findall(text) + SHA1_PATTERN.findall(text) + MD5_PATTERN.findall(text)
    )

    return {
        "cves": cves,
        "ips": ips,
        "domains": domains,
        "hashes": hashes,
        "iocs": cves + ips + domains + hashes,
        # Names have no fixed shape, so patterns can't find them. Left empty on
        # purpose until the AI-based extraction is added - never filled with guesses.
        "threat_actors": [],
        "malware": [],
    }
