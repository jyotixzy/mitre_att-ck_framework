# Purpose: Yeh file URL analyzer ka detection brain hai.
# Har extracted URL par yahin suspicious heuristic checks chalte hain aur matched behavior ko ATT&CK technique se map kiya jata hai.
# Demo-level phishing aur malicious link detection ka core logic isi module me hai.

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import parse_qs, urlparse
import ipaddress

from url_analyzer.config import (
    CREDENTIAL_LURE_KEYWORDS,
    PAYLOAD_EXTENSIONS,
    SHORTENER_DOMAINS,
    SUSPICIOUS_TLDS,
    URL_CHECK_MAPPINGS,
)


@dataclass(frozen=True)
class URLFinding:
    """Yeh dataclass ek single heuristic hit ko represent karti hai.
    Isme original URL, matched check ka naam, mapped technique aur related data source store hota hai.
    Baad me isi structured object ko DB lookup ke liye use kiya jata hai."""

    url: str
    check_name: str
    technique_id: str
    technique_name: str
    data_source: str


def analyze_urls(urls: list[str]) -> list[URLFinding]:
    """Yeh function saari extracted URLs par heuristic engine chalata hai.
    Har URL ke liye matched checks collect karke ATT&CK-mapped findings list return karta hai.
    Service layer analysis phase me isi function ko call karti hai."""
    findings: list[URLFinding] = []
    for url in urls:
        findings.extend(_run_checks(url))
    return findings


def _run_checks(url: str) -> list[URLFinding]:
    """Yeh helper ek single URL ke against saare supported checks evaluate karta hai.
    Hostname, path aur query ko inspect karke suspicious patterns detect kiye jate hain.
    Jo bhi rules hit hote hain, unke liye structured `URLFinding` objects banaye jate hain."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = parsed.query.lower()

    matched_checks: list[str] = []

    if hostname in SHORTENER_DOMAINS:
        matched_checks.append("shortener_domain")

    if _is_ip_literal(hostname):
        matched_checks.append("ip_literal_host")

    if "xn--" in hostname:
        matched_checks.append("punycode_domain")

    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        matched_checks.append("suspicious_tld")

    if any(keyword in url.lower() for keyword in CREDENTIAL_LURE_KEYWORDS):
        matched_checks.append("credential_lure_keywords")

    if _looks_like_downloadable_payload(path):
        matched_checks.append("downloadable_payload")

    if _has_redirect_parameter(query):
        matched_checks.append("redirect_parameter")

    findings: list[URLFinding] = []
    for check_name in sorted(set(matched_checks)):
        mapping = URL_CHECK_MAPPINGS[check_name]
        findings.append(
            URLFinding(
                url=url,
                check_name=check_name,
                technique_id=mapping["technique_id"],
                technique_name=mapping["default_technique_name"],
                data_source=mapping["data_source"],
            )
        )
    return findings


def _is_ip_literal(hostname: str) -> bool:
    """Yeh check karta hai ki hostname normal domain hai ya direct IP address.
    IP-based URLs phishing ya suspicious delivery scenarios me useful indicator hote hain.
    Match hone par URL ko stronger suspicious signal diya jata hai."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _looks_like_downloadable_payload(path: str) -> bool:
    """Yeh function URL path ke ending extension ko inspect karta hai.
    Agar path executable ya archive payload jaisa lage, to malicious download heuristic hit hota hai.
    Demo me yeh user-execution style ATT&CK mapping ke liye use hota hai."""
    suffix = "".join(PurePosixPath(path).suffixes[-1:]).lower()
    return suffix in PAYLOAD_EXTENSIONS


def _has_redirect_parameter(query: str) -> bool:
    """Yeh query string me common redirect keys search karta hai.
    Redirect-based URLs phishing chains me kaafi use hote hain, isliye yeh ek useful heuristic hai.
    Agar suspicious redirect parameter mile, to link ko additional risk signal milta hai."""
    if not query:
        return False

    redirect_keys = {"redirect", "redirect_uri", "url", "target", "dest", "destination", "next"}
    parsed_query = parse_qs(query, keep_blank_values=True)
    return any(key in redirect_keys for key in parsed_query)
