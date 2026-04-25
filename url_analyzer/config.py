# Purpose: Yeh file project ki static configuration ko central place par rakhti hai.
# Yahin database path, hardcoded heuristic-to-technique mapping, aur suspicious keyword/domain lists defined hain.
# Developer ko agar detection rules tweak karne hon, to sabse pehle isi file ko dekhna chahiye.

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "mitre_url_analyzer.db"


# Each URL check is mapped to a demo-friendly ATT&CK technique and data source.
# This hardcoded layer is intentional because the URL analyzer decides technique
# selection from observed URL behavior, then uses ATT&CK data to resolve mitigations.
URL_CHECK_MAPPINGS = {
    "shortener_domain": {
        "technique_id": "T1566.002",
        "default_technique_name": "Phishing: Spearphishing Link",
        "data_source": "Application Log: Email Gateway",
    },
    "ip_literal_host": {
        "technique_id": "T1566.002",
        "default_technique_name": "Phishing: Spearphishing Link",
        "data_source": "Network Traffic: Network Connection Creation",
    },
    "punycode_domain": {
        "technique_id": "T1566.002",
        "default_technique_name": "Phishing: Spearphishing Link",
        "data_source": "Domain Name: Domain Registration",
    },
    "suspicious_tld": {
        "technique_id": "T1566.002",
        "default_technique_name": "Phishing: Spearphishing Link",
        "data_source": "Application Log: Email Gateway",
    },
    "credential_lure_keywords": {
        "technique_id": "T1566.002",
        "default_technique_name": "Phishing: Spearphishing Link",
        "data_source": "Application Log: Email Gateway",
    },
    "downloadable_payload": {
        "technique_id": "T1204.001",
        "default_technique_name": "User Execution: Malicious Link",
        "data_source": "Network Traffic: Network Connection Creation",
    },
    "redirect_parameter": {
        "technique_id": "T1566.002",
        "default_technique_name": "Phishing: Spearphishing Link",
        "data_source": "Network Traffic: Network Connection Creation",
    },
}


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
}


SUSPICIOUS_TLDS = {
    ".zip",
    ".top",
    ".xyz",
    ".click",
    ".shop",
    ".gq",
    ".tk",
    ".work",
    ".country",
    ".stream",
}


CREDENTIAL_LURE_KEYWORDS = {
    "login",
    "verify",
    "update",
    "password",
    "signin",
    "security",
    "account",
    "reset",
    "credential",
    "webscr",
}


PAYLOAD_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".jar",
    ".vbs",
    ".ps1",
    ".zip",
    ".iso",
}
