# Purpose: Yeh file MITRE ATT&CK Enterprise dataset ko fetch aur parse karti hai.
# Iska kaam selected techniques ke liye mitigations aur tactic context nikalna hai, taaki unhe SQLite me store kiya ja sake.
# ATT&CK side ka saara data-ingestion aur transformation logic isi module me isolated rakha gaya hai.

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from url_analyzer.config import URL_CHECK_MAPPINGS


FALLBACK_ENTERPRISE_BUNDLE_URLS = [
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
]


def build_attack_mapping_rows() -> list[tuple[str, str, str, str, str, str]]:
    """Yeh function ATT&CK Enterprise bundle ko process karke SQLite-ready rows banata hai.
    Hardcoded URL mappings me jo techniques defined hain, sirf unhi se related mitigations select ki jati hain.
    Final output tuples ka form DB insert ke liye ready hota hai."""
    bundle = _fetch_enterprise_bundle()
    techniques, mitigations, relationships = _index_bundle_objects(bundle)

    technique_ids_needed = {
        mapping["technique_id"] for mapping in URL_CHECK_MAPPINGS.values()
    }

    data_sources_by_technique: dict[str, set[str]] = {}
    for mapping in URL_CHECK_MAPPINGS.values():
        data_sources_by_technique.setdefault(mapping["technique_id"], set()).add(mapping["data_source"])

    rows: list[tuple[str, str, str, str, str, str]] = []
    for technique in techniques.values():
        technique_id = _extract_attack_id(technique)
        if technique_id not in technique_ids_needed:
            continue

        tactic_names = _extract_tactics(technique)
        technique_name = technique.get("name") or _default_name_for(technique_id)
        target_ref = technique.get("id")

        matched_mitigations = [
            mitigations[relationship["source_ref"]]
            for relationship in relationships
            if relationship.get("relationship_type") == "mitigates"
            and relationship.get("target_ref") == target_ref
            and relationship.get("source_ref") in mitigations
        ]

        for mitigation in matched_mitigations:
            mitigation_id = _extract_attack_id(mitigation)
            if not mitigation_id:
                continue

            mitigation_description = _normalize_text(mitigation.get("description", ""))
            for data_source in sorted(data_sources_by_technique.get(technique_id, set())):
                rows.append(
                    (
                        ", ".join(tactic_names) if tactic_names else "Unknown",
                        technique_id,
                        technique_name,
                        mitigation_id,
                        mitigation_description,
                        data_source,
                    )
                )

    if not rows:
        raise RuntimeError(
            "No MITRE technique-to-mitigation rows were generated. "
            "Check `attackcti` access or ATT&CK bundle parsing."
        )

    return rows


def _fetch_enterprise_bundle() -> dict[str, Any]:
    """Yeh function ATT&CK Enterprise data fetch karne ki primary entry hai.
    Pehle `attackcti` TAXII client try hota hai, aur failure par static JSON fallback use hota hai.
    Is approach se MITRE server issue ke time bhi initialization zyada reliable rehti hai."""
    try:
        import attackcti  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Missing dependency `attackcti`. Install it with: pip install attackcti pandas"
        ) from exc

    try:
        client = None
        if hasattr(attackcti, "ATTACKClient"):
            client = attackcti.ATTACKClient()
        elif hasattr(attackcti, "attack_client"):
            client = attackcti.attack_client()
        else:
            raise RuntimeError("Unsupported `attackcti` version: ATT&CK client class not found.")

        candidate_calls = [
            ("get_enterprise", {"stix_format": False}),
            ("get_enterprise", {}),
            ("get_enterprise_attack", {}),
        ]

        for method_name, kwargs in candidate_calls:
            method = getattr(client, method_name, None)
            if not callable(method):
                continue

            try:
                bundle = method(**kwargs)
            except TypeError:
                continue

            normalized = _normalize_bundle(bundle)
            if normalized:
                return normalized
    except Exception as exc:
        fallback_bundle = _fetch_bundle_from_fallback_urls()
        if fallback_bundle:
            return fallback_bundle
        raise RuntimeError(
            "Failed to fetch ATT&CK Enterprise data from both `attackcti` TAXII and fallback STIX JSON."
        ) from exc

    fallback_bundle = _fetch_bundle_from_fallback_urls()
    if fallback_bundle:
        return fallback_bundle

    raise RuntimeError("Could not fetch ATT&CK Enterprise bundle from any configured source.")


def _normalize_bundle(bundle: Any) -> dict[str, Any]:
    """Yeh helper different bundle response formats ko ek standard STIX dict me convert karta hai.
    `attackcti` kabhi dict, list ya object form me data de sakta hai, isliye normalization zaroori hai.
    Aage ka parsing logic isi normalized structure par depend karta hai."""
    if isinstance(bundle, dict) and "objects" in bundle:
        return bundle

    if isinstance(bundle, list):
        return {"type": "bundle", "objects": bundle}

    if hasattr(bundle, "objects"):
        return {"type": "bundle", "objects": list(bundle.objects)}

    return {}


def _fetch_bundle_from_fallback_urls() -> dict[str, Any]:
    """Yeh fallback helper official static JSON URLs se Enterprise bundle download karta hai.
    Jab live TAXII endpoint fail ho ya unstable ho, tab yeh recovery path ka kaam karta hai.
    Demo project ko robust banane ke liye yeh fallback intentionally add kiya gaya hai."""
    for url in FALLBACK_ENTERPRISE_BUNDLE_URLS:
        try:
            with urlopen(url, timeout=60) as response:
                payload = response.read().decode("utf-8")
        except (HTTPError, URLError, TimeoutError, OSError):
            continue

        try:
            bundle = json.loads(payload)
        except json.JSONDecodeError:
            continue

        normalized = _normalize_bundle(bundle)
        if normalized:
            return normalized

    return {}


def _index_bundle_objects(
    bundle: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Yeh bundle ke raw objects ko useful categories me split karta hai.
    Techniques, mitigations aur relationships alag-alag index hone se lookup fast aur readable ho jata hai.
    Aage mitigation resolution isi indexed data structure par based hota hai."""
    techniques: dict[str, dict[str, Any]] = {}
    mitigations: dict[str, dict[str, Any]] = {}
    relationships: list[dict[str, Any]] = []

    for raw_object in bundle.get("objects", []):
        stix_object = _stix_to_dict(raw_object)
        object_type = stix_object.get("type")

        if object_type == "attack-pattern":
            techniques[stix_object["id"]] = stix_object
        elif object_type == "course-of-action":
            mitigations[stix_object["id"]] = stix_object
        elif object_type == "relationship":
            relationships.append(stix_object)

    return techniques, mitigations, relationships


def _stix_to_dict(raw_object: Any) -> dict[str, Any]:
    """Yeh helper STIX object ko plain Python dict me convert karta hai.
    Different library versions object representation change kar sakti hain, isliye yeh compatibility layer hai.
    Isse downstream parsing code simple aur consistent rehta hai."""
    if isinstance(raw_object, dict):
        return raw_object

    if hasattr(raw_object, "serialize"):
        return json.loads(raw_object.serialize())

    if hasattr(raw_object, "_inner"):
        return dict(raw_object._inner)

    return dict(raw_object)


def _extract_attack_id(stix_object: dict[str, Any]) -> str:
    """Yeh STIX object ke external references me se ATT&CK ID nikalta hai.
    Isi se hume technique IDs jaise `T1566.002` aur mitigation IDs jaise `M1017` milte hain.
    Mapping aur final output dono ke liye yeh helper essential hai."""
    for reference in stix_object.get("external_references", []):
        external_id = reference.get("external_id")
        if external_id:
            return external_id
    return ""


def _extract_tactics(stix_object: dict[str, Any]) -> list[str]:
    """Yeh function technique ke kill chain phases me se tactic names extract karta hai.
    Output me `Initial Access` ya dusre tactic labels dikhane ke liye yahi logic use hota hai.
    Presentation aur reporting clarity ke liye tactic resolution important hai."""
    tactics: list[str] = []
    for phase in stix_object.get("kill_chain_phases", []):
        phase_name = phase.get("phase_name", "").replace("-", " ").title()
        if phase_name:
            tactics.append(phase_name)
    return tactics


def _normalize_text(value: str) -> str:
    """Yeh ATT&CK descriptions ko single-line clean text me convert karta hai.
    Raw description me extra spaces ya line breaks ho sakte hain jo output ko messy bana dete hain.
    SQLite aur JSON output ko readable rakhne ke liye normalization ki jati hai."""
    return " ".join(value.split())


def _default_name_for(technique_id: str) -> str:
    """Yeh fallback technique name return karta hai agar bundle se name missing ho.
    Normal case me ATT&CK dataset se actual name milna chahiye, lekin safety ke liye fallback rakha gaya hai.
    Isse incomplete data ke case me bhi output usable rehta hai."""
    for mapping in URL_CHECK_MAPPINGS.values():
        if mapping["technique_id"] == technique_id:
            return mapping["default_technique_name"]
    return "Unknown Technique"
