"""Independent helpers for extracting business identity and US address details.

This module is intentionally standalone and does not depend on project internals.
"""

from __future__ import annotations

import json
import re
from html import unescape
from typing import Any, Dict, Iterable, List, Tuple

OUTPUT_TEMPLATE: Dict[str, Any] = {
    "business_name": "",
    "street_address": "",
    "city": "",
    "state": "",
    "zip_code": "",
    "confidence_score": 0,
}

_STREET_PATTERN = re.compile(
    r"\b(\d{1,5}\s[A-Za-z0-9.\s]+(?:Street|St|Road|Rd|Ave|Avenue|Boulevard|Blvd|Lane|Ln))\b",
    re.IGNORECASE,
)
_CITY_STATE_ZIP_PATTERN = re.compile(
    r"\b([A-Za-z\s]+),?\s([A-Z]{2})\s(\d{5})(?:-\d{4})?\b"
)
_PRIMARY_ADDRESS_HINT_RE = re.compile(
    r"\b(?:head\s*office|headquarters|hq|main\s*office|corporate\s*office|primary\s*office)\b",
    re.IGNORECASE,
)


def _clean_text(text: str) -> str:
    text = unescape(text or "")
    text = text.replace("\xa0", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip(" |\n\t\r-")


def _html_to_text(html: str) -> str:
    html = html or ""
    html = re.sub(r"<script\b[^>]*>.*?</script>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"<style\b[^>]*>.*?</style>", " ", html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)
    html = re.sub(r"</?(p|div|li|section|article|address|footer|header|h\d)\b[^>]*>", "\n", html, flags=re.IGNORECASE)
    html = re.sub(r"<[^>]+>", " ", html)
    return _clean_text(html)


def _extract_json_ld_blocks(html: str) -> Iterable[str]:
    pattern = re.compile(
        r"<script[^>]*type=['\"]application/ld\+json['\"][^>]*>(.*?)</script>",
        re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(html or ""):
        block = match.group(1).strip()
        if block:
            yield block


def _iter_schema_nodes(obj: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from _iter_schema_nodes(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_schema_nodes(item)


def _is_local_business(node: Dict[str, Any]) -> bool:
    schema_type = node.get("@type", "")
    if isinstance(schema_type, list):
        return any("localbusiness" in str(value).lower() for value in schema_type)
    return "localbusiness" in str(schema_type).lower()


def parse_schema_business_data(html: str) -> Dict[str, Any]:
    """Parse LocalBusiness JSON-LD blocks and return structured fields."""
    best = dict(OUTPUT_TEMPLATE)

    for block in _extract_json_ld_blocks(html):
        try:
            data = json.loads(block)
        except json.JSONDecodeError:
            continue

        for node in _iter_schema_nodes(data):
            if not _is_local_business(node):
                continue

            name = _clean_text(str(node.get("name", "")))
            address = node.get("address", {})

            street = city = state = zip_code = ""
            if isinstance(address, dict):
                street = _clean_text(str(address.get("streetAddress", "")))
                city = _clean_text(str(address.get("addressLocality", "")))
                state = _clean_text(str(address.get("addressRegion", ""))).upper()
                zip_code = _clean_text(str(address.get("postalCode", "")))[:10]
            elif isinstance(address, str):
                parsed = extract_address_components(address)
                street = parsed["street_address"]
                city = parsed["city"]
                state = parsed["state"]
                zip_code = parsed["zip_code"]

            candidate = {
                "business_name": name,
                "street_address": street,
                "city": city,
                "state": state,
                "zip_code": zip_code,
                "confidence_score": 95,
            }

            completeness = sum(bool(candidate[k]) for k in ("business_name", "street_address", "city", "state", "zip_code"))
            best_completeness = sum(bool(best[k]) for k in ("business_name", "street_address", "city", "state", "zip_code"))
            if completeness > best_completeness:
                best = candidate

    return best


def extract_business_name(html: str) -> Dict[str, Any]:
    """Extract business name with source-priority and confidence scoring."""
    html = html or ""

    schema_data = parse_schema_business_data(html)
    if schema_data.get("business_name"):
        return {
            "business_name": schema_data["business_name"],
            "confidence_score": 95,
            "source": "schema_localbusiness",
        }

    og_match = re.search(
        r"<meta[^>]+property=['\"]og:site_name['\"][^>]+content=['\"](.*?)['\"]",
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if og_match:
        return {
            "business_name": _clean_text(og_match.group(1)),
            "confidence_score": 85,
            "source": "og:site_name",
        }

    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if title_match:
        title = _clean_text(re.split(r"[|\-–:]", title_match.group(1))[0])
        if title:
            return {
                "business_name": title,
                "confidence_score": 70,
                "source": "title",
            }

    h1_match = re.search(r"<h1[^>]*>(.*?)</h1>", html, flags=re.IGNORECASE | re.DOTALL)
    if h1_match:
        return {
            "business_name": _clean_text(h1_match.group(1)),
            "confidence_score": 70,
            "source": "h1",
        }

    footer_match = re.search(r"<footer[^>]*>(.*?)</footer>", html, flags=re.IGNORECASE | re.DOTALL)
    if footer_match:
        footer_text = _html_to_text(footer_match.group(1))
        copyright_match = re.search(
            r"(?:copyright|©)\s*\d{0,4}\s*([A-Za-z0-9&.,'\-\s]{2,80})",
            footer_text,
            flags=re.IGNORECASE,
        )
        if copyright_match:
            return {
                "business_name": _clean_text(copyright_match.group(1)),
                "confidence_score": 85,
                "source": "footer_copyright",
            }

    return {"business_name": "", "confidence_score": 0, "source": "none"}


def detect_city_state_zip(text: str) -> Dict[str, str]:
    """Detect city/state/zip using the requested regex pattern."""
    cleaned = _clean_text(text)
    match = _CITY_STATE_ZIP_PATTERN.search(cleaned)
    if not match:
        return {"city": "", "state": "", "zip_code": ""}

    city = _clean_text(match.group(1))
    state = match.group(2).upper()
    zip_code = match.group(3)
    return {"city": city, "state": state, "zip_code": zip_code}


def extract_address_components(text: str) -> Dict[str, Any]:
    """Extract US street/city/state/zip from free text or flattened HTML text."""
    flattened = _clean_text(text)

    street_address = ""
    street_match = _STREET_PATTERN.search(flattened)
    if street_match:
        street_address = _clean_text(street_match.group(1))

    csz = detect_city_state_zip(flattened)

    return {
        "street_address": street_address,
        "city": csz["city"],
        "state": csz["state"],
        "zip_code": csz["zip_code"],
        "confidence_score": 70 if street_address or csz["zip_code"] else 0,
    }


def _address_from_html_fragments(html: str) -> Dict[str, Any]:
    """Reconstruct split DOM text fragments and run regex address extraction."""
    fragments: List[str] = []
    for segment in re.split(r"</?(?:span|div|p|li|br|address|section|article|footer)[^>]*>", html or "", flags=re.IGNORECASE):
        cleaned = _clean_text(re.sub(r"<[^>]+>", " ", segment))
        if cleaned:
            fragments.append(cleaned)

    joined = " ".join(fragments)
    return extract_address_components(joined)


def extract_primary_address_components(text: str) -> Dict[str, Any]:
    """Select a primary address when multiple candidate addresses are present."""
    flattened = _clean_text(text)
    if not flattened:
        return {
            "street_address": "",
            "city": "",
            "state": "",
            "zip_code": "",
            "confidence_score": 0,
        }

    street_matches = list(_STREET_PATTERN.finditer(flattened))
    if not street_matches:
        return extract_address_components(flattened)

    best: Dict[str, Any] = {
        "street_address": "",
        "city": "",
        "state": "",
        "zip_code": "",
        "confidence_score": 0,
    }
    best_score = -1

    global_csz = detect_city_state_zip(flattened)

    for idx, match in enumerate(street_matches):
        street = _clean_text(match.group(1))
        start = match.start()
        end = street_matches[idx + 1].start() if idx + 1 < len(street_matches) else min(len(flattened), match.end() + 220)
        snippet = flattened[start:end]

        csz = detect_city_state_zip(snippet)
        if not csz["zip_code"] and global_csz["zip_code"]:
            csz = global_csz
        elif not (csz["city"] and csz["state"]) and global_csz["city"] and global_csz["state"]:
            csz = {
                "city": csz["city"] or global_csz["city"],
                "state": csz["state"] or global_csz["state"],
                "zip_code": csz["zip_code"] or global_csz["zip_code"],
            }
        score = 1
        if csz["zip_code"]:
            score += 3
        if csz["city"] and csz["state"]:
            score += 2

        context_start = max(0, start - 120)
        context = flattened[context_start:end]
        if _PRIMARY_ADDRESS_HINT_RE.search(context):
            score += 4

        # Tie-break: first complete-looking address wins naturally.
        if score > best_score:
            best_score = score
            best = {
                "street_address": street,
                "city": csz["city"],
                "state": csz["state"],
                "zip_code": csz["zip_code"],
                "confidence_score": 75 if csz["zip_code"] else 65,
            }

    return best


def enhanced_business_extraction(html: str) -> Dict[str, Any]:
    """Return best structured business details from raw HTML."""
    result = dict(OUTPUT_TEMPLATE)

    schema = parse_schema_business_data(html)
    name_data = extract_business_name(html)

    if schema.get("street_address") or schema.get("zip_code"):
        result.update(schema)
    else:
        text = _html_to_text(html)
        regex_data = extract_primary_address_components(text)
        fragment_data = _address_from_html_fragments(html)

        address_best = regex_data
        if fragment_data.get("confidence_score", 0) > regex_data.get("confidence_score", 0):
            address_best = fragment_data

        for key in ("street_address", "city", "state", "zip_code"):
            result[key] = address_best.get(key, "")

        if result["street_address"] or result["zip_code"]:
            result["confidence_score"] = max(result["confidence_score"], 70)

    if name_data.get("business_name"):
        result["business_name"] = name_data["business_name"]
        result["confidence_score"] = max(result["confidence_score"], int(name_data.get("confidence_score", 0)))

    footer_match = re.search(r"<footer[^>]*>(.*?)</footer>", html or "", flags=re.IGNORECASE | re.DOTALL)
    if footer_match and not schema.get("street_address"):
        footer_data = extract_address_components(_html_to_text(footer_match.group(1)))
        if footer_data.get("street_address") or footer_data.get("zip_code"):
            for key in ("street_address", "city", "state", "zip_code"):
                if not result[key]:
                    result[key] = footer_data.get(key, "")
            result["confidence_score"] = max(result["confidence_score"], 85)

    return result
