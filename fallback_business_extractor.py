"""Fallback business/address extraction layer for scraper failures."""

from bs4 import BeautifulSoup
import json
import re

OUTPUT_TEMPLATE = {
    "business_name": "",
    "street_address": "",
    "city": "",
    "state": "",
    "zip_code": "",
    "confidence_score": 0,
}

CITY_STATE_ZIP_RE = re.compile(r"([A-Za-z\s]+),?\s([A-Z]{2})\s(\d{5})")
ZIP_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
STATE_RE = re.compile(r"\b(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b")
STREET_RE = re.compile(
    r"\b\d{1,6}\s+[A-Za-z0-9.#\-\s]+?\s(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Circle|Cir|Way|Parkway|Pkwy)\b(?:[,.\s]+(?:Suite|Ste|Unit)\s*\w+)?",
    re.IGNORECASE,
)


def _clean_text(text):
    text = text or ""
    text = text.replace("\xa0", " ").replace("\n", " ").replace("\t", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip(" |-,:;")


def _extract_city_state_zip(text):
    match = CITY_STATE_ZIP_RE.search(_clean_text(text))
    if not match:
        return "", "", ""
    return _clean_text(match.group(1)), match.group(2).upper(), match.group(3)


def _extract_street(text):
    match = STREET_RE.search(_clean_text(text))
    return _clean_text(match.group(0)) if match else ""


def _result(confidence, business_name="", street_address="", city="", state="", zip_code=""):
    out = dict(OUTPUT_TEMPLATE)
    out.update(
        {
            "business_name": _clean_text(business_name),
            "street_address": _clean_text(street_address),
            "city": _clean_text(city),
            "state": _clean_text(state).upper(),
            "zip_code": _clean_text(zip_code),
            "confidence_score": confidence,
        }
    )
    return out


def _method_title_name(soup):
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    if not title:
        return _result(0)
    title = re.sub(r"\b(Home|Welcome|Official Website)\b", "", title, flags=re.IGNORECASE)
    title = re.split(r"\s*[|\-–:]\s*", title)[0]
    title = _clean_text(title)
    return _result(60, business_name=title) if title else _result(0)


def _method_footer_scan(soup):
    footer = soup.find("footer")
    if not footer:
        return _result(0)
    text = _clean_text(footer.get_text(" ", strip=True))
    street = _extract_street(text)
    city, state, zip_code = _extract_city_state_zip(text)
    if street or zip_code:
        return _result(85, street_address=street, city=city, state=state, zip_code=zip_code)
    return _result(0)


def _method_contact_section(soup):
    keywords = re.compile(r"contact|location|address|office", re.IGNORECASE)
    chunks = []
    for node in soup.find_all(["section", "div", "article", "address", "p"]):
        marker = " ".join(
            [
                node.get("id", ""),
                " ".join(node.get("class", [])) if node.get("class") else "",
                node.get_text(" ", strip=True)[:120],
            ]
        )
        if keywords.search(marker):
            chunks.append(_clean_text(node.get_text(" ", strip=True)))
    if not chunks:
        return _result(0)
    joined = " | ".join(chunks)
    street = _extract_street(joined)
    city, state, zip_code = _extract_city_state_zip(joined)
    if street or zip_code:
        return _result(70, street_address=street, city=city, state=state, zip_code=zip_code)
    return _result(0)


def _method_regex_page_text(visible_text):
    city, state, zip_code = _extract_city_state_zip(visible_text)
    if zip_code:
        street = _extract_street(visible_text)
        return _result(70, street_address=street, city=city, state=state, zip_code=zip_code)
    return _result(0)


def _iter_jsonld_nodes(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            for child in _iter_jsonld_nodes(value):
                yield child
    elif isinstance(node, list):
        for item in node:
            for child in _iter_jsonld_nodes(item):
                yield child


def _method_schema_localbusiness(soup):
    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        raw = (script.string or script.get_text() or "").strip()
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue
        for node in _iter_jsonld_nodes(data):
            if not isinstance(node, dict):
                continue
            node_type = node.get("@type", "")
            type_text = " ".join(node_type) if isinstance(node_type, list) else str(node_type)
            if "localbusiness" not in type_text.lower():
                continue
            name = node.get("name", "")
            addr = node.get("address", {})
            if isinstance(addr, dict):
                street = addr.get("streetAddress", "")
                city = addr.get("addressLocality", "")
                state = addr.get("addressRegion", "")
                zip_code = addr.get("postalCode", "")
            else:
                addr_text = _clean_text(str(addr))
                street = _extract_street(addr_text)
                city, state, zip_code = _extract_city_state_zip(addr_text)
            return _result(95, business_name=name, street_address=street, city=city, state=state, zip_code=zip_code)
    return _result(0)


def _decode_urlish(text):
    text = text.replace("+", " ")
    def repl(match):
        try:
            return bytes.fromhex(match.group(1)).decode("utf-8")
        except Exception:
            return match.group(0)
    return re.sub(r"%([0-9A-Fa-f]{2})", repl, text)


def _method_google_maps_embed(soup):
    for iframe in soup.find_all("iframe"):
        src = iframe.get("src", "")
        if "maps.google.com" not in src and "google.com/maps" not in src:
            continue
        params = re.findall(r"(?:[?&](q|query|destination|daddr)=)([^&]+)", src)
        blob = " ".join(_decode_urlish(v) for _, v in params) or _decode_urlish(src)
        street = _extract_street(blob)
        city, state, zip_code = _extract_city_state_zip(blob)
        if street or zip_code:
            return _result(65, street_address=street, city=city, state=state, zip_code=zip_code)
    return _result(0)


def _method_text_block_scoring(visible_text):
    blocks = [b.strip() for b in re.split(r"[\r\n]+", visible_text) if _clean_text(b)]
    best = (0, "")
    for block in blocks:
        score = 0
        if STREET_RE.search(block):
            score += 3
        if STATE_RE.search(block):
            score += 2
        if ZIP_RE.search(block):
            score += 2
        if "," in block:
            score += 1
        if score > best[0]:
            best = (score, block)
    if best[0] == 0:
        return _result(0)
    street = _extract_street(best[1])
    city, state, zip_code = _extract_city_state_zip(best[1])
    confidence = 70 if zip_code else 50
    return _result(confidence, street_address=street, city=city, state=state, zip_code=zip_code)


def extract_fallback_business_data(html_content, page_url=""):
    """Run fallback extraction strategies and return best JSON-compatible dict."""
    soup = BeautifulSoup(html_content or "", "html.parser")
    visible_text = _clean_text(soup.get_text("\n", strip=True))

    candidates = [
        _method_schema_localbusiness(soup),
        _method_footer_scan(soup),
        _method_regex_page_text(visible_text),
        _method_google_maps_embed(soup),
        _method_title_name(soup),
        _method_contact_section(soup),
        _method_text_block_scoring(visible_text),
    ]

    best = max(candidates, key=lambda c: c.get("confidence_score", 0))

    if not best.get("business_name"):
        title_result = _method_title_name(soup)
        if title_result.get("business_name"):
            best["business_name"] = title_result["business_name"]

    if not (best.get("city") and best.get("state") and best.get("zip_code")):
        city, state, zip_code = _extract_city_state_zip(visible_text)
        best["city"] = best.get("city") or city
        best["state"] = best.get("state") or state
        best["zip_code"] = best.get("zip_code") or zip_code

    if not best.get("street_address"):
        best["street_address"] = _extract_street(visible_text)

    return {
        "business_name": _clean_text(best.get("business_name", "")),
        "street_address": _clean_text(best.get("street_address", "")),
        "city": _clean_text(best.get("city", "")),
        "state": _clean_text(best.get("state", "")).upper(),
        "zip_code": _clean_text(best.get("zip_code", "")),
        "confidence_score": int(best.get("confidence_score", 0) or 0),
    }
