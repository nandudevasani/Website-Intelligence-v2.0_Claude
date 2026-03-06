"""Bridge script for Node.js to run Python business extraction via stdin/stdout JSON."""

from __future__ import annotations

import json
import sys

from business_extraction_helper import enhanced_business_extraction

try:
    from fallback_business_extractor import extract_fallback_business_data
except Exception:  # pragma: no cover - optional dependency pathway
    extract_fallback_business_data = None


def _merge_best(primary: dict, fallback: dict) -> dict:
    out = dict(primary or {})
    fallback = fallback or {}
    name_source = "primary" if out.get("business_name") else "none"

    for key in ("business_name", "street_address", "city", "state", "zip_code"):
        if not out.get(key) and fallback.get(key):
            out[key] = fallback[key]
            if key == "business_name":
                name_source = "fallback"

    out["confidence_score"] = max(
        int(out.get("confidence_score", 0) or 0),
        int(fallback.get("confidence_score", 0) or 0),
    )
    return out, name_source


def main() -> int:
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw or "{}")
        html = payload.get("html", "")
        page_url = payload.get("page_url", "")

        primary = enhanced_business_extraction(html)

        use_fallback = (
            extract_fallback_business_data is not None
            and (
                int(primary.get("confidence_score", 0) or 0) < 80
                or not primary.get("business_name")
                or not primary.get("street_address")
            )
        )

        fallback = extract_fallback_business_data(html, page_url) if use_fallback else {}
        best, best_name_source = _merge_best(primary, fallback)

        response = {
            "ok": True,
            "primary": primary,
            "fallback": fallback,
            "best": best,
            "used_fallback": bool(fallback),
            "best_name_source": best_name_source,
        }
        sys.stdout.write(json.dumps(response))
        return 0
    except Exception as exc:
        sys.stdout.write(json.dumps({"ok": False, "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
