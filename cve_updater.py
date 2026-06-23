#!/usr/bin/env python3
"""
cve_updater.py — Fetches Kubernetes CVEs from NVD API and updates k8s_cves_cache.json.

Run weekly to keep K8s CVE references current. Add to cron:
    0 3 * * 1  cd /opt/app && python cve_updater.py >> /var/log/cve_updater.log 2>&1

Usage:
    python cve_updater.py
    NVD_API_KEY=<key> python cve_updater.py   # higher rate limit (50 req/30s vs 5/30s)
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, List, Set

import requests

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = os.path.join(os.path.dirname(__file__), "k8s_cves_cache.json")

# Each tag maps to substrings searched in CVE English descriptions
_TAG_TERMS: Dict[str, List[str]] = {
    "hostpath":   ["hostpath", "host path", "host_path"],
    "subpath":    ["subpath", "sub-path", "subpath"],
    "volume":     ["persistent volume", "persistentvolume", " pvc "],
    "secret":     ["kubernetes secret", "k8s secret", "kube secret"],
    "rbac":       ["rbac", "clusterrole", "rolebinding", "role binding"],
    "privilege":  ["privilege escalation", "privileged container", "privileged pod"],
    "escape":     ["container escape", "container breakout", "sandbox escape"],
    "api-server": ["kube-apiserver", "api server", "apiserver"],
}

_QUERIES = [
    "kubernetes",
    "kubernetes container escape privilege",
    "kubernetes secret volume hostpath",
]


def _tag(cve_id: str, desc: str) -> List[str]:
    d = desc.lower()
    return [tag for tag, terms in _TAG_TERMS.items() if any(t in d for t in terms)]


def _fetch(keyword: str, start: int, api_key: str | None) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    params = {
        "keywordSearch": keyword,
        "cvssV3Severity": "HIGH",
        "startIndex": start,
        "resultsPerPage": 100,
    }
    resp = requests.get(NVD_BASE, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def fetch_k8s_cves(api_key: str | None = None) -> Dict[str, List[str]]:
    api_key = api_key or os.getenv("NVD_API_KEY")
    # NVD rate limit: 5 req/30s without key, 50/30s with key
    delay = 0.7 if api_key else 6.5
    tagged: Dict[str, Set[str]] = {tag: set() for tag in _TAG_TERMS}

    for query in _QUERIES:
        try:
            data = _fetch(query, 0, api_key)
        except Exception as exc:
            print(f"  ⚠ NVD query '{query}' failed: {exc}")
            time.sleep(delay)
            continue

        vulns = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)
        print(f"  '{query}' → {total} results, fetched {len(vulns)}")

        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            for tag in _tag(cve_id, desc):
                tagged[tag].add(cve_id)

        time.sleep(delay)

    return {tag: sorted(ids) for tag, ids in tagged.items()}


def main() -> None:
    print(f"[cve_updater] {datetime.now(timezone.utc).isoformat()} — fetching K8s CVEs from NVD")

    tagged = fetch_k8s_cves()

    # Merge with existing cache to never lose known CVEs
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            existing = json.load(f).get("tagged", {})
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        existing = {}

    for tag, cves in existing.items():
        tagged.setdefault(tag, [])
        tagged[tag] = sorted(set(tagged[tag]) | set(cves))

    # Remove empty tags
    tagged = {t: v for t, v in tagged.items() if v}

    cache = {"updated_at": datetime.now(timezone.utc).isoformat(), "tagged": tagged}
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

    total = sum(len(v) for v in tagged.values())
    print(f"[cve_updater] Done — {total} CVE refs saved to {CACHE_PATH}")
    for tag, cves in sorted(tagged.items()):
        if cves:
            print(f"  {tag}: {cves}")


if __name__ == "__main__":
    main()
