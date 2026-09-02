#!/usr/bin/env python3
"""
Cache Probe — Web Cache Deception & Poisoning Detection Tool
Tests endpoints for WCD (CWE-524) and cache poisoning via header injection.
Author: Omar Khalid (amooryx) | github.com/amooryx/cache-probe
AUTHORIZED USE ONLY — for authorized security testing and bug bounty.
"""

import argparse
import json
import random
import string
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

CACHE_HEADERS = [
    "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
    "X-Forwarded-For", "X-Host", "X-Forwarded-Server",
    "Forwarded", "CF-Connecting-IP", "True-Client-IP",
]

STATIC_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".gif", ".ico", ".woff",
    ".woff2", ".ttf", ".svg", ".map", ".json", ".xml", ".txt",
]

CACHE_STATUS_HEADERS = [
    "x-cache", "cf-cache-status", "x-cache-status", "age",
    "x-varnish", "x-cdn", "x-served-by", "x-cache-hits",
]

def rand_str(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def fetch(url: str, headers: dict, timeout: float = 10) -> dict:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 CacheProbe/1.0")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(8192)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "status": resp.status,
                "headers": resp_headers,
                "body_len": len(body),
                "body_snippet": body[:200].decode(errors="ignore"),
            }
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": {}, "body_len": 0, "body_snippet": ""}
    except Exception as ex:
        return {"status": 0, "error": str(ex), "headers": {}, "body_len": 0}

def get_cache_headers(resp: dict) -> dict:
    return {h: resp["headers"].get(h, "") for h in CACHE_STATUS_HEADERS if resp["headers"].get(h)}

def test_wcd(base_url: str) -> list[dict]:
    """Test Web Cache Deception: append static extensions to sensitive paths."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    path   = parsed.path.rstrip("/")

    for ext in STATIC_EXTENSIONS[:5]:
        test_url   = urllib.parse.urlunparse(parsed._replace(path=f"{path}/test{ext}"))
        orig_resp  = fetch(base_url, {})
        ext_resp   = fetch(test_url, {})

        orig_cc = orig_resp["headers"].get("cache-control", "")
        ext_cc  = ext_resp["headers"].get("cache-control", "")
        orig_ch = get_cache_headers(orig_resp)
        ext_ch  = get_cache_headers(ext_resp)

        potentially_vulnerable = (
            ("no-store" in orig_cc or "no-cache" in orig_cc) and
            ("no-store" not in ext_cc and "max-age" in ext_cc)
        )
        if potentially_vulnerable or ext_resp["status"] == 200:
            findings.append({
                "type": "WCD",
                "test_url": test_url,
                "original_cc": orig_cc,
                "extension_cc": ext_cc,
                "original_cache": orig_ch,
                "extension_cache": ext_ch,
                "vulnerable": potentially_vulnerable,
                "note": "Cache-Control differs for extension-appended path — potential WCD" if potentially_vulnerable else "Extension URL accessible",
            })
    return findings

def test_cache_poisoning(base_url: str, evil_host: str) -> list[dict]:
    """Test cache poisoning via Host/X-Forwarded-Host header injection."""
    findings = []
    marker = rand_str(6)

    for header in CACHE_HEADERS[:5]:
        test_headers = {header: f"{evil_host}/{marker}"}
        resp = fetch(base_url, test_headers)
        reflected = marker in resp.get("body_snippet", "")
        cached = any(v for v in get_cache_headers(resp).values())
        if reflected:
            findings.append({
                "type": "CachePoison",
                "injected_header": header,
                "value": test_headers[header],
                "reflected_in_body": reflected,
                "cached": cached,
                "cache_headers": get_cache_headers(resp),
                "severity": "High" if (reflected and cached) else "Low",
                "note": f"Marker '{marker}' reflected in response body" +
                        (" AND response appears cached" if cached else ""),
            })
    return findings

def test_freshness(base_url: str, count: int = 4) -> list[dict]:
    """Issue multiple requests and check if Age/Date changes (cache hit vs miss)."""
    results = []
    for i in range(count):
        resp = fetch(base_url, {})
        results.append({
            "req": i + 1,
            "status": resp["status"],
            "age": resp["headers"].get("age", ""),
            "date": resp["headers"].get("date", ""),
            "cache": get_cache_headers(resp),
        })
        time.sleep(1)
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Cache Probe — Web Cache Deception & Poisoning Detection (Authorized use only)",
    )
    parser.add_argument("url",         help="Target URL")
    parser.add_argument("--wcd",       action="store_true", help="Test for Web Cache Deception")
    parser.add_argument("--poison",    action="store_true", help="Test for cache poisoning via header injection")
    parser.add_argument("--freshness", action="store_true", help="Test cache freshness (4 requests)")
    parser.add_argument("--all",   "-a", action="store_true")
    parser.add_argument("--evil-host", default="evil.example.com", help="Evil host for poisoning tests")
    parser.add_argument("--out",       help="Output JSON file")
    args = parser.parse_args()

    if not (args.wcd or args.poison or args.freshness or args.all):
        args.all = True

    all_findings = {}

    if args.wcd or args.all:
        print(f"[*] Testing Web Cache Deception: {args.url}")
        wcd = test_wcd(args.url)
        all_findings["wcd"] = wcd
        for f in wcd:
            flag = "  [!!!]" if f["vulnerable"] else "  [?]  "
            print(f"{flag} {f['test_url']}")
            print(f"         orig CC : {f['original_cc'][:60]}")
            print(f"         ext  CC : {f['extension_cc'][:60]}")

    if args.poison or args.all:
        print(f"\n[*] Testing Cache Poisoning: {args.url}")
        poison = test_cache_poisoning(args.url, args.evil_host)
        all_findings["cache_poisoning"] = poison
        for f in poison:
            sev = f.get("severity", "")
            print(f"  [{sev}] {f['injected_header']}: {f['note']}")

    if args.freshness or args.all:
        print(f"\n[*] Cache freshness test (4 requests): {args.url}")
        fresh = test_freshness(args.url)
        all_findings["freshness"] = fresh
        for r in fresh:
            print(f"  req {r['req']}: status={r['status']} age={r['age']} date={r['date']} {r['cache']}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump(all_findings, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
