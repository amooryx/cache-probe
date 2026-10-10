#!/usr/bin/env python3
"""Safely inspect cache-related response headers for an explicitly scoped host."""

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request

CACHE_HEADERS = (
    "age",
    "cache-control",
    "cf-cache-status",
    "expires",
    "pragma",
    "x-cache",
    "x-cache-hits",
    "x-cache-status",
    "x-cdn",
    "x-served-by",
    "x-varnish",
)
MAX_TIMEOUT = 10.0


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _normalize_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def validate_target(url: str, allowed_host: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Target must be an absolute HTTP or HTTPS URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in target URLs are not allowed.")
    if not allowed_host or _normalize_host(parsed.hostname) != _normalize_host(allowed_host):
        raise ValueError("Target hostname must exactly match --allow-host.")
    return parsed


def redact_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    redacted_query = urllib.parse.urlencode(
        [(key, "[REDACTED]") for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
    )
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, redacted_query, "")
    )


def _cache_headers(headers) -> dict:
    normalized = {key.lower(): value for key, value in headers.items()}
    return {key: normalized[key] for key in CACHE_HEADERS if key in normalized}


def inspect_cache_headers(url: str, allowed_host: str, timeout: float = 5.0) -> dict:
    """Make one in-scope HEAD request; do not follow redirects or read a body."""
    validate_target(url, allowed_host)
    if not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError(f"Timeout must be greater than 0 and no more than {MAX_TIMEOUT:g} seconds.")

    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "CacheProbe/2.0"},
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            headers = _cache_headers(response.headers)
            error = None
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = _cache_headers(exc.headers or {})
        error = None
        exc.close()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        status = 0
        headers = {}
        reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
        error = f"Request failed ({type(reason).__name__})."

    if error:
        interpretation = "No cache conclusion is possible because the request failed."
    elif headers:
        interpretation = (
            "Cache-related headers were observed; headers alone do not prove a cache hit "
            "or a vulnerability, and HEAD may differ from GET behavior."
        )
    else:
        interpretation = (
            "No recognized cache headers were observed; their absence does not prove "
            "that caching is disabled."
        )

    return {
        "url": redact_url(url),
        "method": "HEAD",
        "status": status,
        "cache_headers": headers,
        "error": error,
        "interpretation": interpretation,
    }


def _bounded_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not 0 < timeout <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(f"timeout must be greater than 0 and at most {MAX_TIMEOUT:g}")
    return timeout


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect cache-related response headers with one bounded, in-scope HEAD request."
    )
    parser.add_argument("url", help="HTTP(S) target URL")
    parser.add_argument(
        "--allow-host",
        required=True,
        help="Exact hostname in scope; target host must match (no suffix or wildcard matching)",
    )
    parser.add_argument("--timeout", type=_bounded_timeout, default=5.0, help="Request timeout in seconds (max 10)")
    parser.add_argument("--out", help="Write the redacted result as JSON")
    args = parser.parse_args()

    try:
        result = inspect_cache_headers(args.url, args.allow_host, args.timeout)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
    return 0 if result["status"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
