<div align="center">
  <img src="./banner.svg" alt="cache-probe" width="800">
</div>

# cache-probe

> A bounded, header-only cache diagnostic for authorized testing.

## Usage

```bash
python cache_probe.py https://example.test/account --allow-host example.test
```

The target hostname must exactly match the explicitly supplied `--allow-host`.
The tool sends one `HEAD` request, follows no redirects, reads no response body,
and limits the request timeout to 10 seconds. Query parameter values are
redacted in displayed and saved results.

Only recognized cache-related response headers are reported. Header evidence is
inconclusive: it cannot establish that a response was served from a shared
cache, and `HEAD` behavior may differ from `GET`. Missing cache headers do not
prove that caching is disabled.

The diagnostic deliberately does not run cache-poisoning payloads, append
deception paths, or repeat requests. Test changes offline with:

```bash
python -m unittest discover -s tests -v
```

## Disclaimer

> **Use only on systems you are authorized to assess.** Explicit hostname
> matching is a scope guard, not authorization.

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) | [@amooryx](https://github.com/amooryx)
