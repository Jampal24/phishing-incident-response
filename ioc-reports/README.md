# IOC reports

JSON output from `scripts/phish_analyzer.py --json`. One file per analysed email. Fields:

- `auth`: SPF / DKIM / DMARC results
- `received_hops`: Received headers, origin first
- `links`: visible text + real target for every link
- `attachments`: filename, type, size, MD5/SHA1/SHA256, flags
- `iocs`: deduplicated `ips`, `domains`, `urls`, `emails`, `sha256`, ready to import into a blocklist or SIEM watchlist
- `red_flags`, `score`, `verdict`

Values in the JSON are **not** defanged (so tools can consume them). Treat them as live indicators.
