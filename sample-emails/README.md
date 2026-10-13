# Sample emails

All three emails are **synthetic**, written for this project:

- Domains use reserved TLDs/names (`.test`, `example.com`) that can never resolve (RFC 2606 / RFC 6761).
- IPs come from documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, RFC 5737).
- The HTML attachment in `02` contains no script and posts to a `.test` domain.

| File | Scenario |
|------|----------|
| `01-credential-harvest.eml` | Lookalike-domain credential phishing, SPF/DMARC fail, link text ≠ link target |
| `02-malicious-attachment.eml` | Invoice lure with a double-extension HTML attachment (HTML smuggling / credential form). Passes SPF/DKIM because the sender domain is attacker-owned |
| `03-legitimate.eml` | Benign control email |

**Real phishing samples:** to analyse real ones, use your own spam folder or public datasets, and put them in `sample-emails/private/` (git-ignored). Never commit real recipients' addresses.
