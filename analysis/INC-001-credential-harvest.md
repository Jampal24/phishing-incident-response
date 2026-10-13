# INC-001: Microsoft-themed credential harvesting email

> Analysis of the **synthetic** sample `sample-emails/01-credential-harvest.eml`. Automated output: [01-credential-harvest-auto.md](01-credential-harvest-auto.md). IOCs: [../ioc-reports/01-credential-harvest.json](../ioc-reports/01-credential-harvest.json).

| Field | Value |
|---|---|
| Verdict | **Malicious: credential phishing** |
| Severity | High (credential theft) |
| MITRE ATT&CK | T1566.002 Spearphishing Link, T1684.001 Impersonation |
| Recipient | j.doe@example.com |

## Summary
The email impersonates the Microsoft Account team. It warns about an "unusual sign-in" and pressures the user to "verify within 24 hours". The visible link reads `https://account.microsoft.com/security`, but the real target is a PHP login page on a raw IP (`hxxp://198[.]51[.]100[.]23/owa/login[.]php`). The email fails SPF and DMARC and comes from a lookalike domain using a zero in place of the letter o (`micros0ft-account[.]test`).

## Key evidence
1. **Sender authentication:** `spf=fail`, `dkim=none`, `dmarc=fail`. The sending IP 203[.]0[.]113[.]45 isn't authorised for the envelope domain.
2. **Origin:** the first Received hop is `vps-88[.]cheap-host[.]test [198[.]51[.]100[.]23]`. That's a VPS, and the same IP hosts the phishing page.
3. **Header mismatch:** Reply-To (`protonmail-lookalike[.]test`) and Return-Path (`mailer[.]secure-notify[.]test`) don't match From.
4. **Deceptive link:** the anchor text shows the real Microsoft URL, but the href points to an IP over plain HTTP. The victim's email is pre-filled in the `u=` parameter (a targeted campaign).
5. **Tooling:** `X-Mailer: PHPMailer`, a 1×1 tracking pixel, and a `Message-ID` generated at `localhost`. Together these suggest a bulk phishing kit.
6. **Social engineering:** urgency ("24 hours"), fear ("suspended"), and a foreign sign-in hook.

## IOCs
| Type | Value |
|---|---|
| IP | 198[.]51[.]100[.]23 (phishing host / origin) |
| IP | 203[.]0[.]113[.]45 (sending relay) |
| Domain | micros0ft-account[.]test |
| Domain | protonmail-lookalike[.]test |
| Domain | secure-notify[.]test, track[.]secure-notify[.]test |
| URL | hxxp://198[.]51[.]100[.]23/owa/login[.]php |

## Recommended response
- Purge from all mailboxes; block the IOCs above at the gateway, proxy and DNS.
- Check proxy/DNS logs for any request to `198.51.100.23` or `micros0ft-account.test`.
- If j.doe clicked: reset the password, revoke sessions, check sign-ins and inbox rules.
- Thank the reporter, and use the email as a training example.

## Analyst notes
- Headers were checked by hand against the tool output and matched (auth results, Received path, Reply-To mismatch).
- Reputation lookups (VirusTotal / URLScan) were skipped: the sample uses reserved `.test` domains and RFC 5737 documentation IPs, which don't exist on the internet. For real samples, run them through [soc-automation-python](https://github.com/Jampal24/soc-automation-python).
