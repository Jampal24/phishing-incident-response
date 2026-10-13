# Phishing Response Playbook

Follows the NIST SP 800-61 incident response lifecycle.

## 1. Detection and triage (first 15 minutes)
1. Get the original email **as an attachment / .eml** (not a forward, which strips headers).
2. Run `python scripts/phish_analyzer.py <file>.eml --json ioc-reports/<id>.json --markdown analysis/<id>-auto.md`.
3. Check by hand:
   - Authentication-Results: SPF, DKIM, DMARC.
   - From vs Reply-To vs Return-Path.
   - The first external `Received` hop: the real sending IP.
   - Link **text** vs link **target**.
   - Attachments: hash, real file type, double extension.
4. Look up IOCs in a sandbox or reputation service, without clicking: VirusTotal, URLScan.io, AbuseIPDB, MXToolbox.
   Only upload attachment *hashes* to VirusTotal unless your policy allows uploading files.

## 2. Scoping
- Who else got it? Search the mail gateway / M365 message trace by sender, subject and URL.
- Did anyone click? Check proxy/DNS logs for the phishing domain or IP.
- Did anyone submit credentials? Check sign-in logs for the targeted users after the click time: new IPs or countries, MFA prompts.

## 3. Containment
- Purge the message from every mailbox (e.g. M365 Content Search → Purge).
- Block the sender domain, URLs and IPs at the mail gateway, proxy and DNS.
- For users who submitted credentials: reset the password, revoke sessions/refresh tokens, review MFA methods and inbox rules (forwarding rules are a classic persistence trick).

## 4. Eradication and recovery
- If an attachment ran: isolate the host, collect triage data, re-image if needed.
- Check for attacker-created mailbox rules, OAuth app consents and new MFA devices.

## 5. Lessons learned
- Write the incident report (see `analysis/INC-*.md`).
- Add detections: mail gateway rules, SIEM alerts for logins after clicks.
- Feed the example into security awareness training.
