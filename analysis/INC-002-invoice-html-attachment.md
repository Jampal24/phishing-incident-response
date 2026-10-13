# INC-002: Invoice lure with credential-harvesting HTML attachment

> Analysis of the **synthetic** sample `sample-emails/02-malicious-attachment.eml`. Automated output: [02-malicious-attachment-auto.md](02-malicious-attachment-auto.md). IOCs: [../ioc-reports/02-malicious-attachment.json](../ioc-reports/02-malicious-attachment.json).

| Field | Value |
|---|---|
| Verdict | **Malicious: credential phishing via HTML attachment** |
| Severity | High (finance mailbox targeted; credential theft) |
| MITRE ATT&CK | T1566.001 Spearphishing Attachment, T1204.002 User Execution: Malicious File, T1036.008 Masquerade File Type |
| Recipient | finance@example.com |

## Summary
An "overdue invoice" email to the finance mailbox carries an attachment named `INV-20419.pdf.html`. It looks like a PDF but is an HTML page. Opened in a browser, it shows a fake "Secure Document Viewer" asking for an email and password, and the form sends them to `collect[.]invoice-share[.]test`. The email **passes SPF, DKIM and DMARC**. The attacker controls the sending domain, so authentication only proves who sent it, not that the sender is trustworthy.

## Key evidence
1. **Disguised file type:** a double extension, `.pdf.html`. Windows hides known extensions by default, so the user sees `INV-20419.pdf`.
2. **Credential form:** the attachment contains `<input type="password">` inside a `<form>`, with nothing else on the page.
3. **Exfiltration destination:** `form action="hxxps://collect[.]invoice-share[.]test/post[.]php"` sends the typed credentials to a third-party domain. That domain appears nowhere in the email body. It's only in the attachment, which is why the attachment has to be inspected and not just the email.
4. **Authentication passes:** SPF/DKIM/DMARC = pass for `vendor-billing[.]test`. This is a lookalike or newly registered "vendor" domain the attacker set up, a common way around filters that rely on authentication results.
5. **Social engineering:** financial urgency ("30 days overdue", "payment required today", "avoid late fees") aimed at a team that routinely opens invoices.
6. **Safe handling:** the attachment was extracted and hashed by the script. It was **not opened in a browser**; its contents were read as text.

## IOCs
| Type | Value |
|---|---|
| Domain | collect[.]invoice-share[.]test (credential collection) |
| URL | hxxps://collect[.]invoice-share[.]test/post[.]php |
| Domain | vendor-billing[.]test (sender) |
| Email | accounts@vendor-billing[.]test |
| IP | 192[.]0[.]2[.]77 (sending server) |
| SHA256 | `88f002a3ef10ecd8d9dbf8cd266ff157188e61034a1db3de0fd558d7db701106` (INV-20419.pdf.html) |

## Recommended response
- Purge the email from all mailboxes; search message trace for the same sender, subject and attachment hash.
- Block `invoice-share.test` and `vendor-billing.test` at the mail gateway, web proxy and DNS.
- Check proxy logs for POST requests to `collect.invoice-share.test`. Any hit means credentials were submitted: reset the password, revoke sessions, and review sign-ins and inbox rules for that user.
- Mail gateway rule: quarantine `.html`/`.htm`/`.shtml` attachments, or any attachment with a double extension, from external senders.
- Confirm with the real vendor through a known phone number (not the email) whether invoice INV-20419 exists.

## Lessons learned
- **SPF/DKIM/DMARC passing ≠ safe.** Authentication proves the domain sent the mail, not that the domain is legitimate.
- The most important IOC (where the passwords go) was inside the attachment. The first version of `phish_analyzer.py` only scanned the email body and **missed it**. The analyzer now extracts URLs and form actions from HTML attachments without rendering them, and a test covers this case.
