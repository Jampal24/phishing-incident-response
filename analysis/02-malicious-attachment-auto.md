# Phishing analysis: 02-malicious-attachment.eml

**Verdict:** MALICIOUS (score 90/100)

## Headers
| Field | Value |
|---|---|
| Subject | Overdue invoice INV-20419 - payment required today |
| From | Accounts Receivable `accounts@vendor-billing[.]test` |
| Reply-To | - |
| Return-Path | `accounts@vendor-billing[.]test` |
| Date | Fri, 09 Oct 2026 08:15:40 +0000 |
| Message-ID | `<a1b2c3d4@vendor-billing.test>` |
| SPF / DKIM / DMARC | pass / pass / pass |

## Received path (origin → recipient)
1. from mail[.]vendor-billing[.]test (mail[.]vendor-billing[.]test [192[.]0[.]2[.]77]) by mx1[.]example[.]com (Postfix) with ESMTPS id 9A8B7C6D5E for <finance@example[.]com>; Fri, 09 

## Red flags
- Urgency/pressure language in subject: payment required, overdue
- Attachment INV-20419.pdf.html: double extension (.pdf.html)
- Attachment INV-20419.pdf.html: risky file type (.html)
- Attachment INV-20419.pdf.html: contains a password form (credential harvesting)
- Attachment INV-20419.pdf.html: form submits data to collect[.]invoice-share[.]test

## Links
| Visible text | Actual target |
|---|---|
| - | - |

## Attachments
| File | Type | Size | SHA256 |
|---|---|---|---|
| INV-20419.pdf.html | text/html | 319 | `88f002a3ef10ecd8d9dbf8cd266ff157188e61034a1db3de0fd558d7db701106` |

## IOCs (defanged)
- **ips:** `192[.]0[.]2[.]77`
- **domains:** `collect[.]invoice-share[.]test`, `vendor-billing[.]test`
- **urls:** `hxxps://collect[.]invoice-share[.]test/post[.]php`
- **emails:** `accounts@vendor-billing[.]test`
- **sha256:** `88f002a3ef10ecd8d9dbf8cd266ff157188e61034a1db3de0fd558d7db701106`
