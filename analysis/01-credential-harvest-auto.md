# Phishing analysis: 01-credential-harvest.eml

**Verdict:** MALICIOUS (score 100/100)

## Headers
| Field | Value |
|---|---|
| Subject | Action Required: Unusual sign-in activity |
| From | Microsoft Account Team `no-reply@micros0ft-account[.]test` |
| Reply-To | `account-verify@protonmail-lookalike[.]test` |
| Return-Path | `bounce-7731@mailer[.]secure-notify[.]test` |
| Date | Thu, 08 Oct 2026 14:02:05 +0000 |
| Message-ID | `<20261008140205.88213@localhost>` |
| SPF / DKIM / DMARC | fail / none / fail |

## Received path (origin → recipient)
1. from localhost (vps-88[.]cheap-host[.]test [198[.]51[.]100[.]23]) by mailer[.]secure-notify[.]test with SMTP; Thu, 08 Oct 2026 14:02:09 +0000
2. from mailer[.]secure-notify[.]test (unknown [203[.]0[.]113[.]45]) by mx1[.]example[.]com (Postfix) with ESMTP id 4F1A2B3C4D for <j[.]doe@example[.]com>; Thu, 08 Oct 2026 14:02:11

## Red flags
- SPF = fail
- DKIM = none
- DMARC = fail
- Reply-To domain (protonmail-lookalike[.]test) differs from From (micros0ft-account[.]test)
- Return-Path domain (mailer[.]secure-notify[.]test) differs from From (micros0ft-account[.]test)
- Lookalike domain imitating 'microsoft': micros0ft-account[.]test
- Link text shows account.microsoft.com but points to 198[.]51[.]100[.]23
- Link to a raw IP address: hxxp://198[.]51[.]100[.]23/owa/login[.]php?u=j[.]doe@example[.]com
- Unencrypted HTTP link: 198[.]51[.]100[.]23
- Unencrypted HTTP link: login[.]micros0ft-account[.]test
- Urgency/pressure language in subject: unusual sign-in, action required
- Remote tracking image(s): 1
- Bulk-mail script in X-Mailer: PHPMailer 6.1.4

## Links
| Visible text | Actual target |
|---|---|
| https://account.microsoft.com/security | `hxxp://198[.]51[.]100[.]23/owa/login[.]php?u=j[.]doe@example[.]com` |
| (plain text) | `hxxp://login[.]micros0ft-account[.]test/verify?id=j[.]doe@example[.]com` |

## Attachments
None

## IOCs (defanged)
- **ips:** `198[.]51[.]100[.]23`, `203[.]0[.]113[.]45`
- **domains:** `login[.]micros0ft-account[.]test`, `mailer[.]secure-notify[.]test`, `micros0ft-account[.]test`, `protonmail-lookalike[.]test`, `track[.]secure-notify[.]test`
- **urls:** `hxxp://198[.]51[.]100[.]23/owa/login[.]php?u=j[.]doe@example[.]com`, `hxxp://login[.]micros0ft-account[.]test/verify?id=j[.]doe@example[.]com`, `hxxp://track[.]secure-notify[.]test/open[.]gif?id=88213`
- **emails:** `account-verify@protonmail-lookalike[.]test`, `bounce-7731@mailer[.]secure-notify[.]test`, `no-reply@micros0ft-account[.]test`
