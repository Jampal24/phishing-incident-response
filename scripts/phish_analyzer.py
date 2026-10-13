#!/usr/bin/env python3
"""
phish_analyzer.py - triage a suspicious .eml file.

Extracts headers, the Received path, SPF/DKIM/DMARC results, URLs, attachments
(with hashes) and indicators of compromise, then scores common phishing red flags.

Standard library only. Never opens links or executes attachments.

Usage:
    python scripts/phish_analyzer.py sample-emails/01-credential-harvest.eml
    python scripts/phish_analyzer.py email.eml --json ioc-reports/out.json --markdown analysis/out.md
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

URL_RE = re.compile(r"""https?://[^\s"'<>)\]]+""", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)

URGENCY_WORDS = [
    "urgent", "immediately", "within 24 hours", "suspended", "verify your account",
    "unusual sign-in", "payment required", "overdue", "action required", "password expires",
]
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".html", ".htm",
    ".iso", ".img", ".lnk", ".one", ".docm", ".xlsm", ".pptm", ".bat", ".cmd", ".ps1", ".zip", ".7z",
}
BRANDS = ["microsoft", "office365", "paypal", "apple", "amazon", "docusign", "dhl", "netflix", "google"]


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    flags: list[str] = field(default_factory=list)
    embedded_urls: list[str] = field(default_factory=list)


@dataclass
class Link:
    href: str
    text: str = ""
    domain: str = ""


@dataclass
class Report:
    file: str
    subject: str = ""
    from_addr: str = ""
    from_display: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    message_id: str = ""
    x_mailer: str = ""
    auth: dict[str, str] = field(default_factory=dict)
    received_hops: list[dict] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    red_flags: list[str] = field(default_factory=list)
    score: int = 0
    verdict: str = ""


class _LinkExtractor(HTMLParser):
    """Collects <a href> targets with their visible text, plus <img src>."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[Link] = []
        self.images: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"], []
        elif tag == "img" and a.get("src"):
            self.images.append(a["src"])

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(Link(href=self._href, text="".join(self._text).strip()))
            self._href = None


def defang(value: str) -> str:
    """Make an IOC non-clickable: http -> hxxp, '.' -> '[.]'."""
    v = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    return v.replace(".", "[.]")


def domain_of(address_or_url: str) -> str:
    if "://" in address_or_url:
        return (urlparse(address_or_url).hostname or "").lower()
    return address_or_url.rsplit("@", 1)[-1].lower().strip(">") if "@" in address_or_url else ""


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Documentation ranges count as "external" so the synthetic samples behave like real mail.
    doc_nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    if any(addr in n for n in doc_nets):
        return True
    return addr.is_global


def parse_email(path: Path) -> EmailMessage:
    with path.open("rb") as fh:
        return BytesParser(policy=policy.default).parse(fh)


def analyze(path: Path) -> Report:
    msg = parse_email(path)
    r = Report(file=str(path))

    r.subject = str(msg.get("Subject", ""))
    r.from_display, r.from_addr = parseaddr(str(msg.get("From", "")))
    r.reply_to = parseaddr(str(msg.get("Reply-To", "")))[1]
    r.return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    r.to = str(msg.get("To", ""))
    r.date = str(msg.get("Date", ""))
    r.message_id = str(msg.get("Message-ID", ""))
    r.x_mailer = str(msg.get("X-Mailer", ""))

    # Authentication-Results (take the first verdict for each mechanism)
    for header in msg.get_all("Authentication-Results", []) or []:
        for mech, result in AUTH_RE.findall(str(header)):
            r.auth.setdefault(mech.lower(), result.lower())

    # Received chain: headers are prepended, so reverse to get origin -> destination
    for hop in reversed(msg.get_all("Received", []) or []):
        text = " ".join(str(hop).split())
        r.received_hops.append({"header": text, "ips": IPV4_RE.findall(text)})

    # Bodies and attachments
    html_parser = _LinkExtractor()
    text_urls: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename or part.get_content_disposition() == "attachment":
            r.attachments.append(_attachment(filename or "unnamed", part.get_content_type(), payload))
            continue
        ctype = part.get_content_type()
        content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if ctype == "text/html":
            html_parser.feed(content)
        elif ctype == "text/plain":
            text_urls.extend(URL_RE.findall(content))

    seen: set[str] = set()
    for link in html_parser.links + [Link(href=u) for u in text_urls]:
        if link.href.startswith(("http://", "https://")) and link.href not in seen:
            seen.add(link.href)
            link.domain = domain_of(link.href)
            r.links.append(link)
    tracking_pixels = [u for u in html_parser.images if u.startswith("http")]

    _collect_iocs(r, tracking_pixels)
    _score(r, tracking_pixels)
    return r


def _attachment(filename: str, ctype: str, data: bytes) -> Attachment:
    att = Attachment(
        filename=filename, content_type=ctype, size=len(data),
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )
    suffixes = [s.lower() for s in Path(filename).suffixes]
    if len(suffixes) >= 2:
        att.flags.append(f"double extension ({''.join(suffixes)})")
    if suffixes and suffixes[-1] in RISKY_EXTENSIONS:
        att.flags.append(f"risky file type ({suffixes[-1]})")
    if b"<form" in data.lower() and b"password" in data.lower():
        att.flags.append("contains a password form (credential harvesting)")
    if data[:2] == b"MZ":
        att.flags.append("Windows executable (MZ header)")
    if ctype.startswith("text/") or (suffixes and suffixes[-1] in (".html", ".htm", ".svg")):
        text = data.decode("utf-8", errors="replace")
        att.embedded_urls = sorted(set(URL_RE.findall(text)))
        for action in re.findall(r"""<form[^>]+action=["']?(https?://[^"'\s>]+)""", text, re.IGNORECASE):
            att.flags.append(f"form submits data to {domain_of(action)}")
    return att


def _collect_iocs(r: Report, pixels: list[str]) -> None:
    ips: list[str] = []
    for hop in r.received_hops:
        ips += [ip for ip in hop["ips"] if is_public_ip(ip)]
    for link in r.links:
        if IPV4_RE.fullmatch(link.domain or ""):
            ips.append(link.domain)
    domains = {domain_of(a) for a in (r.from_addr, r.reply_to, r.return_path) if a}
    domains |= {lk.domain for lk in r.links if lk.domain and not IPV4_RE.fullmatch(lk.domain)}
    domains |= {domain_of(p) for p in pixels}
    attachment_urls = {u for a in r.attachments for u in a.embedded_urls}
    domains |= {domain_of(u) for u in attachment_urls if not IPV4_RE.fullmatch(domain_of(u))}
    ips += [domain_of(u) for u in attachment_urls if IPV4_RE.fullmatch(domain_of(u))]
    r.iocs = {
        "ips": sorted(set(ips)),
        "domains": sorted(d for d in domains if d),
        "urls": sorted({lk.href for lk in r.links} | set(pixels) | attachment_urls),
        "emails": sorted({a for a in (r.from_addr, r.reply_to, r.return_path) if a}),
        "sha256": sorted(a.sha256 for a in r.attachments),
    }


def _score(r: Report, pixels: list[str]) -> None:
    flags: list[tuple[int, str]] = []
    for mech in ("spf", "dkim", "dmarc"):
        result = r.auth.get(mech, "missing")
        if result in ("fail", "softfail", "none", "missing", "permerror"):
            flags.append((15 if mech == "dmarc" else 10, f"{mech.upper()} = {result}"))

    from_dom = domain_of(r.from_addr)
    if r.reply_to and domain_of(r.reply_to) != from_dom:
        flags.append((15, f"Reply-To domain ({domain_of(r.reply_to)}) differs from From ({from_dom})"))
    if r.return_path and domain_of(r.return_path) not in (from_dom,) and not domain_of(r.return_path).endswith("." + from_dom):
        flags.append((5, f"Return-Path domain ({domain_of(r.return_path)}) differs from From ({from_dom})"))

    display = r.from_display.lower()
    for brand in BRANDS:
        if brand in display and brand not in from_dom.replace("0", "o"):
            flags.append((20, f"Display name claims '{brand}' but sender domain is {from_dom}"))
        elif brand in from_dom.replace("0", "o").replace("1", "l") and brand not in from_dom:
            flags.append((25, f"Lookalike domain imitating '{brand}': {from_dom}"))

    for link in r.links:
        text_dom = domain_of(link.text) if "://" in link.text else ""
        if text_dom and text_dom != link.domain:
            flags.append((25, f"Link text shows {text_dom} but points to {link.domain}"))
        if IPV4_RE.fullmatch(link.domain or ""):
            flags.append((15, f"Link to a raw IP address: {link.href}"))
        if link.href.lower().startswith("http://"):
            flags.append((5, f"Unencrypted HTTP link: {link.domain}"))

    body_text = (r.subject + " ").lower()
    hits = [w for w in URGENCY_WORDS if w in body_text]
    if hits:
        flags.append((10, f"Urgency/pressure language in subject: {', '.join(hits)}"))

    for att in r.attachments:
        for f in att.flags:
            flags.append((20, f"Attachment {att.filename}: {f}"))
    if pixels:
        flags.append((5, f"Remote tracking image(s): {len(pixels)}"))
    if "phpmailer" in r.x_mailer.lower():
        flags.append((5, f"Bulk-mail script in X-Mailer: {r.x_mailer}"))

    # Deduplicate while keeping order
    seen, unique = set(), []
    for pts, text in flags:
        if text not in seen:
            seen.add(text)
            unique.append((pts, text))
    r.red_flags = [t for _, t in unique]
    r.score = min(100, sum(p for p, _ in unique))
    r.verdict = "MALICIOUS" if r.score >= 50 else "SUSPICIOUS" if r.score >= 20 else "LIKELY BENIGN"


def to_markdown(r: Report) -> str:
    def d(v: str) -> str:
        return f"`{defang(v)}`"

    lines = [
        f"# Phishing analysis: {Path(r.file).name}",
        "",
        f"**Verdict:** {r.verdict} (score {r.score}/100)",
        "",
        "## Headers",
        "| Field | Value |", "|---|---|",
        f"| Subject | {r.subject} |",
        f"| From | {r.from_display} {d(r.from_addr)} |",
        f"| Reply-To | {d(r.reply_to) if r.reply_to else '-'} |",
        f"| Return-Path | {d(r.return_path) if r.return_path else '-'} |",
        f"| Date | {r.date} |",
        f"| Message-ID | `{r.message_id}` |",
        "| SPF / DKIM / DMARC | " + " / ".join(r.auth.get(m, "missing") for m in ("spf", "dkim", "dmarc")) + " |",
        "",
        "## Received path (origin → recipient)",
    ]
    for i, hop in enumerate(r.received_hops, 1):
        lines.append(f"{i}. {defang(hop['header'][:160])}")
    def defang_text(text: str) -> str:
        text = URL_RE.sub(lambda m: defang(m.group(0)), text)
        text = IPV4_RE.sub(lambda m: defang(m.group(0)), text)
        for dom in r.iocs.get("domains", []):
            text = text.replace(dom, defang(dom))
        return text

    lines += ["", "## Red flags"] + [f"- {defang_text(f)}" for f in r.red_flags or ["None"]]
    lines += ["", "## Links", "| Visible text | Actual target |", "|---|---|"]
    lines += [f"| {lk.text or '(plain text)'} | {d(lk.href)} |" for lk in r.links] or ["| - | - |"]
    lines += ["", "## Attachments"]
    if r.attachments:
        lines += ["| File | Type | Size | SHA256 |", "|---|---|---|---|"]
        lines += [f"| {a.filename} | {a.content_type} | {a.size} | `{a.sha256}` |" for a in r.attachments]
    else:
        lines.append("None")
    lines += ["", "## IOCs (defanged)"]
    for kind, values in r.iocs.items():
        if values:
            lines.append(f"- **{kind}:** " + ", ".join(d(v) if kind != "sha256" else f"`{v}`" for v in values))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Triage a suspicious .eml file")
    ap.add_argument("eml", type=Path, nargs="+")
    ap.add_argument("--json", type=Path, help="write the IOC report as JSON (single input only)")
    ap.add_argument("--markdown", type=Path, help="write the analysis as Markdown (single input only)")
    args = ap.parse_args(argv)

    if (args.json or args.markdown) and len(args.eml) > 1:
        ap.error("--json/--markdown only work with a single input file")

    for path in args.eml:
        report = analyze(path)
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(json.dumps(asdict(report), indent=2))
        if args.markdown:
            args.markdown.parent.mkdir(parents=True, exist_ok=True)
            args.markdown.write_text(to_markdown(report))
        print(f"{path.name:40} {report.verdict:14} score={report.score:3}  flags={len(report.red_flags)}")
        for f in report.red_flags:
            print(f"    - {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
