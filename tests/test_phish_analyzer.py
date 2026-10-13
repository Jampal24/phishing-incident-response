import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from phish_analyzer import analyze, defang, to_markdown  # noqa: E402

SAMPLES = ROOT / "sample-emails"


def test_defang():
    assert defang("http://evil.test/a") == "hxxp://evil[.]test/a"
    assert defang("198.51.100.23") == "198[.]51[.]100[.]23"


def test_credential_harvest_is_malicious():
    r = analyze(SAMPLES / "01-credential-harvest.eml")
    assert r.verdict == "MALICIOUS"
    assert r.auth == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert "Action Required" in r.subject  # RFC 2047 encoded subject was decoded
    assert any("Link text shows account.microsoft.com" in f for f in r.red_flags)
    assert any("Reply-To" in f for f in r.red_flags)
    assert "198.51.100.23" in r.iocs["ips"]
    assert "203.0.113.45" in r.iocs["ips"]
    assert "micros0ft-account.test" in r.iocs["domains"]


def test_attachment_hashed_and_flagged():
    r = analyze(SAMPLES / "02-malicious-attachment.eml")
    assert len(r.attachments) == 1
    att = r.attachments[0]
    assert att.filename == "INV-20419.pdf.html"
    assert len(att.sha256) == 64
    assert any("double extension" in f for f in att.flags)
    assert any("password form" in f for f in att.flags)
    assert r.verdict in ("SUSPICIOUS", "MALICIOUS")
    # The credential form's destination is the key IOC and must be extracted from the attachment
    assert any("form submits data to collect.invoice-share.test" in f for f in att.flags)
    assert "collect.invoice-share.test" in r.iocs["domains"]
    assert "https://collect.invoice-share.test/post.php" in r.iocs["urls"]


def test_legitimate_email_is_benign():
    r = analyze(SAMPLES / "03-legitimate.eml")
    assert r.verdict == "LIKELY BENIGN"
    assert r.attachments == []


def test_markdown_is_defanged():
    md = to_markdown(analyze(SAMPLES / "01-credential-harvest.eml"))
    assert "hxxp://" in md
    assert "http://198.51.100.23" not in md
