"""Step 1 of the pipeline: parse a raw email into the pieces we check.

Uses only Python's built-in ``email`` library. Given the full text of an
email (headers + body, e.g. an .eml file), it extracts:

- the headers an analyst looks at first (From, Reply-To, Return-Path,
  Subject, and the Received chain),
- the authentication results (SPF / DKIM / DMARC) recorded by the
  receiving mail server in the Authentication-Results header,
- the plain-text body (HTML is stripped to text),
- every link in the body, keeping the visible text next to the real
  destination so the URL checks can compare them.
"""

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from html import unescape


@dataclass
class Link:
    """One link from the body: what the reader sees vs where it goes."""

    display_text: str  # visible text, e.g. "www.paypal.com/verify"
    url: str           # actual destination, e.g. "http://185.220.14.9/..."


@dataclass
class ParsedEmail:
    """Everything the later pipeline steps need, in one object."""

    subject: str = ""
    from_name: str = ""        # display name, e.g. "PayPal Security Team"
    from_address: str = ""     # e.g. service@paypa1-secure.com
    from_domain: str = ""
    reply_to_address: str = ""
    reply_to_domain: str = ""
    return_path_domain: str = ""
    received_count: int = 0    # hops in the Received chain
    auth_results: dict = field(default_factory=dict)  # spf/dkim/dmarc -> pass/fail/none/...
    body_text: str = ""
    links: list = field(default_factory=list)  # list[Link]


def domain_of(address: str) -> str:
    """Return the lowercase domain part of an email address ('' if none)."""
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().lower().strip("<>")


def _parse_auth_results(header_value: str) -> dict:
    """Pull spf/dkim/dmarc verdicts out of an Authentication-Results header.

    Example header:
        Authentication-Results: mx.example.com;
            spf=fail smtp.mailfrom=evil.com; dkim=none; dmarc=fail
    Returns e.g. {"spf": "fail", "dkim": "none", "dmarc": "fail"}.
    A mechanism that is absent from the header is simply not in the dict;
    the header checks treat "absent" the same as "none".
    """
    results = {}
    if not header_value:
        return results
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{mechanism}\s*=\s*([a-z]+)", header_value.lower())
        if match:
            results[mechanism] = match.group(1)
    return results


def _strip_html(html: str) -> str:
    """Reduce an HTML body to readable text (tags out, entities decoded)."""
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return unescape(re.sub(r"\s+", " ", text)).strip()


def _extract_links(body: str) -> list:
    """Find links in the raw body.

    Two shapes are covered:
    - HTML anchors: <a href="DEST">DISPLAY</a> -- display text and
      destination can differ, which is exactly what phishers abuse.
    - Bare URLs in plain text (display text = the URL itself).
    """
    links = []

    anchor_pattern = re.compile(
        r'<a\s+[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )
    for url, display in anchor_pattern.findall(body):
        display_text = _strip_html(display)
        links.append(Link(display_text=display_text, url=url.strip()))

    # Remove the anchors we already captured so bare-URL scanning does not
    # double-count their destinations.
    body_without_anchors = anchor_pattern.sub(" ", body)
    # hxxp is the defanged form of http used when samples are shared
    # safely; accept it so defanged fixtures still parse.
    for url in re.findall(r"(?:https?|hxxps?)://[^\s\"'<>\)]+", body_without_anchors):
        links.append(Link(display_text=url, url=url))
    return links


def parse_email(raw_text: str) -> ParsedEmail:
    """Parse raw email text into a ParsedEmail. Never raises on bad input:
    a malformed message simply yields empty fields, which the header
    checks then score as missing information."""
    message = Parser(policy=policy.default).parsestr(raw_text)
    parsed = ParsedEmail()

    parsed.subject = str(message.get("Subject", "") or "")

    from_name, from_address = parseaddr(str(message.get("From", "") or ""))
    parsed.from_name = from_name
    parsed.from_address = from_address.lower()
    parsed.from_domain = domain_of(from_address)

    _, reply_to_address = parseaddr(str(message.get("Reply-To", "") or ""))
    parsed.reply_to_address = reply_to_address.lower()
    parsed.reply_to_domain = domain_of(reply_to_address)

    _, return_path_address = parseaddr(str(message.get("Return-Path", "") or ""))
    parsed.return_path_domain = domain_of(return_path_address)

    parsed.received_count = len(message.get_all("Received", []) or [])
    parsed.auth_results = _parse_auth_results(
        str(message.get("Authentication-Results", "") or "")
    )

    # Body: prefer the plain-text part; fall back to stripped HTML.
    body_part = message.get_body(preferencelist=("plain", "html")) if message.is_multipart() else None
    if body_part is not None:
        content = body_part.get_content()
        raw_body = content if isinstance(content, str) else ""
        if body_part.get_content_type() == "text/html":
            parsed.body_text = _strip_html(raw_body)
        else:
            parsed.body_text = raw_body.strip()
        link_source = raw_body
    else:
        payload = message.get_payload(decode=True)
        if payload:
            raw_body = payload.decode("utf-8", errors="replace")
        else:
            raw_body = str(message.get_payload() or "")
        if message.get_content_type() == "text/html":
            parsed.body_text = _strip_html(raw_body)
        else:
            parsed.body_text = raw_body.strip()
        link_source = raw_body

    parsed.links = _extract_links(link_source)
    return parsed
