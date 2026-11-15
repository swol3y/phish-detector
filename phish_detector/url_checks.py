"""Step 4 of the pipeline: URL checks (rules layer).

Phishing lives or dies on the link: the victim has to end up on the
attacker's page. These checks look at where each link really goes:

- Display text vs destination mismatch: the anchor says
  "www.paypal.com/verify" but the href points somewhere else entirely.
- IP-address links: legitimate companies link to domain names, not raw
  IPs. A raw IP also hides who owns the server.
- URL shorteners (bit.ly, tinyurl, ...): they conceal the destination
  until after the click. Marketers use them too, so this is a small
  weight on its own -- it matters in combination.
- Punycode domains (xn--...): the encoding behind lookalike domains
  that render as familiar names in some mail clients.
- Lookalike domains: paypa1.com, micros0ft.com -- a brand name with
  digits swapped for letters, hosted on an unrelated domain.
- Plain HTTP on a login-flavored link: credentials should never be
  typed into a non-HTTPS page.

Nothing here ever fetches a URL. v1 is analysis only -- no clicking,
no detonating (see the spec's safety rules).
"""

import re
from urllib.parse import urlparse

from .findings import Flag
from .parser import Link

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy",
    "shorturl.at", "is.gd", "buff.ly", "cutt.ly", "tiny.cc",
}

# Letter/digit swaps phishers use to build lookalike domains.
LOOKALIKE_BRANDS = ["paypal", "microsoft", "apple", "amazon", "netflix",
                    "chase", "google", "facebook", "instagram", "wellsfargo"]
DIGIT_SWAPS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"})


def _host(url: str) -> str:
    """Hostname of a URL, lowercased, without a leading www."""
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _registrable(host: str) -> str:
    """Last two labels of a hostname (a simplification of the public-suffix
    problem, fine for v1 heuristics): paypal-secure.com -> paypal-secure.com."""
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def check_urls(links: list) -> list:
    flags = []
    seen_kinds = set()  # each kind of URL flag fires once per email, not per link

    def add(flag: Flag) -> None:
        if flag.name not in seen_kinds:
            seen_kinds.add(flag.name)
            flags.append(flag)

    for link in links:
        url = link.url.strip()
        # Sample data in this repo is defanged (hxxp); accept it gracefully.
        normalized = url.replace("hxxp", "http", 1) if url.lower().startswith("hxxp") else url
        host = _host(normalized)
        if not host:
            continue
        domain = _registrable(host)

        # Display text hides a different destination domain.
        display = link.display_text.strip()
        display_domain = ""
        display_match = re.search(r"(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", display.lower())
        if display_match and " " not in display:
            display_domain = _registrable(display_match.group(1))
        if display_domain and display_domain != domain:
            # Name the real destination: the full host when it is a raw IP
            # (a registrable-domain view of an IP is meaningless).
            destination = host if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) else domain
            add(Flag(
                "link_text_mismatch", 20,
                f"A link's visible text hides a different destination: the "
                f"text points to {display_domain} but the link actually goes "
                f"to {destination}.",
                "url"))

        # Raw IP address as the host.
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            add(Flag(
                "ip_address_link", 15,
                f"A link goes to a raw IP address ({host}) instead of a "
                f"company domain name, which hides who owns the server.",
                "url"))

        # URL shortener.
        if domain in SHORTENERS:
            add(Flag(
                "url_shortener", 8,
                f"A link uses a URL shortener ({domain}), so the real "
                f"destination is hidden until after the click.",
                "url"))

        # Punycode.
        if "xn--" in host:
            add(Flag(
                "punycode_domain", 15,
                f"A link uses a punycode domain ({host}), an encoding often "
                f"used to disguise lookalike brand names.",
                "url"))

        # Lookalike brand domain (digits swapped back into letters).
        squashed = domain.split(".")[0].translate(DIGIT_SWAPS).replace("-", "")
        for brand in LOOKALIKE_BRANDS:
            if brand in squashed and brand not in domain:
                add(Flag(
                    "lookalike_domain", 20,
                    f"A link goes to {domain}, which looks like a misspelled "
                    f"imitation of {brand}.com.",
                    "url"))
                break
            if brand in squashed and domain != f"{brand}.com" and any(c.isdigit() for c in domain):
                add(Flag(
                    "lookalike_domain", 20,
                    f"A link goes to {domain}, which imitates {brand}.com "
                    f"with digits swapped for letters.",
                    "url"))
                break

        # Plain HTTP.
        if normalized.lower().startswith("http://"):
            add(Flag(
                "plain_http_link", 5,
                "A link uses plain HTTP instead of HTTPS, so anything typed "
                "on that page would travel unencrypted.",
                "url"))

    return flags
