"""Step 2 of the pipeline: header checks (rules layer).

These are the checks a SOC analyst runs first on a suspicious email.
Each one maps to a real spoofing technique:

- SPF / DKIM / DMARC failures: the sending server was not authorized
  to send for the domain it claims (SPF), the message was not signed
  or the signature does not verify (DKIM), or the domain's own policy
  check failed (DMARC). "fail" is strong evidence; "none" (absent) is
  weaker -- plenty of small legitimate senders never set these up.
- Reply-To / Return-Path on a different domain than From: replies and
  bounces are quietly routed to the attacker.
- A brand name in the display name or subject while the actual sending
  domain is unrelated ("PayPal Security Team" sending from a random
  domain) -- classic display-name spoofing.
- No Received headers at all: a pasted or hand-built message with no
  mail-server trail. Real mail always leaves hops.

Point weights are judgment calls, documented here so they can be
defended and tuned: a hard authentication failure (20-25) outweighs a
soft signal like a missing DKIM (8), because legitimate senders fail
soft signals all the time.
"""

from .findings import Flag
from .parser import ParsedEmail

# Well-known brands phishers impersonate. If one of these names shows up
# in the display name or subject but the From domain is not one of the
# brand's real domains, that is a spoofing pattern.
BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "bank of america": {"bankofamerica.com", "bofa.com"},
    "wells fargo": {"wellsfargo.com"},
    "irs": {"irs.gov"},
    "github": {"github.com"},
}


def check_headers(parsed: ParsedEmail) -> list:
    flags = []
    auth = parsed.auth_results

    # --- Authentication results -------------------------------------------
    # DMARC fail is the strongest single header signal: the domain owner
    # published a policy and this message did not satisfy it.
    if auth.get("dmarc") == "fail":
        flags.append(Flag(
            "dmarc_fail", 25,
            "DMARC check failed in the headers: the message does not line up "
            "with the sending domain's own published email policy.",
            "header"))
    if auth.get("spf") == "fail":
        flags.append(Flag(
            "spf_fail", 20,
            "SPF check failed in the headers: the server that sent this was "
            "not authorized to send mail for the sender's domain.",
            "header"))
    elif auth.get("spf") == "softfail":
        flags.append(Flag(
            "spf_softfail", 10,
            "SPF soft-failed: the sending server is not clearly authorized "
            "for the sender's domain.",
            "header"))
    if auth.get("dkim") in ("fail",):
        flags.append(Flag(
            "dkim_fail", 15,
            "DKIM check failed: the message's digital signature does not "
            "verify, so it may have been altered or forged.",
            "header"))
    if not auth:
        flags.append(Flag(
            "no_auth_results", 8,
            "No authentication results (SPF/DKIM/DMARC) are recorded for this "
            "message, so its origin cannot be verified from the headers.",
            "header"))
    elif auth.get("spf") in (None, "none") and auth.get("dmarc") in (None, "none"):
        flags.append(Flag(
            "no_spf_or_dmarc", 8,
            "Neither SPF nor DMARC results are present for this message.",
            "header"))

    # --- Routing mismatches -------------------------------------------------
    if parsed.reply_to_domain and parsed.from_domain \
            and parsed.reply_to_domain != parsed.from_domain:
        flags.append(Flag(
            "reply_to_mismatch", 15,
            f"Sender domain does not match the Reply-To domain "
            f"({parsed.from_domain} vs {parsed.reply_to_domain}). Replies "
            f"would go somewhere other than the apparent sender.",
            "header"))
    if parsed.return_path_domain and parsed.from_domain \
            and parsed.return_path_domain != parsed.from_domain:
        flags.append(Flag(
            "return_path_mismatch", 8,
            f"The Return-Path domain ({parsed.return_path_domain}) differs "
            f"from the From domain ({parsed.from_domain}).",
            "header"))

    # --- Display-name / brand spoofing --------------------------------------
    haystack = f"{parsed.from_name} {parsed.subject}".lower()
    brand_display = {"paypal": "PayPal", "irs": "IRS"}
    for brand, real_domains in BRAND_DOMAINS.items():
        if brand in haystack and parsed.from_domain not in real_domains:
            display_name = brand_display.get(brand, brand.title())
            flags.append(Flag(
                "brand_spoof", 20,
                f"The message presents itself as {display_name} but was "
                f"sent from {parsed.from_domain or 'an unknown domain'}, "
                f"which is not a {display_name} domain.",
                "header"))
            break  # one brand flag is enough

    # --- Missing mail trail ---------------------------------------------------
    if parsed.received_count == 0:
        flags.append(Flag(
            "no_received_chain", 5,
            "The message has no Received headers, so there is no mail-server "
            "trail showing where it actually came from.",
            "header"))

    return flags
