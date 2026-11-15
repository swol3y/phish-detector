"""Text heuristics: the social-engineering layer.

The ML model reads the whole message statistically; these checks name
the specific pressure tactics a human analyst would circle with a pen.
Phishing works by rushing the reader past their judgment, so the
tactics are consistent across campaigns:

- urgency / deadline pressure ("within 24 hours", "act now", "final
  warning") -- manufacture panic so the victim clicks before thinking;
- credential and payment harvesting asks ("confirm your password",
  "enter your card details") -- the actual payload of most phishing;
- secrecy and isolation ("do not discuss this with anyone") -- the
  signature of CEO fraud / business email compromise, where the
  attacker needs the victim to skip normal approval channels;
- threat language ("account will be closed", "funds will be
  forfeited") -- fear as the lever.

Weights are deliberately modest: legitimate marketing mail uses urgency
constantly (see samples/06, the documented false positive), so language
alone should raise suspicion, not convict. It convicts in combination
with header and URL evidence.
"""

import re

from .findings import Flag

URGENCY_PATTERNS = [
    r"within \d+ hours", r"act now", r"immediately", r"urgent",
    r"final (notice|warning)", r"expires (today|in \d+)", r"last chance",
    r"right away", r"before it is too late", r"ends tonight", r"hurry",
]
CREDENTIAL_PATTERNS = [
    r"confirm your password", r"enter your password", r"verify your password",
    r"your password.{0,30}(confirm|enter|verify)",
    r"card (details|number)", r"bank account (details|number)",
    r"social security number", r"recovery phrase", r"routing number",
    r"confirm your identity", r"update your (payment|billing)",
]
SECRECY_PATTERNS = [
    r"do not discuss", r"confidential", r"do not tell", r"keep this between",
    r"not public yet",
]
THREAT_PATTERNS = [
    r"will be (suspended|closed|deleted|locked|forfeited|seized|cancelled)",
    r"permanently (suspended|deleted|removed|closed)", r"loss of funds",
    r"account closure",
]


def _count_matches(text: str, patterns: list) -> list:
    hits = []
    for pattern in patterns:
        if re.search(pattern, text):
            hits.append(pattern)
    return hits


def check_text(subject: str, body: str) -> list:
    text = f"{subject}\n{body}".lower()
    flags = []

    urgency_hits = _count_matches(text, URGENCY_PATTERNS)
    if len(urgency_hits) >= 2:
        flags.append(Flag(
            "urgency_pressure", 10,
            "The message pushes urgency and deadlines, a classic pressure "
            "tactic meant to get a click before the reader stops to think.",
            "text"))
    elif len(urgency_hits) == 1:
        flags.append(Flag(
            "urgency_pressure", 5,
            "The message uses urgency language, which is common in both "
            "phishing and aggressive marketing.",
            "text"))

    if _count_matches(text, CREDENTIAL_PATTERNS):
        flags.append(Flag(
            "credential_request", 15,
            "The message asks the reader to hand over credentials, payment "
            "card, or bank details. Legitimate companies do not collect "
            "passwords or full card numbers by email.",
            "text"))

    if _count_matches(text, SECRECY_PATTERNS):
        flags.append(Flag(
            "secrecy_request", 10,
            "The message asks for secrecy or confidentiality around a "
            "request, the signature move of CEO fraud: the victim is kept "
            "from checking with anyone else.",
            "text"))

    if _count_matches(text, THREAT_PATTERNS):
        flags.append(Flag(
            "threat_language", 8,
            "The message threatens account closure, deletion, or loss of "
            "funds if the reader does not comply.",
            "text"))

    # Shouty subject line: many capitals or exclamation marks.
    if subject and (subject.count("!") >= 2
                    or sum(1 for c in subject if c.isupper()) > max(10, len(subject) * 0.6)):
        flags.append(Flag(
            "shouty_subject", 3,
            "The subject line shouts (heavy capitals or exclamation marks), "
            "a low-grade signal shared by phishing and spam marketing.",
            "text"))

    return flags
