"""Tests for the phish detector pipeline.

Run:  python -m pytest tests/ -v
(or:  python tests/test_detector.py  -- plain-assert fallback)

The tests cover the behavior a reviewer would probe first:
- the parser pulls the fields the checks depend on,
- each rules layer fires on the pattern it exists to catch,
- the bundled samples land in the verdict bands the project claims
  (including the documented false positive, sample 06),
- the analyzer degrades gracefully with no ML model loaded.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from phish_detector.analyzer import analyze_email  # noqa: E402
from phish_detector.header_checks import check_headers  # noqa: E402
from phish_detector.parser import parse_email  # noqa: E402
from phish_detector.scorer import verdict_for_score  # noqa: E402
from phish_detector.url_checks import check_urls  # noqa: E402

SAMPLES = PROJECT_ROOT / "samples"


def read_sample(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


def flag_names(flags) -> set:
    return {flag.name for flag in flags}


# --- parser -----------------------------------------------------------------

def test_parser_extracts_core_fields():
    parsed = parse_email(read_sample("01_phish_paypal_spoof.eml"))
    assert parsed.from_domain == "paypa1-secure.com"
    assert parsed.reply_to_domain == "paypal-verify-now.net"
    assert parsed.auth_results.get("spf") == "fail"
    assert parsed.auth_results.get("dmarc") == "fail"
    assert parsed.received_count == 1
    assert len(parsed.links) == 1
    assert "185.220.14.9" in parsed.links[0].url
    assert "paypal.com" in parsed.links[0].display_text


# --- header checks ------------------------------------------------------------

def test_header_checks_fire_on_spoof():
    parsed = parse_email(read_sample("01_phish_paypal_spoof.eml"))
    names = flag_names(check_headers(parsed))
    assert "dmarc_fail" in names
    assert "spf_fail" in names
    assert "reply_to_mismatch" in names
    assert "brand_spoof" in names


def test_header_checks_quiet_on_clean_mail():
    parsed = parse_email(read_sample("04_legit_github_notification.eml"))
    assert check_headers(parsed) == []


# --- URL checks -----------------------------------------------------------------

def test_url_checks_fire_on_hidden_ip_link():
    parsed = parse_email(read_sample("01_phish_paypal_spoof.eml"))
    names = flag_names(check_urls(parsed.links))
    assert "link_text_mismatch" in names
    assert "ip_address_link" in names


def test_url_checks_fire_on_shortener():
    parsed = parse_email(read_sample("02_phish_microsoft_shortener.eml"))
    names = flag_names(check_urls(parsed.links))
    assert "url_shortener" in names


# --- scorer bands -----------------------------------------------------------------

def test_verdict_bands():
    assert verdict_for_score(90) == "Likely Phishing"
    assert verdict_for_score(65) == "Likely Phishing"
    assert verdict_for_score(50) == "Suspicious"
    assert verdict_for_score(35) == "Suspicious"
    assert verdict_for_score(10) == "Likely Legitimate"


# --- end to end on the bundled samples (rules-only mode) ---------------------------

def test_samples_land_in_expected_bands_without_model():
    expectations = {
        "01_phish_paypal_spoof.eml": "Likely Phishing",
        "02_phish_microsoft_shortener.eml": "Likely Phishing",
        # CEO fraud has no links to check, but the Reply-To exfiltration
        # route, absent authentication, and the secrecy + urgency stack
        # carry it over the phishing line on rules alone.
        "03_phish_ceo_wire_fraud.eml": "Likely Phishing",
        "04_legit_github_notification.eml": "Likely Legitimate",
        "05_legit_bank_statement.eml": "Likely Legitimate",
        # Documented false positive: real retailer mail, auth passes, but
        # shouty urgency copy + a shortener link push it into Suspicious.
        "06_legit_but_flagged_sale_alert.eml": "Suspicious",
    }
    for filename, expected_verdict in expectations.items():
        analysis = analyze_email(read_sample(filename), model=None)
        actual = analysis.score_result.verdict
        assert actual == expected_verdict, (
            f"{filename}: expected {expected_verdict}, got {actual} "
            f"(score {analysis.score_result.score})")


def test_analyzer_never_crashes_on_garbage():
    analysis = analyze_email("this is not an email at all", model=None)
    assert 0 <= analysis.score_result.score <= 100
    assert analysis.explanation  # always produces an explanation


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} tests passed")
    sys.exit(1 if failures else 0)
