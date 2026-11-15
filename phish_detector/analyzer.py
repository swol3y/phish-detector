"""Pipeline orchestration: raw email text in, verdict report out.

This is the module the CLI (analyze.py) and the Streamlit UI (app.py)
both call, so the demo behaves identically in a terminal and in a
browser tab.
"""

from dataclasses import dataclass, field
from pathlib import Path

from . import explainer
from .header_checks import check_headers
from .model import PhishTextModel
from .parser import ParsedEmail, parse_email
from .scorer import ScoreResult, score_email
from .text_checks import check_text
from .url_checks import check_urls

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "model.pkl"


@dataclass
class AnalysisResult:
    parsed: ParsedEmail
    flags: list                      # all Flag objects from every layer
    score_result: ScoreResult
    explanation: str
    explanation_mode: str            # "ai" or "local"
    model_flag_text: str = ""        # one-line model summary for the report
    links_defanged: list = field(default_factory=list)


def _defang(url: str) -> str:
    """Defang a URL for display (hxxp / [.]) so nobody can click it in a
    report or screenshot. Spec safety rule: sample links are never live."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]", 1) if url else url


def load_default_model() -> PhishTextModel | None:
    """Load models/model.pkl if it exists; None means rules-only mode."""
    return PhishTextModel.load(DEFAULT_MODEL_PATH)


def analyze_email(raw_text: str, model: PhishTextModel | None = None) -> AnalysisResult:
    parsed = parse_email(raw_text)

    # Rules layers.
    flags = []
    flags += check_headers(parsed)
    flags += check_urls(parsed.links)
    flags += check_text(parsed.subject, parsed.body_text)

    # ML layer (graceful: probability is None when no model is loaded).
    model_probability = None
    if model is not None:
        model_probability = model.predict_phishing_probability(
            f"{parsed.subject}\n{parsed.body_text}")
    model_flag_text = (
        f"Text model phishing probability: {model_probability:.0%}"
        if model_probability is not None
        else "Text model not loaded -- score is based on the rules layers only."
    )

    result = score_email(flags, model_probability)
    explanation, mode = explainer.explain(result, parsed.subject)

    return AnalysisResult(
        parsed=parsed,
        flags=flags,
        score_result=result,
        explanation=explanation,
        explanation_mode=mode,
        model_flag_text=model_flag_text,
        links_defanged=[_defang(link.url) for link in parsed.links],
    )


def format_report(analysis: AnalysisResult, source_name: str = "pasted email") -> str:
    """The one-screen text report. Also saved per email under reports/."""
    parsed = analysis.parsed
    result = analysis.score_result
    auth = parsed.auth_results or {}
    lines = [
        "=" * 68,
        "PHISH DETECTOR REPORT",
        "=" * 68,
        f"Source:        {source_name}",
        f"Subject:       {parsed.subject or '(none)'}",
        f"From:          {parsed.from_name} <{parsed.from_address}>".strip(),
        f"Reply-To:      {parsed.reply_to_address or '(not set)'}",
        f"Auth results:  SPF={auth.get('spf', 'absent')}  "
        f"DKIM={auth.get('dkim', 'absent')}  DMARC={auth.get('dmarc', 'absent')}",
        "",
        f"VERDICT:       {result.verdict}",
        f"RISK SCORE:    {result.score}/100",
        f"CONFIDENCE:    {result.confidence}",
        f"               (rules points: {result.rules_points}/60, {analysis.model_flag_text})",
        "",
        "TOP RED FLAGS:",
    ]
    if result.top_flags:
        for index, flag in enumerate(result.top_flags, start=1):
            lines.append(f"  {index}. [{flag.source}, +{flag.points}] {flag.explanation}")
    else:
        lines.append("  None. No checks tripped.")
    lines += ["", "LINKS FOUND (defanged):"]
    if analysis.links_defanged:
        for link in analysis.links_defanged:
            lines.append(f"  - {link}")
    else:
        lines.append("  None.")
    lines += [
        "",
        f"EXPLANATION ({analysis.explanation_mode} mode):",
        f"  {analysis.explanation}",
        "=" * 68,
    ]
    return "\n".join(lines)
