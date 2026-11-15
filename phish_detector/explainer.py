"""Step 6 of the pipeline: the AI explanation layer.

The flags and the score say WHAT the tool found. This layer turns that
into a short plain-English explanation, the way a senior analyst would
talk a junior through a ticket: what is wrong, why it matters, what to
do about it. No jargon without a translation.

Two modes:

1. AI mode (optional): if the environment variable ANTHROPIC_API_KEY
   is set, the findings are sent to Claude with a fixed prompt and its
   explanation is used. Set ANTHROPIC_MODEL to choose the model
   (default: claude-sonnet-4-5). Only the extracted signals are sent --
   header verdicts, flag descriptions, link domains, score -- never
   credentials or anything from a real mailbox (this project only ever
   handles research/sample mail anyway; see the spec's safety rules).

2. Local mode (default): a template explanation assembled from the
   flags themselves. Fully offline, no key, no cost. This is the mode
   the demo and the tests run in.

If AI mode fails for any reason (no network, bad key), the code falls
back to local mode and the report notes which mode produced the text.
"""

import json
import os
import urllib.request

from .scorer import ScoreResult, VERDICT_LEGITIMATE, VERDICT_PHISHING

SYSTEM_PROMPT = (
    "You are a senior SOC analyst teaching a junior analyst. Explain the "
    "phishing verdict for one email in plain English, in 3-5 short "
    "sentences. Use the signals provided. Translate any jargon the first "
    "time it appears. End with what the recipient should do. Do not "
    "invent signals that are not in the list."
)


def _local_explanation(result: ScoreResult) -> str:
    """Template explanation built from the flags. Always available."""
    if result.verdict == VERDICT_LEGITIMATE and not result.top_flags:
        return (
            "Nothing in this message tripped the checks. The headers "
            "authenticate cleanly, the links go where they claim to go, "
            "and the wording does not pressure the reader or ask for "
            "credentials. That does not guarantee the email is safe -- "
            "no filter can promise that -- but there is no evidence "
            "against it. Treat it as normal mail."
        )

    lead = {
        VERDICT_PHISHING: "This email shows strong signs of being a phishing attempt.",
        "Suspicious": "This email has enough wrong with it that it should not be trusted at face value.",
        VERDICT_LEGITIMATE: "This email looks legitimate overall, with only minor signals worth noting.",
    }[result.verdict]

    sentences = [lead]
    for flag in result.top_flags[:4]:
        sentences.append(flag.explanation)
    if result.model_available and result.model_probability is not None:
        sentences.append(
            f"The text model independently rated the wording "
            f"{result.model_probability:.0%} likely to be phishing."
        )
    if result.verdict == VERDICT_PHISHING:
        sentences.append(
            "Do not click any link or reply. Report it through your "
            "organization's phishing process and delete it."
        )
    elif result.verdict == "Suspicious":
        sentences.append(
            "Do not use the links in the message. If the request matters, "
            "reach the sender or service through a channel you already "
            "trust (type the address yourself) and verify."
        )
    return " ".join(sentences)


def _ai_explanation(result: ScoreResult, subject: str) -> str | None:
    """Claude explanation, or None if the call cannot be completed."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    signals = {
        "subject": subject,
        "verdict": result.verdict,
        "risk_score": result.score,
        "confidence": result.confidence,
        "model_phishing_probability": (
            round(result.model_probability, 3)
            if result.model_probability is not None else None
        ),
        "red_flags": [flag.explanation for flag in result.top_flags],
    }
    payload = {
        "model": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5"),
        "max_tokens": 400,
        "system": SYSTEM_PROMPT,
        "messages": [{
            "role": "user",
            "content": "Signals for this email:\n" + json.dumps(signals, indent=2),
        }],
    }
    request = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
        text = "".join(
            block.get("text", "") for block in data.get("content", [])
            if block.get("type") == "text"
        )
        return text.strip() or None
    except Exception:
        return None  # any failure -> local mode; the tool must not break


def explain(result: ScoreResult, subject: str = "") -> tuple:
    """Return (explanation_text, mode) where mode is 'ai' or 'local'."""
    ai_text = _ai_explanation(result, subject)
    if ai_text:
        return ai_text, "ai"
    return _local_explanation(result), "local"
