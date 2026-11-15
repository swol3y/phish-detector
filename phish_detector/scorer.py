"""Step 5 of the pipeline: fuse every layer into one score and verdict.

The fusion formula is deliberately simple and printed in the README,
because a score nobody can explain is a score nobody trusts:

    score = rules points (headers + URLs + text, capped at 60)
          + model's phishing probability x 40        (if a model is loaded)

So the rules layer can carry a message to 60 on hard evidence alone
(a DMARC failure plus a spoofed brand is damning even if the wording
is polite), and the text model contributes up to 40 more. If no model
is available, the score is the rules points rescaled to the same
0-100 range (rules x 100/60, capped at 100) and the report says the
model was not used.

Verdicts:
    65-100  Likely Phishing
    35-64   Suspicious
    0-34    Likely Legitimate

Confidence is reported separately from the score, because they answer
different questions. The score says "how much evidence of phishing";
confidence says "how much do the layers agree". A message the rules
and the model both condemn is high confidence; a message only one
layer dislikes is medium or low, and the report says so.
"""

from dataclasses import dataclass, field

from .findings import Flag

RULES_CAP = 60
MODEL_WEIGHT = 40

VERDICT_PHISHING = "Likely Phishing"
VERDICT_SUSPICIOUS = "Suspicious"
VERDICT_LEGITIMATE = "Likely Legitimate"


@dataclass
class ScoreResult:
    score: int
    verdict: str
    confidence: str           # "high" / "medium" / "low"
    rules_points: int
    model_probability: float | None
    model_available: bool
    top_flags: list = field(default_factory=list)  # list[Flag], highest points first


def verdict_for_score(score: int) -> str:
    if score >= 65:
        return VERDICT_PHISHING
    if score >= 35:
        return VERDICT_SUSPICIOUS
    return VERDICT_LEGITIMATE


def score_email(flags: list, model_probability) -> ScoreResult:
    rules_points = min(RULES_CAP, sum(flag.points for flag in flags))
    model_available = model_probability is not None

    if model_available:
        score = rules_points + round(model_probability * MODEL_WEIGHT)
    else:
        # Rescale rules-only onto 0-100 so the verdict bands still mean
        # roughly the same thing without the model.
        score = round(rules_points * 100 / RULES_CAP)
    score = max(0, min(100, score))
    verdict = verdict_for_score(score)

    # Confidence = agreement between the rules layer and the model.
    if not model_available:
        confidence = "medium" if rules_points >= 20 else "low"
    else:
        rules_say_bad = rules_points >= 25
        model_say_bad = model_probability >= 0.65
        rules_say_clean = rules_points <= 8
        model_say_clean = model_probability <= 0.35
        if (rules_say_bad and model_say_bad) or (rules_say_clean and model_say_clean):
            confidence = "high"
        elif (rules_say_bad and model_say_clean) or (rules_say_clean and model_say_bad):
            confidence = "low"  # the layers disagree -- a human should look
        else:
            confidence = "medium"

    top_flags = sorted(flags, key=lambda f: f.points, reverse=True)
    return ScoreResult(
        score=score,
        verdict=verdict,
        confidence=confidence,
        rules_points=rules_points,
        model_probability=model_probability,
        model_available=model_available,
        top_flags=top_flags,
    )
