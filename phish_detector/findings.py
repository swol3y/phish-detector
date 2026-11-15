"""One shared shape for everything the rules layers find.

Every check in header_checks / url_checks / text_checks returns Flag
objects: how many points the signal is worth, and the plain-English
sentence that will be shown to the user (and fed to the explainer).
Keeping the explanation inside the flag means the report can never
drift out of sync with the scoring.
"""

from dataclasses import dataclass


@dataclass
class Flag:
    name: str          # short machine-friendly id, e.g. "spf_fail"
    points: int        # risk points this signal adds (rules layer)
    explanation: str   # plain-English sentence for the report
    source: str = ""   # which layer raised it: header / url / text / model
