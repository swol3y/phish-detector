"""Step 3 of the pipeline: the text model (ML layer).

TF-IDF features over subject + body feeding a logistic regression
classifier (scikit-learn). Logistic regression is chosen on purpose
(spec decision): its coefficients are explainable. After training we
can list the exact words that push a message toward "phishing"
("verify", "password", "suspended") or toward "legitimate"
("meeting", "attached", "reminder"), and show them in the README and
the interview. A black-box model might score a point or two higher
and explain nothing.

Graceful degradation: if scikit-learn is not installed, or no trained
model file exists, this module reports the model as unavailable and
the scorer falls back to the rules layers alone. The tool never
crashes because the ML layer is missing -- in a SOC, a triage tool
that dies on a dependency helps nobody.
"""

import pickle
from pathlib import Path

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without sklearn
    SKLEARN_AVAILABLE = False


class PhishTextModel:
    """Thin wrapper around the sklearn pipeline so the rest of the
    code never imports sklearn directly."""

    def __init__(self, pipeline=None):
        self.pipeline = pipeline

    # -- training -----------------------------------------------------------
    @classmethod
    def train(cls, texts: list, labels: list) -> "PhishTextModel":
        if not SKLEARN_AVAILABLE:
            raise RuntimeError("scikit-learn is not installed; cannot train.")
        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                lowercase=True,
                stop_words="english",
                ngram_range=(1, 2),      # words + word pairs ("your password")
                max_features=5000,
                sublinear_tf=True,
            )),
            ("clf", LogisticRegression(max_iter=1000, C=1.0)),
        ])
        pipeline.fit(texts, labels)
        return cls(pipeline)

    # -- inference ------------------------------------------------------------
    def predict_phishing_probability(self, text: str):
        """Probability (0.0-1.0) that the text is phishing, or None if
        no model is loaded."""
        if self.pipeline is None:
            return None
        classes = list(self.pipeline.classes_)
        proba = self.pipeline.predict_proba([text])[0]
        return float(proba[classes.index(1)])

    # -- explainability ---------------------------------------------------------
    def top_terms(self, n: int = 10):
        """The words most associated with each class, from the model's
        coefficients. Returns (phishing_terms, legitimate_terms)."""
        if self.pipeline is None or not SKLEARN_AVAILABLE:
            return [], []
        vectorizer = self.pipeline.named_steps["tfidf"]
        classifier = self.pipeline.named_steps["clf"]
        features = vectorizer.get_feature_names_out()
        coefficients = classifier.coef_[0]
        ranked = sorted(zip(features, coefficients), key=lambda pair: pair[1])
        legitimate_terms = [term for term, _ in ranked[:n]]
        phishing_terms = [term for term, _ in ranked[-n:]][::-1]
        return phishing_terms, legitimate_terms

    # -- persistence --------------------------------------------------------------
    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as fh:
            pickle.dump(self.pipeline, fh)

    @classmethod
    def load(cls, path: Path) -> "PhishTextModel | None":
        if not SKLEARN_AVAILABLE or not Path(path).exists():
            return None
        with open(path, "rb") as fh:
            return cls(pickle.load(fh))
