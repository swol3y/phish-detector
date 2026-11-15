"""Train the text model and report honest held-out metrics.

Run:  python train_model.py

What it does:
  1. Builds data/corpus.csv from the bundled corpus if it is missing
     (data/build_corpus.py runs the spec's data-hygiene checks:
     dedupe + eyeball samples).
  2. Dedupes again here (defense in depth), then splits stratified
     75/25 so the same email can never sit on both sides.
  3. Trains TF-IDF + logistic regression on the training split only.
  4. Prints accuracy, precision, recall, and the FALSE-POSITIVE RATE
     on the held-out split. The false-positive rate is the number a
     SOC actually feels: it is the share of legitimate mail the tool
     would flag, i.e. the alert-fatigue cost.
  5. Saves the model to models/model.pkl and the metrics to
     models/metrics.json so the README numbers are reproducible.

Honesty note: the bundled corpus is small and synthetic, so these
numbers describe the demo corpus, not the real world. The README says
exactly that, and explains how to retrain on the Nazario +
SpamAssassin corpora.
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd  # noqa: E402
from sklearn.metrics import accuracy_score, precision_score, recall_score  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

from phish_detector.model import PhishTextModel  # noqa: E402

CORPUS_PATH = PROJECT_ROOT / "data" / "corpus.csv"
MODEL_PATH = PROJECT_ROOT / "models" / "model.pkl"
METRICS_PATH = PROJECT_ROOT / "models" / "metrics.json"


def main() -> None:
    if not CORPUS_PATH.exists():
        print("Corpus not found -- building it (with hygiene checks)...\n")
        sys.path.insert(0, str(PROJECT_ROOT / "data"))
        import build_corpus
        build_corpus.main()
        print()

    df = pd.read_csv(CORPUS_PATH)

    # Hygiene, again, at the point of training: drop exact duplicates and
    # any row with a missing label before the split.
    before = len(df)
    df = df.dropna(subset=["subject", "body", "label"]).drop_duplicates(
        subset=["subject", "body"])
    print(f"Corpus: {len(df)} rows ({before - len(df)} duplicates/invalid removed)")
    print(f"  phishing: {(df.label == 1).sum()}  legitimate: {(df.label == 0).sum()}")

    df["text"] = df["subject"].fillna("") + "\n" + df["body"].fillna("")
    train, test = train_test_split(
        df, test_size=0.25, random_state=42, stratify=df["label"])

    model = PhishTextModel.train(train["text"].tolist(), train["label"].tolist())

    predictions = []
    for text in test["text"]:
        prob = model.predict_phishing_probability(text)
        predictions.append(1 if (prob is not None and prob >= 0.5) else 0)

    y_true = test["label"].tolist()
    tp = sum(1 for t, p in zip(y_true, predictions) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, predictions) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, predictions) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, predictions) if t == 1 and p == 0)
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0

    metrics = {
        "corpus_rows": int(len(df)),
        "train_rows": int(len(train)),
        "test_rows": int(len(test)),
        "accuracy": round(accuracy_score(y_true, predictions), 4),
        "precision": round(precision_score(y_true, predictions, zero_division=0), 4),
        "recall": round(recall_score(y_true, predictions, zero_division=0), 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "corpus_note": "Small synthetic demo corpus bundled with the repo; "
                       "see README for training on the real research corpora.",
    }

    print(f"\nHeld-out test split ({len(test)} emails):")
    print(f"  accuracy:            {metrics['accuracy']:.1%}")
    print(f"  precision:           {metrics['precision']:.1%}")
    print(f"  recall:              {metrics['recall']:.1%}")
    print(f"  false-positive rate: {metrics['false_positive_rate']:.1%} "
          f"({fp} of {fp + tn} legitimate emails flagged)")
    print(f"  confusion: TP={tp} FP={fp} TN={tn} FN={fn}")

    phishing_terms, legit_terms = model.top_terms(10)
    print(f"\nStrongest phishing words:    {', '.join(phishing_terms)}")
    print(f"Strongest legitimate words:  {', '.join(legit_terms)}")
    metrics["top_phishing_terms"] = phishing_terms
    metrics["top_legitimate_terms"] = legit_terms

    model.save(MODEL_PATH)
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"\nSaved model to {MODEL_PATH}")
    print(f"Saved metrics to {METRICS_PATH}")


if __name__ == "__main__":
    main()
