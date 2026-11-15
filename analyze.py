"""Command-line entry point.

Usage:
    python analyze.py samples/01_phish_paypal_spoof.eml
    python analyze.py --samples            # run every file in samples/
    python analyze.py --samples --save     # ... and write reports/ per email
    python analyze.py --text "From: ..."   # analyze pasted raw text

If the trained model (models/model.pkl) does not exist yet, it is
trained first on the bundled corpus so the demo works end to end from
a fresh clone:  git clone -> pip install -> python analyze.py --samples
"""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from phish_detector.analyzer import analyze_email, format_report, load_default_model  # noqa: E402


def ensure_model() -> None:
    """Train the model on first run so the demo has no manual setup step."""
    model_path = PROJECT_ROOT / "models" / "model.pkl"
    if not model_path.exists():
        print("No trained model found -- training on the bundled corpus first.\n")
        import train_model
        train_model.main()
        print("\n" + "-" * 68 + "\n")


def analyze_text(raw_text: str, source_name: str, model, save: bool) -> str:
    analysis = analyze_email(raw_text, model=model)
    report = format_report(analysis, source_name)
    print(report)
    print()
    if save:
        reports_dir = PROJECT_ROOT / "reports"
        reports_dir.mkdir(exist_ok=True)
        out_name = Path(source_name).stem + ".txt"
        (reports_dir / out_name).write_text(report + "\n", encoding="utf-8")
        print(f"(saved to reports/{out_name})\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze an email for phishing signals.")
    parser.add_argument("files", nargs="*", help=".eml files to analyze")
    parser.add_argument("--samples", action="store_true",
                        help="analyze every .eml file in the samples/ folder")
    parser.add_argument("--text", help="raw email text to analyze directly")
    parser.add_argument("--save", action="store_true",
                        help="save each report as a text file under reports/")
    args = parser.parse_args()

    ensure_model()
    model = load_default_model()
    if model is None:
        print("NOTE: running in rules-only mode (no usable ML model).\n")

    if args.text:
        analyze_text(args.text, "pasted text", model, args.save)
        return

    paths = [Path(f) for f in args.files]
    if args.samples:
        paths = sorted((PROJECT_ROOT / "samples").glob("*.eml"))
    if not paths:
        parser.print_help()
        print("\nNothing to analyze: pass an .eml file, --samples, or --text.")
        return

    for path in paths:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
        analyze_text(raw_text, path.name, model, args.save)


if __name__ == "__main__":
    main()
