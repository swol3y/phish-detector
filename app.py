"""Streamlit UI: the one-screen demo from the spec.

Run:  streamlit run app.py

Paste a full email (headers + body) or upload an .eml file, click
Analyze, and get the verdict, risk score, red flags, and plain-English
explanation on one screen. Train the model first (python train_model.py)
or the app runs in rules-only mode and says so.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    import streamlit as st
except ImportError:
    raise SystemExit(
        "Streamlit is not installed. Run: pip install -r requirements.txt\n"
        "Or use the CLI instead: python analyze.py --samples"
    )

from phish_detector.analyzer import analyze_email, load_default_model  # noqa: E402

st.set_page_config(page_title="Phish Detector", page_icon="🎣")
st.title("🎣 Phish Detector")
st.caption(
    "AI-assisted phishing email triage. Paste an email or upload an .eml "
    "file. Analysis only -- nothing is sent, clicked, or fetched."
)

model = load_default_model()
if model is None:
    st.warning("No trained model found -- running in rules-only mode. "
               "Run `python train_model.py` to enable the ML layer.")

uploaded = st.file_uploader("Upload an .eml file", type=["eml"])
raw_text = ""
if uploaded is not None:
    raw_text = uploaded.read().decode("utf-8", errors="replace")
pasted = st.text_area("...or paste the full email (headers + body)",
                      value=raw_text, height=260)

sample_dir = PROJECT_ROOT / "samples"
sample_files = sorted(sample_dir.glob("*.eml"))
if sample_files:
    st.caption("Or load one of the bundled samples:")
    columns = st.columns(len(sample_files))
    for column, sample in zip(columns, sample_files):
        if column.button(sample.stem.split("_", 1)[-1], key=sample.name):
            st.session_state["email_text"] = sample.read_text(encoding="utf-8")
            st.rerun()
if "email_text" in st.session_state and not pasted:
    pasted = st.session_state["email_text"]

if st.button("Analyze", type="primary") and pasted.strip():
    analysis = analyze_email(pasted, model=model)
    result = analysis.score_result

    verdict_emoji = {"Likely Phishing": "🔴", "Suspicious": "🟠",
                     "Likely Legitimate": "🟢"}[result.verdict]
    st.subheader(f"{verdict_emoji} {result.verdict} -- risk score {result.score}/100")
    st.progress(result.score / 100)
    st.write(f"**Confidence:** {result.confidence}  |  {analysis.model_flag_text}")

    st.markdown("### Top red flags")
    if result.top_flags:
        for flag in result.top_flags:
            st.write(f"- **[+{flag.points}]** {flag.explanation}")
    else:
        st.write("None. No checks tripped.")

    st.markdown("### Explanation")
    st.write(analysis.explanation)
    st.caption(f"Explanation mode: {analysis.explanation_mode} "
             f"({'Claude' if analysis.explanation_mode == 'ai' else 'local templates'})")

    if analysis.links_defanged:
        st.markdown("### Links found (defanged)")
        for link in analysis.links_defanged:
            st.code(link, language=None)
