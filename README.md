# Phish Detector — an AI-assisted phishing email analyzer

**Author:** Tyree Coley — IT support and wireless network technician (self-employed since 2017), Google IT Support Professional Certificate (2020), currently studying for CompTIA Security+ (SY0-701) and pursuing a B.S. in Information Technology (Cyber Security emphasis) at Georgia Southern University.

Paste in a full email (headers + body, or an `.eml` file) and get back a **verdict** (Likely Phishing / Suspicious / Likely Legitimate), a **risk score from 0 to 100**, the **top red flags in plain English**, and the model's confidence with the signals that drove it.

![Status](https://img.shields.io/badge/cost-$0-brightgreen) — no paid APIs, no cloud bill, runs fully offline in its default mode.

---

## The security problem

Phishing is still the front door for most breaches, and triaging a reported email is a core daily task in help desk, IT support, and SOC roles: open the headers, check the authentication results, look at where the links really go, read the wording for pressure tactics, decide, document. This project automates that exact workflow the way an analyst performs it, in the same order, and explains its reasoning in plain English — because a verdict a junior analyst cannot explain is a verdict they cannot defend on a ticket.

## How it works

```
raw email (.eml or pasted text)
   │
   ├─ 1. PARSE      Python's built-in email library splits headers from body;
   │                extracts From, Reply-To, Return-Path, the Received chain,
   │                authentication results, and every link (display text
   │                kept next to the real destination).
   │
   ├─ 2. HEADER     SPF / DKIM / DMARC failures, Reply-To and Return-Path
   │   CHECKS       domain mismatches, brand display-name spoofing, missing
   │   (rules)      mail trail. Each hit adds weighted points.
   │
   ├─ 3. URL        Display-text vs destination mismatch, raw-IP links, URL
   │   CHECKS       shorteners, punycode, lookalike domains (paypa1,
   │   (rules)      micros0ft), plain-HTTP links. Analysis only — nothing
   │                is ever fetched or clicked.
   │
   ├─ 4. TEXT       Urgency/deadline pressure, credential & payment
   │   CHECKS       harvesting asks, secrecy requests (the CEO-fraud
   │   (rules)      signature), threat language.
   │
   ├─ 5. TEXT       TF-IDF + logistic regression (scikit-learn) outputs a
   │   MODEL (ML)   phishing probability. Logistic regression was chosen on
   │                purpose: its coefficients are explainable, so the exact
   │                words driving the model can be listed and discussed.
   │
   ├─ 6. SCORE      score = rules points (capped at 60)
   │                        + model probability × 40
   │                65–100 Likely Phishing · 35–64 Suspicious · 0–34 Likely
   │                Legitimate. Confidence is reported separately and means
   │                "how much do the layers agree" — a disagreement is
   │                exactly what should land on a human's desk.
   │
   └─ 7. EXPLAIN    Plain-English writeup of the verdict. Default: local
                    templates built from the flags (offline, no key).
                    Optional: set ANTHROPIC_API_KEY and Claude writes the
                    explanation from the same extracted signals. Any API
                    failure falls back to local mode automatically.
```

If scikit-learn or the trained model is missing, the tool degrades to rules-only scoring and says so in the report. It never crashes because the ML layer is absent.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python train_model.py          # builds the corpus, trains, prints honest metrics
python analyze.py --samples --save   # run the 6 bundled sample emails, save reports
python -m pytest tests/ -q     # 8 tests
streamlit run app.py           # the one-screen browser demo
```

Or analyze your own sample: `python analyze.py path/to/message.eml`. First run trains the model automatically if `models/model.pkl` does not exist yet. End to end, pasted email to verdict takes seconds.

## Example output (real run, captured from this repo)

`python analyze.py samples/01_phish_paypal_spoof.eml` — a spoofed "PayPal" message:

```
====================================================================
PHISH DETECTOR REPORT
====================================================================
Source:        01_phish_paypal_spoof.eml
Subject:       URGENT: Your account has been limited - verify within 24 hours
From:          PayPal Security Team <service@paypa1-secure.com>
Reply-To:      support@paypal-verify-now.net
Auth results:  SPF=fail  DKIM=none  DMARC=fail

VERDICT:       Likely Phishing
RISK SCORE:    86/100
CONFIDENCE:    medium
               (rules points: 60/60, Text model phishing probability: 64%)

TOP RED FLAGS:
  1. [header, +25] DMARC check failed in the headers: the message does not line up with the sending domain's own published email policy.
  2. [header, +20] SPF check failed in the headers: the server that sent this was not authorized to send mail for the sender's domain.
  3. [header, +20] The message presents itself as PayPal but was sent from paypa1-secure.com, which is not a PayPal domain.
  4. [url, +20] A link's visible text hides a different destination: the text points to paypal.com but the link actually goes to 185.220.14.9.
  5. [header, +15] Sender domain does not match the Reply-To domain (paypa1-secure.com vs paypal-verify-now.net). Replies would go somewhere other than the apparent sender.
  6. [url, +15] A link goes to a raw IP address (185.220.14.9) instead of a company domain name, which hides who owns the server.
  7. [text, +15] The message asks the reader to hand over credentials, payment card, or bank details. Legitimate companies do not collect passwords or full card numbers by email.
  8. [text, +10] The message pushes urgency and deadlines, a classic pressure tactic meant to get a click before the reader stops to think.
  9. [header, +8] The Return-Path domain (mailer77.xyz) differs from the From domain (paypa1-secure.com).
 10. [text, +8] The message threatens account closure, deletion, or loss of funds if the reader does not comply.
 11. [url, +5] A link uses plain HTTP instead of HTTPS, so anything typed on that page would travel unencrypted.

LINKS FOUND (defanged):
  - hxxp://185[.]220.14.9/paypal/login/verify

EXPLANATION (local mode):
  This email shows strong signs of being a phishing attempt. ... Do not click any link or reply. Report it through your organization's phishing process and delete it.
```

All six bundled samples, analyzed with the trained model (full reports in `reports/`):

| Sample | What it is | Verdict | Score |
|---|---|---|---|
| 01 | Spoofed PayPal, SPF+DMARC fail, IP link | Likely Phishing | 86 |
| 02 | "Microsoft" alert, lookalike domain, shortener link | Likely Phishing | 78 |
| 03 | CEO wire-transfer fraud, Reply-To routed out, no auth | Likely Phishing | 66 |
| 04 | Real GitHub sign-in notice, SPF/DKIM/DMARC all pass | Likely Legitimate | 17 |
| 05 | Real bank eStatement notice, all auth passes | Likely Legitimate | 18 |
| 06 | **Real retailer sale email — the false positive (below)** | **Suspicious** | **41** |

## Honest results

Model metrics on the held-out split of the bundled corpus (`python train_model.py` reproduces them; also saved in `models/metrics.json`):

| Metric | Value |
|---|---|
| Corpus | 64 emails (32 phishing / 32 legitimate), 75/25 stratified split |
| Accuracy | 87.5% |
| Precision | 87.5% |
| Recall | 87.5% |
| **False-positive rate** | **12.5% (1 of 8 legitimate emails flagged)** |

Read those numbers the way an analyst should: the corpus is small and synthetic (see Data, below), so they describe the demo data, not production performance. The number I watch is the false-positive rate. In a real SOC, a tool that flags one in eight legitimate emails creates alert fatigue, and tired analysts start clicking "benign" without reading — which is how the real phish gets through. That tradeoff, not raw accuracy, is the design problem.

Strongest model words (from the logistic-regression coefficients — the explainability payoff): phishing side — *confirm, password, payment, number, storage, card, details, verify, address, refund*; legitimate side — *ready, available, appointment, minutes, official, website*.

### The false positive is the most valuable file in this repo

`samples/06_legit_but_flagged_sale_alert.eml` is a genuine retailer sale email. Its SPF, DKIM, and DMARC all **pass**; it was really sent by the retailer. The tool still scores it 41 — Suspicious — because it uses a tinyurl link, "LAST CHANCE / ends TONIGHT / act now" urgency copy, and a shouty subject line. Those are the same surface signals phishing uses, because phishing copies marketing. The lesson, and the reason the scoring works the way it does: language signals are deliberately low-weight. They raise suspicion; only header and URL evidence convicts. An analyst who can explain *why* the tool flagged good mail — and what would clear it (authentication passing, no credential ask, no hidden destination) — is doing the actual job.

## Data

- **Bundled demo corpus** (`data/corpus.csv`, generated by `data/build_corpus.py`): 64 short synthetic emails I wrote to imitate common phishing and legitimate patterns, so the project clones and runs offline with zero setup. Clearly a teaching corpus, not a benchmark.
- **Real research corpora (the intended training data):** the [Nazario Phishing Corpus](https://monkey.org/~jose/phishing/) (real hand-classified phishing, CC-BY-4.0 — attribution: José Nazario) and the [Apache SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) (easy_ham sets for legitimate mail). To use them, build a CSV with columns `subject, body, label` (1 = phishing, 0 = legitimate) in place of `data/corpus.csv` and rerun `python train_model.py`.
- **Data hygiene, enforced in code:** before any split, the pipeline removes exact duplicates and prints random samples from each class for a human eyeball check. This step exists because a popular mirrored dataset once shipped with its "spam" rows silently containing duplicated legitimate text — a model trained on it reports great numbers and has learned nothing. Dedupe happens *before* the train/test split so the same email can never appear on both sides and inflate the score.
- **Safety rules:** public research corpora and hand-written fixtures only — never real mailbox mail. All sample links in reports and screenshots are defanged (hxxp / [.]). Nothing from a sample is ever clicked or fetched; there is no live URL detonation in v1.

## Project layout

```
analyze.py                 CLI entry point
app.py                     Streamlit one-screen demo
train_model.py             training + honest metrics (accuracy, precision, recall, FPR)
requirements.txt
phish_detector/
    parser.py              headers, auth results, body, links (stdlib only)
    header_checks.py       SPF/DKIM/DMARC, routing mismatches, brand spoofing
    url_checks.py          link heuristics
    text_checks.py         social-engineering language signals
    model.py               TF-IDF + logistic regression, graceful fallback
    scorer.py              the fusion formula and verdict bands
    explainer.py           plain-English explanation (local, or Claude with a key)
    analyzer.py            pipeline orchestration + report formatting
data/build_corpus.py       synthetic corpus generator with the hygiene check
samples/                   6 worked .eml examples (3 phishing, 2 legitimate, 1 false positive)
reports/                   saved report per sample
tests/test_detector.py     8 tests: parser, each rules layer, verdict bands, end-to-end
```

## Interview notes — what this project demonstrates

- **Header analysis.** Every triage starts with headers: who really sent it (From vs the actual sending domain), where replies go (Reply-To), where bounces go (Return-Path), and how many servers handled it (the Received chain). A mismatch between the address a reader sees and the infrastructure behind it is the oldest spoofing tell there is.
- **SPF, DKIM, DMARC — what each one actually proves.** SPF: "was this server allowed to send for this domain?" DKIM: "was the message signed by the domain, and did it arrive unaltered?" DMARC: "do the SPF/DKIM results line up with the From domain the reader sees, and what did the domain owner say to do when they don't?" A `fail` is strong evidence; a missing result (`none`) is weak evidence, because plenty of small legitimate senders never configured them. That asymmetry is why the weights differ.
- **URL heuristics.** Phishing needs the victim to land on the attacker's page, so links carry heavy signal: anchor text that displays one domain and links to another, raw-IP destinations, shorteners hiding the target, punycode and digit-swapped lookalike domains. Marketers abuse some of the same tricks (shorteners especially), which is why no single URL signal convicts on its own.
- **Scoring rationale.** Explainable fusion over a single black-box score: rules points for hard evidence (authentication failures, hidden destinations), model probability for statistical wording patterns, and a separate confidence value that measures agreement between the layers. When the layers disagree, confidence drops and a human looks — that is a feature, borrowed from how real triage queues prioritize.
- **False positives and alert fatigue.** Measured honestly (12.5% on the demo corpus), named as an operational cost, and designed around: soft signals are low-weight so that legitimate-but-loud mail lands in "Suspicious — verify through a trusted channel" instead of being convicted.
- **Data hygiene.** Dedupe before splitting; eyeball samples before training; distrust a metric you cannot reproduce. A poisoned dataset produces a confident, wrong model.
- **Social engineering.** The non-technical half of the detection problem: urgency, authority, secrecy, and fear are the payload; the link is just the delivery mechanism. The CEO-fraud sample has no malicious link at all and is still caught, on routing and language evidence.

## What I would do next (v2)

- Train and evaluate on the full Nazario + SpamAssassin corpora and publish the (lower, honest) numbers.
- Read-only reputation lookups (VirusTotal / urlscan.io) for extracted domains.
- A second classifier (Naive Bayes) with a side-by-side comparison table.
- Batch mode: score a folder of `.eml` files into a CSV triage queue, sorted by score — the closest thing here to a real SOC workflow.
- Run the codebase through an AI-assisted security code review and document the fixes.

## License / attribution

Code: MIT. Bundled sample emails and corpus: original, written for this project. Nazario corpus (if used): CC-BY-4.0, © José Nazario. SpamAssassin corpus: Apache License 2.0.
