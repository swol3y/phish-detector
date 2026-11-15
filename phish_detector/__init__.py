"""Phish Detector: an AI-assisted phishing email analyzer.

Pipeline (see README for the full walkthrough):
    parser.py        -> split a raw email into headers, body, auth results, links
    header_checks.py -> rules layer: header red flags with point weights
    url_checks.py    -> rules layer: link red flags with point weights
    text_checks.py   -> rules layer: pressure / credential language signals
    model.py         -> ML layer: TF-IDF + logistic regression phishing probability
    scorer.py        -> fuse every layer into a 0-100 score and a verdict
    explainer.py     -> plain-English explanation of the verdict
    analyzer.py      -> runs the whole pipeline and writes the text report
"""
