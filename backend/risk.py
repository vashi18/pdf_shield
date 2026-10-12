from __future__ import annotations


def classify(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"


def score_analysis(result: dict) -> dict:
    counts = result.get("marker_counts", {})
    reasons: list[dict] = []
    score = 0
    rules = [
        ("javascript", "JavaScript indicators", 35, "JavaScript-related names were found in the PDF structure."),
        ("automatic_action", "Automatic actions", 20, "OpenAction or additional-action names were found."),
        ("embedded_file", "Embedded files", 15, "Embedded-file structure was found."),
        ("launch_action", "Launch action", 30, "A Launch action marker was found."),
        ("uri_annotation", "External URI annotations", 8, "URI or form-action structure was found; this is not proof of maliciousness."),
    ]
    for key, label, points, evidence in rules:
        if counts.get(key, 0):
            score += points
            reasons.append({"code": key, "label": label, "points": points, "evidence": evidence})
    if result.get("parsing_status") not in {"readable"}:
        reasons.append({"code": "coverage", "label": "Reduced analysis coverage", "points": 0, "evidence": "One or more parsers could not fully inspect the file; absence of findings is inconclusive."})
    score = min(100, score)
    return {"risk_score": score, "risk_class": classify(score), "risk_reasons": reasons}
