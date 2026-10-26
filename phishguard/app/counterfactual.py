"""Counterfactual comparisons always call the same real URL heuristic pipeline."""
from __future__ import annotations
from .scanner import URLValidationError, run_scan


def compare(original: str, variant: str) -> dict:
    before = run_scan(original)
    after = run_scan(variant)
    bfind = {f["name"]: f for f in before["findings"]}
    afind = {f["name"]: f for f in after["findings"]}
    names = set(bfind) | set(afind)
    changed_rules = [{"name": n, "before": bfind.get(n), "after": afind.get(n)} for n in sorted(names) if bfind.get(n) != afind.get(n)]
    bf = before.get("url_features", {})
    af = after.get("url_features", {})
    changed_features = [{"name": k, "before": bf.get(k), "after": af.get(k)} for k in sorted(set(bf)|set(af)) if bf.get(k) != af.get(k)]
    return {"original": before, "variant": after, "changed_features": changed_features, "changed_rules": changed_rules,
            "model_comparison": {"available": False, "detail": "No trained model is configured; both sides used the same baseline heuristic pipeline."},
            "interpretation": "This is an observed before/after comparison, not proof that a changed feature caused malicious behavior. A lower score does not establish safety; an unchanged output means this variation did not change the implemented rules.",
            "identical_risk_score": before["risk_score"] == after["risk_score"],
            "identical_category": before["risk_category"] == after["risk_category"]}
