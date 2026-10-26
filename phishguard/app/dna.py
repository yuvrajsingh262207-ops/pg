"""Evidence-attributed relationships derived from saved URL reports only."""
from __future__ import annotations
from datetime import datetime, timezone


def build_graph(reports: list[dict]) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    def node(kind: str, value: str, report: dict) -> str:
        key = f"{kind}:{value}"
        if key not in nodes:
            nodes[key] = {"id": key, "type": kind, "label": value, "investigation_ids": []}
        if report.get("id") is not None and report["id"] not in nodes[key]["investigation_ids"]:
            nodes[key]["investigation_ids"].append(report["id"])
        return key
    def edge(source: str, target: str, kind: str, evidence: str, classification: str, strength: str, limitation: str, report: dict):
        edge_id = f"{source}|{target}|{kind}"
        if any(e["id"] == edge_id for e in edges):
            return
        edges.append({"id": edge_id, "source": source, "target": target, "type": kind,
                      "evidence": evidence, "source_name": "PhishGuard URL-derived analysis",
                      "observed_at": report.get("scanned_at"), "classification": classification,
                      "strength": strength, "limitation": limitation,
                      "investigation_id": report.get("id")})
    for report in reports:
        url = report.get("submitted_url") or report.get("normalized_url") or "(URL unavailable)"
        u = node("url", url, report)
        domain = report.get("registered_domain")
        if domain:
            d = node("domain", domain, report)
            edge(u, d, "registered-domain", f"PSL-aware parsing extracted registered domain {domain} from the submitted hostname.", "direct observation", "high", "Domain extraction does not establish ownership or maliciousness.", report)
        trust = report.get("trust_gap") or {}
        brand = trust.get("brand") if trust.get("mismatch") else None
        if brand:
            b = node("brand mention", brand, report)
            edge(u, b, "brand-text-in-hostname", f"Brand-like hostname text was detected; registered domain is {domain}, configured official domain is {trust.get('expected_domain')}.", "heuristic inference", "medium", "Brand text and domain mismatch are not proof of malicious intent or campaign membership.", report)
    # A shared registered domain across distinct URLs is directly observable. No infrastructure is inferred.
    domain_urls: dict[str, list[str]] = {}
    for e in edges:
        if e["type"] == "registered-domain":
            domain_urls.setdefault(e["target"], []).append(e["source"])
    for domain_node, urls in domain_urls.items():
        for i, left in enumerate(urls):
            for right in urls[i+1:]:
                edges.append({"id": f"{left}|{right}|same-registered-domain", "source": left, "target": right,
                    "type": "same-registered-domain", "evidence": f"Both analyzed URLs resolve by parsing to the same registered-domain node {nodes[domain_node]['label']}.",
                    "source_name": "PhishGuard URL-derived analysis", "observed_at": None, "classification": "direct observation",
                    "strength": "high", "limitation": "A shared domain does not prove a shared attacker or campaign."})
    return {"nodes": list(nodes.values()), "edges": edges, "method": "Direct shared-domain relationships plus explicitly marked brand-text hypotheses; no DNS, IP, certificate, ownership, or external intelligence is available or inferred.", "synthetic": False}


def synthetic_demo_graph() -> dict:
    # Reserved example.org/.com domains; entirely illustrative, no real infrastructure assertions.
    items = [
        {"id": 910001, "submitted_url": "https://accounts.example.org/verify", "registered_domain": "example.org", "trust_gap": {"brand": None, "mismatch": False}, "scanned_at": None},
        {"id": 910002, "submitted_url": "https://login.example.org/session", "registered_domain": "example.org", "trust_gap": {"brand": None, "mismatch": False}, "scanned_at": None},
        {"id": 910003, "submitted_url": "https://google.com.account-verification.example.com/login", "registered_domain": "example.com", "trust_gap": {"brand": "Google", "expected_domain": "google.com", "mismatch": True}, "scanned_at": None},
    ]
    graph = build_graph(items)
    graph["synthetic"] = True
    graph["label"] = "Synthetic demonstration only — reserved example domains; not threat intelligence."
    # Demonstrate that shared hosting would be insufficient, without inventing an IP or edge.
    graph["notice"] = "No shared IP, DNS, certificate, or hosting facts are supplied; this demo makes no infrastructure or common-attacker claim."
    return graph
