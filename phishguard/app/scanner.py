"""Offline, explainable URL heuristics. Submitted links are never fetched."""
from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit
import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)
BRANDS = {
    "Google": ["google.com"], "Microsoft": ["microsoft.com", "microsoftonline.com"],
    "Apple": ["apple.com"], "Amazon": ["amazon.com", "amazon.co.uk"],
    "PayPal": ["paypal.com"], "Facebook": ["facebook.com", "fb.com"],
    "Netflix": ["netflix.com"], "Amazon Web Services": ["amazonaws.com"],
}
BRAND_TOKENS = {"google": "Google", "microsoft": "Microsoft", "apple": "Apple", "amazon": "Amazon", "paypal": "PayPal", "facebook": "Facebook", "netflix": "Netflix", "aws": "Amazon Web Services"}

class URLValidationError(ValueError):
    pass

def parse_url(raw: str) -> dict:
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 2048:
        raise URLValidationError("Enter a URL between 1 and 2,048 characters.")
    value = raw.strip()
    if any(ord(c) < 32 or c.isspace() for c in value):
        raise URLValidationError("The URL cannot contain spaces or control characters.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise ValueError
        host = parts.hostname.rstrip(".").lower()
        port = parts.port
    except (ValueError, UnicodeError):
        raise URLValidationError("Enter a valid HTTP or HTTPS URL with a hostname.")
    if not host or len(host) > 253 or "\\" in host:
        raise URLValidationError("Invalid hostname.")
    try:
        ipaddress.ip_address(host.strip("[]")); is_ip = True; registered = host
    except ValueError:
        is_ip = False
        ext = _EXTRACT(host)
        registered = ".".join(x for x in [ext.domain, ext.suffix] if x) or host
        if "." not in host and host != "localhost":
            raise URLValidationError("The hostname must include a domain suffix.")
    netloc = host + (f":{port}" if port is not None else "")
    normalized = urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))
    subdomains = [] if is_ip else (_EXTRACT(host).subdomain.split(".") if _EXTRACT(host).subdomain else [])
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host
    try:
        unicode_host = host.encode("ascii").decode("idna") if host.isascii() else host
    except UnicodeError:
        unicode_host = host
    has_punycode = "xn--" in host
    return {"normalized_url": normalized, "host": host, "ascii_host": ascii_host, "unicode_host": unicode_host, "has_punycode": has_punycode, "registered_domain": registered,
            "subdomains": subdomains, "scheme": parts.scheme.lower(), "port": port, "path": parts.path or "/",
            "query_present": bool(parts.query), "query_length": len(parts.query), "fragment_present": bool(parts.fragment),
            "is_ip": is_ip, "userinfo": bool(parts.username or parts.password)}

def _levenshtein(a: str, b: str) -> int:
    row=list(range(len(b)+1))
    for i,ca in enumerate(a,1):
        prev,row[0]=row[0],i
        for j,cb in enumerate(b,1):
            old=row[j]; row[j]=min(row[j]+1,row[j-1]+1,prev+(ca!=cb)); prev=old
    return row[-1]

def analyze_trust_gap(parsed: dict) -> dict:
    host=parsed["host"].lower(); registered=parsed["registered_domain"].lower(); detected=[]
    for token,brand in BRAND_TOKENS.items():
        if any(token in label for label in host.split(".")):
            detected.append((brand,token))
    if not detected:
        path_tokens=parsed["path"].lower().replace('-', '/').replace('_','/').split('/')
        for token,brand in BRAND_TOKENS.items():
            if any(token in segment for segment in path_tokens):
                return {"brand":None,"brand_mentioned":brand,"registered_domain":registered,"expected_domain":None,"mismatch":False,"indicators":[],"summary":"Brand appears in the URL path only; this does not identify the site operator."}
        return {"brand":None,"brand_mentioned":None,"registered_domain":registered,"expected_domain":None,"mismatch":False,"indicators":[],"summary":"Brand not confidently identified."}
    brand=next((b for b,_ in detected if registered in [d.lower() for d in BRANDS[b]] or any(registered.endswith('.'+d.lower()) for d in BRANDS[b])),detected[0][0])
    official=BRANDS[brand][0]
    legitimate=registered==official or any(registered.endswith('.'+d) for d in BRANDS[brand])
    indicators=[]
    if not legitimate:
        indicators.append({"type":"brand_domain_mismatch","evidence":f"{brand} appears in hostname '{host}', but the registered domain is '{registered}', not a configured official {brand} domain.","severity":"high"})
        if any(token in p for p in parsed["subdomains"] for _,token in detected):
            indicators.append({"type":"brand_in_subdomain","evidence":"Brand-like text is in a subdomain rather than the registered domain.","severity":"high"})
        root=registered.split('.')[0]; token=next(t for b,t in detected if b==brand)
        if root!=token and len(root)>=4 and _levenshtein(root,token)<=2:
            indicators.append({"type":"lookalike_domain","evidence":f"Registered-domain label '{root}' resembles brand name '{token}'.","severity":"medium"})
    return {"brand":brand,"brand_mentioned":brand,"registered_domain":registered,"expected_domain":official,"mismatch":not legitimate,"indicators":indicators,
            "summary":"Potential brand impersonation: registered domain does not match configured official domain." if not legitimate else "Registered domain matches a configured official domain."}

def run_scan(raw: str, privacy_metadata: dict | None = None) -> dict:
    p=parse_url(raw)
    # Sentinel removes userinfo, query values and fragments before sending a URL.
    # Their presence/length are safe structural metadata that preserves relevant checks.
    if privacy_metadata:
        p["userinfo"]=bool(privacy_metadata.get("userinfo_present",p["userinfo"]))
        p["query_present"]=bool(privacy_metadata.get("query_present",p["query_present"]))
        p["query_length"]=max(0,min(8192,int(privacy_metadata.get("query_length",p["query_length"]))))
        p["fragment_present"]=bool(privacy_metadata.get("fragment_present",p["fragment_present"]))
    trust=analyze_trust_gap(p); findings=[]; score=0
    def add(name,evidence,why,severity,points):
        nonlocal score
        findings.append({"name":name,"evidence":evidence,"why_it_matters":why,"severity":severity,"points":points}); score+=points
    if p["userinfo"]: add("URL contains user information","A username/password-like segment appears before the hostname.","This can visually disguise the real destination.","high",25)
    if p["is_ip"]: add("IP address used as hostname",f"Hostname is {p['host']}.","IP-hosted links merit extra scrutiny; this alone is not a verdict.","medium",20)
    if len(p["normalized_url"])>120: add("Unusually long URL",f"Normalized URL is {len(p['normalized_url'])} characters.","Long URLs can hide misleading details and are harder to inspect.","low",10)
    if len(p["subdomains"])>=3: add("Excessive subdomains",f"Hostname has {len(p['subdomains'])} subdomain labels before {p['registered_domain']}.","The registered domain is at the right-hand end; preceding words do not own it.","medium",15)
    if trust["mismatch"]:
        add("Brand-domain mismatch",trust["indicators"][0]["evidence"],"A brand name in a hostname does not prove that the brand operates the registered domain.","high",40)
        if any(i["type"]=="lookalike_domain" for i in trust["indicators"]): add("Lookalike registered domain",next(i["evidence"] for i in trust["indicators"] if i["type"]=="lookalike_domain"),"Small spelling changes can make a domain resemble a trusted brand.","medium",15)
    if p["ascii_host"]!=p["host"] or p["has_punycode"]: add("Internationalized hostname",f"Unicode display is {p['unicode_host']}; ASCII/Punycode form is {p['ascii_host']}.","Unicode characters can resemble Latin letters in some fonts.","medium",15)
    if p["scheme"]=="http": add("Unencrypted HTTP","The URL uses HTTP rather than HTTPS.","Traffic may not be encrypted; HTTPS alone would not prove legitimacy.","low",5)
    if not findings: findings.append({"name":"No flagged URL-structure indicators","evidence":"The implemented URL checks did not find their trigger conditions.","why_it_matters":"This is not proof the website is safe; no website content or reputation database was checked.","severity":"info","points":0})
    score=min(100,score); category="Lower Risk" if score<25 else "Caution" if score<50 else "High Risk" if score<75 else "Very High Risk"
    safe_url=p["normalized_url"].split('?',1)[0].split('#',1)[0]
    features={"url_length":len(p["normalized_url"]),"hostname_length":len(p["host"]),"subdomain_count":len(p["subdomains"]),"dot_count":p["host"].count('.'),"is_ip_literal":p["is_ip"],"userinfo_present":p["userinfo"],"scheme_https":p["scheme"]=="https","path_length":len(p["path"]),"query_present":p["query_present"],"query_length":p["query_length"],"punycode_or_unicode":p["ascii_host"]!=p["host"] or p["has_punycode"]}
    stages=[{"name":n,"status":s,"detail":d} for n,s,d in [
        ("Input validation","completed","HTTP and HTTPS URL syntax validated."),("URL parsing","completed","Hostname, path, scheme, and PSL-aware registered domain extracted."),
        ("URL heuristics","completed",f"{len(findings)} explainable finding(s) evaluated."),("Trust Gap Analyzer","completed",trust["summary"]),
        ("Machine learning","unavailable","No model artifact is configured; no ML inference was performed."),
        ("Threat intelligence","unavailable","No provider configured; no live reputation lookup was performed."),
        ("Infrastructure intelligence","skipped","No DNS, certificate, registration, or hosting lookup performed."),
        ("Relationship analysis","skipped","Requires a multi-URL or saved-history comparison."),]]
    return {"submitted_url":safe_url,"normalized_url":safe_url,"host":p["host"],"registered_domain":p["registered_domain"],"hostname_details":{"scheme":p["scheme"],"port":p["port"],"path":p["path"],"subdomains":p["subdomains"],"ascii_host":p["ascii_host"],"query_present":p["query_present"],"is_ip":p["is_ip"]},
        "url_features":features,"risk_score":score,"risk_category":category,"risk_assessment":{"score":score,"scale":"heuristic triage points, not a probability","category":category,"evidence_strength":"limited URL-derived evidence","completeness":"partial; no model, reputation, or infrastructure checks"},
        "detector_version":"heuristic-1.1","detector_type":"Baseline URL heuristics (not machine learning)","findings":findings,"stages":stages,"trust_gap":trust,
        "model_status":{"available":False,"detail":"No trained model is configured; score uses URL heuristics only."},
        "reputation_status":{"checked":False,"source":None,"status":"not_configured","detail":"No threat-intelligence API is configured; no live reputation lookup was performed."},
        "recommendations":["Do not enter passwords or payment details if you are unsure.","Open the service's official website by typing its known address yourself.","Treat this score as a triage signal, not proof of safety or maliciousness."],
        "limitations":["No website content, DNS, certificate, domain ownership, hosting, or live reputation was checked.","Low risk is not proof of legitimacy; missing intelligence is not evidence of safety.","Heuristic points are not a calibrated probability; correlated URL traits can overlap."],"report_kind":"actual local URL-derived analysis"}
