from __future__ import annotations
import json, os, time, io, zipfile
from collections import defaultdict, deque
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from . import database
from .scanner import URLValidationError, run_scan
from .counterfactual import compare as compare_urls
from .dna import build_graph, synthetic_demo_graph

BASE=Path(__file__).resolve().parent.parent
app=FastAPI(title="PhishGuard 3.0",version="3.0.0",docs_url="/api/docs")
app.add_middleware(CORSMiddleware, allow_origins=[], allow_origin_regex=r"chrome-extension://[a-p]{32}", allow_methods=["POST"], allow_headers=["Content-Type"], allow_credentials=False)
app.mount("/static",StaticFiles(directory=BASE/"static"),name="static")
_hits:dict[str,deque]=defaultdict(deque)
class ScanRequest(BaseModel): url:str=Field(min_length=1,max_length=2048)
class ExtensionScanRequest(BaseModel):
    url:str=Field(min_length=1,max_length=2048)
    userinfo_present:bool=False
    query_present:bool=False
    query_length:int=Field(default=0,ge=0,le=8192)
    fragment_present:bool=False
class BatchRequest(BaseModel): urls:list[str]=Field(min_length=1,max_length=50)
class CompareRequest(BaseModel): original:str=Field(min_length=1,max_length=2048); variant:str=Field(min_length=1,max_length=2048)
class CopilotRequest(BaseModel): scan_id:int|None=None; question:str=Field(min_length=1,max_length=2000)

@app.on_event("startup")
def startup(): database.init_db()
@app.middleware("http")
async def rate_limit(request:Request,call_next):
    if request.url.path in {"/api/scan","/api/batch","/api/copilot","/api/counterfactual","/api/extension/check"} and request.method=="POST":
        ip=request.client.host if request.client else "unknown"; now=time.monotonic(); q=_hits[ip]
        while q and now-q[0]>60:q.popleft()
        if len(q)>=30:return JSONResponse({"detail":"Rate limit exceeded. Try again in a minute."},status_code=429)
        q.append(now)
    return await call_next(request)
@app.get("/")
def index():return FileResponse(BASE/"static"/"index.html")
@app.get("/api/health")
def health():return {"status":"ok","detector":"baseline-heuristic","database":"sqlite","model":"not_configured","threat_intelligence":"not_configured"}
@app.get("/api/extension/package")
def extension_package():
    """Package the reviewed unpacked Chromium extension without project secrets."""
    root=BASE/"extension"
    files=("manifest.json","background.js","local-detector.js","public_suffix_list.dat","popup.html","popup.js","options.html","options.js","warning.html","warning.js","extension.css","README.md")
    content=io.BytesIO()
    with zipfile.ZipFile(content,"w",zipfile.ZIP_DEFLATED) as archive:
        for name in files: archive.write(root/name, f"phishguard-sentinel/{name}")
    content.seek(0)
    return StreamingResponse(content,media_type="application/zip",headers={"Content-Disposition":"attachment; filename=phishguard-sentinel.zip"})
@app.get("/api/source/package")
def source_package():
    """Download a source-only project archive and the standalone Sentinel ZIP."""
    content=io.BytesIO()
    excluded={".venv",".git","__pycache__",".pytest_cache","node_modules"}
    excluded_names={"phishguard.sqlite3",".env"}
    with zipfile.ZipFile(content,"w",zipfile.ZIP_DEFLATED) as archive:
        for name in ("README.md","requirements.txt",".gitignore"):
            path=BASE/name
            if path.is_file():archive.write(path,f"phishguard/{name}")
        for folder in ("app","static","extension","tests"):
            root=BASE/folder
            for path in sorted(root.rglob("*")):
                if not path.is_file():continue
                rel=path.relative_to(BASE)
                if any(part in excluded for part in rel.parts) or path.name in excluded_names or path.suffix in {".pyc",".pyo"}:continue
                archive.write(path,f"phishguard/{rel.as_posix()}")
        extension_files=("manifest.json","background.js","local-detector.js","public_suffix_list.dat","popup.html","popup.js","options.html","options.js","warning.html","warning.js","extension.css","README.md")
        ext_zip=io.BytesIO()
        with zipfile.ZipFile(ext_zip,"w",zipfile.ZIP_DEFLATED) as ext_archive:
            for name in extension_files:ext_archive.write(BASE/"extension"/name,f"phishguard-sentinel/{name}")
        archive.writestr("phishguard/artifacts/phishguard-sentinel-extension.zip",ext_zip.getvalue())
    content.seek(0)
    return StreamingResponse(content,media_type="application/zip",headers={"Content-Disposition":"attachment; filename=phishguard-github-source.zip"})
@app.post("/api/scan")
def scan(body:ScanRequest):
    try:r=run_scan(body.url)
    except URLValidationError as e:raise HTTPException(status_code=422,detail=str(e))
    except Exception:raise HTTPException(status_code=400,detail="Unable to analyze this URL. Check its format and try again.")
    r["id"]=database.save_scan(r);return database.get_scan(r["id"])
@app.post("/api/extension/check")
def extension_check(body:ExtensionScanRequest):
    """Ephemeral extension analysis; browser visits are not added to manual history."""
    try:
        r=run_scan(body.url,body.model_dump(exclude={"url"}))
    except URLValidationError as e:
        raise HTTPException(status_code=422,detail=str(e))
    except Exception:
        raise HTTPException(status_code=400,detail="Unable to analyze this URL.")
    r["analysis_source"]="local URL heuristics"
    r["persisted"]=False
    return r
@app.post("/api/batch")
def batch(body:BatchRequest):
    results=[]
    for i,raw in enumerate(body.urls):
        try:
            r=run_scan(raw);r["id"]=database.save_scan(r);results.append({"index":i,"valid":True,"report":database.get_scan(r["id"])})
        except URLValidationError as e:results.append({"index":i,"valid":False,"error":str(e),"submitted":str(raw)[:160]})
        except Exception:results.append({"index":i,"valid":False,"error":"Analysis failed safely.","submitted":str(raw)[:160]})
    valid=[x["report"] for x in results if x["valid"]]
    return {"results":results,"graph":build_graph(valid),"successful":len(valid),"failed":len(results)-len(valid),"synthetic":False}
@app.post("/api/counterfactual")
def counterfactual(body:CompareRequest):
    try:return compare_urls(body.original,body.variant)
    except URLValidationError as e:raise HTTPException(status_code=422,detail=str(e))
@app.get("/api/attack-dna")
def attack_dna(demo:bool=False):
    if demo:return synthetic_demo_graph()
    return build_graph(database.list_scans(limit=500,full=True))
@app.post("/api/copilot")
def copilot(body:CopilotRequest):
    r=database.get_scan(body.scan_id) if body.scan_id is not None else None
    if body.scan_id is not None and r is None:raise HTTPException(status_code=404,detail="Investigation not found")
    if r is None:return {"mode":"evidence-grounded rules fallback","answer":"Select an investigation first. This local fallback uses saved PhishGuard report fields only; no LLM provider is configured.","evidence":[],"llm_configured":False}
    q=body.question.lower(); evidence=[]
    def cite(label,value):evidence.append({"label":label,"value":value})
    cite("Registered domain",r["registered_domain"]); cite("Heuristic assessment",f"{r['risk_category']} · {r['risk_score']}/100 points (not probability)")
    if "model" in q or "same result" in q:
        answer="No machine-learning model is configured. This report uses URL-derived rules only; no model output or probability exists."
        cite("Model status",r["model_status"]["detail"])
    elif any(k in q for k in ("unavailable","check","complete","limitation")):
        answer="The report completed URL parsing, heuristic checks, and Trust Gap analysis. Machine learning and reputation checks are unavailable because they are not configured; DNS, certificates, ownership and hosting were not checked."
        cite("Stages",", ".join(f"{x['name']}: {x['status']}" for x in r["stages"]))
    elif "false positive" in q or "could this" in q:
        answer="A false positive is possible: these are URL-pattern indicators, not proof of malicious intent. Review each finding, verify the domain through a known official channel, and note that no page or live reputation was checked."
        cite("Findings",", ".join(x["name"] for x in r["findings"]))
    elif "strongest" in q or "evidence" in q or "flag" in q or "why" in q:
        answer="The assessment is based on the URL-derived findings below. These explain observed patterns, but do not prove the site is malicious."
        for f in r["findings"]:cite(f["name"],f["evidence"])
        if r["trust_gap"].get("mismatch"):cite("Trust Gap",r["trust_gap"]["summary"])
    elif "domain" in q or "belong" in q:
        answer=f"The PSL-aware parser extracted {r['registered_domain']} as the registered domain. This identifies the hostname boundary, not the legal owner."
        cite("Hostname",r["host"])
    elif "password" in q or "entered" in q:
        answer="If you entered a password, independently navigate to the legitimate service, change that password, revoke active sessions if available, enable MFA, and change any reused passwords. Do not use the suspicious link to recover the account."
        cite("Context",f"Current investigation: {r['registered_domain']} · {r['risk_category']}")
    elif "counterfactual" in q or "changed" in q:
        answer="No counterfactual is attached to this saved report. Use Counterfactual Lab to submit an explicit original and controlled variant; it runs the same available heuristic pipeline on both."
    elif "related" in q or "campaign" in q:
        answer="This report alone cannot establish campaign membership. Attack DNA can show observable shared registered domains among saved scans; similarity is a hypothesis, not attribution."
        cite("Relationship workflow","GET /api/attack-dna derives relationships from saved scan reports")
    else:
        answer="From this report: verify the registered domain independently, do not enter sensitive information if uncertain, and treat the score as a limited URL triage signal—not a safety guarantee."
        cite("Recommendations", " | ".join(r["recommendations"]))
    return {"mode":"evidence-grounded rules fallback","answer":answer,"evidence":evidence,"llm_configured":False,"investigation_id":r.get("id")}
@app.get("/api/evaluation")
def evaluation():
    return {"status":"Not evaluated","model_available":False,"model_version":None,"dataset":None,"methodology":None,"metrics":None,"detail":"No trained model artifact or dataset is present. No metrics are claimed. The local environment has no scikit-learn installation; this is an honest unavailable state, not an evaluation result."}
@app.get("/api/scans")
def scans(q:str="",category:str="",limit:int=100):return database.list_scans(q,category,limit)
@app.get("/api/scans/summary")
def summary():return database.summary()
@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id:int):
    r=database.get_scan(scan_id)
    if not r:raise HTTPException(status_code=404,detail="Scan not found")
    return r
@app.get("/api/scans/{scan_id}/export")
def export_scan(scan_id:int):
    r=database.get_scan(scan_id)
    if not r:raise HTTPException(status_code=404,detail="Scan not found")
    return JSONResponse(r,headers={"Content-Disposition":f'attachment; filename="phishguard-report-{scan_id}.json"'})
@app.delete("/api/scans")
def clear_history():return {"deleted":database.clear_scans()}
@app.delete("/api/scans/{scan_id}")
def delete_history(scan_id:int):
    if not database.delete_scan(scan_id):raise HTTPException(status_code=404,detail="Scan not found")
    return {"deleted":True}
@app.get("/api/examples")
def examples():
    data=[]
    for title,url in [("Reserved example domain","https://example.com/"),("Many subdomains","https://login.account.verify.example.org/"),("Illustrative brand-like hostname","https://google.com.account-verification.example.org/login"),("Brand text in path only","https://example.org/google/login"),("Synthetic uncertain case","https://example.net/support/request")]:
        r=run_scan(url);data.append({"title":title,"url":url,"valid":True,"synthetic":True,"risk_score":r["risk_score"],"risk_category":r["risk_category"],"trust_gap":r["trust_gap"]})
    return {"label":"Synthetic demonstration cases on reserved example domains; not real threats or intelligence.","examples":data}
