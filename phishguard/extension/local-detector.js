/* Offline Sentinel detector. Mirrors app/scanner.py's URL rules; see the
 * parity tests in tests/test_sentinel_local.js. PSL data is Mozilla-licensed. */
const PhishGuardLocal = (() => {
  const brands={Google:["google.com"],Microsoft:["microsoft.com","microsoftonline.com"],Apple:["apple.com"],Amazon:["amazon.com","amazon.co.uk"],PayPal:["paypal.com"],Facebook:["facebook.com","fb.com"],Netflix:["netflix.com"],"Amazon Web Services":["amazonaws.com"]};
  const tokens={google:"Google",microsoft:"Microsoft",apple:"Apple",amazon:"Amazon",paypal:"PayPal",facebook:"Facebook",netflix:"Netflix",aws:"Amazon Web Services"};
  let pslPromise;
  async function loadPSL(text){
    const exact=new Set(),wild=new Set(),except=new Set();
    const icann=text.split("// ===BEGIN PRIVATE DOMAINS===")[0];
    for(let line of icann.split(/\r?\n/)){
      line=line.trim();if(!line||line.startsWith("//"))continue;
      let kind="exact";if(line.startsWith("!")){kind="except";line=line.slice(1)}else if(line.startsWith("*.")){kind="wild";line=line.slice(2)}
      try{line=new URL(`http://${line}`).hostname.toLowerCase()}catch{continue}
      (kind==="exact"?exact:kind==="wild"?wild:except).add(line);
    }
    return {exact,wild,except};
  }
  async function rules(){
    if(!pslPromise)pslPromise=fetch(chrome.runtime.getURL("public_suffix_list.dat")).then(r=>{if(!r.ok)throw Error("Bundled Public Suffix List is unavailable");return r.text()}).then(loadPSL);
    return pslPromise;
  }
  function registeredDomain(host,psl,isIP){
    if(isIP||host==="localhost")return host;
    const labels=host.split(".");let suffixLength=1;
    for(let i=0;i<labels.length;i++){
      const candidate=labels.slice(i).join("."),length=labels.length-i;
      if(psl.except.has(candidate))suffixLength=Math.max(1,length-1);
      if(psl.exact.has(candidate))suffixLength=Math.max(suffixLength,length);
      if(i>0&&psl.wild.has(candidate))suffixLength=Math.max(suffixLength,length+1);
    }
    return labels.length>suffixLength?labels.slice(-(suffixLength+1)).join("."):host;
  }
  function levenshtein(a,b){const row=Array.from({length:b.length+1},(_,i)=>i);for(let i=1;i<=a.length;i++){let prev=row[0];row[0]=i;for(let j=1;j<=b.length;j++){const old=row[j];row[j]=Math.min(row[j]+1,row[j-1]+1,prev+(a[i-1]===b[j-1]?0:1));prev=old}}return row[b.length]}
  function isIP(host){if(host.startsWith("[")&&host.endsWith("]"))return true;const parts=host.split(".");return parts.length===4&&parts.every(x=>/^\d{1,3}$/.test(x)&&Number(x)<=255)}
  function normalizeMetadata(u,metadata={}){return {userinfo:Boolean(metadata.userinfo_present??(u.username||u.password)),queryPresent:Boolean(metadata.query_present??u.search),queryLength:Math.max(0,Math.min(8192,Number(metadata.query_length??u.search.length)||0)),fragmentPresent:Boolean(metadata.fragment_present??u.hash)}}
  async function analyze(raw,metadata={}){
    const psl=await rules();if(typeof raw!=="string"||!raw.trim()||raw.length>2048)throw Error("Enter a URL between 1 and 2,048 characters.");
    let u;try{u=new URL(raw.trim())}catch{throw Error("Enter a valid HTTP or HTTPS URL with a hostname.")}
    if(!["http:","https:"].includes(u.protocol)||!u.hostname)throw Error("Only HTTP and HTTPS URLs are supported.");
    const scheme=u.protocol.slice(0,-1),host=u.hostname.toLowerCase().replace(/\.$/,"");if(!host||host.length>253||host.includes("\\"))throw Error("Invalid hostname.");
    const ip=isIP(host),registered=registeredDomain(host,psl,ip),labels=ip?[]:host.split("."),subdomains=ip?[]:labels.slice(0,Math.max(0,labels.length-registered.split(".").length));
    const meta=normalizeMetadata(u,metadata),port=u.port?Number(u.port):null,path=u.pathname||"/",safe=new URL(u.href);safe.username="";safe.password="";safe.hash="";const normalized=safe.href;
    const parsed={host,registered_domain:registered,subdomains,path,scheme,port,is_ip:ip,userinfo:meta.userinfo,query_present:meta.queryPresent,query_length:meta.queryLength,fragment_present:meta.fragmentPresent,ascii_host:host,has_punycode:host.includes("xn--")};
    const detected=[];for(const [token,brand]of Object.entries(tokens))if(host.split(".").some(label=>label.includes(token)))detected.push({brand,token});
    let trust;
    if(!detected.length){const pathTokens=path.toLowerCase().replaceAll("-","/").replaceAll("_","/").split("/");const mentioned=Object.entries(tokens).find(([token])=>pathTokens.some(part=>part.includes(token)));trust={brand:null,brand_mentioned:mentioned?.[1]||null,registered_domain:registered,expected_domain:null,mismatch:false,indicators:[],summary:mentioned?"Brand appears in the URL path only; this does not identify the site operator.":"Brand not confidently identified."}}
    else{const found=detected.find(x=>brands[x.brand].some(d=>registered===d||registered.endsWith("."+d)))||detected[0],brand=found.brand,token=found.token,official=brands[brand][0],legitimate=brands[brand].some(d=>registered===d||registered.endsWith("."+d)),indicators=[];
      if(!legitimate){indicators.push({type:"brand_domain_mismatch",evidence:`${brand} appears in hostname '${host}', but the registered domain is '${registered}', not a configured official ${brand} domain.`,severity:"high"});if(subdomains.some(p=>p.includes(token)))indicators.push({type:"brand_in_subdomain",evidence:"Brand-like text is in a subdomain rather than the registered domain.",severity:"high"});const root=registered.split(".")[0];if(root!==token&&root.length>=4&&levenshtein(root,token)<=2)indicators.push({type:"lookalike_domain",evidence:`Registered-domain label '${root}' resembles brand name '${token}'.`,severity:"medium"})}
      trust={brand,brand_mentioned:brand,registered_domain:registered,expected_domain:official,mismatch:!legitimate,indicators,summary:!legitimate?"Potential brand impersonation: registered domain does not match configured official domain.":"Registered domain matches a configured official domain."}}
    let score=0;const findings=[];function add(name,evidence,why,severity,points){findings.push({name,evidence,why_it_matters:why,severity,points});score+=points}
    const safeLength=normalized.length;
    if(meta.userinfo)add("URL contains user information","A username/password-like segment appears before the hostname.","This can visually disguise the real destination.","high",25);
    if(ip)add("IP address used as hostname",`Hostname is ${host}.`,"IP-hosted links merit extra scrutiny; this alone is not a verdict.","medium",20);
    if(safeLength>120)add("Unusually long URL",`Normalized URL is ${safeLength} characters.`,"Long URLs can hide misleading details and are harder to inspect.","low",10);
    if(subdomains.length>=3)add("Excessive subdomains",`Hostname has ${subdomains.length} subdomain labels before ${registered}.`,"The registered domain is at the right-hand end; preceding words do not own it.","medium",15);
    if(trust.mismatch){add("Brand-domain mismatch",trust.indicators[0].evidence,"A brand name in a hostname does not prove that the brand operates the registered domain.","high",40);const look=trust.indicators.find(i=>i.type==="lookalike_domain");if(look)add("Lookalike registered domain",look.evidence,"Small spelling changes can make a domain resemble a trusted brand.","medium",15)}
    if(host!==host.toLowerCase()||host.includes("xn--"))add("Internationalized hostname",`ASCII/Punycode hostname is ${host}.`,"Unicode characters can resemble Latin letters in some fonts.","medium",15);
    if(scheme==="http")add("Unencrypted HTTP","The URL uses HTTP rather than HTTPS.","Traffic may not be encrypted; HTTPS alone would not prove legitimacy.","low",5);
    if(!findings.length)findings.push({name:"No flagged URL-structure indicators",evidence:"The implemented URL checks did not find their trigger conditions.",why_it_matters:"This is not proof the website is safe; no website content or reputation database was checked.",severity:"info",points:0});
    score=Math.min(100,score);const category=score<25?"Lower Risk":score<50?"Caution":score<75?"High Risk":"Very High Risk";
    const safeReport=normalized.split(/[?#]/,1)[0];
    return {submitted_url:safeReport,normalized_url:safeReport,host,registered_domain:registered,hostname_details:{scheme,port,path,subdomains,ascii_host:host,query_present:meta.queryPresent,is_ip:ip},url_features:{url_length:safeLength,hostname_length:host.length,subdomain_count:subdomains.length,dot_count:(host.match(/\./g)||[]).length,is_ip_literal:ip,userinfo_present:meta.userinfo,scheme_https:scheme==="https",path_length:path.length,query_present:meta.queryPresent,query_length:meta.queryLength,punycode_or_unicode:host.includes("xn--")},risk_score:score,risk_category:category,risk_assessment:{score,scale:"heuristic triage points, not a probability",category,evidence_strength:"limited URL-derived evidence",completeness:"partial; no model, reputation, or infrastructure checks"},detector_version:"heuristic-1.1",detector_type:"Baseline URL heuristics (not machine learning)",findings,stages:[{name:"Input validation",status:"completed",detail:"HTTP and HTTPS URL syntax validated."},{name:"URL parsing",status:"completed",detail:"Bundled Mozilla Public Suffix List used for registered-domain extraction."},{name:"URL heuristics",status:"completed",detail:`${findings.length} explainable finding(s) evaluated locally.`},{name:"Trust Gap Analyzer",status:"completed",detail:trust.summary},{name:"Machine learning",status:"unavailable",detail:"No trained model is configured."},{name:"Threat intelligence",status:"unavailable",detail:"No provider configured."}],trust_gap:trust,model_status:{available:false,detail:"No trained model is configured; local heuristic checks only."},reputation_status:{checked:false,status:"not_configured",detail:"No external reputation check was performed."},recommendations:["Verify the domain through a known official channel.","Treat this score as a triage signal, not proof of safety or maliciousness."],limitations:["No website content, DNS, certificate, domain ownership, hosting, or live reputation was checked.","Heuristic points are not a calibrated probability."],report_kind:"local-only URL-derived analysis",analysis_source:"bundled Sentinel detector",persisted:false};
  }
  return {analyze,loadPSL,warm:rules};
})();
if(typeof module!=="undefined")module.exports=PhishGuardLocal;
