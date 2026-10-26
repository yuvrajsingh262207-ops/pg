importScripts("local-detector.js");
const DEFAULTS={enabled:true,pausedUntil:0,excluded:[],mode:"standard",language:"en",apiBase:"http://127.0.0.1:8000"};
const skipSchemes=/^(chrome|edge|about|chrome-extension|view-source|devtools|data|javascript|file):/i;
const inFlight=new Map();
let prefs={...DEFAULTS};
const detectorReady=PhishGuardLocal.warm();
const prefsReady=chrome.storage.local.get(DEFAULTS).then(x=>{prefs={...DEFAULTS,...x}});
chrome.storage.onChanged.addListener((changes,area)=>{if(area==="local")for(const [k,v]of Object.entries(changes))prefs[k]=v.newValue});
function excluded(host,list){return list.some(x=>{const d=String(x).trim().toLowerCase().replace(/^\*\./,"");return d&&(host===d||host.endsWith("."+d))})}
function warnable(report,mode){const score=Number(report?.risk_score||0),findings=report?.findings||[],strong=findings.some(f=>f.name==="Brand-domain mismatch"||f.name==="URL contains user information");return mode==="strict"?score>=25&&(strong||findings.length>=2):score>=50&&strong}
function safeUrlKey(raw){try{const u=new URL(raw),metadata=scrubMetadata(u);u.username="";u.password="";u.search="";u.hash="";return `${u.href}|u:${+metadata.userinfo_present}|q:${metadata.query_length}|f:${+metadata.fragment_present}`}catch{return ""}}
function scrubMetadata(u){return {userinfo_present:Boolean(u.username||u.password),query_present:Boolean(u.search),query_length:u.search.length,fragment_present:Boolean(u.hash)}}
async function updateStatus(tabId,status){const k=String(tabId),x=await chrome.storage.local.get({tabStatuses:{}});x.tabStatuses[k]={...status,tabId,at:Date.now()};await chrome.storage.local.set({tabStatuses:x.tabStatuses})}
async function redirectToWarning(details,report,mode){
  const current=await chrome.tabs.get(details.tabId).catch(()=>null);if(!current)return false;
  const matches=current.url===details.url||current.pendingUrl===details.url||(details.sourceUrl&&(current.url===details.sourceUrl||current.pendingUrl===details.sourceUrl));
  if(!matches||current.url?.startsWith(chrome.runtime.getURL("warning.html")))return false;
  const safe=await chrome.storage.session.get(`lastCommitted:${details.tabId}`),last=safe[`lastCommitted:${details.tabId}`];
  const returnUrl=last&&last!==details.url&&/^https?:|^about:blank$/.test(last)?last:"about:blank";
  await chrome.storage.session.set({[`warning:${details.tabId}`]:{report,originalUrl:details.url,returnUrl,seenAt:Date.now(),mode}});
  await chrome.tabs.update(details.tabId,{url:chrome.runtime.getURL(`warning.html?tab=${details.tabId}`)});return true;
}
async function check(details){
  if(details.frameId!==0||skipSchemes.test(details.url))return;
  await prefsReady;const s={...DEFAULTS,...prefs};if(!s.enabled||Date.now()<s.pausedUntil)return;
  let u;try{u=new URL(details.url)}catch{return}if(!/^https?:$/.test(u.protocol))return;
  if(excluded(u.hostname,s.excluded)){await updateStatus(details.tabId,{kind:"excluded",host:u.hostname,urlKey:safeUrlKey(details.url)});return}
  const allowKey=`allow:${details.tabId}`,once=await chrome.storage.session.get(allowKey);if(once[allowKey]===details.url){await chrome.storage.session.remove(allowKey);return}
  const key=`${details.tabId}:${details.url}`;if(inFlight.has(key))return;inFlight.set(key,true);
  const metadata=scrubMetadata(u),localUrl=new URL(u.href);localUrl.username="";localUrl.password="";localUrl.search="";localUrl.hash="";
  await updateStatus(details.tabId,{kind:"analyzing",host:u.hostname,urlKey:safeUrlKey(details.url)});
  let local=null,localError=null,localWarning=false;
  try{local=await PhishGuardLocal.analyze(details.url,metadata)}catch(e){localError=String(e.message||e)}
  if(local){
    localWarning=warnable(local,s.mode);
    if(localWarning)await redirectToWarning(details,local,s.mode);
    await updateStatus(details.tabId,{kind:localWarning?"warning":s.mode==="local"?"analyzed-local":"local-check",host:u.hostname,urlKey:safeUrlKey(details.url),category:local.risk_category,score:local.risk_score,report:local});
    if(s.mode==="local"){inFlight.delete(key);return}
  }else if(s.mode==="local"){
    await updateStatus(details.tabId,{kind:"unavailable",host:u.hostname,urlKey:safeUrlKey(details.url),detail:localError||"Local detector unavailable"});inFlight.delete(key);return
  }
  try{
    const response=await fetch(`${s.apiBase.replace(/\/$/,"")}/api/extension/check`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:localUrl.href,...metadata}),signal:AbortSignal.timeout(5000)});
    if(!response.ok)throw Error(`Analysis service returned ${response.status}`);
    const report=await response.json();
    await updateStatus(details.tabId,{kind:warnable(report,s.mode)?"warning":"analyzed",host:u.hostname,urlKey:safeUrlKey(details.url),category:report.risk_category,score:report.risk_score,report});
    if(warnable(report,s.mode))await redirectToWarning(details,report,s.mode);
  }catch(error){
    await updateStatus(details.tabId,local?{kind:localWarning?"local-warning-fallback":"local-fallback",host:u.hostname,urlKey:safeUrlKey(details.url),category:local.risk_category,score:local.risk_score,report:local,detail:String(error.message||error)}:{kind:"unavailable",host:u.hostname,urlKey:safeUrlKey(details.url),detail:String(error.message||error)});
  }finally{inFlight.delete(key)}
}
chrome.webNavigation.onBeforeNavigate.addListener(check,{url:[{schemes:["http","https"]}]});
chrome.webNavigation.onCommitted.addListener(details=>{if(details.frameId===0&&/^https?:/.test(details.url)){try{chrome.storage.session.set({[`lastCommitted:${details.tabId}`]:new URL(details.url).origin})}catch{}}});
chrome.webRequest.onBeforeRedirect.addListener(details=>check({...details,sourceUrl:details.url,url:details.redirectUrl}),{urls:["<all_urls>"],types:["main_frame"]});
chrome.tabs.onRemoved.addListener(async tabId=>{const x=await chrome.storage.local.get({tabStatuses:{}});delete x.tabStatuses[String(tabId)];await chrome.storage.local.set({tabStatuses:x.tabStatuses});const session=await chrome.storage.session.get(null),suffix=`:${tabId}`;await chrome.storage.session.remove(Object.keys(session).filter(k=>k.endsWith(suffix)))});
chrome.runtime.onMessage.addListener((msg,_sender,sendResponse)=>{
  if(msg?.type==="get-settings")sendResponse({...DEFAULTS,...prefs});
  else if(msg?.type==="get-tab-status")chrome.storage.local.get({tabStatuses:{}}).then(x=>sendResponse(x.tabStatuses[String(msg.tabId)]||null));
  else if(msg?.type==="pause")chrome.storage.local.set({pausedUntil:Date.now()+msg.ms}).then(()=>sendResponse({ok:true}));
  else if(msg?.type==="resume")chrome.storage.local.set({pausedUntil:0}).then(()=>sendResponse({ok:true}));
  else if(msg?.type==="back-to-safety")chrome.storage.session.get(`warning:${msg.tabId}`).then(async x=>{const warning=x[`warning:${msg.tabId}`],url=warning?.returnUrl||"about:blank";await chrome.storage.session.remove(`warning:${msg.tabId}`);await chrome.tabs.update(Number(msg.tabId),{url});sendResponse({ok:true})});
  else if(msg?.type==="clear-extension-history")Promise.all([chrome.storage.local.remove(["tabStatuses","warningFeedback"]),chrome.storage.session.clear()]).then(()=>sendResponse({ok:true}));
  return true;
});
