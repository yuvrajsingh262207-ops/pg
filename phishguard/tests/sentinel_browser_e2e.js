/* Browser-level Sentinel smoke test. Requires Chromium and Node 22+ (global WebSocket). */
const assert=require("node:assert/strict");
const http=require("node:http");
const os=require("node:os");
const path=require("node:path");
const fs=require("node:fs");
const {spawn}=require("node:child_process");
const root=path.resolve(__dirname,".."),extension=path.join(root,"extension"),chromeBin=process.env.CHROMIUM_BIN||"/usr/bin/chromium",python=path.join(root,".venv/bin/python");
const temp=fs.mkdtempSync(path.join(os.tmpdir(),"phishguard-sentinel-e2e-"));
const fixture=http.createServer((req,res)=>{
  if(req.method==="OPTIONS"){res.writeHead(204,{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type"});res.end();return}
  if(req.method==="POST"&&req.url==="/api/extension/check"){res.writeHead(200,{"Access-Control-Allow-Origin":"*","Content-Type":"application/json"});setTimeout(()=>res.end(JSON.stringify({risk_category:"Lower Risk",risk_score:0,findings:[],analysis_source:"timeout fixture",persisted:false})),6500);return}
  if(req.url==="/redirect"){res.writeHead(302,{Location:`http://google.com.account-verification.example.org:${fixture.address().port}/slow-login`});res.end();return}
  if(req.url?.startsWith("/slow-login")){const timer=setTimeout(()=>{fixtureCompleted=true;res.writeHead(200,{"Content-Type":"text/html"});res.end("<title>Fixture</title>FIXTURE_PAGE_LOADED")},8000);res.on("close",()=>{clearTimeout(timer);if(!res.writableEnded)global.interruptedNavigation=true});return}
  res.writeHead(200,{"Content-Type":"text/html"});res.end("<title>Fixture</title>FIXTURE_PAGE_LOADED");
});
let browser,backend,cdpPort,backendPort,interruptedNavigation=false,fixtureCompleted=false;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function freePort(){const s=http.createServer();await new Promise(r=>s.listen(0,"127.0.0.1",r));const p=s.address().port;await new Promise(r=>s.close(r));return p}
async function json(url,options){const r=await fetch(url,options);if(!r.ok)throw Error(`${url}: HTTP ${r.status}`);return r.json()}
async function waitFor(fn,description,timeout=9000){const start=Date.now();let last;while(Date.now()-start<timeout){try{last=await fn();if(last)return last}catch{}await sleep(100)}throw Error(`Timed out waiting for ${description}${last?`: ${last}`:""}`)}
function connect(target){
  const ws=new WebSocket(target.webSocketDebuggerUrl),pending=new Map();let seq=0;
  ws.addEventListener("message",e=>{const m=JSON.parse(e.data);if(m.id&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result)}});
  return new Promise((resolve,reject)=>{
    ws.addEventListener("open",()=>resolve({
      ws,
      call(method,params={}){const id=++seq;return new Promise((res,rej)=>{const timer=setTimeout(()=>{pending.delete(id);rej(Error(`CDP timeout: ${method}`))},7000);pending.set(id,{resolve:v=>{clearTimeout(timer);res(v)},reject:e=>{clearTimeout(timer);rej(e)}});ws.send(JSON.stringify({id,method,params}))})},
      async evaluate(expression,userGesture=false){const r=await this.call("Runtime.evaluate",{expression,awaitPromise:true,returnByValue:true,userGesture});if(r.exceptionDetails)throw Error(r.exceptionDetails.text||"Runtime.evaluate failed");return r.result?.value}
    }));
    ws.addEventListener("error",reject);
  });
}
async function targets(){return json(`http://127.0.0.1:${cdpPort}/json/list`)}
async function worker(){return waitFor(async()=>{const ts=await targets();return ts.find(x=>x.type==="service_worker"&&x.url.endsWith("/background.js"))},"Sentinel service worker")}
async function setPrefs(c,values){await c.evaluate(`chrome.storage.local.set(${JSON.stringify(values)}).then(()=>true)`);await sleep(200)}
async function findPage(id,predicate){return waitFor(async()=>{const ts=await targets();return ts.find(t=>t.id===id&&predicate(t.url))},"tab navigation")}
async function main(){
  await new Promise(r=>fixture.listen(0,"127.0.0.1",r));cdpPort=await freePort();backendPort=await freePort();
  backend=spawn(python,["-m","uvicorn","app.main:app","--host","127.0.0.1","--port",String(backendPort)],{cwd:root,env:{...process.env,PHISHGUARD_DB:path.join(temp,"browser-e2e.sqlite3")},stdio:"ignore",detached:true});
  await waitFor(async()=>{try{return await json(`http://127.0.0.1:${backendPort}/api/health`)}catch{return null}},"PhishGuard backend");
  browser=spawn(chromeBin,["--headless=new","--no-sandbox","--disable-dev-shm-usage","--disable-gpu","--no-first-run","--no-default-browser-check",`--user-data-dir=${path.join(temp,"profile")}`,`--remote-debugging-port=${cdpPort}`,"--remote-allow-origins=*",`--disable-extensions-except=${extension}`,`--load-extension=${extension}`,"--host-resolver-rules=MAP *.example.org 127.0.0.1,MAP example.org 127.0.0.1,EXCLUDE localhost","about:blank"],{stdio:"ignore",detached:true});
  await waitFor(async()=>{try{return await json(`http://127.0.0.1:${cdpPort}/json/version`)}catch{return null}},"Chromium remote debugging");
  const sw=await worker(),workerCdp=await connect(sw);await workerCdp.call("Runtime.enable");const extensionId=sw.url.split("/")[2];
  const optionsTarget=await json(`http://127.0.0.1:${cdpPort}/json/new?${encodeURIComponent(`chrome-extension://${extensionId}/options.html`)}`,{method:"PUT"}),options=await connect(optionsTarget);await options.call("Runtime.enable");
  await options.evaluate(`(async()=>{await new Promise(r=>setTimeout(r,300));document.querySelector('#api').value='http://127.0.0.1:${backendPort}';document.querySelector('#mode').value='standard';document.querySelector('#form').requestSubmit();await new Promise(r=>setTimeout(r,300));return document.querySelector('#api').value})()`,true);
  let optionsText;try{optionsText=await waitFor(()=>options.evaluate("document.querySelector('#result').textContent").then(x=>x.includes("Settings saved")?x:null),"options settings save")}catch(e){console.log("options form diagnostic:",await options.evaluate("JSON.stringify({result:document.querySelector('#result').textContent,handler:String(document.querySelector('#form').onsubmit),api:document.querySelector('#api').value})"));throw e}assert.match(optionsText,/site-access permission/i);
  assert.equal(await workerCdp.evaluate("chrome.storage.local.get('apiBase').then(x=>x.apiBase)"),`http://127.0.0.1:${backendPort}`,"options must persist backend configuration");
  await fetch(`http://127.0.0.1:${cdpPort}/json/close/${optionsTarget.id}`);
  await setPrefs(workerCdp,{enabled:true,mode:"local",apiBase:`http://127.0.0.1:${backendPort}`,pausedUntil:0,excluded:[],language:"en"});
  const tab=await json(`http://127.0.0.1:${cdpPort}/json/new?${encodeURIComponent("about:blank")}`,{method:"PUT"});const page=await connect(tab);await page.call("Page.enable");
  const browserTabId=await workerCdp.evaluate("chrome.tabs.query({active:true,currentWindow:true}).then(t=>t[0].id)");
  const destination=`http://google.com.account-verification.example.org:${fixture.address().port}/slow-login`;
  page.call("Page.navigate",{url:destination}).catch(()=>{});
  let warning;try{warning=await findPage(tab.id,url=>url.includes("warning.html"))}catch(e){console.log("targets after direct check:",(await targets()).map(t=>({id:t.id,url:t.url})));console.log("tab statuses after direct check:",await workerCdp.evaluate("chrome.storage.local.get('tabStatuses').then(x=>x.tabStatuses)"));throw e}
  const warningCdp=await connect(warning);await warningCdp.call("Runtime.enable");
  const body=await waitFor(()=>warningCdp.evaluate("document.body.innerText").then(x=>x.includes("Brand-domain mismatch")?x:null),"warning findings");
  assert.match(body,/Brand-domain mismatch/);assert.match(body,/example\.org/);assert.match(body,/Go back to safety/i);
  assert.equal(fixtureCompleted,false,"warning should replace the deliberately delayed destination before it completes");
  await warningCdp.evaluate("document.querySelector('#details').click()");
  const detailTarget=await waitFor(async()=>{const t=await targets();return t.find(x=>x.url.includes("sentinel_url="))},"dashboard opened with the flagged URL");
  const detailPage=await connect(detailTarget);await detailPage.call("Runtime.enable");
  const detailed=await waitFor(()=>detailPage.evaluate("document.querySelector('#report')?.hidden===false && document.querySelector('#report').innerText.includes('Brand-domain mismatch')"),"dashboard detailed investigation");
  assert.equal(detailed,true,"the dashboard should rerun the actual scanner for the redacted warning URL");
  await fetch(`http://127.0.0.1:${cdpPort}/json/close/${detailTarget.id}`);
  await warningCdp.evaluate("document.querySelector('#continue').click()");
  await waitFor(async()=>{const t=await targets();const p=t.find(x=>x.id===tab.id);return p&&p.url===destination?p:null},"continue-once navigation");
  await waitFor(()=>page.evaluate("document.body.innerText.includes('FIXTURE_PAGE_LOADED')"),"continued destination");

  await setPrefs(workerCdp,{mode:"local",excluded:["example.org"],pausedUntil:0});
  const excludedUrl=`http://google.com.account-verification.example.org:${fixture.address().port}/excluded`;
  await page.call("Page.navigate",{url:excludedUrl});await waitFor(()=>page.evaluate("document.body.innerText.includes('FIXTURE_PAGE_LOADED')"),"excluded destination");
  const excludedStatus=await workerCdp.evaluate(`chrome.storage.local.get('tabStatuses').then(x=>x.tabStatuses['${browserTabId}']?.kind)`);assert.equal(excludedStatus,"excluded");

  await setPrefs(workerCdp,{mode:"standard",excluded:[],apiBase:`http://127.0.0.1:${backendPort}`,pausedUntil:0});
  const normalUrl=`http://example.org:${fixture.address().port}/api-backed`;
  await page.call("Page.navigate",{url:normalUrl}).catch(()=>{});
  const actualStatus=await waitFor(()=>workerCdp.evaluate(`chrome.storage.local.get('tabStatuses').then(x=>x.tabStatuses['${browserTabId}'])`).then(x=>x?.kind==="analyzed"?x:null),"browser-backed PhishGuard analysis");
  assert.equal(actualStatus.report.analysis_source,"local URL heuristics");assert.equal(actualStatus.report.persisted,false);
  assert.equal(actualStatus.report.risk_category,"Lower Risk","the controlled benign URL should retain the actual backend's lower-risk result");

  await setPrefs(workerCdp,{mode:"standard",excluded:[],apiBase:`http://127.0.0.1:${fixture.address().port}`,pausedUntil:0});
  await page.call("Page.navigate",{url:`http://example.org:${fixture.address().port}/timeout`}).catch(()=>{});
  const timeoutStatus=await waitFor(()=>workerCdp.evaluate(`chrome.storage.local.get('tabStatuses').then(x=>x.tabStatuses['${browserTabId}']?.kind)`).then(x=>x==="local-fallback"?x:null),"local fallback after backend timeout",7000);
  assert.equal(timeoutStatus,"local-fallback");

  await setPrefs(workerCdp,{mode:"standard",excluded:[],apiBase:"http://127.0.0.1:1",pausedUntil:0});
  page.call("Page.navigate",{url:`http://example.org:${fixture.address().port}/redirect`}).catch(()=>{});
  let redirectedWarning;try{redirectedWarning=await findPage(tab.id,url=>url.includes("warning.html"))}catch(e){console.log("targets after redirect:",(await targets()).map(t=>({id:t.id,url:t.url})));console.log("tab statuses:",await workerCdp.evaluate("chrome.storage.local.get('tabStatuses').then(x=>x.tabStatuses)"));throw e}
  const second=await connect(redirectedWarning);await second.call("Runtime.enable");
  const secondBody=await waitFor(()=>second.evaluate("document.body.innerText").then(x=>x.includes("Brand-domain mismatch")?x:null),"redirect warning findings");assert.match(secondBody,/Brand-domain mismatch/);
  const status=await waitFor(()=>workerCdp.evaluate(`chrome.storage.local.get('tabStatuses').then(x=>x.tabStatuses['${browserTabId}']?.kind)`).then(x=>x==="local-warning-fallback"?x:null),"local warning/backend failure status");
  assert.equal(status,"local-warning-fallback","unavailable backend should preserve local warning and disclose fallback");
  const safeReturn=`http://example.org:${fixture.address().port}/`;
  await second.evaluate("document.querySelector('#back').click()");
  await waitFor(async()=>{const t=await targets(),tabTarget=t.find(x=>x.id===tab.id);return tabTarget?.url===safeReturn?tabTarget:null},"go-back action returns to the previous committed page instead of the warning destination");
  assert.equal((await targets()).some(x=>x.id===tab.id&&x.url.includes("warning.html")),false,"go-back must not loop back into the warning page");
  await workerCdp.call("Runtime.evaluate",{expression:"chrome.action.openPopup()",awaitPromise:true,returnByValue:true,userGesture:true});
  const popupTarget=await waitFor(async()=>{const t=await targets();return t.find(x=>x.url.endsWith("/popup.html"))},"Sentinel popup");
  const popup=await connect(popupTarget);await popup.call("Runtime.enable");
  let popupText;try{popupText=await waitFor(()=>popup.evaluate("document.body.innerText").then(x=>x.includes("Current URL")&&/Unencrypted HTTP|No flagged URL-structure indicators/.test(x)?x:null),"popup URL, current analysis findings and status")}catch(e){console.log("popup render error:",await popup.evaluate("render().then(()=>\"ok\").catch(e=>String(e.stack))"));console.log("popup body:",await popup.evaluate("document.body.innerText"));console.log("current tab:",await workerCdp.evaluate("chrome.tabs.query({active:true,currentWindow:true}).then(x=>JSON.stringify(x.map(t=>({id:t.id,url:t.url}))))"));console.log("tab statuses:",await workerCdp.evaluate("chrome.storage.local.get('tabStatuses').then(x=>JSON.stringify(x.tabStatuses))"));throw e}
  assert.match(popupText,/Current URL/);assert.match(popupText,/Last check|Analysis|Warning/i);assert.match(popupText,/\d{1,2}\/\d{1,2}\/\d{4}|\d{4}/,"popup should include analysis time");
  assert.match(popupText,/Unencrypted HTTP|No flagged URL-structure indicators/,"popup should expose the actual latest finding for the current tab");
  await popup.evaluate("document.querySelector('#language').value='hi';document.querySelector('#language').dispatchEvent(new Event('change',{bubbles:true}));true");
  await waitFor(()=>workerCdp.evaluate("chrome.storage.local.get('language').then(x=>x.language==='hi')"),"saved popup language");
  await popup.evaluate("document.querySelector('#mode').value='local';document.querySelector('#excluded').value='example.net';document.querySelector('#save-controls').click()");
  await waitFor(()=>workerCdp.evaluate("chrome.storage.local.get(['mode','excluded']).then(x=>x.mode==='local'&&x.excluded.includes('example.net'))"),"popup privacy mode and exclusion controls");
  await popup.evaluate("document.querySelector('#toggle').click()");
  await waitFor(()=>workerCdp.evaluate("chrome.storage.local.get('pausedUntil').then(x=>x.pausedUntil>Date.now())"),"pause protection control");
  const pausedUrl=`http://google.com.account-verification.example.org:${fixture.address().port}/paused`;
  await page.call("Page.navigate",{url:pausedUrl}).catch(()=>{});
  await waitFor(()=>page.evaluate("document.body.innerText.includes('FIXTURE_PAGE_LOADED')"),"navigation proceeds without extension analysis while paused");
  assert.equal((await targets()).some(x=>x.id===tab.id&&x.url.includes("warning.html")),false,"paused protection must not issue a warning");
  await popup.evaluate("document.querySelector('#resume').click()");
  await waitFor(()=>workerCdp.evaluate("chrome.storage.local.get('pausedUntil').then(x=>x.pausedUntil===0)"),"resume protection control");
  console.log("Sentinel Chromium E2E passed: install/load, options persistence, local auto-analysis, early warning and findings, continue-once, exclusions, backend API success, timeout fallback, redirects, backend-unavailable fallback, popup status/language, pause/resume");
}
main().catch(e=>{console.error(e);process.exitCode=1}).finally(async()=>{if(browser?.pid)try{process.kill(-browser.pid,"SIGKILL")}catch{}if(backend?.pid)try{process.kill(-backend.pid,"SIGKILL")}catch{}fixture.closeAllConnections();await new Promise(r=>fixture.close(()=>r()));fs.rmSync(temp,{recursive:true,force:true})});
