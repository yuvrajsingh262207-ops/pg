const params=new URLSearchParams(location.search),tabId=Number(params.get("tab")), $=s=>document.querySelector(s);
const L={
  hi:{title:"PhishGuard को URL में जोखिम के संकेत मिले",intro:"यह चेतावनी केवल URL की बनावट पर आधारित है; यह दुर्भावनापूर्ण होने का प्रमाण नहीं है। जाँच पूरी होने से पहले पेज खुलना शुरू हो सकता है।",back:"सुरक्षित पेज पर लौटें",continue:"फिर भी आगे जाएँ",details:"विस्तृत जाँच देखें",incorrect:"गलत चेतावनी की रिपोर्ट करें",limits:"वेबसाइट की सामग्री, DNS, TLS या थ्रेट फ़ीड की जाँच नहीं हुई। डोमेन को आधिकारिक स्रोत से सत्यापित करें."},
  mr:{title:"PhishGuard ला URL मध्ये जोखमीचे संकेत आढळले",intro:"ही सूचना फक्त URL च्या रचनेवर आधारित आहे; ती साइट धोकादायक असल्याचा पुरावा नाही. तपासणी पूर्ण होण्यापूर्वी पेज लोड होऊ शकते.",back:"सुरक्षित पेजवर परत जा",continue:"तरीही पुढे जा",details:"तपशीलवार तपासणी पहा",incorrect:"चुकीची सूचना नोंदवा",limits:"वेबसाइटचा मजकूर, DNS, TLS किंवा थ्रेट फीड तपासलेले नाही. डोमेन अधिकृत स्रोतावरून पडताळा."},
  hinglish:{title:"PhishGuard ko URL mein risk ke strong signals mile",intro:"Yeh warning sirf URL structure par based hai; malicious hone ka proof nahi. Analysis complete hone se pehle page load hona shuru ho sakta hai.",back:"Safety par wapas jao",continue:"Phir bhi continue karo",details:"Detailed analysis dekho",incorrect:"Galat warning report karein",limits:"Site content, DNS, TLS ya threat feed check nahi hua. Domain ko official source se verify karein."}
};
function escapeHtml(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
async function render(){
  const data=await chrome.storage.session.get(`warning:${tabId}`),warning=data[`warning:${tabId}`];
  if(!warning){$('#report').textContent="Analysis unavailable or expired. Do not treat this as a safe result.";return}
  const report=warning.report,settings=await chrome.storage.local.get({apiBase:"http://127.0.0.1:8000",language:"en"}),translations=L[settings.language]||{};
  document.documentElement.lang=settings.language;
  for(const [key,value]of Object.entries(translations)){const element=document.querySelector(`[data-l10n=${key}]`);if(element)element.textContent=value}
  $('#report').innerHTML=`<b>${escapeHtml(report.risk_category)} · ${Number(report.risk_score)}/100 heuristic points</b><p>Destination: <code>${escapeHtml(report.submitted_url)}</code></p><p>Registered domain: ${escapeHtml(report.registered_domain)}</p><ul>${(report.findings||[]).map(f=>`<li><b>${escapeHtml(f.name)}</b>: ${escapeHtml(f.evidence)}</li>`).join("")}</ul><p>Analysis at ${new Date(warning.seenAt).toLocaleString()}. ML and threat intelligence are unavailable.</p>`;
  $('#back').onclick=()=>chrome.runtime.sendMessage({type:"back-to-safety",tabId});
  $('#continue').onclick=async()=>{await chrome.storage.session.set({[`allow:${tabId}`]:warning.originalUrl});await chrome.storage.session.remove(`warning:${tabId}`);chrome.tabs.update(tabId,{url:warning.originalUrl})};
  $('#incorrect').onclick=async()=>{const saved=await chrome.storage.local.get({warningFeedback:[]}),hostname=new URL(warning.originalUrl).hostname;saved.warningFeedback.unshift({hostname,at:Date.now()});await chrome.storage.local.set({warningFeedback:saved.warningFeedback.slice(0,100)});$('#feedback').textContent="Saved locally on this device. No report was sent."};
  $('#details').onclick=()=>{const dashboard=new URL(settings.apiBase);dashboard.searchParams.set("sentinel_url",report.submitted_url);dashboard.hash="investigate";chrome.tabs.create({url:dashboard.toString()})};
}
render();
