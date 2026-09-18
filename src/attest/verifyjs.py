"""Self-contained browser verifier embedded in every exported pack.

`verify.html` re-implements the whole verification path in dependency-free
JavaScript: the canonical-JSON serializer (matching ``ledger.canonical``),
SHA-256 payload hashing, and Ed25519 signature verification in raw BigInt —
no CDN, no install, works offline from ``file://``.

The JS canonicalizer parses the source document itself and copies string and
number literals *verbatim*. Packs are produced by Python's ``json.dumps``,
whose literal forms are already canonical, so a verbatim copy reproduces the
exact bytes ``ledger.canonical`` emitted — including float spellings like
``34.0`` that a ``JSON.parse``/``JSON.stringify`` round-trip would collapse
to ``34`` and break the hash.

The node smoke test (tests/test_verifyjs.py) executes the same script block
against a real signed receipt to prove the crypto, not just the packaging.
"""

_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Attest pack verifier</title>
<style>
 body{font:15px/1.5 system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#1c1c1e}
 h1{font-size:1.3rem} h2{font-size:1.05rem;margin-top:1.6rem}
 .drop{border:2px dashed #999;border-radius:10px;padding:2rem;text-align:center;color:#555}
 .drop.over{border-color:#2563eb;background:#eff6ff}
 .ok{color:#146c2e}.bad{color:#b3261e}.warn{color:#8a5a00}
 .row{display:flex;gap:.5rem;align-items:baseline}
 .row.ok::before{content:"\\2713 "}.row.bad::before{content:"\\2717 "}
 .row.warn::before{content:"\\26a0 "}
 small{color:#666}
</style>
</head>
<body>
"""

_JS_OPEN = '<script>\n"use strict";\n'

_JS_LIB = """/* ---------- canonical JSON (mirrors attest.ledger.canonical) ----------
   Parses the document keeping every string/number literal verbatim, then
   re-emits with sorted keys and no whitespace — identical bytes to
   json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=False)
   for any document Python itself serialized. */
function parseKeep(text){
  let i=0;const n=text.length;
  const ws=()=>{while(i<n&&" \\t\\n\\r".includes(text[i]))i++;};
  function literal(){const m=/^-?\\d+(\\.\\d+)?([eE][+-]?\\d+)?/.exec(text.slice(i));
    if(m){i+=m[0].length;return{t:"lit",r:m[0]};}
    if(text.startsWith("true",i)){i+=4;return{t:"lit",r:"true"};}
    if(text.startsWith("false",i)){i+=5;return{t:"lit",r:"false"};}
    if(text.startsWith("null",i)){i+=4;return{t:"lit",r:"null"};}
    throw new Error("bad literal at "+i);}
  function str(){if(text[i]!=='"')throw new Error("expected string at "+i);
    const st=i;i++;let esc=false;
    while(i<n){const c=text[i];
      if(esc){esc=false;i++;}
      else if(c==="\\\\"){esc=true;i++;}
      else if(c==='"'){i++;return{t:"lit",r:text.slice(st,i),str:JSON.parse(text.slice(st,i))};}
      else i++;}
    throw new Error("unterminated string");}
  function val(){ws();const c=text[i];
    if(c==='"')return str();
    if(c==="{"){i++;const o=[];
      ws();if(text[i]==="}"){i++;return{t:"obj",v:o};}
      for(;;){ws();const k=str();ws();
        if(text[i++]!==":")throw new Error("expected :");
        o.push([k.str,val()]);ws();
        if(text[i]==="}"){i++;return{t:"obj",v:o};}
        if(text[i++]!==",")throw new Error("expected , or }");}}
    if(c==="["){i++;const a=[];
      ws();if(text[i]==="]"){i++;return{t:"arr",v:a};}
      for(;;){a.push(val());ws();
        if(text[i]==="]"){i++;return{t:"arr",v:a};}
        if(text[i++]!==",")throw new Error("expected , or ]");}}
    return literal();}
  const v=val();ws();if(i!==n)throw new Error("trailing bytes");return v;}
function toJS(n){
  if(n.t==="lit")return n.str!==undefined?n.str:JSON.parse(n.r);
  if(n.t==="arr")return n.v.map(toJS);
  const o={};for(const[k,v]of n.v)o[k]=toJS(v);return o;}
function canonical(n){
  /* Strings re-serialize through JSON.stringify — the decoded value's canonical
     spelling — so `\u2014` and `—` in a file canonicalize identically, matching
     Python's ensure_ascii=False. Non-string literals keep the file's verbatim
     spelling (float spellings like 34.0 must survive). */
  if(n.t==="lit")return n.str!==undefined?JSON.stringify(n.str):n.r;
  if(n.t==="arr")return "["+n.v.map(canonical).join(",")+"]";
  const keys=n.v.map(([k])=>k).sort();
  const m=new Map(n.v);
  return "{"+keys.map(k=>JSON.stringify(k)+":"+canonical(m.get(k))).join(",")+"}";}
function get(node,k){return node.t==="obj"?(node.v.find(([kk])=>kk===k)||[null,null])[1]:null;}
/* ---------- hashing ---------- */
async function sha256hex(b){const d=await crypto.subtle.digest("SHA-256",b);
  return[...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,"0")).join("");}
async function sha512(b){return new Uint8Array(await crypto.subtle.digest("SHA-512",b));}
const enc=s=>new TextEncoder().encode(s);
const hex2b=h=>Uint8Array.from(h.match(/../g).map(x=>parseInt(x,16)));
const b64d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
/* ---------- Ed25519 verification (pure BigInt, RFC 8032) ---------- */
const P=(1n<<255n)-19n,L=(1n<<252n)+27742317777372353535851937790883648493n;
const mod=(a,m=P)=>((a%m)+m)%m;
function pow(a,e){let r=1n,b=mod(a);while(e){if(e&1n)r=mod(r*b);b=mod(b*b);e>>=1n;}return r;}
const D=mod(-121665n*pow(121666n,P-2n));
const I=pow(2n,(P-1n)/4n);
function le(b){let x=0n;for(let i=b.length-1;i>=0;i--)x=(x<<8n)|BigInt(b[i]);return x;}
function decodePoint(bytes){
  const y=le(bytes)&((1n<<255n)-1n),sign=bytes[31]>>7;
  if(y>=P)return null;
  const u=mod(y*y-1n),v=mod(D*y*y+1n);
  let x=mod(u*pow(v,3n)*pow(mod(u*pow(v,7n)),(P-5n)/8n));
  const vx2=()=>mod(v*x*x);
  if(vx2()!==u){if(mod(vx2()+u)===0n)x=mod(x*I);}
  if(vx2()!==u)return null;
  if(x===0n&&sign)return null;
  if((x&1n)!==BigInt(sign))x=P-x;
  return{x,y};}
const B=decodePoint(Uint8Array.from({length:32},(_,i)=>i===0?0x58:0x66));
function pAdd(p,q){
  const xx=mod(p.x*q.x),yy=mod(p.y*q.y),dxy=mod(D*xx*yy);
  const x=mod(mod(p.x*q.y+p.y*q.x)*pow(mod(1n+dxy),P-2n));
  const y=mod(mod(yy+xx)*pow(mod(1n-dxy),P-2n));
  return{x,y};}
function pMul(p,n){let r={x:0n,y:1n},b=p;while(n){if(n&1n)r=pAdd(r,b);b=pAdd(b,b);n>>=1n;}return r;}
async function edVerify(sig,pk,msg){
  if(sig.length!==64||pk.length!==32)return false;
  const R=decodePoint(sig.slice(0,32)),A=decodePoint(pk);
  if(!R||!A)return false;
  const S=le(sig.slice(32));if(S>=L)return false;
  const h=mod(le(await sha512(Uint8Array.from([...sig.slice(0,32),...pk,...msg]))),L);
  const lhs=pMul(B,S),rhs=pAdd(R,pMul(A,h));
  return lhs.x===rhs.x&&lhs.y===rhs.y;}
/* ---------- receipt + chain checks (mirrors ledger.verify_*) ---------- */
async function checkReceipt(rNode){
  const r=toJS(rNode);
  const canon=canonical(get(rNode,"payload"));
  const h=await sha256hex(enc(canon));
  if(h!==r.payload_hash)return{ok:false,why:"payload hash mismatch (payload was altered)"};
  const p=r.payload;
  if(p.sequence!==r.sequence||p.prev_hash!==r.prev_hash)
    return{ok:false,why:"envelope fields disagree with signed payload"};
  if(p.visit_id!==r.visit_id)return{ok:false,why:"visit id disagrees with signed payload"};
  if(p.schema==="attest.receipt/2"){
    if(p.receipt_id!==r.id)return{ok:false,why:"receipt id disagrees with signed payload"};
  }else if(p.schema!=="attest.receipt/1")return{ok:false,why:"unsupported receipt schema"};
  const ok=await edVerify(b64d(r.signature),b64d(r.public_key),hex2b(r.payload_hash));
  return ok?{ok:true}:{ok:false,why:"signature invalid"};}
async function checkBundle(root,key){
  /* Full parity with attest.reviews.verify_bundle: each review entry binds its
     id/visit_id to the original, revision==sequence==position, prev_hash links
     to the previous receipt, record_type is 'review', and the signed
     original_receipt anchor names this original's id + payload_hash. The
     original's own sequence is a GLOBAL chain position that legitimately
     interleaves with other receipts, so it is checked as a receipt only. */
  const oNode=get(root,"original");
  if(!oNode)return{ok:false,why:"no original receipt"};
  const original=toJS(oNode);
  if(key&&original.public_key!==key)return{ok:false,why:"original: different issuer key"};
  const c0=await checkReceipt(oNode);
  if(!c0.ok)return{ok:false,why:"original: "+c0.why};
  let prev=original.payload_hash,n=0;
  const rev=get(root,"reviews");
  const entries=rev&&rev.t==="arr"?rev.v:[];
  for(let i=0;i<entries.length;i++){
    n=i+1;
    const e=toJS(entries[i]);
    const rNode=get(entries[i],"receipt");
    if(!rNode)return{ok:false,why:`review ${n}: entry has no receipt`};
    const r=toJS(rNode);
    if(key&&r.public_key!==key)return{ok:false,why:`review ${n}: different issuer key`};
    const c=await checkReceipt(rNode);
    if(!c.ok)return{ok:false,why:`review ${n}: ${c.why}`};
    if(e.id!==r.id||e.visit_id!==original.visit_id||r.visit_id!==original.visit_id)
      return{ok:false,why:`review ${n}: identity does not match original`};
    if(e.revision!==n||r.sequence!==n||r.prev_hash!==prev)
      return{ok:false,why:`review ${n}: sequence or previous hash mismatch`};
    const p=r.payload||{},a=p.original_receipt||{};
    if(p.record_type!=="review"||a.id!==original.id||a.hash!==original.payload_hash)
      return{ok:false,why:`review ${n}: not anchored to this original`};
    prev=r.payload_hash;}
  return{ok:true,why:`original and ${n} review(s) verified (integrity only)`};}
/* ---------- timeline renderer (mirrors attest.timeline semantics) ---------- */
const _ESC={"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"};
function esc(s){return String(s).replace(/[&<>"']/g,c=>_ESC[c]);}
function timelineSVG(p){
  const iso=s=>s?Date.parse(s)/1000:null;
  const pts=[];
  const ws=p.schedule?iso(p.schedule.window_start):null,
    we=p.schedule?iso(p.schedule.window_end):null;
  if(ws)pts.push(ws,we);
  for(const e of p.evidence||[])pts.push(iso(e.at));
  const ci=iso(p.checked_in_at);if(ci)pts.push(ci);
  const cov=p.history_poll_coverage;
  for(const iv of(cov&&cov.covered)||[])pts.push(iso(iv.start),iso(iv.end));
  if(!pts.length)return"";
  let lo=Math.min.apply(null,pts),hi=Math.max.apply(null,pts);
  if(hi-lo<600){const m=(lo+hi)/2;lo=m-300;hi=m+300;}
  const pad=(hi-lo)*0.04;lo-=pad;hi+=pad;const span=hi-lo;
  const x=t=>(Math.min(Math.max((t-lo)/span,0),1)*100).toFixed(2);
  const w=(a,b)=>Math.max(0.4,x(b)-x(a)).toFixed(2);
  let s='<svg viewBox="0 0 100 34" preserveAspectRatio="none" '
    +'style="width:100%;height:64px;display:block;margin:4px 0">';
  if(ws)s+=`<rect x="${x(ws)}" y="4" width="${w(ws,we)}" height="20" rx="1.5" `
    +'fill="#3b4a63" opacity="0.55"><title>scheduled window</title></rect>';
  if(cov){
    const bands=(cov.covered||[]).map(i=>[i,true]).concat((cov.gaps||[]).map(i=>[i,false]));
    for(const[iv,watched]of bands){
      const a=iso(iv.start),b=iso(iv.end);
      const fill=watched?"#2f9e63":"#9aa3b2",
        title=watched?"watched by polling":"coverage gap — not watched";
      s+=`<rect x="${x(a)}" y="25" width="${w(a,b)}" height="3.2" `
        +`fill="${fill}"><title>${title}</title></rect>`;
    }
  }
  const KIND={arrival_motion:"motion",doorbell:"doorbell",door_opened:"door opened",
    door_closed:"door closed",activity:"activity",departure_motion:"departure cue",
    on_demand:"on-demand media",snapshot:"snapshot",late:"late-arriving event",
    checkin:"worker check-in"};
  for(const e of p.evidence||[]){
    const k=KIND[e.kind]||String(e.kind||"activity").replace(/_/g," ");
    const col=String(e.kind).indexOf("departure")===0?"#c05a5a":"#5aa2e8";
    const X=x(iso(e.at)),title=esc(k+" — "+e.at);
    s+=`<line x1="${X}" y1="8" x2="${X}" y2="24" stroke="${col}" `
      +`stroke-width="0.7"><title>${title}</title></line>`
      +`<circle cx="${X}" cy="7" r="1.1" fill="${col}"><title>${title}</title></circle>`;
  }
  if(ci){
    const X=x(ci),title=esc("worker check-in — "+p.checked_in_at);
    s+=`<line x1="${X}" y1="8" x2="${X}" y2="24" stroke="#e8b93e" `
      +`stroke-width="0.7"><title>${title}</title></line>`
      +`<circle cx="${X}" cy="7" r="1.1" fill="#e8b93e"><title>${title}</title></circle>`;
  }
  return s+"</svg>";
}
/* ---------- signed export manifest (engine.issue_export_manifest) ---------- */
function dropKey(node,k){
  if(node.t!=="obj")return node;
  return{t:"obj",v:node.v.filter(([kk])=>kk!==k)};}
async function checkManifestNode(mNode,key){
  /* A signed manifest makes the export itself a chain event: it names exactly
     which receipt hashes it carries, so a pack that drops or swaps a record
     fails here — not just on a missing file. Pre-signature packs report
     unsigned rather than failing. */
  const m=toJS(mNode);
  const sig=get(mNode,"signature_receipt");
  if(!sig)return{ok:true,why:"unsigned manifest (pre-signature pack)"};
  const c=await checkReceipt(sig);
  if(!c.ok)return{ok:false,why:"manifest signature: "+c.why};
  const js=toJS(sig);
  if(key&&js.public_key!==key)return{ok:false,why:"manifest signed by a different key"};
  const p=js.payload;
  const h=await sha256hex(enc(canonical(dropKey(mNode,"signature_receipt"))));
  if(h!==p.manifest_sha256)
    return{ok:false,why:"manifest content hash mismatch (manifest was altered)"};
  const signed=p.receipt_hashes||{};
  const listed={};for(const v of m.visits||[])listed[v.visit_id]=v.payload_hash;
  const same=Object.keys(listed).length===Object.keys(signed).length
    &&Object.keys(listed).every(k=>listed[k]===signed[k]);
  if(!same)return{ok:false,why:"manifest visit list disagrees with the signed export"};
  return{ok:true,why:`export signed: ${Object.keys(listed).length} record(s)`};}
/* ---------- shared pack helpers ---------- */
function digests(o,out=[]){
  if(Array.isArray(o))o.forEach(v=>digests(v,out));
  else if(o&&typeof o==="object"){
    if(typeof o.media_sha256==="string")out.push(o.media_sha256);
    for(const v of Object.values(o))digests(v,out);}
  return out;}
"""

_VERIFY_DRIVER = """/* ---------- pack driver ---------- */
async function verifyFiles(files){
  const byName={};for(const f of files)byName[f.name]=f;
  const out=[];const say=(c,m)=>out.push(`<div class="row ${c}">${m}</div>`);
  const text=async n=>byName[n]?await byName[n].text():null;
  const bundles=[];let mNode=null;
  const mText=await text("manifest.json");
  if(mText){
    mNode=parseKeep(mText);
    const manifest=toJS(mNode);
    say("ok",`manifest: ${manifest.visits?.length||0} visit(s)`);
    for(const v of manifest.visits||[]){
      const t=await text(`visits/${v.visit_id}/bundle.json`);
      if(!t){say("bad",`${v.visit_id}: bundle missing from selection`);continue;}
      bundles.push([v.visit_id,parseKeep(t)]);
    }
  }else{
    const t=await text("bundle.json");
    if(!t)return"<div class='row bad'>no bundle.json or manifest.json in the selected files</div>";
    const root=parseKeep(t);
    const vid=toJS(get(root,"original")||{t:"obj",v:[]}).visit_id||"visit";
    bundles.push([vid,root]);
  }
  let anyBad=false,key=null;const actual={};
  for(const[vid,root]of bundles){
    const oNode=get(root,"original");
    if(!key)key=toJS(get(oNode,"public_key"));
    const c=await checkBundle(root,key);
    if(!c.ok)anyBad=true;
    const js=toJS(root);
    actual[vid]=(js.original||{}).payload_hash;
    const stance=js.countersign_status?` — worker: ${js.countersign_status.state}`:"";
    say(c.ok?"ok":"bad",`${vid}: ${c.why}${stance}`);
    const svg=timelineSVG((js.original||{}).payload||{});
    if(svg)out.push(svg);
    const redT=await text(vid==="visit"?"redaction.json":`visits/${vid}/redaction.json`);
    const rj=redT?JSON.parse(redT):{};
    const withheld=new Set(rj.withheld_digests||rj.withheld_media_sha256||[]);
    for(const d of digests(js)){
      if(withheld.has(d)){say("warn",`  media ${d.slice(0,12)}… withheld by redaction`);continue;}
      const f=byName[`media/${d}`]||byName[`visits/${vid}/media/${d}`];
      if(!f){say("bad",`  media ${d.slice(0,12)}… missing (not listed as withheld)`);anyBad=true;continue;}
      const hh=await sha256hex(new Uint8Array(await f.arrayBuffer()));
      if(hh!==d){say("bad",`  media ${d.slice(0,12)}… digest mismatch`);anyBad=true;}
      else say("ok",`  media ${d.slice(0,12)}… digest matches`);
    }
  }
  if(mNode){
    const mc=await checkManifestNode(mNode,key);
    if(!mc.ok)anyBad=true;
    say(mc.ok?"ok":"bad",`manifest: ${mc.why}`);
    const manifest=toJS(mNode);
    for(const v of manifest.visits||[]){
      if(actual[v.visit_id]&&actual[v.visit_id]!==v.payload_hash){
        anyBad=true;
        say("bad",`${v.visit_id}: manifest hash disagrees with signed original`);
      }
    }
  }
  say(anyBad?"bad":"ok",anyBad
    ?"FAILED — do not rely on this pack"
    :"VERIFIED — chain intact under issuer key "+(key||"").slice(0,16)+"…");
  return out.join("");}
async function go(fileList){
  const files=[...fileList];if(!files.length)return;
  const out=document.getElementById("out");
  out.innerHTML="<p>verifying "+files.length+" file(s)…</p>";
  try{out.innerHTML=await verifyFiles(files);}
  catch(e){out.innerHTML="<div class='row bad'>verifier error: "+e.message+"</div>";}}
const dz=document.getElementById("drop");
dz.ondragover=e=>{e.preventDefault();dz.classList.add("over");};
dz.ondragleave=()=>dz.classList.remove("over");
dz.ondrop=e=>{e.preventDefault();dz.classList.remove("over");go(e.dataTransfer.files);};
document.getElementById("pick").onchange=e=>go(e.target.files);
"""

_VERIFY_BODY = """<h1>Attest pack verifier</h1>
<p>This page verifies an exported Attest pack <strong>in your browser</strong>. Nothing is
uploaded — all hashing and signature checks run locally, offline. Select every file from the
extracted pack, or just bundle.json for a single-visit pack.</p>
<div class="drop" id="drop">Drop pack files here, or <input type="file" id="pick" multiple></div>
<div id="out"></div>
<h2>What this does and does not establish</h2>
<p><small>A green result proves the signed records are intact and were issued under the pinned
issuer key — integrity, not physical truth. It does not prove anyone was present, absent, or
honest; it proves the evidence chain was not altered after signing. Media reported as
"withheld" was deliberately redacted, not lost.</small></p>
"""

VERIFY_HTML = _HEAD + _VERIFY_BODY + _JS_OPEN + _JS_LIB + _VERIFY_DRIVER + "</script>\n</body>\n</html>\n"

_INDEX_BODY = """<h1 id="site">Attest case record</h1>
<p id="meta" class="muted"></p>
<div id="verdict"></div>
<div id="cards"></div>
<h2>Verify the media bytes</h2>
<p><small>This page verifies every signed record and renders its timeline offline.
Signed media digests are listed per record; to check the media bytes themselves, open
<code>verify.html</code> and drop every file from this extracted pack onto it.</small></p>
<h2>What this does and does not establish</h2>
<p><small>A green result proves the signed records are intact and were issued under the pinned
issuer key — integrity, not physical truth. It does not prove anyone was present, absent, or
honest; it proves the evidence chain was not altered after signing.</small></p>
<style>
 .card{border:1px solid #ddd;border-radius:10px;padding:.8rem 1rem;margin:0 0 1rem}
 .muted{color:#666}
 .pill{display:inline-block;border-radius:99px;padding:.05rem .6rem;font-size:.8rem;
   background:#eef1f6;border:1px solid #ccd3df}
 .corr{width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.85rem}
 .corr td{border-top:1px solid #eee;padding:.15rem .4rem .15rem 0;vertical-align:top}
 .corr td:first-child{white-space:nowrap;font-weight:600;width:1%}
</style>
"""

_INDEX_DRIVER = """/* ---------- index driver: inlined pack data ---------- */
const d64=s=>new TextDecoder().decode(Uint8Array.from(atob(s),c=>c.charCodeAt(0)));
const STATE_CLS={closed:"ok",no_observation:"warn",open:"warn",unmatched:"warn"};
const hhmm=s=>s?String(s).slice(11,16):"";
/* corroboration table — mirrors attest.corroborate semantics: each row says
   what a source reported and what it establishes; silence is labelled. */
function corroborationHTML(p){
  const ev=p.evidence||[],site=p.site||{},cov=p.history_poll_coverage||{};
  const cam=ev.filter(e=>e.device===site.door_camera_id);
  const sen=ev.filter(e=>site.door_sensor_id&&e.device===site.door_sensor_id);
  const snaps=ev.filter(e=>e.media_sha256);
  const hist=p.ring_history||[];
  const span=es=>es.length?hhmm(es[0].at)+"–"+hhmm(es[es.length-1].at)+" UTC":"";
  const COV={observed:"fully watched",observed_with_events:"watched — events seen",
    partial:"partially watched",blind:"blind — polls failed",no_polls:"not polled"};
  const rows=[
    ["Scheduled expectation",p.schedule
      ?hhmm(p.schedule.window_start)+"–"+hhmm(p.schedule.window_end):"unscheduled",
      "What was planned — never what happened"],
    ["Camera/doorbell",cam.length?cam.length+" event(s) "+span(cam):"silent",
      "Device-observed activity timestamps only"],
    ["Contact sensor",!site.door_sensor_id?"not bound"
      :sen.length?sen.length+" event(s) "+span(sen):"silent",
      "Open/close transitions at the door"],
    ["Worker self-report",p.checked_in_at?"check-in "+hhmm(p.checked_in_at):"none received",
      "The worker's account — a claim, not verification"],
    ["Media on record",snaps.length+" snapshot(s)",
      snaps.length?"sha256 digests signed in receipt":"Bytes received at fetch time, hashed at ingest"],
    ["Ring Event History",hist.length?hist.length+" corroborating entries":"none in payload",
      "Ring-side record independent of delivery path"],
    ["Pipeline coverage",(COV[cov.state]||"not polled")
      +(cov.fraction!=null?" · "+Math.round(cov.fraction*100)+"%":""),
      "How much silence is meaningful vs. unwatched"],
  ];
  if(p.checked_in_at&&cam.length){
    const d=(new Date(p.checked_in_at)-new Date(cam[0].at))/60000;
    if(Math.abs(d)>=10)rows.push(["Source divergence",Math.round(Math.abs(d))+" min apart",
      "first device observation vs. worker check-in — neither source is authoritative"]);
  }
  return '<table class="corr">'+rows.map(r=>
    `<tr><td>${esc(r[0])}</td><td>${esc(r[1])}</td><td class="muted"><small>${esc(r[2])}</small></td></tr>`
  ).join("")+"</table>";
}
async function renderIndex(){
  const meta=JSON.parse(d64(document.getElementById("packmeta").textContent));
  document.getElementById("site").textContent=
    "Attest case record — "+(meta.site&&meta.site.name||meta.site_id||"site");
  document.getElementById("meta").textContent=
    "Generated "+meta.generated_at+" · issuer key "+String(meta.issuer_key||"").slice(0,16)+"…";
  const cards=document.getElementById("cards");
  const verdict=document.getElementById("verdict");
  let key=null,anyBad=false,n=0,declared=0;
  const rows=[];const actual={};
  for(const tag of document.querySelectorAll("script.bundle")){
    const root=parseKeep(d64(tag.textContent));
    const js=toJS(root);
    const oNode=get(root,"original");
    if(!key)key=toJS(get(oNode,"public_key"));
    const c=await checkBundle(root,key);
    if(!c.ok)anyBad=true;
    n++;
    actual[tag.dataset.vid]=(js.original||{}).payload_hash;
    const p=(js.original||{}).payload||{};
    const stance=js.countersign_status?js.countersign_status.state:null;
    const ds=digests(js);declared+=ds.length;
    const cls=c.ok?(STATE_CLS[p.state]||"ok"):"bad";
    const win=p.schedule
      ?esc(p.schedule.window_start||"")+" → "+esc(p.schedule.window_end||"")
      :"unscheduled";
    rows.push(
      `<div class="card"><div class="row ${cls}">`
      +`<span class="pill">${esc(p.state||"?")}</span> `
      +`<strong>${esc(tag.dataset.vid)}</strong>`
      +(p.scheduled_worker?` · worker ${esc(p.scheduled_worker.name||"")}`:"")
      +(stance?` · statement: ${esc(stance)}`:"")
      +` — ${c.why}</div>`
      +`<small>${win} · ${ds.length} media digest(s)</small>`
      +timelineSVG(p)+corroborationHTML(p)+"</div>");
  }
  cards.innerHTML=rows.join("");
  let mLine="";
  const mtag=document.getElementById("packmanifest");
  if(mtag){
    const mNode=parseKeep(d64(mtag.textContent));
    const mc=await checkManifestNode(mNode,key);
    if(!mc.ok)anyBad=true;
    mLine=`<div class="row ${mc.ok?"ok":"bad"}">manifest: ${mc.why}</div>`;
    for(const v of toJS(mNode).visits||[]){
      if(actual[v.visit_id]&&actual[v.visit_id]!==v.payload_hash){
        anyBad=true;
        mLine+=`<div class="row bad">${esc(v.visit_id)}: manifest hash disagrees with signed original</div>`;
      }
    }
  }
  verdict.innerHTML=anyBad
    ?'<div class="row bad">FAILED — '+n
     +" record(s), at least one does not verify. Do not rely on this pack.</div>"+mLine
    :`<div class="row ok">VERIFIED — ${n} record(s), chains intact under issuer key `
     +String(key||"").slice(0,16)+"…</div>"+mLine
     +`<small>${declared} declared media digest(s)`
     +(meta.media_redacted?" — media withheld by redaction; signed digests preserved":"")+"</small>";
}
renderIndex().catch(e=>{
  document.getElementById("verdict").innerHTML=
    "<div class='row bad'>index error: "+e.message+"</div>";});
"""


def case_index_html(meta: dict, bundles: list[tuple[str, str]], manifest_text: str = "") -> str:
    """Self-contained offline case browser embedded in case packs.

    Each visit's bundle.json text is inlined base64-encoded — immune to
    ``</script>`` breakout inside signed statement text and decoded back to the
    exact bytes, so ``parseKeep`` still canonicalizes the original literal
    spellings. ``meta`` (site, generated_at, issuer_key) and the raw
    ``manifest.json`` text — so the signed export receipt is verified too —
    are inlined the same way. Everything else — Ed25519, canonicalization,
    the timeline — is the shared ``_JS_LIB``, so the browser *is* the verifier.
    """
    import base64
    import json as _json

    enc = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731
    tags = "".join(f'<script class="bundle" data-vid="{vid}">{enc(text)}</script>\n' for vid, text in bundles)
    meta_tag = f'<script id="packmeta">{enc(_json.dumps(meta))}</script>\n'
    if manifest_text:
        meta_tag += f'<script id="packmanifest">{enc(manifest_text)}</script>\n'
    return (
        _HEAD.replace("<title>Attest pack verifier</title>", "<title>Attest case record</title>")
        + _INDEX_BODY
        + meta_tag
        + tags
        + _JS_OPEN
        + _JS_LIB
        + _INDEX_DRIVER
        + "</script>\n</body>\n</html>\n"
    )


if __name__ == "__main__":  # pragma: no cover - developer tool
    import sys

    sys.stdout.write(VERIFY_HTML)
