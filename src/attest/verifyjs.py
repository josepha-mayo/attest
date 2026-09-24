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
<meta name="viewport" content="width=device-width,initial-scale=1">
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
  /* Duplicate keys: last wins — same as toJS/JSON.parse — and keys sort by
     codepoint (Python order), not UTF-16 units: astral chars would differ. */
  const m=new Map(n.v);
  const keys=[...m.keys()].sort((a,b)=>{
    const A=[...a],B=[...b];
    for(let i=0;;i++){
      const x=i<A.length?A[i].codePointAt(0):undefined;
      const y=i<B.length?B[i].codePointAt(0):undefined;
      if(x===undefined&&y===undefined)return 0;
      if(x===undefined)return-1;
      if(y===undefined)return 1;
      if(x!==y)return x-y;}});
  return "{"+keys.map(k=>JSON.stringify(k)+":"+canonical(m.get(k))).join(",")+"}";}
function get(node,k){
  /* Duplicate keys: last wins — matching toJS/canonical/JSON.parse so the
     value hashed is always the value semantically checked. */
  if(node.t!=="obj")return null;
  let hit=null;for(const[kk,vv]of node.v)if(kk===k)hit=vv;return hit;}
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
    /* issued_at serializes as "...Z" in the envelope but "+00:00" in the
       signed payload — compare parsed instants, mirroring the embedded
       Python verifier (ledger uses exact strings on in-model objects). */
    const sameInstant=Date.parse(p.issued_at||"")===Date.parse(r.issued_at||"");
    if(p.receipt_id!==r.id||!sameInstant)
      return{ok:false,why:"receipt envelope identity disagrees with signed payload"};
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
  /* ReviewBundle is extra="forbid" — honest files carry exactly kind,
     original, reviews. Any other top-level key (e.g. a forged
     countersign_status) is unsigned attacker content: fail, don't render it. */
  const kd=toJS(get(root,"kind")||{t:"lit",str:null});
  if(kd!=="attest.review_bundle/1")return{ok:false,why:"unrecognized bundle kind"};
  const KNOWN=new Set(["kind","original","reviews"]);
  for(const[k]of root.v)if(!KNOWN.has(k))
    return{ok:false,why:"unsigned extra field in bundle: "+JSON.stringify(k)};
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
function deriveStance(js){
  /* Derive the worker stance from the SIGNED review chain — mirrors
     countersign_status(). A file-level countersign_status field is unsigned
     and ignored: ReviewBundle serializes only kind/original/reviews, so that
     field can only exist in a forged pack (checkBundle now rejects it). */
  const ST={confirm:"acknowledged",dispute:"contested",correction:"corrected",inconclusive:"inconclusive"};
  let lastWorker=null,lastRes=null;
  for(const e of js.reviews||[]){
    const p=((e||{}).receipt||{}).payload||{};
    if((p.actor||{}).role==="worker")lastWorker=e;
    if((p.review||{}).kind==="resolution")lastRes=e;
  }
  let state="no_statement";
  if(lastWorker)state=ST[(lastWorker.receipt.payload.review||{}).decision]||"reviewed";
  if(lastRes&&lastRes.revision>(lastWorker?lastWorker.revision:0))state="resolved";
  return state;}
"""

_VERIFY_DRIVER = """/* ---------- pack driver ---------- */
async function verifyFiles(files){
  const byName={};for(const f of files)byName[f.name]=f;
  const out=[];const say=(c,m)=>out.push(`<div class="row ${c}">${m}</div>`);
  const text=async n=>byName[n]?await byName[n].text():null;
  const bundles=[];let mNode=null,manifest=null;
  let anyBad=false,key=null;const actual={};
  const mText=await text("manifest.json");
  if(mText){
    mNode=parseKeep(mText);
    manifest=toJS(mNode);
    /* Structural claims on the manifest itself — unsigned manifests have no
       hash-cover over these fields, so check them explicitly (the server-side
       verifier requires both). */
    if(manifest.schema!=="attest.case-pack/1"){
      anyBad=true;
      say("bad",`manifest: unsupported schema ${esc(String(manifest.schema||"?"))}`);
    }
    say("ok",`manifest: ${esc(String(Number(manifest.visits?.length)||0))} visit(s)`);
    for(const v of manifest.visits||[]){
      const t=await text(`visits/${v.visit_id}/bundle.json`);
      /* A manifest-listed bundle absent from the zip fails closed — the row is
         red AND the verdict fails; anything less fails open on a dropped record. */
      if(!t){anyBad=true;say("bad",`${esc(v.visit_id)}: bundle listed but missing from pack`);continue;}
      bundles.push([v.visit_id,parseKeep(t)]);
    }
  }else{
    const t=await text("bundle.json");
    if(!t)return"<div class='row bad'>no bundle.json or manifest.json in the selected files</div>";
    const root=parseKeep(t);
    const vid=toJS(get(root,"original")||{t:"obj",v:[]}).visit_id||"visit";
    bundles.push([vid,root]);
  }
  for(const[vid,root]of bundles){
    const oNode=get(root,"original");
    if(!key)key=toJS(get(oNode,"public_key"));
    const c=await checkBundle(root,key);
    if(!c.ok)anyBad=true;
    const js=toJS(root);
    actual[vid]=(js.original||{}).payload_hash;
    /* Stance derives from the verified review chain — a countersign_status
       field in the file is unsigned forgery bait and is never consulted. */
    const st=deriveStance(js);
    const stance=st!=="no_statement"?` — worker: ${esc(st)}`:"";
    say(c.ok?"ok":"bad",`${esc(vid)}: ${esc(c.why)}${stance}`);
    const svg=timelineSVG((js.original||{}).payload||{});
    if(svg)out.push(svg);
    const redT=await text(mNode?`visits/${vid}/redaction.json`:"redaction.json");
    const rj=redT?JSON.parse(redT):{};
    /* Python's redaction_for recognizes only withheld_digests — the browser
       must be at least as strict, so no alias fallback here. */
    const withheld=new Set(rj.withheld_digests||[]);
    /* The marker file is unsigned — the signed manifest's media_withheld list
       is the authority. If they disagree, a "withheld" claim may be masking a
       deletion: fail closed, mirroring _verify_case_pack. */
    if(manifest){
      const mv=(manifest.visits||[]).find(x=>x.visit_id===vid);
      const listed=new Set((mv&&mv.media_withheld)||[]);
      if(listed.size!==withheld.size||[...listed].some(d=>!withheld.has(d))){
        anyBad=true;
        say("bad",`${esc(vid)}: manifest redaction list disagrees with redaction.json`);
      }
    }
    /* Media is matched by CONTENT hash, not filename — the pack stores files as
       media/<vid>/<label>.<digest-prefix>.png, mirroring _check_pack_bundle.
       Case packs nest under visits/<vid>/; single packs use media/ flat.
       Digests come only from the signed original payload — unsigned extra
       keys must not be able to inject "verified" media rows. */
    const mprefix=mNode?`visits/${vid}/media/`:"media/";
    const found=new Set();
    for(const name of Object.keys(byName)){
      if(name.startsWith(mprefix)&&!name.endsWith("/"))
        found.add(await sha256hex(new Uint8Array(await byName[name].arrayBuffer())));
    }
    for(const d of digests((js.original||{}).payload||{})){
      if(withheld.has(d)){say("warn",`  media ${esc(d.slice(0,12))}… withheld by redaction`);continue;}
      if(found.has(d))say("ok",`  media ${esc(d.slice(0,12))}… digest matches`);
      else{say("bad",`  media ${esc(d.slice(0,12))}… missing (not listed as withheld)`);anyBad=true;}
    }
  }
  if(mNode){
    const mc=await checkManifestNode(mNode,key);
    if(!mc.ok)anyBad=true;
    say(mc.ok?"ok":"bad",`manifest: ${esc(mc.why)}`);
    if(!manifest.issuer_key){
      anyBad=true;
      say("bad","manifest: missing issuer_key");
    }else if(key&&manifest.issuer_key!==key){
      anyBad=true;
      say("bad","manifest: issuer_key disagrees with the bundles' issuer");
    }
    for(const v of manifest.visits||[]){
      if(actual[v.visit_id]&&actual[v.visit_id]!==v.payload_hash){
        anyBad=true;
        say("bad",`${esc(v.visit_id)}: manifest hash disagrees with signed original`);
      }
    }
    /* Site attestations (coverage certs, digests, prior exports, disconnects)
       travel in the pack — each must verify and match the manifest entry. */
    for(const a of manifest.attestations||[]){
      const at=await text(`attestations/${a.receipt_id}.json`);
      if(!at){anyBad=true;say("bad",`attestation ${esc(a.receipt_id)}: missing from pack`);continue;}
      const aNode=parseKeep(at);const rjs=toJS(aNode);
      if(key&&rjs.public_key!==key){
        anyBad=true;say("bad",`attestation ${esc(a.receipt_id)}: different issuer key`);continue;}
      const rc=await checkReceipt(aNode);
      if(!rc.ok){anyBad=true;say("bad",`attestation ${esc(a.receipt_id)}: ${esc(rc.why)}`);continue;}
      if(rjs.payload_hash!==a.payload_hash||rjs.visit_id!==a.visit_id){
        anyBad=true;say("bad",`attestation ${esc(a.receipt_id)}: disagrees with signed manifest`);continue;}
      say("ok",`attestation ${esc(a.record_type||"record")}: signed and intact`);
    }
    /* Fail closed on pack files the signed manifest does not name — a smuggled
       attestation or visit bundle would otherwise pass unverified. */
    const listedAtts=new Set((manifest.attestations||[]).map(a=>`attestations/${a.receipt_id}.json`));
    const listedVids=new Set((manifest.visits||[]).map(v=>`visits/${v.visit_id}/`));
    for(const name of Object.keys(byName)){
      if(name.endsWith("/"))continue;
      if(name.startsWith("attestations/")&&!listedAtts.has(name)){
        anyBad=true;say("bad",`${esc(name)}: present but not in the signed manifest`);
      }
      if(name.startsWith("visits/")&&![...listedVids].some(p=>name.startsWith(p))){
        anyBad=true;say("bad",`${esc(name)}: present but not in the signed manifest`);
      }
    }
  }
  say(anyBad?"bad":"ok",anyBad
    ?"FAILED — do not rely on this pack"
    :"VERIFIED — chain intact under issuer key "+esc((key||"").slice(0,16))+"…");
  return out.join("");}
/* ---------- minimal zip reader: stored + deflate via DecompressionStream ---------- */
async function inflate(raw){
  const ds=new DecompressionStream("deflate-raw");
  const reader=new Blob([raw]).stream().pipeThrough(ds).getReader();
  /* Declared sizes can lie — cap actual decompressed bytes while streaming. */
  const chunks=[];let total=0;
  for(;;){
    const{done,value}=await reader.read();
    if(done)break;
    total+=value.length;
    if(total>256*1024*1024){reader.cancel();throw new Error("entry expands beyond the 256 MB bound");}
    chunks.push(value);
  }
  const out=new Uint8Array(total);let o=0;
  for(const c of chunks){out.set(c,o);o+=c.length;}
  return out;}
async function readZipEntries(file){
  /* Parse the EOCD + central directory; returns File-like {name,text,arrayBuffer}. */
  const buf=new Uint8Array(await file.arrayBuffer());
  const dv=new DataView(buf.buffer);
  let eocd=-1;
  for(let i=buf.length-22;i>=Math.max(0,buf.length-22-65536);i--){
    if(dv.getUint32(i,true)===0x06054b50){eocd=i;break;}
  }
  if(eocd<0)throw new Error("not a zip file (no end-of-central-directory)");
  const n=dv.getUint16(eocd+10,true),cdOff=dv.getUint32(eocd+16,true);
  const dec=new TextDecoder();let p=cdOff;const files=[];
  let totalUncompressed=0;
  for(let e=0;e<n;e++){
    if(dv.getUint32(p,true)!==0x02014b50)throw new Error("corrupt central directory");
    const method=dv.getUint16(p+10,true),csize=dv.getUint32(p+20,true);
    const usize=dv.getUint32(p+24,true);
    /* Bound total decompressed bytes — a small zip can expand unboundedly. */
    totalUncompressed+=usize;
    if(totalUncompressed>256*1024*1024)
      throw new Error("pack expands beyond the 256 MB verification bound");
    const nlen=dv.getUint16(p+28,true),elen=dv.getUint16(p+30,true),clen=dv.getUint16(p+32,true);
    const lhoff=dv.getUint32(p+42,true);
    const name=dec.decode(buf.slice(p+46,p+46+nlen));
    const lnlen=dv.getUint16(lhoff+26,true),lelen=dv.getUint16(lhoff+28,true);
    const start=lhoff+30+lnlen+lelen;
    const raw=buf.slice(start,start+csize);
    let data;
    if(method===0)data=raw;
    else if(method===8)data=await inflate(raw);
    else continue;  // unsupported compression — skip, the verifier reports it missing
    files.push({name,
      arrayBuffer:async()=>data.buffer.slice(data.byteOffset,data.byteOffset+data.byteLength),
      text:async()=>dec.decode(data)});
    p+=46+nlen+elen+clen;
  }
  return files;}
async function go(fileList){
  const out=document.getElementById("out");
  try{
    let files=[...fileList];if(!files.length)return;
    if(files.length===1&&/\\.zip$/i.test(files[0].name))files=await readZipEntries(files[0]);
    else files=files.map(f=>{
      /* A folder pick (webkitdirectory) yields webkitRelativePath like
         'pack/visits/vis_x/bundle.json' — strip the root segment so paths match
         the zip layout. Plain multi-select has no relative path: keep the
         basename (works for a single-visit pack's flat bundle.json). */
      const rel=f.webkitRelativePath||"";
      const stripped=rel.includes("/")?rel.split("/").slice(1).join("/"):"";
      return{name:stripped||f.name,text:()=>f.text(),arrayBuffer:()=>f.arrayBuffer()};
    });
    out.innerHTML="<p>verifying "+files.length+" file(s)…</p>";
    out.innerHTML=await verifyFiles(files);
  }catch(e){out.innerHTML="<div class='row bad'>verifier error: "+esc(e.message)+"</div>";}}
const dz=document.getElementById("drop");
dz.ondragover=e=>{e.preventDefault();dz.classList.add("over");};
dz.ondragleave=()=>dz.classList.remove("over");
dz.ondrop=e=>{e.preventDefault();dz.classList.remove("over");go(e.dataTransfer.files);};
document.getElementById("pick").onchange=e=>go(e.target.files);
document.getElementById("pickdir").onchange=e=>go(e.target.files);
"""

_VERIFY_BODY = """<h1>Attest pack verifier</h1>
<p>This page verifies an exported Attest pack <strong>in your browser</strong>. Nothing is
uploaded — all hashing and signature checks run locally, offline. Drop the
<strong>.zip pack itself</strong>, select every extracted file, or just bundle.json for a
single-visit pack.</p>
<div class="drop" id="drop">Drop the pack .zip here, or
pick files: <input type="file" id="pick" multiple aria-label="Choose pack files">
or the extracted folder: <input type="file" id="pickdir" webkitdirectory
aria-label="Choose the extracted pack folder"></div>
<div id="out" role="status" aria-live="polite"></div>
<h2>What this does and does not establish</h2>
<p><small>A green result proves the signed records are intact and were issued under the pinned
issuer key — integrity, not physical truth. It does not prove anyone was present, absent, or
honest; it proves the evidence chain was not altered after signing. Media reported as
"withheld" was deliberately redacted, not lost.</small></p>
<p><small><strong>Trust note:</strong> this verifier file traveled inside the pack it is
checking. For a dispute that matters, re-verify with a verifier obtained independently —
the deployment's <code>/verify-pack</code> page, <code>verify_case.py</code> pinned from
the issuing deployment, or the operator's hosted verifier — never trust only the copy a
pack carries about itself.</small></p>
"""

VERIFY_HTML = _HEAD + _VERIFY_BODY + _JS_OPEN + _JS_LIB + _VERIFY_DRIVER + "</script>\n</body>\n</html>\n"

_INDEX_BODY = """<h1 id="site">Attest case record</h1>
<p id="meta" class="muted"></p>
<div id="verdict" role="status" aria-live="polite"></div>
<div id="cards"></div>
<h2>Verify the media bytes</h2>
<p><small>This page verifies every signed record and renders its timeline offline — and every
record can be toggled between the technical view and the plain-language family view
(&ldquo;View as the family sees it&rdquo;). Signed media digests are listed per record;
to check the media bytes themselves, open <code>verify.html</code> and drop every file
from this extracted pack onto it.</small></p>
<h2>What this does and does not establish</h2>
<p><small>A green result proves the signed records are intact and were issued under the pinned
issuer key — integrity, not physical truth. It does not prove anyone was present, absent, or
honest; it proves the evidence chain was not altered after signing.</small></p>
<p><small><strong>Trust note:</strong> this page traveled inside the pack it checks —
for a dispute that matters, re-verify the pack with a verifier obtained independently
(the deployment's <code>/verify-pack</code> or a pinned <code>verify_case.py</code>).</small></p>
<style>
 .card{border:1px solid #ddd;border-radius:10px;padding:.8rem 1rem;margin:0 0 1rem}
 .muted{color:#666}
 .pill{display:inline-block;border-radius:99px;padding:.05rem .6rem;font-size:.8rem;
   background:#eef1f6;border:1px solid #ccd3df}
 .corr{width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.85rem}
 .corr td{border-top:1px solid #eee;padding:.15rem .4rem .15rem 0;vertical-align:top}
 .corr td:first-child{white-space:nowrap;font-weight:600;width:1%}
 .stmt{border-left:3px solid #ccd3df;padding:.15rem .6rem;margin:.4rem 0;font-size:.85rem}
 .plain-hero{text-align:center;padding:1.2rem .5rem .8rem}
 .plain-mark{width:52px;height:52px;border-radius:50%;display:inline-flex;align-items:center;
   justify-content:center;font-size:26px;margin-bottom:.5rem}
 .plain-hero.ok .plain-mark{background:#e2f4ea;color:#1a7f4b}
 .plain-hero.warn .plain-mark{background:#f9edd4;color:#b4740c}
 .plain-hero.quiet .plain-mark{background:#e9eef3;color:#5f6e7c}
 .plain-h2{font-size:1.2rem;font-weight:600;line-height:1.3;margin-bottom:.3rem}
 .plain-p{color:#5c6b7a;font-size:.9rem}
 .plain-facts{border-collapse:collapse;margin:.8rem 0;font-size:.9rem}
 .plain-facts td{padding:.25rem .8rem .25rem 0;vertical-align:top;border-bottom:1px solid #eef1f6}
 .plain-facts td.k{color:#5c6b7a;white-space:nowrap}
 .plain-quote{border-left:3px solid #b4740c;padding:.3rem .8rem;margin:.5rem 0;
  font-style:italic;color:#4a3d28}
 .plain-quote.household{border-left-color:#2563a8;color:#26374a}
 .plain-byline{color:#5f6e7c;font-size:.8rem}
 .plain-foot{margin-top:1rem;color:#5f6e7c;font-size:.8rem;line-height:1.5;
  border-top:1px solid #eee;padding-top:.7rem}
 .view-toggle{display:inline-block;margin-top:.6rem;color:#2563a8;text-decoration:underline;cursor:pointer}
 .week-row{display:flex;align-items:center;gap:.6rem;margin:1px 0}
 .week-label{width:6.5em;text-align:right;flex:none}
 .week-strip{flex:1;min-width:0}
 .week-legend{margin-bottom:.4rem;line-height:1.9}
 .sw{display:inline-block;width:.9em;height:.7em;border-radius:2px;vertical-align:-1px;margin-left:.6em}
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
/* signed statements — worker/coordinator words from the review chain,
   verbatim with actor + honesty markers. */
function statementsHTML(js){
  const out=[];
  for(const e of js.reviews||[]){
    const p=((e||{}).receipt||{}).payload||{};
    const a=p.actor||{},rv=p.review||{};
    if(!rv.decision&&!rv.outcome&&!rv.statement)continue;
    const who=a.name?`${esc(a.name)} (${esc(a.role||"reviewer")})`:esc(a.role||"reviewer");
    const note=a.identity_verified===false?" — identity not independently verified":"";
    const window=rv.reported_start
      ?` <small class="muted">reports ${esc(hhmm(rv.reported_start))}–`
        +`${esc(hhmm(rv.reported_end))}</small>`:"";
    const label=rv.kind==="resolution"
      ?`resolution: ${String(rv.outcome||"").replaceAll("_"," ")}`
      :rv.kind==="household_account"
      ?`household account: ${String(rv.perception||"").replaceAll("_"," ")}`
      :(rv.decision||"statement");
    out.push(`<div class="stmt"><strong>${esc(label)}</strong> by ${who}${note}:`
      +` ${esc(rv.statement||"")}`+window+`</div>`);
  }
  return out.join("");
}
/* Plain-language view of the same verified payload — the family-facing read,
   mirroring /household on the server. The pack carries the data; this renders
   it for someone who has never seen a coordinator console. */
function plainHTML(p,js){
  const cov=p.history_poll_coverage||{},st=String(p.state||"");
  /* Schema-tolerant reads: receipts signed before the first_observed_at/
     scheduled_worker fields existed carry arrived_at/departed_at/worker
     instead — an old pack must render the same honest story. */
  const obsA=p.first_observed_at||p.arrived_at||null;
  const obsB=p.last_observed_at||p.departed_at||obsA;
  const span=p.observed_span_minutes!=null?p.observed_span_minutes:p.duration_minutes;
  const hasObs=!!obsA;
  const reviews=js.reviews||[];
  const workerEntries=reviews.filter(e=>((((e||{}).receipt||{}).payload||{}).actor||{}).role==="worker");
  const resEntries=reviews.filter(e=>((((e||{}).receipt||{}).payload||{}).review||{}).kind==="resolution");
  const stance=deriveStance(js);
  let hero;
  if(st==="open"||st==="in_progress")
    hero=["&#9202;","This visit is still in progress",
      "This record hasn't been closed and signed yet — shown is what has been received so far.","quiet"];
  else if(st==="unmatched")
    hero=["&#9888;","Activity was recorded outside any scheduled visit",
      "The camera reported activity that doesn't match a scheduled window —"
      +" flagged for a person to review.","warn"];
  else if(!hasObs){
    let line;
    if(cov.fraction!=null&&cov.fraction>=0.999)
      line=`The camera was checked ${esc(String(Number(cov.polls)||0))} times`
        +" across the whole window and reported nothing.";
    else if(cov.polls)
      line=`The camera was checked for ${Math.round((cov.fraction||0)*100)}%`
        +" of the window and reported nothing"
        +((cov.gaps||[]).length?" — some of the window wasn't watched":"")+".";
    else line="The camera reported no activity during this window.";
    hero=["&#9675;","No activity was reported",
      line+" No activity is not proof nobody came — it only means the camera reported nothing.","quiet"];
  }else
    hero=["&#10003;","Activity was observed",
      `The camera reported activity between ${esc(hhmm(obsA))}`
      +` and ${esc(hhmm(obsB))}`
      +(span!=null?` — about ${Math.round(span)} minutes of observed span`:"")
      +".","ok"];
  const facts=[];
  if(hasObs){
    facts.push(["First observation",esc(hhmm(obsA))]);
    facts.push(["Last observation",esc(hhmm(obsB))]);}
  const sw=p.scheduled_worker||(p.worker?{name:p.worker}:null);
  if(sw&&sw.name)facts.push(["Scheduled worker",esc(sw.name)]);
  if(p.checked_in_at)
    facts.push(["Worker check-in",
      esc(hhmm(p.checked_in_at))
      +" — self-reported from their link; identity isn't verified by the check-in itself."]);
  else if(sw)facts.push(["Worker check-in","Not received"]);
  if(stance!=="no_statement"){
    const label={acknowledged:"Agrees with this record",contested:"<strong>Disputes this record</strong>",
      corrected:"Submitted a correction",resolved:"Concluded by a coordinator",
      inconclusive:"Responded inconclusively"}[stance]||"Recorded";
    facts.push(["Worker's account",label]);}
  if(resEntries.length){
    const lp=resEntries[resEntries.length-1].receipt.payload;
    facts.push(["Conclusion",
      esc(String((lp.review||{}).outcome||"").replaceAll("_"," "))
      +" — signed by the coordinator. The worker's statement stays in the record unchanged."]);}
  let quote="";
  if(workerEntries.length&&(stance==="contested"||stance==="corrected"||stance==="inconclusive")){
    const lw=workerEntries[workerEntries.length-1].receipt.payload;
    quote=`<div class="plain-quote">&ldquo;${esc((lw.review||{}).statement||"")}&rdquo;</div>`
      +`<div class="plain-byline">— ${esc((lw.actor||{}).name||"worker")},`
      +` appended to the signed record (never edited after)</div>`;
  }else if(workerEntries.length&&stance==="resolved"){
    const lw=workerEntries[workerEntries.length-1].receipt.payload;
    quote=`<div class="plain-quote">&ldquo;${esc((lw.review||{}).statement||"")}&rdquo;</div>`
      +`<div class="plain-byline">— ${esc((lw.actor||{}).name||"worker")}; concluded, kept on record</div>`;
  }
  const hhEntries=reviews.filter(e=>((((e||{}).receipt||{}).payload||{}).actor||{}).role==="household");
  for(const he of hhEntries){
    const hp=he.receipt.payload,hrv=hp.review||{};
    quote+=`<div class="plain-quote household">&ldquo;${esc(hrv.statement||"")}&rdquo;</div>`
      +`<div class="plain-byline">— household account`
      +(hrv.perception?` (${String(hrv.perception).replaceAll("_"," ")})`:"")
      +` via the family link — self-reported; it doesn't change the camera's`
      +` observations or the worker's account</div>`;
  }
  return `<div class="plain-hero ${hero[3]}"><div class="plain-mark" aria-hidden="true">${hero[0]}</div>`
    +`<div class="plain-h2">${esc(hero[1])}</div><div class="plain-p">${hero[2]}</div></div>`
    +`<table class="plain-facts">${facts.map(f=>
      `<tr><td class="k">${esc(f[0])}</td><td>${f[1]}</td></tr>`).join("")}</table>`
    +quote
    +`<div class="plain-foot">The camera's report, the schedule, the worker's account, and the household's
    account are kept separate.
    A signature proves the record hasn't been altered since it was signed — not identity, attendance, or
    time worked. No reported activity is not proof nobody came.</div>`;
}
/* ---------- site-level week strip: the whole exported window at a glance.
   Every mark derives from verified signed payloads only — the strip can show
   what the receipts attest (coverage, interruptions, observations, the
   worker's self-reported check-in), never anything more. */
function weekSVG(payloads){
  const iso=s=>s?Date.parse(s)/1000:null;
  const DAY=86400,days={};
  const key=t=>new Date(t*1000).toISOString().slice(0,10);
  const slot=(t,k,v)=>{
    const dk=key(t);
    (days[dk]||(days[dk]={sched:[],cov:[],gap:[],intr:[],ev:[],live:[]}))[k].push(v);};
  const eachDay=(a,b,fn)=>{ /* clip an interval to each UTC day it overlaps */
    if(!(a<b))return;
    for(let d=Math.floor(a/DAY)*DAY;d<b;d+=DAY){
      const ca=Math.max(a,d),cb=Math.min(b,d+DAY);
      if(ca<cb)fn(d,ca,cb);}};
  for(const p of payloads){
    const cov=p.history_poll_coverage||{};
    if(p.schedule&&p.schedule.window_start)
      eachDay(iso(p.schedule.window_start),iso(p.schedule.window_end||p.schedule.window_start),
        (d,a,b)=>slot(a,"sched",[a,b]));
    for(const iv of cov.covered||[])
      eachDay(iso(iv.start),iso(iv.end),(d,a,b)=>slot(a,"cov",[a,b]));
    for(const g of cov.gaps||[])
      eachDay(iso(g.start),iso(g.end),(d,a,b)=>slot(a,"gap",[a,b,g.explained_by||null]));
    for(const it of cov.interruptions||[]){const t=iso(it.at);if(t)slot(t,"intr",it);}
    for(const s of cov.live_sessions||[]){
      const a=iso(s.opened_at),b=s.closed_at?iso(s.closed_at):null;
      if(!a)continue;
      if(b&&b>a)eachDay(a,b,(d,ca,cb)=>slot(ca,"live",[ca,cb,s.device_id,false]));
      else slot(a,"live",[a,null,s.device_id,true]); /* open or zero-length: a point mark */}
    for(const e of p.evidence||[]){const t=iso(e.at);if(t)slot(t,"ev",e);}
    const ci=iso(p.checked_in_at);
    if(ci)slot(ci,"ev",{kind:"checkin",at:p.checked_in_at});
  }
  const keys=Object.keys(days).sort();
  if(!keys.length)return"";
  const WD=["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
  const x=(d,t)=>((t-d)/DAY*100).toFixed(2);
  const w=(d,a,b)=>Math.max(0.35,x(d,b)-x(d,a)).toFixed(2);
  let html='<div class="week"><div class="week-legend muted"><small>UTC days:'
    +' <span class="sw" style="background:#3b4a63"></span>scheduled window'
    +' <span class="sw" style="background:#2f9e63"></span>watched by polling'
    +' <span class="sw" style="background:#9aa3b2"></span>unwatched gap'
    +' <span class="sw" style="background:#d97706"></span>gap with a signed channel interruption'
    +' <span class="sw" style="background:#b45309"></span>lifecycle mark'
    +' <span class="sw" style="background:#5aa2e8"></span>device observation'
    +' <span class="sw" style="background:#7c5cc4"></span>worker check-in (self-report)'
    +' <span class="sw" style="background:#22b8cf"></span>live view opened (a stream was'
    +' established — never proof anyone watched)'
    +'<br>A quiet stretch is not proof nobody came; an interruption explains why the channel'
    +' went silent, not what happened physically.</small></div>';
  for(const k of keys){
    const day=days[k],d=Date.parse(k+"T00:00:00Z")/1000;
    let s='<svg viewBox="0 0 100 30" preserveAspectRatio="none" role="img"'
      +' style="width:100%;height:30px;display:block">';
    for(const[a,b]of day.sched)
      s+=`<rect x="${x(d,a)}" y="5" width="${w(d,a,b)}" height="16" rx="1.5" `
        +'fill="#3b4a63" opacity="0.5"><title>scheduled window</title></rect>';
    for(const[a,b]of day.cov)
      s+=`<rect x="${x(d,a)}" y="23" width="${w(d,a,b)}" height="3.4" fill="#2f9e63">`
        +"<title>watched by Event History polling</title></rect>";
    for(const[a,b,why]of day.gap){
      const title=why
        ?"unwatched gap — channel reported "+esc(String(why[0].kind||"").replaceAll("_"," "))
          +" (explains the silence, not absence)"
        :"unwatched gap — the pipeline was not polling";
      s+=`<rect x="${x(d,a)}" y="23" width="${w(d,a,b)}" height="3.4" `
        +`fill="${why?"#d97706":"#9aa3b2"}"><title>${title}</title></rect>`;}
    for(const it of day.intr){
      const X=Math.min(99.3,Math.max(0,x(d,iso(it.at))));
      s+=`<rect x="${X}" y="0.6" width="0.7" height="3.6" fill="#b45309">`
        +`<title>${esc(String(it.kind||"").replaceAll("_"," "))} — ${esc(it.at||"")}`
        +(it.device_id?` · ${esc(it.device_id)}`:" · account-wide")+`</title></rect>`;}
    for(const[a,b,dev,open]of day.live){
      const title="live view opened — "+esc(dev||"camera")
        +(open?" · still open when signed":" · stream established")
        +" — attests a session, never viewership";
      if(b)s+=`<rect x="${x(d,a)}" y="21.4" width="${w(d,a,b)}" height="1.7" fill="#22b8cf">`
        +`<title>${title}</title></rect>`;
      else s+=`<rect x="${Math.min(99.3,Math.max(0,x(d,a)))}" y="20.9" width="0.7" `
        +`height="2.6" fill="#22b8cf"><title>${title}</title></rect>`;}
    for(const e of day.ev){
      const X=Math.min(99.3,Math.max(0,x(d,iso(e.at))));
      const isCk=e.kind==="checkin";
      const fill=isCk?"#7c5cc4":String(e.kind).indexOf("departure")===0?"#c05a5a":"#5aa2e8";
      s+=`<rect x="${X}" y="7" width="0.7" height="13" fill="${fill}"${isCk?' opacity="0.8"':""}>`
        +`<title>${esc(String(e.kind||"").replaceAll("_"," "))} — ${esc(e.at||"")}`
        +(isCk?" (self-reported)":"")+`</title></rect>`;}
    s+="</svg>";
    const wd=WD[new Date(d*1000).getUTCDay()];
    html+=`<div class="week-row"><div class="week-label muted"><small>${esc(wd)} `
      +`${esc(k.slice(5))}</small></div><div class="week-strip">${s}</div></div>`;
  }
  return html+"</div>";
}
/* Site-level attestations render as provenance cards, not just verify rows —
   the coverage cert is the pack's answer to "was anyone watching?". */
function attestationHTML(p){
  const t=p.record_type||"record";
  if(t==="coverage_attestation"){
    const cov=p.coverage||{};const w=cov.window||{};
    const pct=cov.fraction!=null?Math.round(cov.fraction*100):null;
    return `<div class="row ok"><span class="pill">coverage</span> `
      +`<strong>coverage attestation</strong> — ${esc(w.start||"")} → ${esc(w.end||"")}</div>`
      +`<small>watched ${pct!=null?pct+"%":"?"} of the window · ${esc(cov.polls||0)} poll(s)`
      +` · ${(cov.gaps||[]).length} gap(s) — silence is not absence</small>`;
  }
  if(t==="period_digest"){
    const i=p.interval||{};const c=p.counts||{};
    return `<div class="row ok"><span class="pill">digest</span> `
      +`<strong>period digest</strong> — ${esc(i.start||"")} → ${esc(i.end||"")}</div>`
      +`<small>${esc(c.visits_observed||0)} observed · ${esc(c.visits_no_observation||0)}`
      +` no-observation · ${esc(c.worker_disputes||0)} dispute(s)`
      +` · ${esc(c.coordinator_resolutions||0)} resolution(s)</small>`;
  }
  if(t==="source_disconnected"){
    return `<div class="row bad"><span class="pill">disconnected</span> `
      +`<strong>source disconnected</strong> — ${esc(p.disconnected_at||"")}</div>`
      +`<small>${esc(p.reason||"consent revoked")}`
      +` — ingestion and polling stopped; signed records preserved</small>`;
  }
  if(t==="case_export"){
    const n2=Object.keys(p.receipt_hashes||{}).length;
    return `<div class="row ok"><span class="pill">export</span> `
      +`<strong>case export</strong> — signed manifest naming ${n2} record(s)</div>`;
  }
  return `<div class="row ok"><span class="pill">${esc(t)}</span> <strong>${esc(t)}</strong></div>`;
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
  const rows=[];const actual={};const payloads=[];
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
    if(c.ok)payloads.push(p);
    const stance=deriveStance(js);
    const ds=digests((js.original||{}).payload||{});declared+=ds.length;
    const cls=c.ok?(STATE_CLS[p.state]||"ok"):"bad";
    const win=p.schedule
      ?esc(p.schedule.window_start||"")+" → "+esc(p.schedule.window_end||"")
      :"unscheduled";
    rows.push(
      `<div class="card"><div class="row ${cls}">`
      +`<span class="pill">${esc(p.state||"?")}</span> `
      +`<strong>${esc(tag.dataset.vid)}</strong>`
      +(p.scheduled_worker?` · worker ${esc(p.scheduled_worker.name||"")}`:"")
      +(stance!=="no_statement"?` · statement: ${esc(stance)}`:"")
      +` — ${esc(c.why)}</div>`
      +`<div class="tech"><small>${win} · ${ds.length} media digest(s)</small>`
      +timelineSVG(p)+corroborationHTML(p)+statementsHTML(js)+`</div>`
      +`<div class="plain" style="display:none">${plainHTML(p,js)}</div>`
      +`<a href="#" class="view-toggle muted"><small>View as the family sees it</small></a></div>`);
  }
  const wk=weekSVG(payloads);
  if(wk)rows.unshift(
    `<div class="card"><div class="row ok"><span class="pill">week</span> `
    +`<strong>the exported window at a glance</strong> `
    +`<small class="muted">— assembled only from verified signed payloads</small></div>`
    +wk+`</div>`);
  cards.innerHTML=rows.join("");
  cards.onclick=e=>{
    const a=e.target.closest(".view-toggle");if(!a)return;e.preventDefault();
    const card=a.closest(".card"),t=card.querySelector(".tech"),pl=card.querySelector(".plain");
    const showPlain=pl.style.display==="none";
    pl.style.display=showPlain?"":"none";t.style.display=showPlain?"none":"";
    a.innerHTML="<small>"+(showPlain?"View the technical record":"View as the family sees it")+"</small>";
  };
  let mLine="";
  const mtag=document.getElementById("packmanifest");
  if(mtag&&mtag.textContent){
    const mNode=parseKeep(d64(mtag.textContent));
    const mc=await checkManifestNode(mNode,key);
    if(!mc.ok)anyBad=true;
    mLine=`<div class="row ${mc.ok?"ok":"bad"}">manifest: ${esc(mc.why)}</div>`;
    const listedVids=new Set();
    for(const v of toJS(mNode).visits||[]){
      listedVids.add(v.visit_id);
      /* Fail closed both directions: a listed visit with no inlined bundle is
         a dropped record; an inlined bundle the manifest does not list is
         smuggled content outside the signed set. */
      if(!(v.visit_id in actual)){
        anyBad=true;
        mLine+=`<div class="row bad">${esc(v.visit_id)}: listed in manifest but not inlined</div>`;
      }else if(actual[v.visit_id]!==v.payload_hash){
        anyBad=true;
        mLine+=`<div class="row bad">${esc(v.visit_id)}: manifest hash disagrees with signed original</div>`;
      }
    }
    for(const vid of Object.keys(actual)){
      if(!listedVids.has(vid)){
        anyBad=true;
        mLine+=`<div class="row bad">${esc(vid)}: inlined bundle not in the signed manifest</div>`;
      }
    }
    /* Attestations inlined as <script class="attestation"> — verify each
       against the manifest's signed list (signature + hash + visit_id). */
    const alist={};for(const a of toJS(mNode).attestations||[])alist[a.receipt_id]=a;
    const present=new Set();
    for(const tag of document.querySelectorAll("script.attestation")){
      present.add(tag.dataset.rid);
      const aNode=parseKeep(d64(tag.textContent));const rjs=toJS(aNode);
      const listed=alist[tag.dataset.rid];
      const rid=esc(tag.dataset.rid);
      if(key&&rjs.public_key!==key){
        anyBad=true;mLine+=`<div class="row bad">attestation ${esc(rid)}: different issuer key</div>`;
        continue;}
      const rc=await checkReceipt(aNode);
      if(!rc.ok){
        anyBad=true;mLine+=`<div class="row bad">attestation ${rid}: ${esc(rc.why)}</div>`;continue;}
      if(!listed||listed.payload_hash!==rjs.payload_hash||listed.visit_id!==rjs.visit_id){
        anyBad=true;
        mLine+=`<div class="row bad">attestation ${esc(rid)}: not in the signed manifest</div>`;continue;}
      mLine+=`<div class="row ok">attestation ${esc(listed.record_type||"record")}: signed and intact</div>`;
      cards.innerHTML+=`<div class="card">${attestationHTML(rjs.payload||{})}</div>`;
    }
    for(const a of toJS(mNode).attestations||[]){
      if(!present.has(a.receipt_id)){
        anyBad=true;
        mLine+=`<div class="row bad">attestation ${esc(a.receipt_id)}: listed but not inlined</div>`;}
    }
  }
  verdict.innerHTML=anyBad
    ?'<div class="row bad">FAILED — '+n
     +" record(s), at least one does not verify. Do not rely on this pack.</div>"+mLine
    :`<div class="row ok">VERIFIED — ${n} record(s), chains intact under issuer key `
     +esc(String(key||"").slice(0,16))+"…</div>"+mLine
     +`<small>${declared} declared media digest(s)`
     +(meta.media_redacted?" — media withheld by redaction; signed digests preserved":"")+"</small>";
}
renderIndex().catch(e=>{
  document.getElementById("verdict").innerHTML=
    "<div class='row bad'>index error: "+esc(e.message)+"</div>";});
"""


def case_index_html(
    meta: dict,
    bundles: list[tuple[str, str]],
    manifest_text: str = "",
    attestations: list[tuple[str, str]] = (),
) -> str:
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
    tags += "".join(
        f'<script class="attestation" data-rid="{rid}">{enc(text)}</script>\n' for rid, text in attestations
    )
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
