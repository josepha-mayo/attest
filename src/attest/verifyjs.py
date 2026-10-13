"""Self-contained browser verifier embedded in every exported pack.

`verify.html` re-implements the whole verification path in dependency-free
JavaScript: the canonical-JSON serializer (matching ``ledger.canonical``),
SHA-256 payload hashing, and Ed25519 signature verification (WebCrypto first,
pure-BigInt fallback — same RFC 8032 math) — no CDN, no install, works offline
from ``file://``.

The JS canonicalizer parses the source document itself and copies string and
number literals *verbatim*. Packs are produced by Python's ``json.dumps``,
whose literal forms are already canonical, so a verbatim copy reproduces the
exact bytes ``ledger.canonical`` emitted — including float spellings like
``34.0`` that a ``JSON.parse``/``JSON.stringify`` round-trip would collapse
to ``34`` and break the hash.

The node smoke test (tests/test_verifyjs.py) executes the same script block
against a real signed receipt to prove the crypto, not just the packaging.
"""

# A shield-check favicon — inline data URI so every generated page stays
# fully self-contained (the self-containment test whitelists only this tag).
_FAVICON = (
    "data:image/svg+xml,%3Csvg xmlns='http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg' viewBox='0 0 16 16'%3E"
    "%3Cpath d='M8 1l6 2v5c0 3.5-2.6 6-6 7-3.4-1-6-3.5-6-7V3z' fill='%231c1c1e'/%3E"
    "%3Cpath d='M4.6 8.2l2.2 2.2 4.6-4.9' stroke='%23fff' stroke-width='1.5' fill='none'/%3E%3C/svg%3E"
)

_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Verify an Attest evidence pack entirely in your browser —
  Ed25519 (WebCrypto, pure-JS BigInt fallback), SHA-256, and Merkle proofs.
  Nothing uploads; the math is the check.">
<meta property="og:title" content="Attest pack verifier — zero install">
<meta property="og:description" content="Drop a signed evidence pack; the browser runs Ed25519
  and Merkle checks locally. Records, not verdicts.">
<meta property="og:type" content="website">
<link rel="icon" href="{_FAVICON}">
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
 .row.stamp{display:block;font-size:1.1rem;font-weight:700;border:2px solid;
   border-radius:10px;padding:.7rem 1rem;margin:.9rem 0;animation:stampin .28s ease-out}
 .row.stamp.ok{border-color:#146c2e;background:#f0fdf4}
 .row.stamp.bad{border-color:#b3261e;background:#fef2f2}
 .row.stamp.warn{border-color:#a16207;background:#fefce8}
 .copybtn{display:block;margin-top:.6rem;font:inherit;font-size:.82rem;
   padding:.3rem .7rem;border:1px solid #999;border-radius:6px;
   background:#fff;color:#1c1c1e;cursor:pointer}
 .copybtn:hover{background:#f4f4f5}
 @media print{.drop,#live-wrap,button,.copybtn{display:none}
   body{max-width:none}}
 @keyframes stampin{from{transform:scale(1.5);opacity:0}to{transform:scale(1);opacity:1}}
 @media (prefers-reduced-motion:reduce){.row.stamp{animation:none}}
 small{color:#666}
 .muted,.mut{color:#666}
 .pill{display:inline-block;border-radius:99px;padding:.05rem .6rem;font-size:.8rem;
   background:#eee;color:#444}
 .pill.warn{background:#fef3c7;color:#8a5a00}.pill.bad{background:#fee2e2;color:#b3261e}
 #liveurl{max-width:100%}
</style>
</head>
<body>
""".replace("{_FAVICON}", _FAVICON)

_JS_OPEN = '<script>\n"use strict";\n'

_JS_LIB = """/* ---------- canonical JSON (mirrors attest.ledger.canonical) ----------
   Parses the document keeping every string/number literal verbatim, then
   re-emits with sorted keys and no whitespace — identical bytes to
   json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=False)
   for any document Python itself serialized. */
function parseKeep(text){
  let i=0;const n=text.length;
  const ws=()=>{while(i<n&&" \\t\\n\\r".includes(text[i]))i++;};
  function literal(){const m=/^-?(0|[1-9]\\d*)(\\.\\d+)?([eE][+-]?\\d+)?/.exec(text.slice(i));
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
  if(!n)return null;
  if(n.t==="lit")return n.str!==undefined?n.str:JSON.parse(n.r);
  if(n.t==="arr")return n.v.map(toJS);
  /* null-prototype map: a literal "__proto__" key must become an OWN
     property — assigning through a plain {}'s prototype setter silently
     drops it where Python's dict keeps it (one doc, two member sets). */
  const o=Object.create(null);for(const[k,v]of n.v)o[k]=toJS(v);return o;}
/* CPython repr()/json.dumps float spelling — shortest round-trip digits:
   integral floats carry ".0"; fixed notation for -4 <= exp10 < 16;
   scientific with a signed >=2-digit exponent beyond it. */
function _pyFloat(x){
  if(Number.isNaN(x))return"NaN";
  if(!isFinite(x))return x<0?"-Infinity":"Infinity";
  if(x===0)return Object.is(x,-0)?"-0.0":"0.0";
  const neg=x<0?"-":"";
  const s=Math.abs(x).toExponential();
  const ix=s.indexOf("e");
  const digits=s.slice(0,ix).replace(".","");
  const e=+s.slice(ix+1);
  if(e>=-4&&e<16){
    if(e>=digits.length-1)
      return neg+digits+"0".repeat(e-digits.length+1)+".0";
    if(e<0)return neg+"0."+"0".repeat(-e-1)+digits;
    return neg+digits.slice(0,e+1)+"."+digits.slice(e+1);}
  return neg+digits[0]+(digits.length>1?"."+digits.slice(1):"")
    +"e"+(e<0?"-":"+")+String(Math.abs(e)).padStart(2,"0");}
/* A literal's canonical spelling — Python json.dumps semantics: ints stay
   exact via BigInt (past double precision), floats get CPython repr,
   bool/null keep the file spelling. */
function _pyLit(r){
  if(/^-?[0-9]+$/.test(r))return BigInt(r).toString();
  if(/^(true|false|null)$/.test(r))return r;
  return _pyFloat(Number(r));}
function canonical(n){
  /* Strings re-serialize through JSON.stringify — the decoded value's canonical
     spelling — so `\u2014` and `—` in a file canonicalize identically, matching
     Python's ensure_ascii=False. Number literals re-normalize through the
     CPython float/int repr — the file's verbatim spelling ("34.00") must
     canonicalize to what Python emits ("34.0") for the hash to agree. */
  if(n.t==="lit")return n.str!==undefined?JSON.stringify(n.str):_pyLit(n.r);
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
  if(!node||node.t!=="obj")return null;
  let hit=null;for(const[kk,vv]of node.v)if(kk===k)hit=vv;return hit;}
/* ---------- hashing ---------- */
async function sha256hex(b){const d=await crypto.subtle.digest("SHA-256",b);
  return[...new Uint8Array(d)].map(x=>x.toString(16).padStart(2,"0")).join("");}
async function sha512(b){return new Uint8Array(await crypto.subtle.digest("SHA-512",b));}
const enc=s=>new TextEncoder().encode(s);
const hex2b=h=>Uint8Array.from(h.match(/../g).map(x=>parseInt(x,16)));
const b64d=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
/* ---------- Ed25519 verification (RFC 8032) ----------
   Two engines, one semantics. WebCrypto Ed25519 is the fast path on modern
   browsers/node — a real RFC 8032 verify, not a shortcut. The pure-BigInt
   verifier below stays authoritative wherever WebCrypto lacks the algorithm
   or refuses an input: a native TRUE is a genuine signature, anything else
   falls through to the math. Strictness gates (length, decodable R/A,
   canonical S < L) run in JS first so both engines share the same edge
   semantics — the counters record which engine answered, for the verdict's
   honesty line. */
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
let _engWc=0,_engJs=0;
async function _wcVerify(sig,pk,msg){
  try{
    if(!crypto.subtle||!crypto.subtle.importKey)return null;
    const k=await crypto.subtle.importKey("raw",pk,"Ed25519",false,["verify"]);
    return await crypto.subtle.verify("Ed25519",k,sig,msg)?true:false;
  }catch(e){return null;}
}
async function edVerify(sig,pk,msg){
  if(sig.length!==64||pk.length!==32)return false;
  const R=decodePoint(sig.slice(0,32)),A=decodePoint(pk);
  if(!R||!A)return false;
  const S=le(sig.slice(32));if(S>=L)return false;
  const w=await _wcVerify(sig,pk,msg);
  if(w===true){_engWc++;return true;}
  /* w===false means WebCrypto ran and rejected — but the BigInt check still
     produces the verdict below, so the JS engine served it either way. */
  _engJs++;
  const h=mod(le(await sha512(Uint8Array.from([...sig.slice(0,32),...pk,...msg]))),L);
  const lhs=pMul(B,S),rhs=pAdd(R,pMul(A,h));
  return lhs.x===rhs.x&&lhs.y===rhs.y;}
/* ---------- receipt + chain checks (mirrors ledger.verify_*) ---------- */
/* Python ``==`` between a validated int and a raw JSON literal: bools
   coerce (True==1), numbers compare at exact mathematical value, strings/
   null/objects never equal a number. ``n`` is a keep-node (the verbatim
   literal — a Number unwrap would round past 2^53), ``b`` a BigInt. */
function _pyEqN(n,b){
  if(!n||n.t!=="lit"||n.str!==undefined)return false;
  if(n.r==="true")return b===1n;
  if(n.r==="false")return b===0n;
  if(n.r==="null")return false;
  if(/^-?(0|[1-9][0-9]*)$/.test(n.r))return BigInt(n.r)===b;
  const f=Number(n.r);
  return isFinite(f)&&Number.isInteger(f)&&BigInt(f)===b;}
/* Model-side int gate — mirrors models._json_int / json_is_int /
   Number.isInteger: a REAL JSON integer, or an integral float literal.
   Strings ("5") and booleans reject on every surface now that the pydantic
   model is strict — the node must be a number literal. Returns BigInt so
   arbitrary-precision literals compare exactly, like Python ints. */
function _pyModelInt(n){
  if(!n||n.t!=="lit"||n.str!==undefined)return null;
  if(/^-?(0|[1-9][0-9]*)$/.test(n.r))return BigInt(n.r);
  if(n.r==="true"||n.r==="false"||n.r==="null")return null;
  const f=Number(n.r);  /* float literal — Python float.is_integer() semantics */
  return isFinite(f)&&Number.isInteger(f)?BigInt(f):null;}
/* The instant spelling every verifier surface agrees on — shared with
   models.ISO_INSTANT_RE / disputepack._iso_instant. */
const _ISO_INSTANT=new RegExp(
  "^([0-9]{4})-([0-9]{2})-([0-9]{2})([T ]([01][0-9]|2[0-3]):[0-5][0-9]"+
  "(:[0-5][0-9]([.][0-9]+)?)?(Z|[+-]([01][0-9]|2[0-3]):?[0-5][0-9])?)?$");
function _pyInstant(v){
  /* Instant parse under the shared ISO grammar, computed from the captures —
     Date.parse is TZ- and engine-dependent ("2026-01-01"→UTC, "T00:00"→local,
     space-separator/+HHMM spellings vary by engine), and Date.UTC maps years
     0-99 to 1900+y. Returns [key, aware] — keys carry µs so .123456 vs .1235
     compare exactly; awareness mirrors Python's naive-never-equals-aware. */
  if(typeof v!=="string")return null;
  const m=_ISO_INSTANT.exec(v);if(!m)return null;
  const y=+m[1],mo=+m[2],dd=+m[3];
  if(y===0)return null;
  let hh=0,mi=0,ss=0,us=0,aware=false,offM=0;
  if(m[4]!==undefined){
    hh=+m[4].slice(1,3);mi=+m[4].slice(4,6);
    if(m[6]!==undefined)ss=+m[6].slice(1,3);
    if(m[7]!==undefined)us=+(m[7].slice(1)+"000000").slice(0,6);
    if(m[8]!==undefined){aware=true;
      if(m[8]!=="Z"){const sgn=m[8][0]==="-"?-1:1;
        offM=sgn*(+m[9]*60+(+m[8].slice(-2)));}}
  }
  const d=new Date(Date.UTC(0,mo-1,dd,hh,mi,ss));
  d.setUTCFullYear(y);
  if(d.getUTCFullYear()!==y||d.getUTCMonth()!==mo-1||d.getUTCDate()!==dd||
     d.getUTCHours()!==hh||d.getUTCMinutes()!==mi||d.getUTCSeconds()!==ss)
    return null;
  const sec=d.getTime()/1000;
  return[(aware?sec-offM*60:sec)+"|"+us,aware];}
let _checked=0;
async function _tick(){
  /* Refresh the "verifying…" line with a live receipt count — then yield a
     macrotask so the browser actually repaints it. Guarded: the conformance
     harness runs verifyFiles under node with no document at all. */
  if(typeof document==="undefined")return;
  const el=document.getElementById("out");
  /* Only while the first child is the "<p>verifying…" placeholder go() plants —
     liveCheck/diffPacks reach checkReceipt after real rows exist, and a mut
     row must never be overwritten by stale progress text. */
  if(el&&el.firstElementChild&&el.firstElementChild.tagName==="P")
    el.firstElementChild.textContent="checking signatures… "+_checked+" receipt(s) so far";
  await new Promise(r=>setTimeout(r,0));
}
async function checkReceipt(rNode){
  const r=toJS(rNode);
  if(!r||typeof r!=="object")return{ok:false,why:"malformed receipt"};
  const pn=get(rNode,"payload");
  /* Mirrors Receipt.model_validate typing on the consumed fields — a pool
     member missing or mistyping them is malformed (Python drops it at
     model validation), never a throw and never a lenient pass. */
  if(!pn||pn.t!=="obj"||typeof r.id!=="string"||typeof r.visit_id!=="string"||
     typeof r.public_key!=="string"||typeof r.payload_hash!=="string"||
     typeof r.signature!=="string"||
     !(typeof r.prev_hash==="string"||r.prev_hash===null))
    return{ok:false,why:"malformed receipt"};
  /* issued_at is model-gated at intake on the Python surfaces: absent →
     default_factory; present must be an ISO-grammar instant (pydantic's
     BeforeValidator rejects null and everything else). Applies on every
     schema — /1 receipts never reach the instant compare below. */
  if(r.issued_at!==undefined&&_pyInstant(r.issued_at)===null)
    return{ok:false,why:"malformed receipt"};
  const rs=_pyModelInt(get(rNode,"sequence"));
  if(rs===null)return{ok:false,why:"malformed receipt"};
  const canon=canonical(pn);
  const h=await sha256hex(enc(canon));
  if(h!==r.payload_hash)return{ok:false,why:"payload hash mismatch (payload was altered)"};
  const p=r.payload;
  /* payload.get("prev_hash") — an absent key reads null on the Python side,
     so absent and explicit null both compare equal to an envelope null. */
  if(!_pyEqN(get(pn,"sequence"),rs)||(p.prev_hash===undefined?null:p.prev_hash)!==r.prev_hash)
    return{ok:false,why:"envelope fields disagree with signed payload"};
  if(p.visit_id!==r.visit_id)return{ok:false,why:"visit id disagrees with signed payload"};
  if(p.schema==="attest.receipt/2"){
    /* issued_at serializes as "...Z" in the envelope but "+00:00" in the
       signed payload — compare parsed instants under the shared grammar
       (models.ISO_INSTANT_RE / _iso_instant). Date.parse accepts RFC-2822
       spellings ("Mar 1, 2026") Python rejects, and rolls invalid dates —
       the regex gate + rollover check pin both sides to one grammar.
       Awareness must match: Python never equates naive with aware. */
    const i1=_pyInstant(p.issued_at),i2=_pyInstant(r.issued_at);
    const sameInstant=i1!==null&&i2!==null&&i1[0]===i2[0]&&i1[1]===i2[1];
    if(p.receipt_id!==r.id||!sameInstant)
      return{ok:false,why:"receipt envelope identity disagrees with signed payload"};
  }else if(p.schema!=="attest.receipt/1")return{ok:false,why:"unsupported receipt schema"};
  /* atob throws on non-alphabet bytes where Python's _unb64(validate=True)
     returns ValueError->False — a malformed envelope must fail HERE, not
     abort the whole pack check up at go()'s catch. */
  let sigB,pkB;
  try{sigB=b64d(r.signature);pkB=b64d(r.public_key);}
  catch(e){return{ok:false,why:"signature invalid"};}
  /* BigInt Ed25519 is the slow step — on a packed case pack the deep-link
     path runs ~50+ of these back-to-back, so a live count tells the judge
     the page is working, not hung. The setTimeout yield is the paint. */
  _checked++;
  if(_checked%4===0)await _tick();
  const ok=await edVerify(sigB,pkB,hex2b(r.payload_hash));
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
  /* ``key`` is a pinned issuer key (string) or a trusted-key Set built by
     trustedKeys()/descendantKeys() — a pack written across a key rotation
     legitimately mixes issuer keys; only keys the signed rotation chain
     endorses are inside the set. */
  const outOf=k=>key instanceof Set?!key.has(k):(key&&k!==key);
  const oNode=get(root,"original");
  if(!oNode)return{ok:false,why:"no original receipt"};
  const original=toJS(oNode)||{};
  if(outOf(original.public_key))
    return{ok:false,why:"original: signed by a key outside the trusted issuer chain"};
  const c0=await checkReceipt(oNode);
  if(!c0.ok)return{ok:false,why:"original: "+c0.why};
  let prev=original.payload_hash,n=0;
  const rev=get(root,"reviews");
  if(rev&&rev.t!=="arr")
    return{ok:false,why:"reviews is not a list"};
  const entries=rev?rev.v:[];
  /* ReviewBundle caps at max_length=500 — enforce the same ceiling so a
     chain Python rejects can't verify here (and a hostile chain can't
     hang the tab on thousands of BigInt verifies). */
  if(entries.length>500)
    return{ok:false,why:"review chain exceeds the 500-entry cap"};
  for(let i=0;i<entries.length;i++){
    n=i+1;
    const e=toJS(entries[i]);
    const rNode=get(entries[i],"receipt");
    if(!rNode)return{ok:false,why:`review ${n}: entry has no receipt`};
    /* Entry typing mirrors ReviewEntry.model_validate — malformed members
       fail the bundle, never slip through a lenient raw compare. */
    if(!e||typeof e!=="object"||typeof e.id!=="string"||
       typeof e.visit_id!=="string"||_pyModelInt(get(entries[i],"revision"))===null)
      return{ok:false,why:`review ${n}: malformed entry`};
    const r=toJS(rNode)||{};
    if(outOf(r.public_key))
      return{ok:false,why:`review ${n}: signed by a key outside the trusted issuer chain`};
    const c=await checkReceipt(rNode);
    if(!c.ok)return{ok:false,why:`review ${n}: ${c.why}`};
    if(e.id!==r.id||e.visit_id!==original.visit_id||r.visit_id!==original.visit_id)
      return{ok:false,why:`review ${n}: identity does not match original`};
    if(_pyModelInt(get(entries[i],"revision"))!==BigInt(n)||
       _pyModelInt(get(rNode,"sequence"))!==BigInt(n)||r.prev_hash!==prev)
      return{ok:false,why:`review ${n}: sequence or previous hash mismatch`};
    const p=r.payload||{},a=p.original_receipt;
    /* reviews.py compares the anchor by exact dict equality — an anchor with
       extra keys is content the signer committed that must not verify. */
    const aOk=a!==null&&typeof a==="object"&&!Array.isArray(a)&&
      Object.keys(a).length===2&&a.id===original.id&&a.hash===original.payload_hash;
    if(p.record_type!=="review"||!aOk)
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
  for(const lv of(cov&&cov.live_sessions)||[]){
    pts.push(iso(lv.opened_at));if(lv.closed_at)pts.push(iso(lv.closed_at));}
  if(!pts.length)return"";
  let lo=Math.min.apply(null,pts),hi=Math.max.apply(null,pts);
  if(hi-lo<600){const m=(lo+hi)/2;lo=m-300;hi=m+300;}
  const pad=(hi-lo)*0.04;lo-=pad;hi+=pad;const span=hi-lo;
  const x=t=>(Math.min(Math.max((t-lo)/span,0),1)*100).toFixed(2);
  const w=(a,b)=>Math.max(0.4,x(b)-x(a)).toFixed(2);
  const KIND_LBL={arrival_motion:"motion",doorbell:"doorbell",door_opened:"door opened",
    door_closed:"door closed",activity:"activity",departure_motion:"departure cue",
    on_demand:"on-demand media",snapshot:"snapshot",late:"late-arriving event",
    checkin:"worker check-in"};
  /* role=img hides child <title>s from screen readers — build a prose
     aria-label from the same data so the strip reads for everyone. */
  const counts=Object.create(null);for(const e of p.evidence||[]){
    /* a checkin evidence item at the payload's own checked_in_at instant is
       the same event the self-reported count below names — skip the dup */
    if(e.kind==="checkin"&&ci&&iso(e.at)===ci)continue;
    const lbl=KIND_LBL[e.kind]||String(e.kind||"activity").replace(/_/g," ");
    counts[lbl]=(counts[lbl]||0)+1;}
  if(p.checked_in_at)counts["worker check-in (self-reported)"]=
    (counts["worker check-in (self-reported)"]||0)+1;
  const hm=t=>new Date(t*1000).toISOString().slice(11,16)+"Z";
  const label=(
    (ws?"scheduled "+hm(ws)+" to "+hm(we)+"; ":"")
    +(cov?((cov.covered||[]).length+" watched interval(s), "
      +(cov.gaps||[]).length+" coverage gap(s)"
      +((cov.live_sessions||[]).length?", "+(cov.live_sessions||[]).length
        +" live-view session(s) (provenance only)":"")+"; "):"")
    +Object.keys(counts).map(k=>counts[k]+" "+k).join(", "));
  let s='<svg viewBox="0 0 100 34" preserveAspectRatio="none" role="img" '
    +'aria-label="Timeline — '+esc(label||"empty")+'" '
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
    for(const lv of cov.live_sessions||[]){
      const a=iso(lv.opened_at),b=lv.closed_at?iso(lv.closed_at):null;
      if(!a)continue;
      const title=esc("live view — a stream was established "+lv.opened_at
        +(b?" -> "+lv.closed_at:" · still open")+"; viewership not shown");
      if(b&&b>a)s+=`<rect x="${x(a)}" y="21.4" width="${w(a,b)}" height="3.2" `
        +`fill="#22b8cf"><title>${title}</title></rect>`;
      else s+=`<line x1="${x(a)}" y1="19" x2="${x(a)}" y2="24.5" stroke="#22b8cf" `
        +`stroke-width="0.7"><title>${title}</title></line>`;
    }
  }
  for(const e of p.evidence||[]){
    /* same dedup: the gold checkin tick below already draws this instant */
    if(e.kind==="checkin"&&ci&&iso(e.at)===ci)continue;
    const k=KIND_LBL[e.kind]||String(e.kind||"activity").replace(/_/g," ");
    const col=String(e.kind).indexOf("departure")===0?"#c05a5a"
      :e.kind==="late"?"#9aa3b2":"#5aa2e8";
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
  const m=toJS(mNode)||{};
  const sig=get(mNode,"signature_receipt");
  /* Python's `sig is None` reads explicit null as absent — the keep-node is
     truthy either way, so test the VALUE. */
  if(!sig||toJS(sig)===null)return{ok:true,why:"unsigned manifest (pre-signature pack)"};
  const c=await checkReceipt(sig);
  if(!c.ok)return{ok:false,why:"manifest signature: "+c.why};
  const js=toJS(sig);
  const sigOut=key instanceof Set?!key.has(js.public_key):(key&&js.public_key!==key);
  if(sigOut)return{ok:false,why:"manifest signed by a key outside the trusted issuer chain"};
  const p=js.payload;
  const h=await sha256hex(enc(canonical(dropKey(mNode,"signature_receipt"))));
  if(h!==p.manifest_sha256)
    return{ok:false,why:"manifest content hash mismatch (manifest was altered)"};
  /* Homogeneous str->str maps on both sides — Python dict equality bridges
     True==1 and keeps int keys distinct from "5"; JS object keys stringify,
     so type-gate first, then compare per-key. null/non-object signed maps
     reject (Python: listed != None always mismatches). */
  const signed=p.receipt_hashes===undefined?{}:p.receipt_hashes;
  const isObj=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
  let same=isObj(signed)&&Object.keys(signed).every(k=>typeof signed[k]==="string");
  const listed=Object.create(null);
  if(same)for(const v of m.visits||[]){
    if(v&&typeof v==="object"&&"visit_id"in v&&"payload_hash"in v){
      if(typeof v.visit_id!=="string"||typeof v.payload_hash!=="string"){same=false;break;}
      listed[v.visit_id]=v.payload_hash;
    }  /* entries missing either key are dropped — the Python filter does too */
  }
  if(same)same=Object.keys(listed).length===Object.keys(signed).length
    &&Object.keys(listed).every(k=>listed[k]===signed[k]);
  if(!same)return{ok:false,why:"manifest visit list disagrees with the signed export"};
  return{ok:true,why:`export signed: ${Object.keys(listed).length} record(s)`};}
/* ---------- signed key rotation (ledger.trusted_issuer_keys parity) ---------- */
async function adoptedBy(keyReceipts,rotation,newKey){
  /* The successor's countersignature: a key_adoption receipt signed under
     newKey naming this exact rotation (id + payload hash). A retiring key's
     endorsement is self-serve — any key can claim any successor — so consent
     is what separates a real handoff from a grafted "predecessor". */
  const rr=toJS(rotation)||{},rp=rr.payload||{};
  for(const an of keyReceipts){
    const a=toJS(an)||{},ap=a.payload||{},link=ap.rotation_receipt||{};
    if(ap.record_type==="key_adoption"&&link.id===rr.id&&link.hash===rr.payload_hash
      &&a.public_key===newKey){
      const c=await checkReceipt(an);
      if(c.ok)return true;
    }
  }
  return false;}
async function _ancHop(keyNodes,cur){
  /* The deterministic predecessor pick (ledger._rotation_hop parity):
     EVERY consented rotation endorsing cur, then min(previous_key) — the
     pool order is attacker-controlled, so only a key-ordered pick yields
     the same lineage on every verifier surface. */
  let best=null;
  for(const rn of keyNodes){
    const r=toJS(rn)||{},p=r.payload||{};
    if(p.record_type==="key_rotation"&&p.new_key===cur
      &&typeof p.previous_key==="string"&&r.public_key===p.previous_key){
      const c=await checkReceipt(rn);
      if(c.ok&&await adoptedBy(keyNodes,rn,cur)&&(best===null||p.previous_key<best))
        best=p.previous_key;
    }
  }
  return best;}
async function trustedKeys(issuerKey,rotationNodes,maxHops=32){
  /* The keys a case-pack verification may trust: the manifest issuer plus
     every ancestor reachable through signed key_rotation receipts that the
     successor countersigned via key_adoption. An uncountersigned rotation
     is a graft attempt — it never lands in the set. */
  const trusted=new Set([issuerKey]);let cur=issuerKey;
  for(let i=0;i<maxHops;i++){
    const nxt=await _ancHop(rotationNodes,cur);
    if(nxt===null)break;
    cur=nxt;trusted.add(cur);
  }
  return trusted;}
async function descendantKeys(rootKey,rotationNodes,maxHops=32){
  /* The forward walk for single-visit bundles: reviews append after the
     original, so a bundle legitimately carries keys the signed rotations
     endorse — the root key plus every verified successor. Each hop needs
     BOTH signatures (retiring endorsement + successor key_adoption): an
     orphaned rotation is a dead branch, not a trusted descendant.
     Competing rotations resolve deterministically — the highest-sequence
     CONSENTED hop wins, matching the Python verifiers exactly. */
  const trusted=new Set([rootKey]);let cur=rootKey;
  for(let i=0;i<maxHops;i++){
    const cands=[];
    for(const rn of rotationNodes){
      const r=toJS(rn)||{},p=r.payload||{};
      if(p.record_type==="key_rotation"&&p.previous_key===cur&&r.public_key===cur
        &&typeof p.new_key==="string"&&_pyModelInt(get(rn,"sequence"))!==null){
        const c=await checkReceipt(rn);
        if(c.ok)cands.push([rn,r]);  /* adoptedBy takes the RAW node */
      }
    }
    /* Python sorts the exact int — sort the verbatim literal as BigInt so a
       >2^53 sequence orders identically (toJS Number would round it). */
    cands.sort((a,b)=>{
      const sa=_pyModelInt(get(a[0],"sequence")),sb=_pyModelInt(get(b[0],"sequence"));
      return sa===null||sb===null?0:sa<sb?1:sa>sb?-1:0;});
    let nxt=null;
    for(const [rn,r] of cands){
      if(await adoptedBy(rotationNodes,rn,r.payload.new_key)){nxt=r.payload.new_key;break;}
    }
    if(nxt===null)break;
    cur=nxt;trusted.add(cur);
  }
  return trusted;}
async function lineageRoot(issuerKey,keyNodes){
  /* The oldest ancestor the consented pivots reach from issuerKey — where a
     revocation-authority walk must seed. In a pack the receipt pool is
     attacker-controlled, so pool position can never confer authority: a
     self-signed key_revocation at sequence 0 must not make itself the root. */
  let cur=issuerKey;
  for(let i=0;i<32;i++){
    const nxt=await _ancHop(keyNodes,cur);
    if(nxt===null)break;
    cur=nxt;}
  return cur;}
async function revokedKeys(keyNodes,issuerKey){
  /* key -> suspect_after ISO for valid key_revocation receipts signed by the
     in-effect issuer at their position. Only the live key can revoke — a
     retired key revoking its successor would let a compromised key smear the
     healthy one, and position alone can't name the tip: a forged
     high-sequence revocation would make itself the tip and self-authorize.
     The walk seeds at the lineage ROOT reachable from the verified issuer,
     not pool order, and a revocation counts only for a key the lineage has
     already produced — a grafted foreign key or a retired key smearing a
     successor that hasn't pivoted in yet are both inert. */
  /* Malformed sequence sorts as -1 — an attacker controls this unsigned
     field, and a NaN comparator would order differently than Python. The
     key is the verbatim literal via _pyModelInt (BigInt, arbitrary
     precision) — toJS Numbers round past 2^53 and would order differently
     than Python's exact ints. */
  const _seq=n=>{const s=_pyModelInt(get(n,"sequence"));return s===null?-1n:s;};
  const ord=[...keyNodes].sort((a,b)=>{const sa=_seq(a),sb=_seq(b);return sa<sb?-1:sa>sb?1:0;});
  let inEffect=issuerKey?await lineageRoot(issuerKey,ord):null;
  const seen=new Set();if(inEffect)seen.add(inEffect);
  /* Null-prototype map — revoked_key is attacker-controlled and "__proto__"
     writes would silently drop, reads would hit Object.prototype. */
  const out=Object.create(null);
  for(const rn of ord){
    const r=toJS(rn)||{},p=r.payload||{};
    /* not signed by the in-effect key: out-of-band history, no authority */
    if(inEffect!==null&&r.public_key!==inEffect)continue;
    const c=await checkReceipt(rn);
    if(!c.ok)continue;
    if(inEffect===null)inEffect=r.public_key;
    seen.add(r.public_key);
    if(p.record_type==="key_rotation"&&p.previous_key===inEffect&&p.new_key
       &&await adoptedBy(ord,rn,p.new_key)){inEffect=p.new_key;seen.add(inEffect);continue;}
    if(p.record_type==="key_revocation"&&typeof p.revoked_key==="string"
       &&seen.has(p.revoked_key)&&r.public_key===inEffect){
      out[p.revoked_key]=p.suspect_after||"";
    }
  }
  return out;}
function suspectRecords(receiptNodes,revoked){
  /* Receipts signed by a revoked key inside its suspect window — valid,
     but annotated. Revocation overlays trust; it never flips integrity.
     Malformed members (missing fields, literal nodes) annotate as nothing —
     never crash the verifier's report on adversarial input. */
  const out=[];
  for(const rn of receiptNodes){
    if(!rn)continue;
    const r=toJS(rn);
    if(!r||typeof r!=="object")continue;
    const after=revoked[r.public_key];
    if(after!==undefined&&r.issued_at&&new Date(r.issued_at)>new Date(after))out.push(rn);
  }
  return out;}
/* ---------- shared pack helpers ---------- */
function digests(payload,out=[]){
  /* Evidence-only, matching app/disputepack: only payload.evidence[*]'s
     media_sha256 entries count — a media_sha256 nested anywhere else must
     neither mint ("digest matches" for a smuggled file) nor mask ("missing")
     a digest the signed evidence never declared. */
  const ev=payload&&payload.evidence;
  if(Array.isArray(ev))for(const e of ev){
    if(e&&typeof e.media_sha256==="string")out.push(e.media_sha256);}
  return out;}
function deriveStance(js){
  /* Derive the worker stance from the SIGNED review chain — mirrors
     countersign_status(). A file-level countersign_status field is unsigned
     and ignored: ReviewBundle serializes only kind/original/reviews, so that
     field can only exist in a forged pack (checkBundle now rejects it). */
  const ST={confirm:"acknowledged",dispute:"contested",correction:"corrected",inconclusive:"inconclusive"};
  let lastWorker=null,lastRes=null;
  for(const e of Array.isArray(js.reviews)?js.reviews:[]){
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
/* A dropped attest.issuer/1 document is a PIN, not pack content — it pins
   verification to the deployment's current issuer and supplies the signed
   lifecycle receipts that extend trust across rotations. */
let issuerDoc=null;
/* The pack's validated signed tree head — stashed by checkLog so the
   optional live cross-check (verify --issuer-url parity) can compare it
   against the head the deployment serves NOW. */
let packStash=null;
/* Blob URL for the verified pack's index.html — revoked on every new verify so
   re-runs don't accumulate dead object URLs. */
let _idxUrl=null;
let _packCtx=null; /* last FAILED pack: {byName, failedVids} for the
  "name what changed" post-verdict comparison */
/* The dropped/fetched file's own name — stamped into the verdict so a
   screenshot of the result is self-labelling. */
let packName="";
const _TOOLNAMES=new Set(["verify_case.py","verify_bundle.py","verify.html","index.html","README.txt"]);
async function checkTools(byName,trustedSet,scope,bad,ok){
  /* verifier_manifest.json pins the pack's tooling BYTES to the issuer —
     membership whitelists check names only, so without this a forged
     always-green verify_case.py could ride a genuine pack. Mirrors the
     Python check_tools/_verify_tools_pin on every other surface. */
  if(!byName["verifier_manifest.json"])return;
  let vn=null;
  try{vn=parseKeep(await byName["verifier_manifest.json"].text());}catch(e){}
  if(!vn){bad("verifier_manifest.json: malformed receipt");return;}
  const vm=toJS(vn)||{};const p=vm.payload||{};
  if(p.record_type!=="verifier_manifest"){
    bad("verifier_manifest.json: not a verifier_manifest receipt");return;
  }
  if(p.scope!==scope){bad("verifier_manifest.json: signed for a different pack — grafted pin");return;}
  if(!trustedSet||!trustedSet.has(vm.public_key)){
    bad("verifier_manifest.json: signed outside the trusted issuer chain");return;}
  const rc=await checkReceipt(vn);
  if(!rc.ok){bad(`verifier_manifest.json: ${esc(rc.why)}`);return;}
  const tools=p.tools;
  if(!tools||typeof tools!=="object"||Array.isArray(tools)||!Object.keys(tools).length){
    bad("verifier_manifest.json: tools map missing or malformed");return;}
  for(const[name,want]of Object.entries(tools)){
    if(!_TOOLNAMES.has(name)||typeof want!=="string"){
      bad(`verifier_manifest.json: unsafe or unknown member ${esc(String(name))}`);continue;}
    if(!byName[name]){bad(`${esc(name)}: pinned verifier tool missing from the pack`);continue;}
    const h=await sha256hex(new Uint8Array(await byName[name].arrayBuffer()));
    if(h!==want)
      bad(`${esc(name)}: bytes differ from the issuer-signed pin — a verifier script `
        +"modified after export cannot be trusted");
    else ok(`${esc(name)}: tool bytes match the issuer-signed pin`);
  }
  for(const n of Object.keys(byName))
    if(_TOOLNAMES.has(n)&&!(n in tools))
      bad(`${esc(n)}: verifier tooling present but not covered by the signed pin`);
}
/* RFC 6962 audit-path verification (transparency.py/check_log parity):
   leaf = sha256(0x00||payload_hash bytes), interior = sha256(0x01||l||r). */
async function _incOk(leafHex,size,index,pathHex,rootHex){
  /* 2147483647 = MAX_TREE_SIZE: JS proof arithmetic uses 32-bit bitwise
     ops — sizes at/past 2**31 would miscompute here while Python's
     arbitrary precision verifies, so both surfaces bound identically. */
  if(!Number.isInteger(size)||!Number.isInteger(index)||index<0||index>=size
    ||size<1||size>2147483647)return false;
  if(typeof leafHex!=="string"||!/^[0-9a-f]{64}$/i.test(leafHex)
    ||typeof rootHex!=="string"||!/^[0-9a-f]{64}$/i.test(rootHex))return false;
  /* path must be a JSON array — an object would crash for-of where Python
     iterates keys; both must read as "not a valid proof", not a pass. */
  if(pathHex!==undefined&&pathHex!==null&&!Array.isArray(pathHex))return false;
  rootHex=rootHex.toLowerCase();  /* Python compares decoded bytes — case-insensitive */
  const cat=(...a)=>{const n=a.reduce((t,x)=>t+x.length,0);const o=new Uint8Array(n);let p=0;
    for(const x of a){o.set(x,p);p+=x.length;}return o;};
  let r=await sha256hex(cat(new Uint8Array([0]),hex2b(leafHex)));
  if(size===1)return(!pathHex||!pathHex.length)&&r===rootHex;
  let fn=index,sn=size-1;
  for(const ph of pathHex||[]){
    if(!/^[0-9a-f]{64}$/i.test(ph)||sn===0)return false;
    if((fn&1)||fn===sn){
      r=await sha256hex(cat(new Uint8Array([1]),hex2b(ph),hex2b(r)));
      while(fn&&!(fn&1)){fn>>=1;sn>>=1;}
    }else r=await sha256hex(cat(new Uint8Array([1]),hex2b(r),hex2b(ph)));
    fn>>=1;sn>>=1;
  }
  return sn===0&&r===rootHex;
}
/* RFC 6962 §2.1.2 consistency verification (transparency.py parity): the
   proof that newRoot's tree extends oldRoot's. When the older size is an
   exact power of two the minimal proof omits the old root — the verifier
   knows it, so it is prepended. */
async function _conOk(oldRootHex,oldSize,newRootHex,newSize,pathHex){
  if(typeof oldRootHex!=="string"||!/^[0-9a-f]{64}$/i.test(oldRootHex)
    ||typeof newRootHex!=="string"||!/^[0-9a-f]{64}$/i.test(newRootHex))return false;
  oldRootHex=oldRootHex.toLowerCase();newRootHex=newRootHex.toLowerCase();
  if(!Number.isInteger(oldSize)||!Number.isInteger(newSize)
    ||oldSize>2147483647||newSize>2147483647)return false;
  /* non-array proof: {} reads "empty" under !{}.length — a dict literal would
     verify here while Python iterates keys and rejects; gate the shape. */
  if(pathHex!==undefined&&pathHex!==null&&!Array.isArray(pathHex))return false;
  if(oldSize===newSize)return(!pathHex||!pathHex.length)&&oldRootHex===newRootHex;
  if(oldSize<1||oldSize>=newSize||!pathHex||!pathHex.length)return false;
  const cat=(...a)=>{const n=a.reduce((t,x)=>t+x.length,0);const o=new Uint8Array(n);let p=0;
    for(const x of a){o.set(x,p);p+=x.length;}return o;};
  const path=(oldSize&(oldSize-1))===0?[oldRootHex,...pathHex]:pathHex.slice();
  let fn=oldSize-1,sn=newSize-1;
  while(fn&1){fn>>=1;sn>>=1;}
  let fr=path[0],sr=path[0];
  for(let i=1;i<path.length;i++){
    const c=path[i];
    if(!/^[0-9a-f]{64}$/i.test(c)||sn===0)return false;
    if((fn&1)||fn===sn){
      fr=await sha256hex(cat(new Uint8Array([1]),hex2b(c),hex2b(fr)));
      sr=await sha256hex(cat(new Uint8Array([1]),hex2b(c),hex2b(sr)));
      while(fn&&!(fn&1)){fn>>=1;sn>>=1;}
    }else sr=await sha256hex(cat(new Uint8Array([1]),hex2b(sr),hex2b(c)));
    fn>>=1;sn>>=1;
  }
  return sn===0&&fr===oldRootHex&&sr===newRootHex;
}
/* Python coercion parity: verify_extends evaluates whatever int()/fromhex()
   CAN interpret — a signed `first:"5"` still gets judged (and a bad proof
   convicts), never silently dropped to the fallback path the way a
   type-strict read would. Only truly unparseable material is absent. */
const _CIWS=new RegExp(
  "^[ \\t\\n\\r\\x0b\\f\\xa0\\u1680-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]*"+
  "[+-]?[0-9]+"+
  "[ \\t\\n\\r\\x0b\\f\\xa0\\u1680-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]*$");
function _pyInt(v){
  if(typeof v==="boolean")return v?1:0;
  if(typeof v==="number"&&Number.isInteger(v))return v;
  /* Whitespace = the JS-ws ∩ int()-strippable intersection (same class as
     transparency._COERCIBLE_INT): JS's whitespace class adds the BOM char
     int() won't strip, Python's adds \\x1c-\\x1f/\\x85 JS won't match —
     spelling it out pins both sides identical. */
  if(typeof v==="string"&&_CIWS.test(v))return parseInt(v,10);
  if(typeof v==="number"&&isFinite(v))return Math.trunc(v);
  return null;
}
/* Contiguous-hex decode matching transparency.hex_bytes — a spaced
   spelling must fail on EVERY surface the same way (the strictest
   spelling wins), so whitespace is rejected, never skipped. */
function _pyHex(s){
  if(typeof s!=="string"||!/^[0-9a-fA-F]+$/.test(s)||s.length%2)return null;
  return s.toLowerCase();
}
/* A checkpoint's embedded `extends` bridge — the issuer's signed attestation
   that this head extends the predecessor it names. Mirrors verify_extends:
   true/false when a bridge resolves, null when absent, malformed, or
   bridging a different ancestry than the caller asks about. */
async function _extOk(p,firstSize,firstRootHex){
  const ext=p&&p.extends;
  if(!ext||typeof ext!=="object")return null;
  const ef=_pyInt(ext.first),er=_pyHex(ext.first_root_sha256),
    size=_pyInt(p&&p.tree_size),root=_pyHex(p&&p.root_sha256);
  if(ef===null||er===null||size===null||root===null||!Array.isArray(ext.proof))return null;
  const nodes=ext.proof.map(h=>_pyHex(h));
  if(nodes.some(h=>h===null))return null;
  if(firstSize!=null&&ef!==firstSize)return null;
  if(firstRootHex!=null&&er!==String(firstRootHex).toLowerCase())return false;
  return await _conOk(er,ef,root,size,nodes);
}
/* A signed tree head — signature, lineage, and head shape. Mirrors
   logmonitor._check_sth: returns [payload|null, why|null]. */
async function _sthCheck(node,trustedSet){
  const cp=node?toJS(node):null;
  if(!cp||typeof cp!=="object")return[null,"checkpoint missing"];
  const p=cp.payload||{};
  if(p.record_type!=="log_checkpoint")return[null,"not a log_checkpoint receipt"];
  if(!trustedSet||!trustedSet.has(cp.public_key))
    return[null,"signed outside the issuer's certified lineage"];
  const rc=await checkReceipt(node);
  if(!rc.ok)return[null,"checkpoint signature invalid: "+rc.why];
  const size=p.tree_size,root=p.root_sha256;
  if(!Number.isInteger(size)||size<1||size>2147483647
    ||typeof root!=="string"||!/^[0-9a-f]{64}$/i.test(root))
    return[null,"malformed tree head"];
  return[p,null];
}
/* The live fork cross-check (logmonitor.live_check parity): the pack proves
   membership in A signed log — this asks whether that log is the one the
   deployment still serves everyone. Fetches the deployment's issuer doc and
   live head, verifies BOTH checkpoints under the live lineage, then compares:
   same head → agree; same size different root → an unforgeable fork; the
   live head ahead → its own signed `extends` bridge or a fetched consistency
   proof must bridge from the pack's head — a forked history cannot produce
   one. The only online step this page ever takes; say(cls,msg) renders. */
/* Same remote-trust policy as the CLI: loopback (127/8, ::1, localhost)
   may speak plain HTTP for local development; anything else must be
   HTTPS — an on-path attacker on cleartext could replay whichever signed
   head produces a false "agree". */
function isLoopHost(h){
  h=String(h||"").toLowerCase();
  if(h==="localhost"||h==="::1"||h==="[::1]")return true;
  const m=h.match(/^([0-9]+)[.]([0-9]+)[.]([0-9]+)[.]([0-9]+)$/);
  if(m)return +m[1]===127;
  return false;
}
/* Bodies are verification material, not trusted content — but an
   unbounded read is still a memory DoS, so stream with the same 4 MB
   bound the CLI enforces on every remote fetch. */
async function fetchCap(url){
  const big=()=>{const e=new Error("response exceeds the 4 MB bound");
    e.oversize=true;return e;};
  /* Same deadline as the Python fetches (timeout=15): a stalled endpoint
     must not hang the cross-check forever where the CLI reports it. */
  const r=await fetch(url,{signal:AbortSignal.timeout?AbortSignal.timeout(15000):undefined});
  if(!r.ok)throw new Error(url.split("/").pop()+" HTTP "+r.status);
  if(!r.body||!r.body.getReader){const t=await r.text();
    if(t.length>4194304)throw big();
    return t;}
  const rd=r.body.getReader(),parts=[];let n=0;
  for(;;){const c=await rd.read();if(c.done)break;
    n+=c.value.length;
    if(n>4194304){try{await rd.cancel();}catch(e){}
      throw big();}
    parts.push(c.value);}
  const all=new Uint8Array(n);let off=0;
  for(const p of parts){all.set(p,off);off+=p.length;}
  return new TextDecoder().decode(all);
}
async function liveCheck(base,say){
  if(!packStash){say("bad","no checkpoint in this pack to cross-check");return;}
  base=String(base||"").trim().replace(/[/]+$/,"");
  let bu;
  try{bu=new URL(base);}catch(e){say("bad","enter the deployment URL (https://… )");return;}
  if(bu.protocol!=="https:"&&!isLoopHost(bu.hostname)){
    say("bad","live cross-check requires HTTPS for remote deployments — "
      +"loopback excepted for local verification");return;}
  if(bu.protocol!=="https:"&&bu.protocol!=="http:"){
    say("bad","enter the deployment URL (https://… )");return;}
  say("","fetching the deployment's issuer document and live log head…");
  let docDn,headDn;
  try{
    docDn=parseKeep(await fetchCap(base+"/.well-known/attest-issuer.json"));
    headDn=parseKeep(await fetchCap(base+"/api/log/head"));
  }catch(e){
    if(e&&e.oversize){say("bad","live response is unusable ("+esc(e.message)
      +") — a deployment serving oversized verification material fails "
      +"closed, like the CLI's bound");return;}
    say("warn","live check unreachable ("+esc(e.message)+") — the offline "
      +"verification above still holds; the fork question just can't be "
      +"answered without the deployment");return;
  }
  const d=toJS(docDn)||{};
  if(d.schema!=="attest.issuer/1"||typeof d.issuer_key!=="string"){
    say("bad","live issuer document is not attest.issuer/1");return;}
  const kn=get(docDn,"key_receipts");
  if(kn&&kn.t!=="arr"){
    say("bad","live issuer document key_receipts is not a list");return;}
  const inodes=kn?kn.v:[];
  /* Same bound the CLI puts on the served document — the lineage walk is
     one signature verification per candidate per hop, so a hostile
     deployment can't serve a CPU amplifier as its identity document. */
  if(inodes.length>64){say("bad","live issuer document key_receipts exceeds "
    +"the 64-entry bound");return;}
  const liveTrusted=new Set([d.issuer_key,
    ...(await trustedKeys(d.issuer_key,inodes)),
    ...(await descendantKeys(d.issuer_key,inodes))]);
  /* Both heads are verified under the LIVE lineage — a pack checkpoint from
     some other issuer fails here, and so does a live head outside its own
     certified chain. */
  const pcErr=(await _sthCheck(packStash.node,liveTrusted))[1];
  if(pcErr){say("bad","pack checkpoint fails under the live lineage: "+esc(pcErr));return;}
  const liveCpNode=get(headDn,"checkpoint");
  if(!liveCpNode){say("warn","deployment serves no signed head — cannot cross-check");return;}
  const [lpay,lerr]=await _sthCheck(liveCpNode,liveTrusted);
  if(lerr){say("warn","live checkpoint does not validate ("+esc(lerr)
    +") — cannot cross-check");return;}
  const ps=packStash.size,pr=packStash.root,ls=lpay.tree_size,lr=lpay.root_sha256;
  if(ps===ls){
    if(pr===lr)say("ok",`pack's signed head IS the live head — tree size ${ps}: `
      +"the log this pack proves membership in is the one the deployment still serves");
    else say("bad",`FORK: pack and live heads both sign tree size ${ps} with different `
      +"roots — the deployment served this auditor a different log");
    return;
  }
  if(ps<ls){
    const emb=await _extOk(lpay,ps,pr);
    if(emb===true){say("ok",`live checkpoint's own signed bridge extends the pack's `
      +`head (${ps} → ${ls} leaves) — the pack's log is the one still served`);return;}
    if(emb===false){say("bad","FORK: the live checkpoint signs a bridge claiming the "
      +"pack's tree size but starting from a different root — split-view log");return;}
    let proof=null;
    try{
      proof=toJS(parseKeep(await fetchCap(`${base}/api/log/consistency?first=${ps}&size=${ls}`)));
    }catch(e){proof=null;}
    if(!proof||!Array.isArray(proof.proof)){
      say("bad","live head cannot bridge from the pack's head — the deployment cannot "
        +"show the pack's log inside the one it serves now");return;
    }
    /* Header strictness parity with logmonitor.check(): the response's
       first/tree_size must be JSON integers equal to the sizes requested —
       a proof answering a different question cannot stand in for this one. */
    if(!Number.isInteger(proof.first)||!Number.isInteger(proof.tree_size)
      ||proof.first!==ps||proof.tree_size!==ls){
      say("bad","served consistency proof is for different tree sizes than the "
        +"bridge requested — it cannot stand in for the pack's ancestry");return;
    }
    if(await _conOk(pr,ps,lr,ls,proof.proof))
      say("ok",`live log provably extends the pack's head (${ps} → ${ls} leaves) — `
        +"the pack's log is the one still served");
    else say("bad","FORK: the deployment's live log does not extend the head this "
      +"pack signed — the bridging consistency proof cannot be produced");
    return;
  }
  say("warn",`pack's signed head (size ${ps}) postdates the live head (${ls}) — the `
    +"pack may come from a newer or different log instance");
}
async function checkLog(byName,trustedSet,refs,bad,ok){
  /* log_checkpoint.json turns 'each receipt verifies' into 'each receipt was
     committed to the deployment's published log' — a signed tree head plus an
     inclusion path per member. Absent → a pre-checkpoint pack, reported not
     failed; present → every receipt must carry a working proof, so a receipt
     never committed to the log fails closed. Mirrors check_log/check_log_pin. */
  if(!byName["log_checkpoint.json"])return;
  let dn=null;
  try{dn=parseKeep(await byName["log_checkpoint.json"].text());}catch(e){}
  if(!dn){bad("log_checkpoint.json: not readable JSON");return;}
  const doc=toJS(dn)||{};const cp=doc.checkpoint,proofs=doc.proofs;
  if(!cp||typeof cp!=="object"||!proofs||typeof proofs!=="object"||Array.isArray(proofs)){
    bad("log_checkpoint.json: malformed checkpoint document");return;}
  const p=cp.payload||{};
  if(p.record_type!=="log_checkpoint"){bad("log_checkpoint.json: not a log_checkpoint receipt");return;}
  if(!trustedSet||!trustedSet.has(cp.public_key)){
    bad("log_checkpoint.json: signed outside the trusted issuer chain");return;}
  const cpNode=get(dn,"checkpoint");
  const rc=await checkReceipt(cpNode);
  if(!rc.ok){bad(`log_checkpoint.json: ${esc(rc.why)}`);return;}
  const size=p.tree_size,rootHex=p.root_sha256;
  if(!Number.isInteger(size)||size<1||size>2147483647
    ||typeof rootHex!=="string"||!/^[0-9a-f]{64}$/i.test(rootHex)){
    bad("log_checkpoint.json: malformed tree head");return;}
  /* The checkpoint's own signed continuity claim — a head whose embedded
     bridge fails verification is attesting a history it cannot prove; the
     standalone checkpoint path convicts the same way (verify_extends). */
  if((await _extOk(p))===false){
    bad("log_checkpoint.json: extends bridge attests a history it cannot prove");return;}
  /* Validated signed head — the live cross-check compares it against the
     head the deployment serves now. */
  packStash={node:cpNode,size,root:rootHex};
  let proven=0;const verifiedPh=new Set();
  for(const ref of refs||[]){
    if(!ref||!ref.payload_hash)continue;
    /* only issuer-lineage receipts owe proofs — a foreign pool entry is
       inert and never claimed log membership */
    if(!trustedSet.has(ref.public_key))continue;
    if(ref.payload_hash===cp.payload_hash)continue;  /* the STH anchors itself */
    const pr=proofs[ref.payload_hash];
    if(!pr||typeof pr!=="object"){
      bad(`log_checkpoint.json: receipt ${esc(String(ref.id||"?"))} has no inclusion `
        +"proof — never committed to the deployment log");continue;}
    if(!await _incOk(ref.payload_hash,size,pr.leaf_index,pr.path,rootHex)){
      bad(`log_checkpoint.json: inclusion proof for receipt ${esc(String(ref.id||"?"))} `
        +"does not reach the signed tree head");continue;}
    verifiedPh.add(ref.payload_hash);
    proven++;
  }
  /* Embedded evidence receipts (`attest checkpoint --include monitor:`):
     each must verify under the issuer lineage AND carry a proof reaching
     the signed head — CLI _verify_log_doc parity, every failure fatal. */
  /* receipts:null reads as absent on the Python surfaces (is-not-None gate). */
  if(doc.receipts!==undefined&&doc.receipts!==null){
    if(!Array.isArray(doc.receipts)||doc.receipts.length>2048){
      bad("log_checkpoint.json: 'receipts' must be a list of at most 2048");return;}
    const rsec=get(dn,"receipts"),rNodes=rsec&&rsec.t==="arr"?rsec.v:[];
    const seenIds=new Set();
    for(let i=0;i<doc.receipts.length;i++){
      const r=doc.receipts[i]||{};
      const rid=String(r.id||"?").slice(0,24);
      if(seenIds.has(r.id)){bad(`log_checkpoint.json: embedded receipt ${esc(rid)}… listed twice`);return;}
      seenIds.add(r.id);
      if(!trustedSet||!trustedSet.has(r.public_key)){
        bad(`log_checkpoint.json: embedded receipt ${esc(rid)}… signed outside the issuer lineage`);return;}
      const rc=await checkReceipt(rNodes[i]);
      if(!rc.ok){bad(`log_checkpoint.json: embedded receipt ${esc(rid)}… ${esc(rc.why)}`);return;}
      const pr=proofs[r.payload_hash];
      if(!pr||typeof pr!=="object"||!await _incOk(r.payload_hash,size,pr.leaf_index,pr.path||[],rootHex)){
        bad(`log_checkpoint.json: embedded receipt ${esc(rid)}… carries no working inclusion proof`);return;}
      verifiedPh.add(r.payload_hash);
      proven++;
    }
  }
  /* CLI parity: every proofs entry must verify — an unreferenced junk
     entry is a lie, not decoration. */
  for(const ph of Object.keys(proofs)){
    if(verifiedPh.has(ph))continue;
    const pr=proofs[ph];
    if(!pr||typeof pr!=="object"||!await _incOk(ph,size,pr.leaf_index,pr.path||[],rootHex)){
      bad(`log_checkpoint.json: unreferenced inclusion proof for ${esc(ph.slice(0,16))}… `
        +"does not reach the signed tree head");return;}
  }
  const {cosigs,anchored}=await _cosigReport(dn,doc,cp.id,size,rootHex,trustedSet,
    m=>bad(`log_checkpoint.json: ${m}`));
  if(proven)ok(`${proven} receipt(s) proven inside the deployment transparency `
    +`log at checkpoint size ${size}${cosigs?` — cosigned by ${cosigs} witness(es)`:""}`
    +`${anchored?` (${anchored} anchored in the witness's own published log)`:""}`);
}
/* Cosignature + self-anchor accounting for a checkpoint document — shared by
   the pack path (checkLog) and the standalone attest.log-checkpoint/1 path.
   Witness counter-signatures are auxiliary attestation — verified and counted,
   never the gate. The count tracks INDEPENDENT witnesses: duplicate receipts
   count once, repeat cosigs from one key count once, and a cosig signed inside
   the issuer's own lineage is self-vouching — not a witness. Packed anchors
   prove the cosig was committed to the witness's own published log; a present
   anchor that fails is a lie, not a downgrade. Mirrors _cosig_count /
   check_cosig_anchors. */
async function _cosigReport(dn,doc,cpId,size,rootHex,trustedSet,bad){
  let cosigs=0;const seenCosig=new Set(),seenKeys=new Set();
  const cosec=get(dn,"cosignatures"),coNodes=cosec&&cosec.t==="arr"?cosec.v:[];
  for(let i=0;i<(doc.cosignatures||[]).length;i++){
    const raw=doc.cosignatures[i]||{},cp2=raw.payload;
    if(!cp2||cp2.record_type!=="witness_cosignature")continue;
    if(cp2.subject_checkpoint!==cpId||cp2.subject_tree_size!==size
      ||cp2.subject_root_sha256!==rootHex)continue;
    /* the cosig must name THIS issuer — attesting another deployment's
       head never counts here (logmonitor parity) */
    if(trustedSet&&!trustedSet.has(cp2.subject_issuer))continue;
    const pk=raw.public_key;
    if(seenCosig.has(raw.id)||seenKeys.has(pk)||(trustedSet&&trustedSet.has(pk)))continue;
    const rc=await checkReceipt(coNodes[i]);
    if(rc.ok){seenCosig.add(raw.id);seenKeys.add(pk);cosigs++;}
  }
  let anchored=0;
  const asec=get(dn,"cosig_anchors");
  /* Python parity: a non-object cosig_anchors is absent, not hostile — but
     a present-and-broken anchor entry is a lie and fails closed. */
  const anchorsObj=(doc.cosig_anchors&&typeof doc.cosig_anchors==="object"
    &&!Array.isArray(doc.cosig_anchors))?doc.cosig_anchors:{};
  for(const cid of Object.keys(anchorsObj)){
    const anchor=anchorsObj[cid];
    const cosig=(Array.isArray(doc.cosignatures)?doc.cosignatures:[])
      .find(c=>c&&c.id===cid);
    if(!cosig){
      bad(`cosig_anchors ${esc(cid)} anchors a cosignature `
        +"the doc doesn't carry");continue;}
    const acp=anchor&&anchor.checkpoint,ap=acp&&acp.payload;
    if(!ap||ap.record_type!=="log_checkpoint"){
      bad(`cosig_anchors ${esc(cid)}: anchor is not a `
        +"log_checkpoint receipt");continue;}
    if(acp.public_key!==cosig.public_key){
      bad(`cosig_anchors ${esc(cid)}: anchor head not `
        +"signed by the cosig's own witness key");continue;}
    const anode=get(asec,cid);
    const arc=anode?await checkReceipt(get(anode,"checkpoint"))
      :{ok:false,why:"anchor checkpoint missing from canonical map"};
    if(!arc.ok){bad(`cosig_anchors ${esc(cid)}: ${esc(arc.why)}`);continue;}
    const proof=anchor.proof||{};
    if(!await _incOk(cosig.payload_hash,ap.tree_size,proof.leaf_index,proof.path||[],ap.root_sha256)){
      bad(`cosig_anchors ${esc(cid)}: the cosig does not reach `
        +"the anchor's signed tree head");continue;}
    anchored++;
  }
  return{cosigs,anchored};
}
async function verifyFiles(files){
  /* null-prototype map — a zip member literally named "__proto__" must land
     as an own key or the smuggle-member sweep (and Python's dict) see it. */
  if(_idxUrl){URL.revokeObjectURL(_idxUrl);_idxUrl=null;}
  _packCtx=null;
  /* packStash must reset HERE, not in go() — trysite/diffPacks call
     verifyFiles directly, and a stale checkpoint would keep arming the live
     cross-check with the previous pack's head. */
  packStash=null;
  _checked=0;_engWc=0;_engJs=0; /* engine counters are per-verify — a second
    drop must never inherit the first run's attribution line */
  const _t0=Date.now(); /* elapsed lands on the verdict stamp — the wait
    the live count narrated becomes a credibility detail, not dead time */
  const byName=Object.create(null);for(const f of files)byName[f.name]=f;
  const out=[];const say=(c,m)=>out.push(`<div class="row ${c}">${m}</div>`);
  const failedVids=[]; /* bundles that failed checkBundle — feeds the
    post-verdict "name what changed" comparison against the shipped clean pack */
  const text=async n=>byName[n]?await byName[n].text():null;
  const bundles=[];let mNode=null,manifest=null;
  /* Null-prototype: visit_id "__proto__" is a legal member name but a
     silently-ignored write on a plain object — it must compare, not poison. */
  let anyBad=false,key=null;const actual=Object.create(null);
  const mText=await text("manifest.json");
  if(issuerDoc&&!issuerDoc.nodes){
    /* Callers that assign the parsed doc directly (tests, tooling) skip the
       drop path's parseKeep — derive nodes here so either route arms. One
       caveat a file drop doesn't have: the parse→stringify round-trip
       respells floats (34.0→34), so a float-carrying lifecycle receipt's
       payload hash won't match and its link silently drops — fail closed.
       Dropping the doc FILE preserves canonical spellings and never respells. */
    issuerDoc={issuer_key:issuerDoc.issuer_key,
      nodes:(issuerDoc.key_receipts||[]).map(r=>parseKeep(JSON.stringify(r)))};
  }
  /* A lone signed receipt (verify-live report, anchor, any exported receipt
     JSON) verifies too — detect the receipt shape before the pack paths so
     `attest verify-live --sign --out report.json` drops straight onto this
     page. */
  if(!mText&&files.length===1&&/\\.json$/i.test(files[0].name)){
    const node=parseKeep(await files[0].text());
    const r=toJS(node)||{};
    /* A JSON array of receipts (the receipts index's "verify all" link drops
       demo-receipts.json here) verifies each element under the same
       single-receipt checks and reports the tally — one bad receipt fails
       the batch. */
    if(Array.isArray(r)){
      if(!node.v||!node.v.length){say("bad","receipt array is empty");return out.join("");}
      let pass=0;const fails=[];
      for(const el of node.v){
        const c=await checkReceipt(el);
        const ej=toJS(el)||{};
        if(c.ok)pass++;
        else fails.push(`${esc(String(ej.id||"?"))}: ${esc(c.why)}`);
      }
      say("ok",`${pass} receipt(s) verified — signatures and payload hashes intact`);
      for(const f of fails.slice(0,12))say("bad",f);
      if(fails.length>12)say("bad",`… and ${fails.length-12} more`);
      say(`stamp ${fails.length?"bad":"ok"}`,(fails.length
        ?`<strong>FAILED</strong> — ${fails.length} of ${node.v.length} receipts did not verify`
        :`<strong>VERIFIED</strong> — all ${pass} receipts intact`)
        +(packName?` · ${esc(packName)}`:""));
      return out.join("");
    }
    /* A standalone transparency evidence doc (`attest checkpoint --out`, or
       split-demo's divergence-checkpoint.json) verifies too — the same checks
       the CLI's _verify_log_doc runs: the checkpoint receipt verifies, every
       packed proof reaches its signed head, embedded receipts sit inside the
       lineage AND carry proofs, the self-bridge verifies, and cosig anchors
       fail closed. The armed pin (if any) supplies the lineage; otherwise the
       checkpoint's own key anchors it. */
    if(r.checkpoint&&typeof r.checkpoint==="object"&&!Array.isArray(r.checkpoint)){
      const cpNode=get(node,"checkpoint");
      const cp=r.checkpoint||{},cpay=cp.payload||{};
      if(cpay.record_type!=="log_checkpoint"){
        say("bad","checkpoint: not a log_checkpoint receipt");
        say(`stamp bad`,"<strong>FAILED</strong>"
          +(packName?` · ${esc(packName)}`:""));
        return out.join("");
      }
      let allowed=new Set([cp.public_key]);
      if(issuerDoc){
        const inodes=issuerDoc.nodes||[];
        allowed=new Set([issuerDoc.issuer_key,
          ...(await trustedKeys(issuerDoc.issuer_key,inodes)),
          ...(await descendantKeys(issuerDoc.issuer_key,inodes))]);
        say("warn",`pinned to the issuer document's deployment key `
          +`${esc(String(issuerDoc.issuer_key).slice(0,16))}…`);
        if(!allowed.has(cp.public_key)){
          say("bad","checkpoint signed by a key outside the pinned deployment's lineage");
          say(`stamp bad`,"<strong>FAILED</strong>"
            +(packName?` · ${esc(packName)}`:""));
          return out.join("");
        }
        if(suspectRecords([cpNode],await revokedKeys(inodes,issuerDoc.issuer_key)).length)
          say("warn","checkpoint signed inside its issuer's declared suspect window");
      }
      const crc=await checkReceipt(cpNode);
      if(!crc.ok)say("bad","checkpoint signature invalid: "+esc(crc.why));
      const size=cpay.tree_size,rootHex=cpay.root_sha256;
      let headOk=crc.ok;
      if(!Number.isInteger(size)||size<1||size>2147483647
        ||typeof rootHex!=="string"||!/^[0-9a-f]{64}$/i.test(rootHex)){
        say("bad","checkpoint carries a malformed root or size");headOk=false;}
      if(headOk){
        say("ok",`signed transparency head: tree size ${size}, root `
          +`${esc(String(rootHex).slice(0,16))}…`);
        packStash={node:cpNode,size,root:rootHex};
        /* proofs: absent means nothing to prove; non-object is a lie. Every
           entry must reach the signed head — unreferenced junk is not
           decoration. */
        let proofs=r.proofs;
        if(proofs===undefined||proofs===null)proofs={};
        if(typeof proofs!=="object"||Array.isArray(proofs)){
          say("bad","checkpoint document: 'proofs' must be an object");proofs=null;}
        if(proofs){
          let proven=0;
          for(const ph of Object.keys(proofs)){
            const pr=proofs[ph];
            if(!pr||typeof pr!=="object"
              ||!await _incOk(ph,size,pr.leaf_index,pr.path||[],rootHex)){
              say("bad",`inclusion proof for ${esc(String(ph).slice(0,16))}… fails `
                +"against this signed head — never committed there");
            }else proven++;
          }
          if(proven)say("ok",`${proven} packed inclusion proof(s) verified`);
          /* Embedded evidence receipts: each must verify, sit inside the
             lineage, and carry a proof — 'signed AND inside the head'. */
          const receipts=r.receipts;
          if(receipts!==undefined&&receipts!==null){
            if(!Array.isArray(receipts)||receipts.length>2048)
              say("bad","checkpoint document: 'receipts' must be a list of at most 2048");
            else{
              const rsec=get(node,"receipts"),rNodes=rsec&&rsec.t==="arr"?rsec.v:[];
              const seenIds=new Set();
              for(let i=0;i<receipts.length;i++){
                const rr=receipts[i]||{};
                const rid=String(rr.id||"?").slice(0,24);
                /* model_validate parity: a non-object entry is malformed,
                   not a dup — check shape before the id set. */
                if(typeof rr!=="object"||rr===null||Array.isArray(rr)){
                  say("bad",`embedded receipt ${esc(rid)}… malformed`);continue;}
                if(seenIds.has(rr.id)){say("bad",`embedded receipt ${esc(rid)}… listed twice`);continue;}
                seenIds.add(rr.id);
                if(!allowed.has(rr.public_key)){
                  say("bad",`embedded receipt ${esc(rid)}… signed by a key `
                    +"outside the issuer lineage");continue;}
                const rrc=await checkReceipt(rNodes[i]);
                if(!rrc.ok){say("bad",`embedded receipt ${esc(rid)}… invalid: ${esc(rrc.why)}`);continue;}
                if(!Object.prototype.hasOwnProperty.call(proofs,rr.payload_hash)){
                  say("bad",`embedded receipt ${esc(rid)}… carries no inclusion proof — `
                    +"'inside the signed head' is unproven");continue;}
                const rt=(rr.payload&&rr.payload.record_type)||"record";
                let extra="";
                if(rt==="monitor_observation"&&rr.payload.outcome)
                  extra=` — outcome: ${esc(String(rr.payload.outcome))}`;
                say("ok",`embedded receipt ${esc(rid)}… (${esc(rt)}): signed and `
                  +"inside the signed head"+extra);
              }
            }
          }
        }
        const selfExt=await _extOk(cpay);
        if(selfExt===false)
          say("bad","checkpoint's embedded `extends` bridge does not verify — "
            +"the signed head attests a history it cannot prove");
        else if(selfExt===true){
          const e=cpay.extends||{};
          say("ok",`embedded bridge extends checkpoint `
            +`${esc(String(e.checkpoint_id||"").slice(0,16))}… from size ${esc(String(e.first))}`);
        }
        const {cosigs,anchored}=await _cosigReport(node,r,cp.id,size,rootHex,allowed,
          m=>say("bad",m));
        if(cosigs)say("ok",`cosigned by ${cosigs} witness(es)`
          +(anchored?` — ${anchored} anchored in the witness's own published log`:""));
      }
      const dBad=out.some(l=>l.includes('class="row bad"'));
      say(`stamp ${dBad?"bad":"ok"}`,(dBad
        ?"<strong>FAILED</strong> — do not rely on this document"
        :"<strong>VERIFIED</strong> — signed transparency evidence intact")
        +(packName?` · ${esc(packName)}`:""));
      return out.join("");
    }
    if(r.signature&&r.payload_hash&&r.public_key&&r.payload){
      const c=await checkReceipt(node);
      const p=r.payload||{};
      if(issuerDoc){
        /* An armed pin applies to lone receipts too: the signer must sit
           inside the pinned deployment's signed lineage — a foreign receipt
           fails rather than verifying under its self-declared key. */
        const inodes=issuerDoc.nodes||[];
        const lin=new Set([issuerDoc.issuer_key,
          ...(await trustedKeys(issuerDoc.issuer_key,inodes)),
          ...(await descendantKeys(issuerDoc.issuer_key,inodes))]);
        say("warn",`pinned to the issuer document's deployment key `
          +`${esc(String(issuerDoc.issuer_key).slice(0,16))}…`);
        if(!lin.has(r.public_key)){
          say("bad","receipt signed by a key outside the pinned deployment's lineage");
          /* stamp class — the gauntlet reads .stamp to score verdicts; a plain
             bad row would render as "crashed mid-verify" there. */
          say(`stamp bad`,"<strong>FAILED</strong>");
          return out.join("");
        }
        if(suspectRecords([node],await revokedKeys(inodes,issuerDoc.issuer_key)).length)
          say("warn","receipt signed inside its issuer's declared suspect window");
      }
      if(p.record_type==="verification_report"){
        const s=p.summary||{};
        const cls=x=>x==="pass"?"ok":x==="fail"?"bad":x==="warn"?"warn":"muted";
        out.push(`<div class="row ${c.ok?"ok":"bad"}"><span class="pill">verification</span> `
          +`<strong>signed verify-live report</strong> — ${esc(p.generated_at||"")}<br>`
          +`<small>against <code>${esc(p.base_url||"")}</code> · `
          +`${esc(s.pass||0)} pass · ${esc(s.fail||0)} fail · ${esc(s.warn||0)} warn `
          +`· ${esc(s.skip||0)} skip</small></div>`);
        for(const chk of p.checks||[])
          say(cls(chk.status),`<span class="pill">${esc(chk.status||"?")}</span> ${esc(chk.check||"")}`
            +(chk.detail?` <small class="muted">— ${esc(String(chk.detail)).slice(0,160)}</small>`:""));
      }else
        say(c.ok?"ok":"bad",`receipt ${esc(r.id||"")} (${esc(p.record_type||"record")}): `
          +esc(c.why||(c.ok?"signature + chain links intact":"check failed")));
      say(`stamp ${c.ok?"ok":"bad"}`,`<strong>${c.ok?"VERIFIED":"FAILED"}</strong>`
        +(c.ok?" — this record is intact":" — this record was altered")
        +(packName?` · ${esc(packName)}`:""));
      return out.join("");
    }
  }
  let trusted=null;let revoked=Object.create(null);let suspectTotal=0;let lifecycleNodes=[];
  const logRefs=[];  /* pack-member receipts the transparency checkpoint must prove */
  /* Guarded manifest visit ids — populated inside the manifest walk, read by
     the member-sweep below; function-scoped so both blocks see it. */
  const seenVids=new Set();
  /* Issuer-doc pin: the doc's lifecycle receipts merge into the lineage pools
     and the doc's issuer_key becomes the pinned key — reachability through
     the signed rotation walk is enforced below (a doc naming an unrelated
     issuer fails closed rather than silently downgrading the pin). */
  let issuerNodes=[];
  if(issuerDoc){
    /* The doc's lifecycle receipts arrive as parseKeep nodes — canonical
       spellings preserved (a JSON.parse→stringify round-trip would respell
       34.0 as 34 and silently break the receipts' own payload hashes). */
    issuerNodes=issuerDoc.nodes||[];
    key=issuerDoc.issuer_key;
    say("warn",`pinned to the issuer document's deployment key ${esc(String(key).slice(0,16))}… `
      +`(${issuerNodes.length} lifecycle receipt(s)) — the pin's authenticity rides on how that `
      +"document reached you");
  }
  if(mText){
    mNode=parseKeep(mText);
    manifest=toJS(mNode)||{};
    /* Structural claims on the manifest itself — unsigned manifests have no
       hash-cover over these fields, so check them explicitly (the server-side
       verifier requires both). */
    if(manifest.schema!=="attest.case-pack/1"){
      anyBad=true;
      say("bad",`manifest: unsupported schema ${esc(String(manifest.schema||"?"))}`);
    }
    /* verify_case.py parity: visits must be a list (absent verifies nothing);
       attestations may be absent but never a non-list — a dict would crash
       for-of here and silently iterate keys on the Python surfaces. */
    if(!Array.isArray(manifest.visits)){
      anyBad=true;say("bad","manifest: visits is missing or not a list");
      manifest.visits=[];}
    if(manifest.attestations!==undefined&&manifest.attestations!==null&&
       !Array.isArray(manifest.attestations)){
      anyBad=true;say("bad","manifest: attestations is not a list");
      manifest.attestations=[];}
    say("ok",`manifest: ${esc(String(Number(manifest.visits?.length)||0))} visit(s)`);
    /* Rotation receipts travel as manifest-listed attestations — collect them
       before the bundle loop so the trusted issuer set spans the signed
       rotation chain (a pack exported after rotation mixes keys). */
    const rotNodes=[...issuerNodes];
    for(const a of manifest.attestations||[]){
      /* receipt_id names a zip member — inert-skip the malformed here; the
         attestation loop below fails the same entry (verify_case.py parity). */
      const rid=a&&typeof a==="object"?a.receipt_id:null;
      if(typeof rid!=="string"||!rid||rid.includes("/")||rid.includes("\\\\")||rid.includes(".."))
        continue;
      const at=await text(`attestations/${rid}.json`);
      if(!at)continue;
      const aNode=parseKeep(at);
      const art=((toJS(aNode)||{}).payload||{}).record_type;
      if(art==="key_rotation"||art==="key_adoption"||art==="key_revocation")rotNodes.push(aNode);
    }
    lifecycleNodes=rotNodes;
    trusted=await trustedKeys(manifest.issuer_key||"",rotNodes);
    if(issuerDoc){
      /* Pin enforcement: the doc's issuer must be reachable from the pack's
         declared issuer through the signed lifecycle — either direction
         (a newer doc pins a pre-rotation pack; an older doc still verifies a
         rotated deployment's newer packs). */
      const reach=new Set([manifest.issuer_key,...trusted,
        ...(await descendantKeys(manifest.issuer_key||"",rotNodes))]);
      if(!reach.has(issuerDoc.issuer_key)){
        anyBad=true;
        say("bad","issuer document pin has no signed link to this pack — wrong deployment?");
      }
    }
    revoked=await revokedKeys(rotNodes,manifest.issuer_key||"");
    for(const v of manifest.visits||[]){
      /* The manifest names member paths — verify_case.py parity: visit_id
         must be a safe single segment, and a duplicate listing fails (the
         Python verifiers and packdiff both reject it). */
      const vid=v&&typeof v==="object"?v.visit_id:null;
      if(typeof vid!=="string"||!vid||vid.includes("/")||vid.includes("\\\\")||vid.includes("..")){
        anyBad=true;say("bad",`manifest: malformed visit_id ${esc(String(vid))}`);continue;}
      if(seenVids.has(vid)){
        anyBad=true;say("bad",`manifest: visit_id ${esc(vid)} listed twice`);continue;}
      seenVids.add(vid);
      const t=await text(`visits/${vid}/bundle.json`);
      /* A manifest-listed bundle absent from the zip fails closed — the row is
         red AND the verdict fails; anything less fails open on a dropped record. */
      if(!t){anyBad=true;say("bad",`${esc(vid)}: bundle listed but missing from pack`);continue;}
      bundles.push([vid,parseKeep(t)]);
    }
  }else{
    const t=await text("bundle.json");
    if(!t)return"<div class='row bad'>no bundle.json or manifest.json in the selected files</div>";
    const root=parseKeep(t);
    const vid=(toJS(get(root,"original"))||{}).visit_id||"visit";
    bundles.push([vid,root]);
    /* key_rotations.json carries the signed pivot links — reviews appended
       after a rotation verify under the successor. Malformed content fails
       closed, mirroring verify_bundle.py. */
    const oKey=(toJS(get(root,"original"))||{}).public_key;
    const kt=await text("key_rotations.json");
    const rnV=[...issuerNodes];
    if(kt){
      const rn=get(parseKeep(kt),"rotations");
      if(!rn||rn.t!=="arr"){
        anyBad=true;say("bad","key_rotations.json: malformed");
      }else{
        /* Unsigned pool content: malformed members are inert-skipped inside
           the lineage walks (checkReceipt fails closed on them) — matching
           the embedded/CLI rule that only signed pivots extend trust. */
        rnV.push(...rn.v);
        /* Pack-member lifecycle receipts owe inclusion proofs; the issuer
           doc's external pin receipts do not — they never were members. */
        for(const rnN of rn.v){
          const rjs=toJS(rnN)||{};
          if(rjs.payload_hash)logRefs.push({id:rjs.id,payload_hash:rjs.payload_hash,public_key:rjs.public_key});
        }
      }
    }
    if(rnV.length){
      lifecycleNodes=rnV;
      trusted=new Set([
        ...(await trustedKeys(oKey,rnV)),
        ...(await descendantKeys(oKey,rnV)),
      ]);
      revoked=await revokedKeys(rnV,oKey);
      if(issuerDoc&&!trusted.has(issuerDoc.issuer_key)){
        anyBad=true;
        say("bad","issuer document pin has no signed link to this bundle — wrong deployment?");
      }
    }else if(issuerDoc&&issuerDoc.issuer_key!==oKey){
      anyBad=true;
      say("bad","issuer document pin has no signed link to this bundle — wrong deployment?");
    }
  }
  for(const[vid,root]of bundles){
    const oNode=get(root,"original");
    if(!key)key=toJS(get(oNode,"public_key"));
    const c=await checkBundle(root,trusted||key);
    if(!c.ok){anyBad=true;failedVids.push(vid);}
    const js=toJS(root)||{};
    /* Log leaves are the receipts-table chain — review entries anchor to the
       original's hash (verified by checkBundle), not to the log itself. */
    if(js.original&&js.original.payload_hash)
      logRefs.push({id:js.original.id,payload_hash:js.original.payload_hash,public_key:js.original.public_key});
    /* Revocation is a trust overlay — never a FAIL: count bundle records
       signed by a revoked key inside its declared suspect window and warn. */
    const revN=get(root,"reviews");
    const sN=suspectRecords(
      [oNode].concat((revN&&revN.t==="arr"?revN.v:[]).map(en=>get(en,"receipt"))),
      revoked).length;
    if(sN){suspectTotal+=sN;
      say("warn",`${esc(vid)}: ${sN} record(s) signed by a revoked issuer inside its suspect window`);}
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
    /* Python reads the marker via data.get — a parsed non-object marker
       (array/scalar) crashes → FAIL there; match it, don't silently ∅. */
    if(redT&&(rj===null||typeof rj!=="object"||Array.isArray(rj))){
      anyBad=true;
      say("bad",`${esc(vid)}: redaction.json is not an object`);
    }
    /* set() mirror: Python set() takes a dict's keys and a string's chars but
       raises on null/number/bool — the Python surfaces fail those, so _set
       returns null there and the compares below fail closed. Absent
       (undefined) is ∅; explicit null is the Python crash → fail. */
    const _set=x=>x===undefined?new Set()
      :Array.isArray(x)?new Set(x)
      :typeof x==="string"?new Set(x)
      :(x&&typeof x==="object"&&x!==null)?new Set(Object.keys(x))
      :null;
    const withheld=_set(rj?rj.withheld_digests:undefined);
    /* Media is matched by CONTENT hash, not filename — the pack stores files as
       media/<vid>/<label>.<digest-prefix>.png, mirroring _check_pack_bundle.
       Case packs nest under visits/<vid>/; single packs use media/ flat.
       Digests come only from the signed original payload — unsigned extra
       keys must not be able to inject "verified" media rows. */
    const mprefix=mNode?`visits/${vid}/media/`:"media/";
    const found=new Set();
    const dset=new Set(digests((js.original||{}).payload||{}));
    /* The marker file is unsigned — a withheld digest the signed evidence
       never names is itself suspicious (app.py:2367 / redaction_for). */
    if(withheld===null||[...withheld].some(d=>!dset.has(d))){
      anyBad=true;
      say("bad",`${esc(vid)}: redaction.json lists digests not in the signed evidence`);
    }
    /* The marker file is unsigned — the signed manifest's media_withheld list
       is the authority. If they disagree, a "withheld" claim may be masking a
       deletion: fail closed, mirroring _verify_case_pack. Compared even with
       no marker (withheld=∅) — an absent marker can't skip the compare. */
    if(manifest){
      const mv=(manifest.visits||[]).find(x=>x.visit_id===vid);
      const listed=_set(mv?mv.media_withheld:undefined);
      if(listed===null||listed.size!==(withheld||new Set()).size
         ||[...listed].some(d=>!withheld||!withheld.has(d))){
        anyBad=true;
        say("bad",`${esc(vid)}: manifest redaction list disagrees with redaction.json`);
      }
    }
    for(const name of Object.keys(byName)){
      if(name.startsWith(mprefix)&&!name.endsWith("/")){
        const h=await sha256hex(new Uint8Array(await byName[name].arrayBuffer()));
        /* A media member whose bytes don't hash to a signed digest is smuggled
           content riding inside the pack — fail it, don't silently skip it. */
        if(!dset.has(h)){
          anyBad=true;
          say("bad",`${esc(name)}: media not named by the signed evidence`);
          continue;
        }
        found.add(h);
      }
    }
    const wset=withheld||new Set();
    for(const d of digests((js.original||{}).payload||{})){
      if(wset.has(d)){say("warn",`  media ${esc(d.slice(0,12))}… withheld by redaction`);continue;}
      if(found.has(d))say("ok",`  media ${esc(d.slice(0,12))}… digest matches`);
      else{say("bad",`  media ${esc(d.slice(0,12))}… missing (not listed as withheld)`);anyBad=true;}
    }
  }
  if(mNode){
    const mc=await checkManifestNode(mNode,trusted||key);
    if(!mc.ok)anyBad=true;
    say(mc.ok?"ok":"bad",`manifest: ${esc(mc.why)}`);
    if(!manifest.issuer_key){
      anyBad=true;
      say("bad","manifest: missing issuer_key");
    }else if(trusted&&!trusted.has(manifest.issuer_key)){
      anyBad=true;
      say("bad","manifest: issuer_key outside the trusted rotation chain");
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
      /* Same member-name guard as verify_case.py: receipt_id must be a safe
         single segment — a malformed one fails the row, not a for-of crash. */
      const rid=a&&typeof a==="object"?a.receipt_id:null;
      if(typeof rid!=="string"||!rid||rid.includes("/")||rid.includes("\\\\")||rid.includes("..")){
        anyBad=true;say("bad",`attestation: malformed receipt_id ${esc(String(rid))}`);continue;}
      const at=await text(`attestations/${rid}.json`);
      if(!at){anyBad=true;say("bad",`attestation ${esc(rid)}: missing from pack`);continue;}
      const aNode=parseKeep(at);const rjs=toJS(aNode)||{};
      const aOut=trusted?!trusted.has(rjs.public_key):(key&&rjs.public_key!==key);
      if(aOut){
        anyBad=true;
        say("bad",`attestation ${esc(rid)}: key outside the trusted issuer chain`);continue;}
      const rc=await checkReceipt(aNode);
      if(!rc.ok){anyBad=true;say("bad",`attestation ${esc(rid)}: ${esc(rc.why)}`);continue;}
      if(rjs.id!==rid){
        anyBad=true;
        say("bad",`attestation ${esc(rid)}: filename disagrees with `+
          `the signed receipt id`);continue;}
      if(rjs.payload_hash!==a.payload_hash||rjs.visit_id!==a.visit_id){
        anyBad=true;say("bad",`attestation ${esc(rid)}: disagrees with signed manifest`);continue;}
      say("ok",`attestation ${esc(a.record_type||"record")}: signed and intact`);
      logRefs.push({id:rjs.id,payload_hash:rjs.payload_hash,public_key:rjs.public_key});
    }
    /* Fail closed on ANY file the signed manifest does not name — a smuggled
       top-level file or an extra member inside a listed visit dir would ride
       inside a VERIFIED pack. Media members are digest-checked per visit. */
    /* seenVids holds only the entries that passed the member-name guard —
       a malformed visit_id must never name an allowed path. */
    const vids=seenVids;
    const allowed=new Set(["manifest.json","README.txt","verify_case.py","verify.html","index.html",
      "verifier_manifest.json","log_checkpoint.json"]);
    for(const a of manifest.attestations||[])allowed.add(`attestations/${a.receipt_id}.json`);
    for(const v of vids){allowed.add(`visits/${v}/bundle.json`);allowed.add(`visits/${v}/redaction.json`);}
    for(const name of Object.keys(byName)){
      if(name.endsWith("/")||allowed.has(name))continue;
      const parts=name.split("/");
      if(parts.length>=4&&parts[0]==="visits"&&parts[2]==="media"&&vids.has(parts[1]))continue;
      anyBad=true;say("bad",`${esc(name)}: present but not in the signed manifest`);
    }
    await checkTools(byName,trusted||new Set([manifest.issuer_key||""]),
      `site:${(manifest.site||{}).id||""}`,
      m=>{anyBad=true;say("bad",m);},m=>say("ok",m));
    const sigR=(manifest.signature_receipt||{});
    if(sigR.payload_hash)logRefs.push({id:sigR.id,payload_hash:sigR.payload_hash,public_key:sigR.public_key});
    if(byName["verifier_manifest.json"]){
      const vmj=toJS(parseKeep(await byName["verifier_manifest.json"].text()))||{};
      if(vmj.payload_hash)logRefs.push({id:vmj.id,payload_hash:vmj.payload_hash,public_key:vmj.public_key});
    }
    await checkLog(byName,trusted||new Set([manifest.issuer_key||""]),logRefs,
      m=>{anyBad=true;say("bad",m);},m=>say("ok",m));
  }else{
    /* Single-visit dispute pack — the format names a fixed top-level set plus
       media/* (digest-checked above). */
    const allowed=new Set([
      "bundle.json","README.txt","verify_bundle.py","verify.html","index.html","redaction.json",
      "key_rotations.json","verifier_manifest.json","log_checkpoint.json"]);
    for(const name of Object.keys(byName)){
      if(name.endsWith("/")||allowed.has(name)||name.startsWith("media/"))continue;
      anyBad=true;say("bad",`${esc(name)}: present but not in the signed manifest`);
    }
    await checkTools(byName,trusted||new Set([key||""]),
      `visit:${bundles.length?bundles[0][0]:""}`,
      m=>{anyBad=true;say("bad",m);},m=>say("ok",m));
    if(byName["verifier_manifest.json"]){
      const vmj=toJS(parseKeep(await byName["verifier_manifest.json"].text()))||{};
      if(vmj.payload_hash)logRefs.push({id:vmj.id,payload_hash:vmj.payload_hash,public_key:vmj.public_key});
    }
    await checkLog(byName,trusted||new Set([key||""]),logRefs,
      m=>{anyBad=true;say("bad",m);},m=>say("ok",m));
  }
  /* A rotation signed by a key later declared suspect means the handoff
     itself may be attacker-authored — the lineage carries the doubt. */
  const pivotSuspect=suspectRecords(lifecycleNodes,revoked).length;
  if(pivotSuspect)
    say("warn",`${pivotSuspect} key-lifecycle receipt(s) signed inside a suspect `
      +"window — the trust pivot itself is qualified: the rotation receipts "
      +"verify, but they were signed during the compromised window");
  say(`stamp ${anyBad?"bad":"ok"}`,(anyBad
    ?"FAILED — do not rely on this pack"
    :"VERIFIED — chain intact under issuer key "+esc((key||"").slice(0,16))+"…"
      /* A pack that spans a key rotation verifies under more than one issuer —
         say so: the lineage is the signed pivot, not a weaker check. */
      +(trusted&&trusted.size>1
        ?` · ${trusted.size} issuer keys via the signed rotation chain`:""))
    +(packName?` · ${esc(packName)}`:"")
    +` · ${((Date.now()-_t0)/1000).toFixed(1)}s`
    /* Which signature engine answered — honest about the optimization, and
       the line doubles as proof nothing was skipped (the BigInt fallback is
       the same math, slower). Mixed runs name both: a WebCrypto "no" still
       pays the BigInt check, so unusual inputs can exercise both. */
    +(_engWc&&_engJs?` · signatures via WebCrypto Ed25519 + BigInt fallback`
      :_engWc?` · signatures via WebCrypto Ed25519`
      :_engJs?` · signatures via pure-JS BigInt Ed25519`:""));
  if(suspectTotal)
    /* Cold-reader gloss: the signature still holds — the warning marks the
       compromised window the records were signed in. Annotated, not hidden:
       this row is the product's honesty thesis in one line. */
    say("warn",`${suspectTotal} record(s) signed by a revoked issuer inside `
      +"its suspect window — still valid, signed during the compromised "
      +"window (annotated, not hidden)");
  /* Verified packs carry their own record browser — offer it only on a green
     verdict: a FAILED pack's narrative is untrusted and must not render. */
  if(!anyBad&&byName["index.html"]){
    try{
      const idx=await byName["index.html"].text();
      const url=_idxUrl=URL.createObjectURL(new Blob([idx],{type:"text/html"}));
      say("ok","this pack carries its own record browser — "
        +`<a href="${url}" target="_blank" rel="noopener" `
        +'aria-label="open index.html — the pack\u2019s record browser, in a new tab">'
        +"open index.html \u2197</a>"
        +" — it re-verifies every record and renders the timelines");
    }catch(e){/* no Blob URLs in this host — the verdict stands alone */}
  }
  /* A FAILED pack keeps its parsed members reachable for the post-verdict
     field-diff affordance: the signature proves the bytes moved, the compare
     names where. */
  _packCtx=(anyBad&&failedVids.length)?{byName,failedVids:[...failedVids]}:null;
  return out.join("");}
/* Post-verdict "name what changed": a FAILED verdict proves bytes moved —
   fetching the shipped clean pack and field-diffing the same signed bundle
   names *where*. Honest frame: the signature proves THIS pack was altered
   after signing; the comparison cannot say which copy is true. */
async function diagnoseTamper(){
  const out=document.getElementById("out");
  const note=(c,m)=>{if(out)out.insertAdjacentHTML("beforeend",
    `<div class="row ${c}">${m}</div>`);};
  const ctx=_packCtx;
  if(!ctx||!ctx.failedVids||!ctx.failedVids.length)return;
  note("warn","comparing against the shipped clean pack (sample-pack.zip)…");
  let cleanByName;
  try{
    const rsp=await fetch("sample-pack.zip");
    if(!rsp.ok){note("bad","clean pack unreachable over HTTP — the FAILED verdict stands alone");return;}
    const ents=await readZipEntries(new File([await rsp.arrayBuffer()],"sample-pack.zip"));
    cleanByName=Object.create(null);for(const f of ents)cleanByName[f.name]=f;
  }catch(e){note("bad","comparison fetch failed: "+esc(e.message||e));return;}
  for(const vid of ctx.failedVids){
    const mine=ctx.byName[`visits/${vid}/bundle.json`]||ctx.byName["bundle.json"];
    const clean=cleanByName[`visits/${vid}/bundle.json`];
    if(!mine||!clean){
      note("warn",`${esc(vid)}: no same-named bundle in the shipped clean pack`
        +" — its bytes can't be diffed (wrong deployment or new record)");
      continue;}
    try{
      const mo=(toJS(get(parseKeep(await mine.text()),"original"))||{}).payload||{};
      const co=(toJS(get(parseKeep(await clean.text()),"original"))||{}).payload||{};
      const ks=new Set([...Object.keys(co),...Object.keys(mo)]);let found=false;
      for(const k of ks){
        const a=JSON.stringify(co[k]===undefined?null:co[k]);
        const b=JSON.stringify(mo[k]===undefined?null:mo[k]);
        if(a!==b){found=true;
          const tr=s=>esc(s.length>72?s.slice(0,72)+"…":s);
          note("warn",`<code>${esc(k)}</code>: shipped clean pack reads `
            +`<code>${tr(a)}</code> · this pack reads <code>${tr(b)}</code>`);}
      }
      if(!found)note("warn",`${esc(vid)}: top-level payload fields agree`
        +" — the alteration sits in receipts, reviews, or raw bytes, not a named field");
    }catch(e){note("warn",`${esc(vid)}: diff failed — ${esc(e.message||e)}`);}
  }
  note("warn","the signature proves this pack's bytes differ from what was"
    +" signed — which copy is authentic is for the dispute to settle");
}
/* Two packs dropped together — the dispute story's natural endpoint: "the
   pack the agency produced for the hearing" vs "the pack I kept". Each is
   verified on its own merits first (a forged copy fails BEFORE any compare),
   then their signed membership is diffed: members only in one, shared members
   with different bytes, the signed field names inside differing bundles, and
   — decisive — the two signed log heads: same head, proven append-only
   growth, or a provable fork. Mirrored on packdiff._log_head_verdict. */
async function diffPacks(fileA,fileB,out){
  const say=(c,m)=>{out.innerHTML+="<div class='row "+c+"'>"+m+"</div>";};
  const nm=f=>esc(f.name);
  say("mut","two packs dropped — each is verified on its own merits, then "
    +"their signed contents are compared");
  let entA,entB;
  try{
    entA=await readZipEntries(fileA);
  }catch(e){say("bad","<strong>"+nm(fileA)+"</strong>: "+esc(e.message||e));return;}
  try{
    entB=await readZipEntries(fileB);
  }catch(e){say("bad","<strong>"+nm(fileB)+"</strong>: "+esc(e.message||e));return;}
  const byA=Object.create(null),byB=Object.create(null);
  for(const f of entA)byA[f.name]=f;
  for(const f of entB)byB[f.name]=f;
  /* Each pack's own verdict, preserved under a collapsible — the compare is
     meaningless if a copy already failed on its own. */
  for(const [label,ents] of [["A",entA],["B",entB]]){
    const html=await verifyFiles(ents);
    const det=document.createElement("details");
    const sum=document.createElement("summary");
    sum.innerHTML="pack "+label+" — its own verdict";
    det.appendChild(sum);
    const inner=document.createElement("div");
    inner.innerHTML=html
      .replace(/<button[^>]*>[\s\S]*?<\/button>/g,"")
      .replace(/<a [^>]*href="blob:[^"]*"[^>]*>([\s\S]*?)<\/a>/g,
        '<span class="mut">$1 (link expires with the live run)</span>');
    det.appendChild(inner);out.appendChild(det);
    const st=inner.querySelector(".stamp");
    say(st&&st.classList.contains("bad")?"bad":"mut",
      "pack "+label+" self-verdict: "+(st?esc(st.textContent.trim().slice(0,120))
        :"no verdict rendered"));
  }
  /* Membership diff. */
  const namesA=new Set(Object.keys(byA)),namesB=new Set(Object.keys(byB));
  const onlyA=[...namesA].filter(n=>!namesB.has(n)).sort();
  const onlyB=[...namesB].filter(n=>!namesA.has(n)).sort();
  const shared=[...namesA].filter(n=>namesB.has(n)).sort();
  const changed=[];
  for(const n of shared){
    const [ba,bb]=[await byA[n].arrayBuffer(),await byB[n].arrayBuffer()];
    if(ba.byteLength!==bb.byteLength){changed.push(n);continue;}
    const ua=new Uint8Array(ba),ub=new Uint8Array(bb);let same=true;
    for(let i=0;i<ua.length;i++)if(ua[i]!==ub[i]){same=false;break;}
    if(!same)changed.push(n);
  }
  /* Long membership lists (9 redaction markers, 9 media files) drown the one
     row that matters — cap with a "+N more" rollup, exact count intact. */
  const cap6=(list,tag)=>{for(const n of list.slice(0,6))
    say("warn","only in "+tag+": <code>"+esc(n)+"</code>");
    if(list.length>6)say("warn","only in "+tag+": +"+(list.length-6)+
      " more member(s)");};
  cap6(onlyA,"A");cap6(onlyB,"B");
  for(const n of changed){
    /* Name the signed fields when a bundle diverges — a byte-diff without
       the field reads as noise. */
    let fields="";
    if(/bundle\.json$/i.test(n)){
      try{
        const pa=(toJS(get(parseKeep(await byA[n].text()),"original"))||{}).payload||{};
        const pb=(toJS(get(parseKeep(await byB[n].text()),"original"))||{}).payload||{};
        const ks=new Set([...Object.keys(pa),...Object.keys(pb)]);const dif=[];
        for(const k of ks)
          if(JSON.stringify(pa[k]??null)!==JSON.stringify(pb[k]??null))dif.push(k);
        if(dif.length)fields=" — changed signed field(s): "+dif.slice(0,6)
          .map(k=>"<code>"+esc(k)+"</code>").join(", ")+(dif.length>6?", …":"");
      }catch(e){/* unreadable JSON — byte-diff alone still reported */}
    }
    say("bad","different bytes: <code>"+esc(n)+"</code>"+fields);
  }
  /* The two signed log heads — the decisive compare. Same head: identical
     evidence state. Bridge: proven append-only growth. Same-size different
     root: a provable fork — the issuer signed two histories. */
  let headLine=null;
  try{
    const ca=byA["log_checkpoint.json"],cb=byB["log_checkpoint.json"];
    if(!ca&&!cb)headLine=["mut","neither pack carries a signed log head — "
      +"membership is all that can be compared"];
    else if(!ca||!cb)headLine=["warn","only one pack carries a signed log head"
      +" — append-only growth cannot be proven"];
    else{
      /* The shipped document wraps the signed head: {checkpoint, proofs,…} —
         the receipt's payload carries tree_size/root_sha256/extends. */
      const pa=((toJS(get(parseKeep(await ca.text()),"checkpoint"))||{}).payload)||{};
      const pb=((toJS(get(parseKeep(await cb.text()),"checkpoint"))||{}).payload)||{};
      const sa=_pyInt(pa.tree_size),sb=_pyInt(pb.tree_size),
        ra=_pyHex(pa.root_sha256),rb=_pyHex(pb.root_sha256);
      if(sa===null||sb===null||ra===null||rb===null)
        headLine=["warn","a log head is malformed here — the pack's own "
          +"verdict above already flags it"];
      else if(sa===sb&&ra===rb)
        headLine=["ok","both exports commit to the same signed log head "
          +"(tree size "+sa+")"];
      else if(sa===sb)
        headLine=["bad","both exports carry size-"+sa+" log heads with "
          +"DIFFERENT roots — the issuer signed two histories at one tree "
          +"size: a provable fork"];
      else{
        /* The larger head's own signed extends bridge proves append-only —
           a smaller B is reported as drift: provably older, but that is the
           shape a rollback replay produces (packdiff parity). */
        const[bigP,bigS,bigR,smallS,smallR]=sb>sa?[pb,sb,rb,sa,ra]:[pa,sa,ra,sb,rb];
        const ext=await _extOk(bigP,smallS,smallR);
        if(sb>sa)
          headLine=ext===true?["ok","B's size-"+sb+" head provably extends "
            +"A's size-"+sa+" head via its own signed bridge — the log only "
            +"appended between these exports"]
            :ext===false?["bad","B's size-"+sb+" checkpoint's signed extends "
              +"bridge names A's size-"+sa+" head but does not reach it — "
              +"fork evidence inside the issuer's own proof material"]
              :["warn","B's head is larger ("+sb+" > "+sa+") but carries no "
                +"usable bridge — a later export or a regression, undecidable "
                +"offline"];
        else
          headLine=ext===true?["warn","B pins an EARLIER signed head (size "
            +sb+" < "+sa+") it provably extends — an older export, or a "
            +"replayed regression: offline these are indistinguishable"]
            :["warn","B pins an earlier signed head (size "+sb+" < "+sa
              +") with no bridge — older export or regression, undecidable "
              +"offline"];
      }
    }
  }catch(e){headLine=["warn","log-head compare failed: "+esc(e.message||e)];}
  const ident=!onlyA.length&&!onlyB.length&&!changed.length;
  if(headLine)say(headLine[0],headLine[1]);
  if(ident)
    say("stamp ok","<strong>IDENTICAL EVIDENCE</strong> — every member of both "
      +"packs is byte-for-byte the same");
  else{
    const sev=(changed.length||(headLine&&headLine[0]==="bad"))?"bad":"warn";
    say("stamp "+sev,"<strong>PACKS DIFFER</strong> — "+onlyA.length+
      " member(s) only in A · "+onlyB.length+" only in B · "+changed.length+
      " shared member(s) with different bytes");
    say("mut","honest reading: divergence is not automatically an attack — "
      +"a re-export a week later legitimately differs. The log-head line above "
      +"is what separates proven append-only growth from a provable fork, and "
      +"each pack's own verdict says whether either copy is already forged.");
  }
  /* The stamp lands ~30 rows down — bring it into view like the verdict
     path does. Direct children only: the per-pack <details> carry inner
     stamps that must not steal the scroll target. */
  try{
    let st=null;
    if(out.children)for(const ch of out.children)
      if(ch.classList&&ch.classList.contains&&ch.classList.contains("stamp"))
        st=ch;
    if(st&&st.scrollIntoView)
      st.scrollIntoView({behavior:"smooth",block:"nearest"});
  }catch(e){}
}
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
  let totalUncompressed=0,actualTotal=0;const seenNames=new Set();
  for(let e=0;e<n;e++){
    if(dv.getUint32(p,true)!==0x02014b50)throw new Error("corrupt central directory");
    const method=dv.getUint16(p+10,true),csize=dv.getUint32(p+20,true);
    const usize=dv.getUint32(p+24,true);
    /* Method first (BoundedZip reports it before the version): only
       stored/deflate exist in the shared envelope. */
    if(method!==0&&method!==8)
      throw new Error("unsupported compression method "+method+
        " — a member the verifier cannot read must fail, never vanish");
    /* ZIP64 sits outside the shared verification envelope — the same
       version-needed field BoundedZip rejects (>=45), plus the 0xFFFFFFFF
       sentinels a lazy writer could leave without raising the version. */
    const verNeed=dv.getUint16(p+6,true),lhoff0=dv.getUint32(p+42,true);
    if(verNeed>=45||csize===0xffffffff||usize===0xffffffff||lhoff0===0xffffffff)
      throw new Error("ZIP64 member exceeds the verification envelope");
    /* Bound total decompressed bytes — a small zip can expand unboundedly. */
    totalUncompressed+=usize;
    if(totalUncompressed>256*1024*1024)
      throw new Error("pack expands beyond the 256 MB verification bound");
    const nlen=dv.getUint16(p+28,true),elen=dv.getUint16(p+30,true),clen=dv.getUint16(p+32,true);
    const name=dec.decode(buf.slice(p+46,p+46+nlen));
    /* Same fail-closed rule as check_member_names: duplicate names are
       ambiguous across extractors, and ../absolute/drive segments escape the
       pack root or dodge prefix whitelists. Reject the pack, not the member. */
    if(seenNames.has(name))throw new Error(`duplicate member name: ${name}`);
    seenNames.add(name);
    if(name.split(/[\\\\/]/).includes("..")||/^[\\\\/]/.test(name)||name.includes(":"))
      throw new Error(`unsafe member name: ${name}`);
    const lnlen=dv.getUint16(lhoff0+26,true),lelen=dv.getUint16(lhoff0+28,true);
    const start=lhoff0+30+lnlen+lelen;
    const raw=buf.slice(start,start+csize);
    let data;
    if(method===0)data=raw;
    else if(method===8)data=await inflate(raw);
    else throw new Error("unsupported compression method "+method+
      " — a member the verifier cannot read must fail, never vanish");
    /* Per-member bound — BoundedZip.per_file: the cumulative cap alone
       would let one member claim the whole budget. */
    if(data.length>64*1024*1024)
      throw new Error("pack member expands beyond the 64 MB per-file bound");
    /* Declared usize can lie — bound ACTUAL decompressed bytes cumulatively
       too, else many small entries each under the per-member cap still
       inflate the tab into OOM. Mirrors packdiff.BoundedZip's seen counter. */
    actualTotal+=data.length;
    if(actualTotal>256*1024*1024)
      throw new Error("pack expands beyond the 256 MB verification bound");
    files.push({name,
      arrayBuffer:async()=>data.buffer.slice(data.byteOffset,data.byteOffset+data.byteLength),
      text:async()=>dec.decode(data)});
    p+=46+nlen+elen+clen;
  }
  return files;}
/* Tamper lab: a minimal stored-method zip writer — the lab rebuilds a real
   pack around the judge's doctored member so the verifier can refuse it. */
function crc32(u8){
  if(!crc32.t){const t=new Uint32Array(256);
    for(let n=0;n<256;n++){let c=n;
      for(let k=0;k<8;k++)c=(c&1)?(0xedb88320^(c>>>1)):(c>>>1);t[n]=c;}
    crc32.t=t;}
  let c=0xffffffff;
  for(let i=0;i<u8.length;i++)c=crc32.t[(c^u8[i])&0xff]^(c>>>8);
  return (c^0xffffffff)>>>0;}
function buildZip(entries){
  /* entries: [{name,u8}] — stored (method 0) members only; UTF-8 name flag
     set, timestamps zeroed, version 20 — inside the verifier's own
     non-ZIP64 envelope. */
  const enc2=new TextEncoder();let off=0;
  const parts=[],cent=[];
  for(const e of entries){
    const nb=enc2.encode(e.name),crc=crc32(e.u8),n=e.u8.length;
    const lh=new DataView(new ArrayBuffer(30));
    lh.setUint32(0,0x04034b50,true);lh.setUint16(4,20,true);
    lh.setUint16(6,0x0800,true);lh.setUint16(8,0,true);
    lh.setUint32(14,crc,true);lh.setUint32(18,n,true);lh.setUint32(22,n,true);
    lh.setUint16(26,nb.length,true);
    parts.push(new Uint8Array(lh.buffer),nb,e.u8);
    cent.push({nb,crc,n,off});
    off+=30+nb.length+n;
  }
  const cdOff=off;const cdparts=[];
  for(const c of cent){
    const ch=new DataView(new ArrayBuffer(46));
    ch.setUint32(0,0x02014b50,true);ch.setUint16(4,20,true);
    ch.setUint16(6,20,true);ch.setUint16(8,0x0800,true);
    ch.setUint16(10,0,true);ch.setUint16(12,0,true);ch.setUint16(14,0,true);
    ch.setUint32(16,c.crc,true);ch.setUint32(20,c.n,true);ch.setUint32(24,c.n,true);
    ch.setUint16(28,c.nb.length,true);ch.setUint32(42,c.off,true);
    cdparts.push(new Uint8Array(ch.buffer),c.nb);off+=46+c.nb.length;
  }
  const eo=new DataView(new ArrayBuffer(22));
  eo.setUint32(0,0x06054b50,true);eo.setUint16(8,cent.length,true);
  eo.setUint16(10,cent.length,true);eo.setUint32(12,off-cdOff,true);
  eo.setUint32(16,cdOff,true);
  const outb=new Uint8Array(off+22);let p=0;
  for(const b of[...parts,...cdparts,new Uint8Array(eo.buffer)]){outb.set(b,p);p+=b.length;}
  return outb;}
/* One verification at a time, period. go() owns the flag unless a caller
   (the gauntlet) already holds it — _force bypass is for the owner whose
   rounds must still reach verifyFiles. Every #out writer funnels here or
   checks the flag first; interleaved runs would erase each other's rows. */
let _busy=false;
async function go(fileList,_force){
  const out=document.getElementById("out");
  if(_busy&&!_force){
    /* A refused call is a dead click unless it says so — append (never wipe)
       a muted note so button-spam during a run reads as feedback, not
       silence. Deduped so it can't stack up under repeated clicks. */
    const o=out||document.getElementById("out");
    if(o&&!(o.querySelector&&o.querySelector(".busy-note")))
      o.insertAdjacentHTML("beforeend",
        "<div class='row mut busy-note'>a verification is already running "
        +"— this click was ignored</div>");
    return;}
  const _owned=!_busy;if(_owned)_busy=true;
  try{
    let files=[...fileList];if(!files.length)return;
    packStash=null;  /* a fresh drop re-arms the live check's subject */
    /* A fresh doc replaces the armed pin; the pin persists across drops so a
       reviewer can arm it once and check several packs. */
    let freshDoc=null,multiDoc=false;
    const rest=[];
    for(const f of files){
      /* An attest.issuer/1 document among the drops pins verification to the
         deployment it came from — remove it from the pack's member list so it
         can't be mistaken for smuggled content. Only a LOOSE drop counts:
         inside a folder pick (webkitRelativePath is set for every member) a
         doc is pack content — verify_case.py fails it as an unlisted member,
         so the browser must too rather than silently arming the pin. */
      if(/\\.json$/i.test(f.name||"")&&!f.webkitRelativePath){
        try{
          const dn=parseKeep(await f.text()),d=toJS(dn);
          if(d&&d.schema==="attest.issuer/1"&&typeof d.issuer_key==="string"){
            const kn=get(dn,"key_receipts");
            /* Same intake rules as the CLI/fetch paths: a non-list or
               >64-entry key_receipts is a malformed document — fall through
               to the verify set rather than arming a pin on junk. */
            if(!kn||kn.t==="arr"&&kn.v.length<=64){
              if(freshDoc)multiDoc=true;
              freshDoc={issuer_key:d.issuer_key,nodes:kn?kn.v:[]};
              continue;}}
        }catch(e){/* ordinary pack JSON — stays in the verify set */}
      }
      rest.push(f);
    }
    if(freshDoc)issuerDoc=freshDoc;
    files=rest;
    if(issuerDoc&&!files.length){
      out.innerHTML="<div class='row warn'>issuer document armed — the pin now applies to the "
        +"next pack you drop. Its authenticity rides on how the document reached you.</div>"
        +(multiDoc?"<div class='row warn'>multiple issuer documents dropped — armed the last one.</div>":"");
      return;
    }
    packName="";
    if(files.length===1&&/\\.(zip|json)$/i.test(files[0].name))packName=files[0].name;
    /* Two packs dropped together is a COMPARE, not two verifies: the dispute
       story is "the copy they produced" vs "the copy I kept" — verify each,
       then diff what their signatures commit to (packdiff in the browser). */
    if(files.length===2&&files.every(f=>/\\.zip$/i.test(f.name))){
      out.innerHTML="";
      await diffPacks(files[0],files[1],out);
      /* The last-verified head (pack B's) is the live cross-check's subject —
         same reveal rule as a single-pack drop. */
      const lw=document.getElementById("live-wrap");
      if(lw)lw.hidden=!packStash;
      return;
    }
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
    try{
    /* Cite the verdict verbatim — a judge can paste the exact stamp + detail
       rows into notes or an issue. Text only; the verdict is claims, not a
       signed artifact itself. Post-render affordances are best-effort: the
       conformance harness runs this under node with a stub document, and
       nothing here may corrupt a rendered verdict. */
    if(typeof navigator!=="undefined"&&navigator.clipboard&&navigator.clipboard.writeText){
      const cp=document.createElement("button");
      cp.className="copybtn";cp.textContent="copy verdict";
      cp.onclick=async()=>{try{
        await navigator.clipboard.writeText(out.innerText);
        cp.textContent="copied";setTimeout(()=>cp.textContent="copy verdict",1600);
      }catch(e){cp.textContent="copy failed";}};
      out.appendChild(cp);}
    /* The verdict as a document — a transcript a mediator or reviewer can
       file. Plain text and explicitly unsigned: anyone can type one, so the
       header says what it is and where the real evidence lives. */
    try{
      const dl=document.createElement("button");
      dl.className="copybtn";dl.textContent="download report";
      dl.onclick=()=>{try{
        const head="Attest verification transcript\\n"
          +"page: "+location.href.split("#")[0]+"\\n"
          +"when: "+new Date().toISOString()+"\\n"
          +"NOTE: unsigned transcript produced by the verifier page — anyone\\n"
          +"can type one; the evidence is the pack. Reproduce independently\\n"
          +"with the pack's verify_case.py or `attest verify`.\\n\\n";
        const b=new Blob([head+out.innerText],{type:"text/plain"});
        const a=document.createElement("a");
        a.href=URL.createObjectURL(b);a.download="verification-report.txt";
        a.click();setTimeout(()=>URL.revokeObjectURL(a.href),4000);
        dl.textContent="downloaded";setTimeout(()=>dl.textContent="download report",1600);
      }catch(e){dl.textContent="download failed";}};
      out.appendChild(dl);
    }catch(e){/* no Blob/URL host — copy still works */}
    /* FAILED + signed fields present + served over HTTP → offer the field-diff
       against the shipped clean pack. The stamp says the bytes moved; this
       names where. file:// has no sibling to fetch, so the offer stays
       hidden rather than dead-clicking. */
    try{
      if(_packCtx&&_packCtx.failedVids.length&&location.protocol.indexOf("http")===0){
        const dg=document.createElement("button");
        dg.className="copybtn";dg.textContent="name what changed";
        /* diagnoseTamper awaits several fetches then appends rows to #out —
           hold _busy across the whole diagnosis or a drop mid-compare both
           wipes the rows it already wrote and lets the late rows land on the
           new verdict. */
        dg.onclick=async()=>{if(_busy)return;
          dg.disabled=true;dg.textContent="comparing…";_busy=true;
          try{await diagnoseTamper();dg.textContent="compared";}
          catch(e){dg.textContent="compare failed";}
          finally{_busy=false;}};
        out.appendChild(dg);}
    }catch(e){/* affordance only */}
    /* Move focus+scroll to the verdict — the stamp lands last and a keyboard
       user at the button shouldn't have to hunt for it. */
    if(out.setAttribute){out.setAttribute("tabindex","-1");if(out.focus)out.focus();}
    }catch(e){/* non-DOM host — the verdict above already stands */}
    /* A pack with a validated signed head can answer the fork question —
       reveal the live cross-check; a checkpoint-less pack cannot. */
    const lw=document.getElementById("live-wrap");
    if(lw)lw.hidden=!packStash;
  }catch(e){out.innerHTML="<div class='row bad'>verifier error: "+esc(e.message)+"</div>";}
  finally{if(_owned)_busy=false;}}
const dz=document.getElementById("drop");
dz.ondragover=e=>{e.preventDefault();dz.classList.add("over");};
dz.ondragleave=()=>dz.classList.remove("over");
dz.ondrop=e=>{e.preventDefault();dz.classList.remove("over");
  if(_busy)return;go(e.dataTransfer.files);};
document.getElementById("pick").onchange=e=>{if(!_busy)go(e.target.files);};
document.getElementById("pickdir").onchange=e=>{if(!_busy)go(e.target.files);};
const _lgo=document.getElementById("livego");
if(_lgo)_lgo.onclick=async()=>{if(_busy)return;_busy=true;try{
  /* packStash is the subject — a mid-check drop must not swap it out. */
  await liveCheck(document.getElementById("liveurl").value,
  (c,m)=>{document.getElementById("liveout").innerHTML="<div class='row "+c+"'>"+m+"</div>";});
  }finally{_busy=false;}};
/* file:// copies can't fetch — every hosted feature below stays hidden.
   An unconsumed deep link must say why instead of dying silently. */
if(location.protocol.indexOf("http")!==0&&location.hash.length>1){
  const _h=location.hash.slice(1);
  if(/^(tamper-lab|verify-self|verify-site|sample-pack|demo-receipts|vectors|anchor-demo|live-sweep-receipt|divergence-checkpoint|gauntlet|compare-packs)/.test(_h))
    document.getElementById("out").innerHTML="<div class='row warn'>"+
      "This copy is running as a local file — the one-click demos named by "+
      "#"+esc(_h)+" need a hosted copy, which can fetch its sibling files. "+
      "Verification itself still works: drop a pack above.</div>";
}
/* Hosted copies (Pages, a deployment's /verify-pack) sit next to
   sample-pack.zip — offer one-click verification. file:// embedded copies
   can't fetch; the button stays hidden. */
if(location.protocol.indexOf("http")===0){
  /* The "New here?" row links siblings only the hosted site ships — inside an
     extracted pack it would 404, so it stays hidden off-http. */
  const _nh=document.getElementById("newhere");if(_nh)_nh.hidden=false;
  /* Served by a deployment (its /verify-pack page), the base URL is already
     known — prefill it so the cross-check is one click. A hosted copy (Pages)
     isn't a deployment: the probe 404s and the field stays a placeholder. */
  fetch("/.well-known/attest-issuer.json",{method:"HEAD"}).then(r=>{
    if(r.ok)document.getElementById("liveurl").value=location.origin;
  }).catch(()=>{});
  /* The bundled sample plus its attack gallery — one button per attack, each
     caught by a different layer of the verifier. Absent files just leave
     their buttons hidden. */
  const _samples=[
    ["sample-pack.zip","trysample"],
    ["sample-pack-tampered.zip","trytamper"],
    ["sample-pack-attack-missing-record.zip","tryatk1"],
    ["sample-pack-attack-smuggled-file.zip","tryatk2"],
    ["sample-pack-attack-forged-verifier.zip","tryatk3"],
    ["live-sweep-receipt.json","tryreceipt"],
    ["divergence-checkpoint.json","tryfork"],
  ];
  /* A claimed-but-unhosted deep link must say so — #sample-pack on a copy
     that doesn't serve the zip otherwise renders nothing at all. Neither it
     nor a fetch-failure row may stomp a verification in progress: write only
     when #out is idle. */
  const _failOut=(msg)=>{const o=document.getElementById("out");
    if(_busy||!o)return;o.innerHTML=msg;};
  const _miss=(file)=>{_failOut("<div class='row warn'>this copy doesn't serve "
      +"<code>"+esc(file)+"</code> — the deep link named a hosted one-click "
      +"demo. Drop the file itself above to verify it anyway.</div>");};
  for(const [file,bid] of _samples){

    fetch(file,{method:"HEAD"}).then(r=>{
      if(!r.ok){
        if(location.hash==="#"+file.replace(/\.(zip|json)$/,""))_miss(file);
        return;}
      document.getElementById(bid+"-wrap").hidden=false;
      if(bid==="tryatk1"){const h=document.getElementById("tryatk-hint");
        if(h)h.hidden=false;}
      document.getElementById(bid).onclick=async()=>{
        /* A mid-run click would interleave writes into the scratch #out —
           _busy covers go() runs; dataset.running covers the gauntlet span. */
        const _g=document.getElementById("gauntlet-out");
        if(_busy||(_g&&_g.dataset.running))return;
        try{
          /* Put the deep-link in the bar — the verdict URL is shareable. */
          history.replaceState(null,"",location.pathname+"#"+file.replace(/\\.(zip|json)$/,""));
          const buf=await(await fetch(file)).arrayBuffer();
          go([new File([buf],file)]);
        }catch(e){
          _failOut("<div class='row bad'>sample fetch failed: "+esc(e.message)+"</div>");
        }
      };
      /* verify.html#sample-pack-tampered deep-links straight to a verdict —
         the landing page uses it so one click is the whole demo. */
      if(location.hash.length>1&&(file===location.hash.slice(1)+".zip"
        ||file===location.hash.slice(1)+".json"))
        document.getElementById(bid).click();
    }).catch(()=>{});
  }
  /* The gauntlet: one click verifies everything this page ships, in oracle
     order, and scores agreement. The whole demo — the green, the doctored
     twin, the three-layer attack gallery, the real-API sweep, the signed
     fork, the Bitcoin anchor — as a single stream. Each round's full
     verdict detail is preserved under a collapsible, so nothing is lost.
     While it runs, #out is an off-screen scratch — eight full verdicts
     would flood the polite live region and steal focus eight times; the
     accessible record lands once in #gauntlet-out. */
  async function gauntlet(){
    const gout=document.getElementById("gauntlet-out"),out=
      document.getElementById("out"),live=document.getElementById("live-wrap");
    if(!gout||!out||gout.dataset.running||_busy)return;
    gout.dataset.running="1";_busy=true;gout.innerHTML="";out.innerHTML="";
    /* The stream lands below the click — bring it into view or the first
       two rounds print above the fold a judge is watching. */
    try{gout.scrollIntoView({behavior:"smooth",block:"nearest"});}catch(e){}
    const gb=document.getElementById("trygauntlet");
    if(gb)gb.disabled=true;
    /* The verdict URL is shareable like every other demo's. */
    try{history.replaceState(null,"",location.pathname+"#gauntlet");}catch(e){}
    const _role=out.getAttribute("role"),_al=out.getAttribute("aria-live"),
      _focus=out.focus?out.focus.bind(out):null;
    out.removeAttribute("role");out.setAttribute("aria-hidden","true");
    if(_focus)out.focus=()=>{};
    /* An issuer doc pinned earlier in the session must not re-scope the
       oracle's artifacts — the gauntlet scores self-declared verification.
       Restored in finally with everything else. */
    const _savedIssuer=issuerDoc;issuerDoc=null;
    const seq=[
      ["sample-pack.zip","VERIFIED"],
      ["sample-pack-tampered.zip","FAILED"],
      ["sample-pack-attack-missing-record.zip","FAILED"],
      ["sample-pack-attack-smuggled-file.zip","FAILED"],
      ["sample-pack-attack-forged-verifier.zip","FAILED"],
      ["live-sweep-receipt.json","VERIFIED"],
      ["divergence-checkpoint.json","VERIFIED — the signed fork evidence"],
      ["anchor-demo.json","VERIFIED — the Bitcoin-anchored head"],
    ];
    let agree=0,ran=0;
    /* Restore in finally — a surprise throw mid-run must not leave the live
       region silenced, the button dead, and the busy flag wedged. */
    try{
      for(const [f,expect] of seq){
        const row=document.createElement("div");
        row.className="row mut";row.textContent="checking "+f+"…";
        gout.appendChild(row);
        if(live)live.hidden=true; /* per-pack live sections don't apply mid-run */
        try{
          const resp=await fetch(f);
          if(!resp.ok)throw new Error("HTTP "+resp.status);
          const buf=await resp.arrayBuffer();
          await go([new File([buf],f)],true); /* we hold _busy for the run */
          const stamp=out.querySelector(".stamp");
          ran++;
          if(!stamp){
            /* A crashed render is never oracle agreement — expected FAIL or
               not, no verdict means the verifier didn't speak. */
            row.className="row bad";
            row.innerHTML="<strong>"+esc(f)+"</strong> — crashed mid-verify, "
              +"no verdict rendered <span class='mut'>(oracle: "+esc(expect)+")</span>";
            continue;
          }
          const ok=stamp.classList.contains("ok");
          const agreed=ok===!expect.startsWith("FAILED");
          if(agreed)agree++;
          /* Row colour codes AGREEMENT, not the artifact verdict — green when
             the verdict landed where the oracle put it (a caught forgery is a
             correct catch), red only when they disagree. */
          row.className="row "+(agreed?"ok":"bad");
          row.innerHTML="<strong>"+esc(f)+"</strong> — "+
            esc(stamp.textContent.trim().slice(0,140))+
            " <span class='mut'>(oracle: "+esc(expect)+")</span>";
          const det=document.createElement("details");
          const sum=document.createElement("summary");
          sum.className="mut";sum.textContent="full verdict detail";
          det.appendChild(sum);
          const inner=document.createElement("div");
          /* Serialized innerHTML loses every wired handler, and blob: URLs die
             when the next round revokes them — strip the affordances so the
             archive contains no dead controls. */
          inner.innerHTML=out.innerHTML
            .replace(/<button[^>]*>[\s\S]*?<\/button>/g,"")
            .replace(/<a [^>]*href="blob:[^"]*"[^>]*>([\s\S]*?)<\/a>/g,
              '<span class="mut">$1 (link expires with the live run)</span>');
          det.appendChild(inner);gout.appendChild(det);out.innerHTML="";
        }catch(e){
          /* ran stays put — an artifact that couldn't even be fetched lands in
             the "N artifact(s) couldn't even be fetched" verdict branch, not
             the "a verdict disagreed" one. */
          row.className="row bad";
          row.innerHTML="<strong>"+esc(f)+"</strong> — fetch/verify failed: "+
            esc(e.message)+" <span class='mut'>(oracle: "+esc(expect)+")</span>";
        }
      }
      const verdict=document.createElement("div");
      const allOk=agree===seq.length;
      verdict.className="row stamp "+(allOk?"ok":"bad");
      verdict.innerHTML="ORACLE AGREEMENT "+agree+"/"+seq.length+" — "+
        (allOk
          ?"every verdict landed where the shared oracle put it"
          :ran<seq.length
            ?(seq.length-ran)+" artifact(s) couldn't even be fetched — "+
              "check hosting before trusting any agreement"
            :"a verdict disagreed with the oracle — that itself is the finding");
      gout.appendChild(verdict);
    }finally{
      issuerDoc=_savedIssuer;
      if(_role!=null)out.setAttribute("role",_role);
      out.removeAttribute("aria-hidden");
      if(_al!=null)out.setAttribute("aria-live",_al);
      if(_focus)out.focus=_focus;
      if(gb)gb.disabled=false;
      delete gout.dataset.running;_busy=false;
    }
  }
  /* Offer the button only when the page is actually hosted (file:// fetch
     is dead) — and #gauntlet runs it on load. */
  if(location.protocol.startsWith("http")){
    const gb=document.getElementById("trygauntlet-wrap");
    if(gb){gb.hidden=false;
      document.getElementById("trygauntlet").onclick=gauntlet;
      if(location.hash==="#gauntlet")gauntlet();}
  }
  /* Per-receipt deep links: #demo-receipts/rcpt_<hex> fetches a lone signed
     receipt the site ships (the receipts index links each row here) — the
     lone-file path verifies its signature the same way it does the sweep
     report. #demo-receipts (bare) fetches the whole array and verifies all
     array at once. Same-origin fetch only; the pattern pins it to receipts. */
  const _rm=location.hash.match(/^#demo-receipts(?:\\/(rcpt_[0-9a-f]{4,64}))?$/);
  if(_rm){
    const path=_rm[1]?`demo-receipts/${_rm[1]}.json`:"demo-receipts.json";
    fetch(path).then(async r=>{
      if(!r.ok){_failOut(
        "<div class='row bad'>deep link failed: <code>"+esc(path)+
        "</code> returned HTTP "+r.status+"</div>");return;}
      const buf=await r.arrayBuffer();
      go([new File([buf],path.split("/").pop())]);
    }).catch(e=>{_failOut(
      "<div class='row bad'>deep link failed: "+esc(e.message)+"</div>");});
  }
  /* The Bitcoin-anchored journal head: #anchor-demo verifies the signed
     anchor receipt the landing links — the .ots proof is a sidecar the
     browser can't complete, so the row names the honest limit. */
  /* #compare-packs / the compare button: the clean pack vs its doctored twin,
     fetched and diffed — the whole dispute in one click: the twin verifies
     FAILED on its own, the diff names observed_span_minutes as the moved
     field, and the signed heads prove the log only appended between the two
     exports. */
  const comparePacks=async()=>{
    const out=document.getElementById("out");
    /* diffPacks writes #out for ~seconds — hold the flag or a mid-compare
       drop interleaves a whole second verdict into the report. */
    if(_busy)return;_busy=true;
    try{
    out.innerHTML="<p>fetching both packs for comparison…</p>";
    const fa=fetch("sample-pack.zip").then(r=>{
      if(!r.ok)throw new Error("sample-pack.zip HTTP "+r.status);
      return r.arrayBuffer().then(b=>new File([b],"sample-pack.zip"));});
    const fb=fetch("sample-pack-tampered.zip").then(r=>{
      if(!r.ok)throw new Error("sample-pack-tampered.zip HTTP "+r.status);
      return r.arrayBuffer().then(b=>new File([b],"sample-pack-tampered.zip"));});
    const[a,b]=await Promise.all([fa,fb]);
    out.innerHTML="";
    await diffPacks(a,b,out);
    }catch(e){
      out.innerHTML="<div class='row bad'>compare link failed: "+
        esc(e.message||e)+"</div>";
    }finally{_busy=false;}
  };
  /* The button shows only where fetches can succeed — http gate, same as the
     gauntlet. */
  if(location.protocol.startsWith("http")){
    const cw=document.getElementById("trycompare-wrap");
    if(cw){cw.hidden=false;
      document.getElementById("trycompare").onclick=()=>{
        if(_busy)return;
        try{history.replaceState(null,"",location.pathname+"#compare-packs");}
        catch(e){}
        comparePacks();};}
  }
  if(location.hash==="#compare-packs")comparePacks();
  if(location.hash==="#anchor-demo"){
    fetch("anchor-demo.json").then(async r=>{
      if(!r.ok){_failOut(
        "<div class='row bad'>deep link failed: <code>anchor-demo.json</code>"+
        " returned HTTP "+r.status+"</div>");return;}
      const buf=await r.arrayBuffer();
      /* go() refuses mid-run — and then this .ots note would land on someone
         else's verdict. Checking first predicts exactly whether go ran. */
      if(_busy)return;
      await go([new File([buf],"anchor-demo.json")]);
      const out=document.getElementById("out");
      if(out){
        const note=document.createElement("div");
        note.className="row mut";
        note.innerHTML="anchor-demo.json.ots rides alongside — a real "+
          "OpenTimestamps submission over this file's digest (pending the "+
          "calendar's Bitcoin commit). This page verifies the signed receipt; "+
          "<code>ots verify</code> or <code>attest verify</code> completes the "+
          "timestamp proof.";
        /* The copy/download buttons append after the verdict rows — the note
           belongs with the verdict it annotates, not below the buttons. */
        const cb=out.querySelector?out.querySelector(".copybtn"):null;
        out.insertBefore(note,cb||null);
      }
    }).catch(e=>{_failOut(
      "<div class='row bad'>deep link failed: "+esc(e.message)+"</div>");});
  }
  /* Conformance-vector deep links: #vectors/<slug> fetches one of the
     Wycheproof-style packs the site ships under vectors/ (the index links
     each row here) — the judge lands directly on the verdict the oracle
     predicts. Slug pattern pins it to the vector names. */
  const _vm=location.hash.match(/^#vectors\\/([a-z0-9-]{3,60})$/);
  if(_vm){
    /* The shared oracle rides along: a judge landing on a vector sees what it
       was DESIGNED to conclude beside the stamp — and a pin-verdict vector
       (fail-wrong-pin) doesn't read as a corpus-vs-verifier contradiction
       when it verifies self-declared. The row is inserted AFTER go() returns:
       the verdict rewrites #out, so anything inserted earlier is wiped. */
    const _oracleP=fetch("vectors-manifest.json").then(r=>r.ok?r.json():null)
      .then(man=>(man||[]).find(v=>v.name===_vm[1])).catch(()=>null);
    fetch("vectors/"+_vm[1]+".zip").then(async r=>{
      if(!r.ok){_failOut(
        "<div class='row bad'>deep link failed: <code>vectors/"+esc(_vm[1])+
        ".zip</code> returned HTTP "+r.status+"</div>");return;}
      const buf=await r.arrayBuffer();
      /* go() refuses mid-run — and then the oracle row would prepend onto a
         foreign verdict (and break the progress-line guard as new first
         child). Check before the call; re-check after the awaits in case a
         run started while this one resolved. */
      if(_busy)return;
      await go([new File([buf],_vm[1]+".zip")]);
      const row=await _oracleP,out=document.getElementById("out");
      if(!row||!out||_busy)return;
      const oracle=row.verdict==="fail"?"FAIL":"PASS";
      const pinNote=row.pin_required
        ?" — <strong>under a <code>--key</code> pin.</strong> The browser has no "+
          "pin flag, so it verified self-declared above: that green stamp IS "+
          "the attack the pin defeats (<code>attest verify pack.zip --key &lt;issuer-key&gt;</code> "+
          "reproduces the FAIL)"
        :"";
      out.insertAdjacentHTML("afterbegin",
        `<div class="row mut">shared oracle: this vector must ${oracle}`+
        pinNote+` — ${esc(row.note||"")}</div>`);
    }).catch(e=>{_failOut(
      "<div class='row bad'>deep link failed: "+esc(e.message)+"</div>");});
  }
  /* Out-of-band pin demo: the pack's trust anchor arrives over a different
     surface than the artifact it anchors — the issuer document this site
     serves at .well-known/ (attest issuer --out output, hosted as a
     downloadable because the well-known convention is origin-rooted and
     project pages can't serve it). Loose .json drops arm the pin, so the
     two-File batch goes through the ordinary drop path. */
  fetch(".well-known/attest-issuer.json",{method:"HEAD"}).then(r=>{
    if(!r.ok){if(location.hash==="#sample-pack-pinned")_miss(".well-known/attest-issuer.json");return;}
    document.getElementById("trypin-wrap").hidden=false;
    document.getElementById("trypin").onclick=async()=>{
      if(_busy)return;
      try{
        history.replaceState(null,"",location.pathname+"#sample-pack-pinned");
        const pk=await(await fetch("sample-pack.zip")).arrayBuffer();
        const dc=await(await fetch(".well-known/attest-issuer.json")).text();
        go([new File([pk],"sample-pack.zip"),
            new File([dc],"attest-issuer.json")]);
      }catch(e){
        _failOut("<div class='row bad'>sample fetch failed: "+esc(e.message)+"</div>");
      }
    };
    if(location.hash==="#sample-pack-pinned")
      document.getElementById("trypin").click();
  }).catch(()=>{});
  /* Self-check: this page's own bytes against the issuer-signed
     verifier_manifest.json inside the bundled sample pack — proof the hosted
     copy is the exact tool the issuer pinned at export. A swapped hosted
     verifier shows PIN MISMATCH instead of a borrowed verdict. It cannot
     prove the running copy is honest — a swapped page could swap the check
     too — so the trust note below still stands. */
  fetch("sample-pack.zip",{method:"HEAD"}).then(r=>{
    if(!r.ok){if(location.hash==="#verify-self")_miss("sample-pack.zip");return;}
    document.getElementById("tryself-wrap").hidden=false;
    document.getElementById("tryself").onclick=async()=>{
      if(_busy)return;
      const out=document.getElementById("out");
      _busy=true;
      try{
        history.replaceState(null,"",location.pathname+"#verify-self");
        out.innerHTML="<p>hashing this page…</p>";
        const [pageBytes,packBytes]=await Promise.all([
          fetch(location.pathname,{cache:"no-store"}).then(rr=>rr.arrayBuffer()),
          fetch("sample-pack.zip").then(rr=>rr.arrayBuffer()),
        ]);
        const mine=await sha256hex(new Uint8Array(pageBytes));
        const ents=await readZipEntries(new File([packBytes],"sample-pack.zip"));
        let man=null;
        for(const e of ents)if(e.name==="verifier_manifest.json")
          man=JSON.parse(await e.text());
        const pin=man&&man.payload&&man.payload.tools
          &&man.payload.tools["verify.html"];
        const say=(c,m)=>{out.innerHTML+="<div class='row "+c+"'>"+m+"</div>";};
        out.innerHTML="";
        if(!pin){say("warn","the bundled pack carries no verify.html pin — "
          +"nothing to check against");return;}
        say("","this page's sha256: <code>"+mine.slice(0,24)+"…</code>");
        say("","issuer-signed pin: <code>"+esc(pin.slice(0,24))+"…</code>");
        if(mine===pin){
          say("ok","<strong>byte-identical</strong> — this hosted verifier is "
            +"the exact tool the issuer pinned at export; a swapped page is "
            +"caught, not trusted");
          say("stamp ok","<strong>PINNED</strong> — page bytes match the "
            +"signed manifest");
        }else{
          say("bad","the hosted page's bytes do NOT match the issuer-signed "
            +"pin — the verifier was modified after export; do not rely on "
            +"its verdicts");
          say("stamp bad","<strong>PIN MISMATCH</strong>");
        }
        say("warn","honest scope: a signed pin was compared, not a running "
          +"page proven honest — a hostile page could rewrite this check too. "
          +"For a dispute that matters, the pack's own verify_case.py or an "
          +"independently fetched copy remains the stronger path.");
      }catch(e){
        out.innerHTML="<div class='row bad'>self-check failed: "+esc(e.message)+"</div>";
      }finally{_busy=false;}
    };
    if(location.hash==="#verify-self")
      document.getElementById("tryself").click();
  }).catch(()=>{});
  /* Tamper lab — the judge commits the attack: pick a signed field in a real
     bundle, rewrite it client-side, rebuild the pack as a stored zip, and run
     the same verifier over it. Nothing is simulated: the doctored pack is a
     real artifact you can download, and the signature genuinely refuses it. */
  fetch("sample-pack.zip",{method:"HEAD"}).then(r=>{
    if(!r.ok){if(location.hash==="#tamper-lab")_miss("sample-pack.zip");return;}
    const lab=document.getElementById("lab");if(!lab)return;lab.hidden=false;
    const lout=document.getElementById("lab-out");
    const ldl=document.getElementById("lab-dl");
    const memb=document.getElementById("lab-member");
    const enc2=new TextEncoder();
    let ents=null,packBytes=null,labLoading=null;
    const loadLab=async()=>{
      if(labLoading)return labLoading;
      labLoading=(async()=>{
        packBytes=await(await fetch("sample-pack.zip")).arrayBuffer();
        ents=await readZipEntries(new File([packBytes],"sample-pack.zip"));
        let first=null;
        for(const e of ents){
          if(!/^visits\\/[^\\/]+\\/bundle\\.json$/.test(e.name))continue;
          const o=document.createElement("option");
          o.value=e.name;o.textContent=e.name;memb.appendChild(o);
          if(e.name.indexOf("vis_70e42116a4cf")>=0)first=e.name;
        }
        if(first)memb.value=first;
        if(!memb.options.length)
          lout.innerHTML="<div class='row warn'>no visit bundles in this pack</div>";
        return ents;})();
      labLoading.catch(()=>{labLoading=null;});
      return labLoading;};
    if(lab.addEventListener)
      lab.addEventListener("toggle",()=>{if(lab.open)loadLab();});
    if(location.hash==="#tamper-lab"){lab.open=true;loadLab();}
    document.getElementById("lab-go").onclick=async()=>{
      if(_busy)return;
      try{
        lout.innerHTML="<p>rebuilding the pack around your edit…</p>";
        await loadLab();
        const field=document.getElementById("lab-field").value.trim();
        const vraw=document.getElementById("lab-value").value.trim();
        if(!field){lout.innerHTML="<div class='row warn'>name a field</div>";return;}
        let v;try{v=JSON.parse(vraw);}catch(e){v=vraw;}
        let src=null;
        for(const e of ents)if(e.name===memb.value)src=await e.text();
        if(src===null){lout.innerHTML="<div class='row bad'>member missing</div>";return;}
        const key=JSON.stringify(field);let edited=null;
        const ki=src.indexOf(key);
        if(ki>=0){
          let j=ki+key.length;
          while(j<src.length&&/\\s/.test(src[j]))j++;
          if(src[j]===":"){
            j++;while(j<src.length&&/\\s/.test(src[j]))j++;
            let vend=j;
            if(src[j]==='"'){let k=j+1;
              while(k<src.length){if(src[k]==="\\\\")k++;
                else if(src[k]==='"')break;k++;}
              vend=k+1;
            }else{let k=j;
              while(k<src.length&&",}]".indexOf(src[k])<0&&!(/\\s/.test(src[k])))k++;
              vend=k;}
            edited=src.slice(0,j)+JSON.stringify(v)+src.slice(vend);
          }
        }
        if(edited===null){
          const tail=src.lastIndexOf("}");
          edited=src.slice(0,tail)+","+key+":"+JSON.stringify(v)+src.slice(tail);
          lout.innerHTML="<div class='row warn'><code>"+esc(field)+
            "</code> wasn't in this bundle — it was injected; unknown fields fail too</div>";
        }else{
          lout.innerHTML="";
        }
        const eu=enc2.encode(edited);
        const rebuilt=[];
        for(const e of ents)
          rebuilt.push({name:e.name,
            u8:e.name===memb.value?eu:new Uint8Array(await e.arrayBuffer())});
        const zb=buildZip(rebuilt);
        ldl.innerHTML="";
        if(URL&&URL.createObjectURL){
          for(const nm of["sample-pack.zip","tampered-by-you.zip"]){
            const a=document.createElement("a");
            a.href=URL.createObjectURL(new Blob(
              [nm==="sample-pack.zip"?packBytes:zb],{type:"application/zip"}));
            a.download=nm;a.textContent="download "+nm;
            ldl.appendChild(a);ldl.appendChild(document.createTextNode(" "));
          }
        }
        history.replaceState(null,"",location.pathname+"#tamper-lab");
        await go([new File([zb],"tampered-by-you.zip")]);
      }catch(e){
        lout.innerHTML="<div class='row bad'>lab failed: "+esc(e.message)+"</div>";
      }
    };
  }).catch(()=>{});
  /* Site verification — the deployment attests itself: site-manifest.json is
     a signed receipt pinning every artifact's sha256. Verify the manifest as
     a lone receipt, then hash every file it names against the served bytes. */
  fetch("site-manifest.json",{method:"HEAD"}).then(r=>{
    if(!r.ok){if(location.hash==="#verify-site")_miss("site-manifest.json");return;}
    const w=document.getElementById("trysite-wrap");if(!w)return;w.hidden=false;
    document.getElementById("trysite").onclick=async()=>{
      if(_busy)return;
      const out=document.getElementById("out");
      const say=(c,m)=>{out.innerHTML+="<div class='row "+c+"'>"+m+"</div>";};
      _busy=true;
      try{
        history.replaceState(null,"",location.pathname+"#verify-site");
        out.innerHTML="<p>verifying the site's signed manifest…</p>";
        const man=await(await fetch("site-manifest.json")).text();
        out.innerHTML=await verifyFiles([{name:"site-manifest.json",
          text:async()=>man}]);
        const d=toJS(parseKeep(man));
        const arts=d&&d.payload&&d.payload.artifacts;
        if(!arts||typeof arts!=="object"||Array.isArray(arts)){
          say("warn","manifest carries no artifact map — nothing to sweep");return;}
        const names=Object.keys(arts);
        if(names.length>512){say("bad","manifest lists "+names.length+
          " artifacts — beyond the sweep bound");return;}
        /* Sweep 8-at-a-time — a hundred-plus serial fetches is seconds of silence;
           results collect in deterministic order before verdict lines emit. */
        const results=[];
        let checked=0,total=0,idx=0;
        const prog=document.createElement("p");
        prog.textContent="sweeping 0/"+names.length+" artifacts…";
        out.appendChild(prog);
        const worker=async()=>{
          while(idx<names.length){
            const nm=names[idx++];
            if(!/^[A-Za-z0-9._\\/-]+$/.test(nm)||nm.split("/").includes("..")
              ||nm[0]==="/"||nm.includes(":")){
              results.push({nm,ok:false,why:"unsafe artifact name in manifest"});
              prog.textContent="sweeping "+idx+"/"+names.length+" artifacts…";
              continue;}
            const want=String(arts[nm]);
            try{
              const rr=await fetch(nm);
              if(!rr.ok){results.push({nm,ok:false,why:"listed but not served"});
                prog.textContent="sweeping "+idx+"/"+names.length+" artifacts…";
                continue;}
              const b=await rr.arrayBuffer();total+=b.byteLength;
              if(total>256*1024*1024){results.push({nm,ok:false,
                why:"sweep exceeded the byte bound"});continue;}
              const got=await sha256hex(new Uint8Array(b));
              if(got===want)checked++;
              else results.push({nm,ok:false,
                why:"sha256 mismatch (signed "+esc(want.slice(0,16))+
                  "…, served "+got.slice(0,16)+"…)"});
            }catch(e){results.push({nm,ok:false,why:"fetch failed"});}
            prog.textContent="sweeping "+idx+"/"+names.length+" artifacts…";
          }};
        await Promise.all([...Array(Math.min(8,names.length))].map(worker));
        prog.remove();
        for(const r2 of results)
          say("bad","<code>"+esc(r2.nm)+"</code> — "+esc(String(r2.why||"")));
        const bad=results.length;
        if(!bad&&checked===names.length)
          say("stamp ok","<strong>SITE VERIFIED</strong> — all "+checked+
            " artifacts byte-match the issuer-signed manifest");
        else
          say("stamp bad","<strong>SITE TAMPER</strong> — "+bad+" of "+
            names.length+" artifacts differ from the signed manifest");
        say("warn","honest scope: the manifest signed by the site's own key "
          +"verified above; matching hashes prove the served bytes are what "
          +"the issuer shipped — a host forging BOTH manifest and files is "
          +"caught only if you pin the issuer key out-of-band.");
      }catch(e){
        out.innerHTML="<div class='row bad'>site check failed: "+esc(e.message)+"</div>";
      }finally{_busy=false;}
    };
    if(location.hash==="#verify-site")
      document.getElementById("trysite").click();
  }).catch(()=>{});
  /* Near-miss deep links: `#vectors` bare, `#gaunlet`, `#receipts` — nothing
     claims them and every handler quietly no-ops, which reads as broken.
     Name the miss plus the valid set; the stamp check guards against
     flagging a hash a slower handler already served. */
  if(location.hash.length>1){
    const h=location.hash;
    const claimed=_rm||_vm||h==="#anchor-demo"||h==="#gauntlet"
      ||h==="#compare-packs"||h==="#tamper-lab"||h==="#verify-self"
      ||h==="#verify-site"
      ||h==="#sample-pack-pinned"
      ||_samples.some(([f])=>h==="#"+f.replace(/\.(zip|json)$/,""));
    if(!claimed)setTimeout(()=>{
      const out=document.getElementById("out");
      /* _busy means a handler IS working on the hash — the innerHTML scrape
         alone can't tell "in flight" from "unclaimed" (zip reads, doc sniffs,
         and gauntlet rounds all hold #out without a stamp or 'verifying'). */
      if(out&&!_busy&&!/stamp|verifying|checking/i.test(out.innerHTML))
        out.insertAdjacentHTML("afterbegin",
          "<div class='row mut'>no such deep link: <code>"+esc(h)+"</code> — try "
          +"<code>#sample-pack</code>, <code>#gauntlet</code>, "
          +"<code>#tamper-lab</code>, or a <code>#vectors/&lt;slug&gt;</code>.</div>");
    },1500);
  }
}
"""

_VERIFY_BODY = """<h1>Attest pack verifier</h1>
<p>This page verifies an exported Attest pack <strong>in your browser</strong>. Nothing is
uploaded — all hashing and signature checks run locally, offline. Drop the
<strong>.zip pack itself</strong>, select every extracted file, just bundle.json for a
single-visit pack, or a signed receipt JSON (e.g. a <code>verify-live --sign</code> report).</p>
<div class="drop" id="drop">Drop the pack .zip or a signed receipt .json here, or
pick files: <input type="file" id="pick" multiple accept=".zip,.json" aria-label="Choose pack files">
or the extracted folder: <input type="file" id="pickdir" webkitdirectory
aria-label="Choose the extracted pack folder"><br>
<small>To pin the pack to a deployment, drop its <code>attest.issuer/1</code>
document too (from <code>/.well-known/attest-issuer.json</code> or
<code>attest issuer --out</code>) — the pin arms for the pack, and the doc's
signed lifecycle bridges pre-rotation exports.<br>
Drop <strong>two</strong> packs at once to compare them: each is verified on
its own merits, then their signed membership is diffed — the copy the agency
produced vs the copy you kept ("both verify" and "both identical" are
different claims).</small></div>
<p id="newhere" hidden><small>New here? <a href="index.html">The story</a>
explains why the record exists. New to the math? <a href="anatomy.html">
Anatomy of a signed receipt</a> decomposes one field-by-field, <a
href="pipeline.svg">the seven gates</a> show which check kills which attack —
or take the <a href="tour.html">two-minute tour</a> of the headline
features.</small></p>
<p id="trysample-wrap" hidden><button id="trysample" type="button">Verify the bundled
sample pack — one click, fetched from this site</button></p>
<p id="trytamper-wrap" hidden><button id="trytamper" type="button">Verify the tampered
twin — the same pack, but someone inflated the contested visit's observed span from 65.25 to 135.25 minutes.
Watch the signature catch it</button></p>
<p id="trygauntlet-wrap" hidden><button id="trygauntlet" type="button"><strong>Run
the whole gauntlet</strong> — every artifact on this page verified in sequence:
the clean pack, the doctored twin, all three attacks, the real-API sweep, the
signed fork, the Bitcoin anchor — scored against the shared oracle</button><br>
<small class="mut">the oracle is the verdict each artifact was built to
produce — agreement means the verifier and the published spec say the same
thing about all eight.</small></p>
<p id="trycompare-wrap" hidden><button id="trycompare" type="button"><strong>Compare
two packs</strong> — the clean pack vs its doctored twin: each verifies on its
own merits, then their signed membership diffs member-by-member — the moved
field named — and the two signed log heads reconcile</button><br>
<small class="mut">"the copy the agency produced" vs "the copy I kept" — two
packs that both verify can still carry different records. Or drop any two
exported zips at once for the same compare.</small></p>
<p id="tryatk-hint" hidden><small>Or pick an attack — each is caught by a
different layer:</small></p>
<p id="tryatk1-wrap" hidden><button id="tryatk1" type="button">Attack: deleted record
— a visit bundle was removed, but the signed manifest still names its receipt</button></p>
<p id="tryatk2-wrap" hidden><button id="tryatk2" type="button">Attack: smuggled file
— extra-evidence.json injected after signing; nothing signed commits to it</button></p>
<p id="tryatk3-wrap" hidden><button id="tryatk3" type="button">Attack: forged verifier
— the embedded checker swapped for an always-green stub; the tooling pin names its bytes</button></p>
<p id="tryreceipt-wrap" hidden><button id="tryreceipt" type="button">Verify the signed
report from a real sweep against the Ring Partner API — a lone receipt, verified
by the same math</button></p>
<p id="tryfork-wrap" hidden><button id="tryfork" type="button">Verify the caught fork
— a signed monitor observation documenting two irreconcilable views of one log,
proven inside its own signed tree head</button></p>
<p id="trypin-wrap" hidden><button id="trypin" type="button">Verify the sample pack
<em>pinned to this site's issuer document</em> — the trust anchor arrives over a
different surface than the artifact it anchors</button></p>
<p id="tryself-wrap" hidden><button id="tryself" type="button">Verify this page —
hash the bytes you're reading against the issuer-signed <code>verify.html</code>
pin inside the bundled sample pack</button><br>
<small>Proves the hosted copy is the exact pinned tool — a swapped verifier is
caught, not trusted. (A hostile page could rewrite this check too; for a real
dispute, the pack's own <code>verify_case.py</code> stays the stronger path.)</small></p>
<p id="trysite-wrap" hidden><button id="trysite" type="button">Verify this whole
site — a signed manifest pins the sha256 of every artifact it ships; watch
each file prove itself</button><br>
<small>Extends the self-check to the whole deployment: the manifest's own
signature verifies first, then every listed file is fetched and hashed.</small></p>
<details id="lab" hidden>
<summary><strong>Tamper lab — commit the attack yourself</strong></summary>
<p>Pick a visit's signed bundle, a field in it, and a new value. This page
rebuilds a real pack around your edit — same members, same signatures,
different bytes — then verifies it. Change the value and the signed hash
refuses it; write the exact signed value back and it verifies — the math
checks bytes, not intentions. Download your doctored pack and the clean twin
and diff them yourself; nothing here is simulated.</p>
<p><label>record bundle <select id="lab-member"></select></label>
<label>field <input id="lab-field" size="22" value="observed_span_minutes"
aria-label="Field name"></label>
<label>new value <input id="lab-value" size="14" value="135.25"
aria-label="New value"></label>
<button id="lab-go" type="button">tamper + verify</button></p>
<p><small>fields worth forging: <code>observed_span_minutes</code> (how long
cameras observed, in minutes — the contested visit signed 65.25; the shipped
twin sets 135.25), <code>state</code>, <code>duration_minutes</code>. A field
the bundle lacks gets injected — and still fails.</small></p>
<div id="lab-out" role="status" aria-live="polite"></div>
<p id="lab-dl"></p>
</details>
<div id="out" role="status" aria-live="polite"></div>
<div id="gauntlet-out" role="status" aria-live="polite"></div>
<div id="live-wrap" hidden>
<h2>Is this still the log the deployment serves?</h2>
<p><small>The pack proves membership in <em>a</em> signed log — a hostile deployment
could keep a second, forked log it shows only to you, and every proof above would
still close. Cross-check the pack's signed tree head against the head the deployment
serves <em>everyone</em> right now:
<input id="liveurl" type="url" size="34" placeholder="https://attest.example.com"
aria-label="Deployment base URL">
<button id="livego" type="button">Cross-check the live log</button></small></p>
<div id="liveout" role="status" aria-live="polite"></div>
<p><small>This reads <code>/.well-known/attest-issuer.json</code>,
<code>/api/log/head</code>, and <code>/api/log/consistency</code> — the only
network step this page takes; everything else ran fully offline.</small></p>
</div>
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

_OG = (
    '<meta property="og:image"\n'
    '  content="https://josepha-mayo.github.io/attest/og-image.png">\n'
    '<meta name="twitter:card" content="summary_large_image">\n'
    '<meta name="theme-color" content="#146c2e">\n'
)

# Packs' index.html shares _HEAD and must stay strictly offline — no external
# URL anywhere (a test enforces it) — so the social card lives on the hosted
# verifier page only.
VERIFY_HTML = (
    _HEAD.replace("</head>", _OG + "</head>")
    + '<main id="main">\n'
    + "<noscript><p>This verifier is dependency-free JavaScript and needs JS "
    "enabled. The same pack verifies offline with <code>verify_case.py</code> "
    "on a stock Python install, or <code>attest verify</code>.</p></noscript>\n"
    + _VERIFY_BODY
    + _JS_OPEN
    + _JS_LIB
    + _VERIFY_DRIVER
    + "</script>\n</main>\n</body>\n</html>\n"
)

_INDEX_BODY = """<h1 id="site">Attest case record</h1>
<noscript><p><strong>This page is the verifier</strong> — it needs JavaScript to check
the signed records inlined below and render them; without it, nothing here verifies.</p></noscript>
<p id="meta" class="muted"></p>
<div id="verdict" role="status" aria-live="polite"></div>
<div id="cards"></div>
<h2>Verify the media bytes</h2>
<p><small>This page verifies every signed record and renders its timeline offline — and every
record can be toggled between the technical view and the plain-language family view
(the &ldquo;plain language (family)&rdquo; tab on each card). Signed media digests are
listed per record; to check the media bytes themselves, open
<a href="verify.html">verify.html</a> (from the extracted pack folder) and drop every
file from this pack onto it.</small></p>
<h2>The transparency checkpoint</h2>
<p><small>This pack also carries <code>log_checkpoint.json</code> — a signed Merkle
tree head over the deployment's receipt log (RFC 6962-style), with an inclusion
proof per pack receipt and, when present, <code>cosignatures</code> from independent
witness deployments. This page verifies the records' signatures and chains; to prove
each receipt was committed to the published log — and see which witnesses vouched
for that head — drop the whole pack on <code>verify.html</code> or run
<code>attest verify</code>. This page can't inline the checkpoint doc: the pack's
verifier manifest signs this page's bytes before the checkpoint can be issued.</small></p>
<h2>What this does and does not establish</h2>
<p><small>A green result proves the signed records are intact and were issued under the pinned
issuer key — integrity, not physical truth. It does not prove anyone was present, absent, or
honest; it proves the evidence chain was not altered after signing.</small></p>
<p><small><strong>Trust note:</strong> this page traveled inside the pack it checks —
for a dispute that matters, re-verify the pack with a verifier obtained independently
(the deployment's <code>/verify-pack</code> or a pinned <code>verify_case.py</code>).</small></p>
<style>
 .card{border:1px solid #ddd;border-radius:10px;padding:.8rem 1rem;margin:0 0 1rem}
 .muted,.mut{color:#666}
 .pill{display:inline-block;border-radius:99px;padding:.05rem .6rem;font-size:.8rem;
   background:#eef1f6;border:1px solid #ccd3df}
 .corr{width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.85rem}
 .corr td,.corr th{border-top:1px solid #eee;padding:.15rem .4rem .15rem 0;
   vertical-align:top;text-align:left;font-weight:400}
 .corr th{white-space:nowrap;font-weight:600;width:1%}
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
 .plain-facts td,.plain-facts th{padding:.25rem .8rem .25rem 0;vertical-align:top;
   border-bottom:1px solid #eef1f6;text-align:left;font-weight:400}
 .plain-facts th.k{color:#5c6b7a;white-space:nowrap;font-weight:600}
 .plain-quote{border-left:3px solid #b4740c;padding:.3rem .8rem;margin:.5rem 0;
  font-style:italic;color:#4a3d28}
 .plain-quote.household{border-left-color:#2563a8;color:#26374a}
 .plain-byline{color:#5f6e7c;font-size:.8rem}
 .plain-foot{margin-top:1rem;color:#5f6e7c;font-size:.8rem;line-height:1.5;
  border-top:1px solid #eee;padding-top:.7rem}
 .view-toggle{display:inline-flex;border:1px solid #ccd3df;border-radius:8px;
   overflow:hidden;margin-top:.6rem}
 .view-tab{border:0;background:#eef1f6;color:#3b4a63;padding:.3rem .85rem;
   font:inherit;font-size:.82rem;cursor:pointer}
 .view-tab.on{background:#3b4a63;color:#fff}
 .anchors{margin-top:.6rem}
 .anchors .kv{width:100%;border-collapse:collapse;font-size:.82rem}
 .anchors .kv td,.anchors .kv th{border-top:1px solid #eee;padding:.12rem .4rem .12rem 0;
   vertical-align:top;text-align:left;font-weight:400}
 .anchors .kv th.k{white-space:nowrap;font-weight:600;width:1%;color:#5c6b7a}
 .print-btn{margin-left:auto;border:1px solid #ccd3df;border-radius:8px;
   background:#eef1f6;color:#3b4a63;padding:.2rem .7rem;font-size:.8rem;cursor:pointer}
 .week-row{display:flex;align-items:center;gap:.6rem;margin:1px 0}
 .week-label{width:6.5em;text-align:right;flex:none}
 .week-strip{flex:1;min-width:0}
 .week-legend{margin-bottom:.4rem;line-height:1.9}
 .sw{display:inline-block;width:.9em;height:.7em;border-radius:2px;vertical-align:-1px;margin-left:.6em}
 .voices{font-size:.85rem;margin:.35rem 0 .1rem}
 .flag{display:inline-block;border-radius:6px;padding:0 .45rem;font-size:.78rem;
   background:#f9edd4;color:#8a5a00;border:1px solid #e8d3a8}
 .plink{color:#5f6e7c;text-decoration:none;font-size:.78rem;font-weight:400}
 .plink:focus-visible{outline:2px solid #5f6e7c;outline-offset:2px}
 .plink:hover{text-decoration:underline}
 .tl{border-bottom:1px dotted #9aa3b2}
 @media print{
  .plain{display:block !important}
  .view-toggle,.print-btn{display:none !important}
  .card,.stamp,.week-row,tr{break-inside:avoid}
 }
</style>
"""

_INDEX_DRIVER = """/* ---------- index driver: inlined pack data ---------- */
const d64=s=>new TextDecoder().decode(Uint8Array.from(atob(s),c=>c.charCodeAt(0)));
const STATE_CLS={closed:"ok",no_observation:"warn",open:"warn",unmatched:"warn"};
/* Human-facing instants render in the viewer's local zone — the zone label
   comes from the same Intl pipeline that formats the digits, so it can never
   disagree with the rendered time. The exact signed UTC literal stays on
   hover (title); signed-literal surfaces (anchor rows, inlined payloads)
   keep the verbatim spelling. */
const _DTF=(()=>{try{return new Intl.DateTimeFormat(undefined,{month:"short",
  day:"numeric",hour:"numeric",minute:"2-digit",timeZoneName:"short"});
  }catch(e){return null;}})();
const _DTF_D=(()=>{try{return new Intl.DateTimeFormat(undefined,{month:"short",
  day:"numeric"});}catch(e){return null;}})();
const _DTF_T=(()=>{try{return new Intl.DateTimeFormat(undefined,{hour:"numeric",
  minute:"2-digit",timeZoneName:"short"});}catch(e){return null;}})();
const _tmOnly=t=>_DTF_T.formatToParts(t).filter(x=>x.type!=="timeZoneName")
  .map(x=>x.value).join("").trim();
const _zone=t=>{const z=_DTF_T.formatToParts(t).find(x=>x.type==="timeZoneName");
  return z?z.value:"";};
function fmtLocal(iso){
  const t=Date.parse(iso);
  if(!isFinite(t)||!_DTF)return esc(iso==null?"":iso);
  return `<span class="tl" title="${esc(iso)}">${esc(_DTF.format(t))}</span>`;
}
function fmtRange(a,b){
  /* Same local day collapses to "Oct 2, 6:31 – 7:36 PM EDT"; crossing days
     give each endpoint its own full label. Both ends keep their UTC literal
     on hover. */
  const ta=Date.parse(a),tb=Date.parse(b);
  if(!isFinite(ta))return fmtLocal(b);
  if(!isFinite(tb))return fmtLocal(a);
  if(!_DTF_D||!_DTF_T)return esc(a)+" – "+esc(b);
  if(new Date(ta).toDateString()===new Date(tb).toDateString()){
    const zA=_zone(ta),zB=_zone(tb),z=zA===zB?zA:zA+"/"+zB;
    return `<span class="tl" title="${esc(a)} – ${esc(b)}">`
      +`${esc(_DTF_D.format(ta))}, ${esc(_tmOnly(ta))} – ${esc(_tmOnly(tb))}`
      +(z?` ${esc(z)}`:"")+"</span>";
  }
  return fmtLocal(a)+" – "+fmtLocal(b);
}
/* corroboration table — mirrors attest.corroborate semantics: each row says
   what a source reported and what it establishes; silence is labelled. */
function corroborationHTML(p){
  const ev=p.evidence||[],site=p.site||{},cov=p.history_poll_coverage||{};
  const cam=ev.filter(e=>e.device===site.door_camera_id);
  const sen=ev.filter(e=>site.door_sensor_id&&e.device===site.door_sensor_id);
  const snaps=ev.filter(e=>e.media_sha256);
  const hist=p.ring_history||[];
  /* Cells carrying rendered times arrive pre-marked {h:html} (the fmt*
     helpers escape internally); every other cell is signed text esc()'d at
     emission below. */
  const HC=h=>({h});
  const cell=v=>v&&typeof v==="object"&&"h"in v?v.h:esc(v);
  const COV={observed:"fully watched",observed_with_events:"watched — events seen",
    partial:"partially watched",blind:"blind — polls failed",no_polls:"not polled"};
  const rows=[
    ["Scheduled expectation",p.schedule
      ?HC(fmtRange(p.schedule.window_start,p.schedule.window_end)):"unscheduled",
      "What was planned — never what happened"],
    ["Camera/doorbell",cam.length
      ?HC(esc(cam.length+" event(s) ")+fmtRange(cam[0].at,cam[cam.length-1].at)):"silent",
      "Device-observed activity timestamps only"],
    ["Contact sensor",!site.door_sensor_id?"not bound"
      :sen.length
      ?HC(esc(sen.length+" event(s) ")+fmtRange(sen[0].at,sen[sen.length-1].at)):"silent",
      "Open/close transitions at the door"],
    ["Worker self-report",p.checked_in_at
      ?HC("check-in "+fmtLocal(p.checked_in_at)):"none received",
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
    `<tr><th scope="row">${esc(r[0])}</th><td>${cell(r[1])}</td>`
    +`<td class="muted"><small>${esc(r[2])}</small></td></tr>`
  ).join("")+"</table>";
}
/* Voices rollup — one compact line naming who has spoken on this record and
   whether the signed accounts disagree. Worker/coordinator/household stay
   separate (the same chain statementsHTML renders verbatim below); a
   household disagreement is flagged, never merged or adjudicated. */
function voicesHTML(js){
  const rv=Array.isArray(js.reviews)?js.reviews:[];
  if(!rv.length)return"";
  const W={confirm:"confirmed",dispute:"disputed",correction:"sent a correction",
    inconclusive:"responded inconclusively"};
  let wDec=null,wN=0,cord=null;const hh=[];
  for(const e of rv){
    const p=((e||{}).receipt||{}).payload||{};
    const role=(p.actor||{}).role,r=p.review||{};
    if(r.kind==="household_account"||role==="household")
      hh.push(r.perception==null?"":String(r.perception));
    else if(r.kind==="resolution")
      cord=String(r.outcome||"concluded").replaceAll("_"," ");
    else if(role==="worker"&&r.decision){wDec=r.decision;wN++;}
    else if(role==="coordinator"&&r.decision)
      cord=String(r.decision).replaceAll("_"," ");
  }
  const parts=[];
  if(wDec)parts.push(`worker: <span${wDec==="dispute"?' class="warn"':""}>`
    +`${esc(W[wDec]||String(wDec).replaceAll("_"," "))}</span>`
    +(wN>1?` <small class="muted">(${wN} statements, latest shown)</small>`:""));
  if(cord)parts.push(`coordinator: ${esc(cord)}`);
  if(hh.length){
    const percs=[...new Set(hh.filter(x=>x))];
    parts.push(`household: ${hh.length} account${hh.length>1?"s":""}`
      +(percs.length===1?` (${esc(percs[0].replaceAll("_"," "))})`:"")
      +(percs.length>1
        ?` <span class="flag">household accounts disagree — both recorded verbatim</span>`
        :""));
  }
  if(!parts.length)return"";
  return `<div class="voices"><small class="muted">voices on this record —</small> `
    +parts.join(" · ")+"</div>";
}
/* signed statements — worker/coordinator words from the review chain,
   verbatim with actor + honesty markers. */
function statementsHTML(js){
  const out=[];
  for(const e of Array.isArray(js.reviews)?js.reviews:[]){
    const p=((e||{}).receipt||{}).payload||{};
    const a=p.actor||{},rv=p.review||{};
    if(!rv.decision&&!rv.outcome&&!rv.statement)continue;
    const who=a.name?`${esc(a.name)} (${esc(a.role||"reviewer")})`:esc(a.role||"reviewer");
    const note=a.identity_verified===false?" — identity not independently verified":"";
    const window=rv.reported_start
      ?` <small class="muted">reports ${fmtRange(rv.reported_start,rv.reported_end)}</small>`:"";
    const recv=p.statement_received_at
      ?` <small class="muted">· received ${fmtLocal(p.statement_received_at)}</small>`:"";
    const label=rv.kind==="resolution"
      ?`resolution: ${String(rv.outcome||"").replaceAll("_"," ")}`
      :rv.kind==="household_account"
      ?`household account: ${String(rv.perception||"").replaceAll("_"," ")}`
      :(rv.decision||"statement");
    const reason=rv.reason_code
      ?` <small class="muted">reason <code>${esc(rv.reason_code)}</code>`
        +`${rv.reason_label?` — ${esc(rv.reason_label)}`:""} (stated, not verified)</small>`:"";
    out.push(`<div class="stmt"><strong>${esc(label)}</strong> by ${who}${note}:`
      +` ${esc(rv.statement||"")}`+window+reason+recv+`</div>`);
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
      `The camera reported activity between ${fmtLocal(obsA)}`
      +` and ${fmtLocal(obsB)}`
      +(span!=null?` — about ${Math.round(span)} minutes of observed span`:"")
      +".","ok"];
  const facts=[];
  if(hasObs){
    facts.push(["First observation",fmtLocal(obsA)]);
    facts.push(["Last observation",fmtLocal(obsB)]);}
  const sw=p.scheduled_worker||(p.worker?{name:p.worker}:null);
  if(sw&&sw.name)facts.push(["Scheduled worker",esc(sw.name)]);
  if(p.checked_in_at)
    facts.push(["Worker check-in",
      fmtLocal(p.checked_in_at)
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
      +(hrv.perception?` (${esc(String(hrv.perception).replaceAll("_"," "))})`:"")
      +` via the family link — self-reported; it doesn't change the camera's`
      +` observations or the worker's account</div>`;
  }
  return `<div class="plain-hero ${hero[3]}"><div class="plain-mark" aria-hidden="true">${hero[0]}</div>`
    +`<h3 class="plain-h2">${esc(hero[1])}</h3><div class="plain-p">${hero[2]}</div></div>`
    +`<table class="plain-facts">${facts.map(f=>
      `<tr><th scope="row" class="k">${esc(f[0])}</th><td>${f[1]}</td></tr>`).join("")}</table>`
    +quote
    +`<div class="plain-foot">The camera's report, the schedule, the worker's account, and the household's
    account are kept separate.
    A signature proves the record hasn't been altered since it was signed — not identity, attendance, or
    time worked. No reported activity is not proof nobody came.</div>`;
}
/* Signed anchors — the receipt's envelope facts (what the signature actually
   commits to) plus the payload's own provenance declarations: where the data
   came from, which clock timed it, who wrote the summary. Compact key/value
   rows; everything shown is inside the signed bytes. ``oNode`` is the
   parseKeep node so the sequence renders its verbatim literal spelling. */
function anchorsHTML(oNode,o,p){
  const rows=[];
  const row=(k,v,note)=>rows.push(`<tr><th scope="row" class="k">${k}</th><td>${v}</td>`
    +`<td class="muted"><small>${esc(note||"")}</small></td></tr>`);
  const hash=String(o.payload_hash||"");
  const seqN=get(oNode,"sequence");
  const seq=seqN&&seqN.t==="lit"?seqN.r:(o.sequence==null?"—":o.sequence);
  row("receipt",`<code>${esc(o.id||"—")}</code>`,"the signed envelope naming this record");
  row("payload hash",`<code title="${esc(hash)}">${esc(hash.slice(0,16))}…</code>`,
    "what the signature commits to");
  row("sequence",esc(seq),"position in the issuer's receipt chain");
  if(o.issued_at)
    row("issued at",esc(o.issued_at),"issuer signing time — wall clock, even in replays");
  if(p.data_origin)
    row("data origin",
      `<span class="pill">${esc(p.data_origin==="ring_api"?"Ring API"
        :p.data_origin==="local_or_test"?"local test / replay"
        :String(p.data_origin).replaceAll("_"," "))}</span>`,
      p.data_origin==="ring_api"
        ?"device facts came from the Ring Partner API"
        :p.data_origin==="local_or_test"
        ?"device facts came from a local emulator or replay — demo data, not a home"
        :"payload-declared ingestion source");
  const clk=p.clock||{};
  if(clk.mode&&clk.mode!=="wall")
    row("clock",`<span class="pill">${esc(clk.mode)}</span>`
      +(clk.replay_id?` <code>${esc(clk.replay_id)}</code>`:""),
      "a replay-clocked record — event times are simulated; signing used real time");
  const scope=p.signature_scope||(p.assessment||{}).signature_scope;
  if(scope)
    row("signature scope",esc(String(scope).replaceAll("_"," ")),
      "integrity of this record — never physical truth");
  const sp=p.summary_provenance||{};
  if(sp.source)
    row("summary",esc(sp.source==="bedrock"
        ?`bedrock — ${sp.model||"model unstated"}`
        :sp.source==="template"?"deterministic template":String(sp.source)),
      "which writer produced the narrative — wording, not evidence");
  const CR={departure:"closed on a departure cue",idle:"closed after an activity idle timeout",
    window_elapsed:"closed when the scheduled window elapsed",
    coordinator_review:"closed for coordinator review"};
  if(p.close_reason)
    row("closed",esc(CR[p.close_reason]||String(p.close_reason).replaceAll("_"," ")),"");
  for(const f of Array.isArray(p.flags)?p.flags:[]){
    const fo=f&&typeof f==="object"?f:{};
    const msg=fo.message||fo.code||(typeof f==="string"?f:"");
    if(!msg)continue;
    row("flag",`<span class="pill ${esc({warn:"warn",critical:"bad"}[fo.severity]||"")}">`
      +`${esc(fo.severity||"flag")}</span> ${esc(msg)}`,"flagged for human review");}
  /* 21st Century Cures Act EVV element crosswalk (42 U.S.C. §1396b(l)(5)(A)) —
     a real signed field on visit records: each statutory element mapped to
     the strongest basis this record actually establishes. Mirrors the
     server brief's statutory crosswalk table. */
  const cw=p.cures_act_elements;
  if(cw&&typeof cw==="object"){
    const ELS=[["service_type","type of service"],
      ["individual_receiving","individual receiving"],["date","date"],
      ["location","location"],["individual_providing","individual providing"],
      ["time_begins_ends","time begins / ends"]];
    let head=false;
    for(const[k,lbl]of ELS){
      const el=cw[k];
      if(!el||typeof el!=="object")continue;
      if(!head){
        row("cures act",'<span class="pill">crosswalk</span>',
          "EVV elements mapped to the strongest basis this record establishes"
          +" — a corroboration map, never an EVV submission");
        head=true;}
      let v;
      if(k==="time_begins_ends"&&Array.isArray(el.value))
        v=!el.value.length||el.value.every(x=>x==null)?"—"
          :el.value.map(x=>x==null?"—":fmtLocal(x)).join(" → ");
      else
        v=el.value==null?"—"
          :esc(typeof el.value==="object"?JSON.stringify(el.value):el.value);
      row(lbl,v,String(el.basis||"").replaceAll("_"," "));}
  }
  return `<div class="anchors"><small class="muted">signed anchors — envelope facts and the`
    +` payload's own provenance declarations</small><table class="kv">${rows.join("")}</table></div>`;
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
    const ci=iso(p.checked_in_at);
    for(const e of p.evidence||[]){
      const t=iso(e.at);if(!t)continue;
      /* a checkin evidence item at the checked_in_at instant is the same
         event the checkin mark below names — don't slot it twice */
      if(e.kind==="checkin"&&ci&&t===ci)continue;
      slot(t,"ev",e);}
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
    const lbl=k+": "+day.sched.length+" scheduled window(s), "
      +day.cov.length+" watched interval(s), "+day.gap.length+" gap(s), "
      +day.ev.length+" observation/check-in mark(s), "+day.live.length
      +" live-view mark(s), "+day.intr.length+" lifecycle interruption(s)";
    let s='<svg viewBox="0 0 100 30" preserveAspectRatio="none" role="img"'
      +' aria-label="'+esc(lbl)+'"'
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
      +`<strong>coverage attestation</strong> — ${fmtRange(w.start||"",w.end||"")}</div>`
      +`<small>watched ${pct!=null?pct+"%":"?"} of the window · ${esc(cov.polls||0)} poll(s)`
      +` · ${(cov.gaps||[]).length} gap(s) — silence is not absence</small>`;
  }
  if(t==="period_digest"){
    const i=p.interval||{};const c=p.counts||{};
    return `<div class="row ok"><span class="pill">digest</span> `
      +`<strong>period digest</strong> — ${fmtRange(i.start||"",i.end||"")}</div>`
      +`<small>${esc(c.visits_observed||0)} observed · ${esc(c.visits_no_observation||0)}`
      +` no-observation · ${esc(c.worker_disputes||0)} dispute(s)`
      +` · ${esc(c.coordinator_resolutions||0)} resolution(s)</small>`;
  }
  if(t==="source_disconnected"){
    return `<div class="row bad"><span class="pill">disconnected</span> `
      +`<strong>source disconnected</strong> — ${fmtLocal(p.disconnected_at||"")}</div>`
      +`<small>${esc(p.reason||"consent revoked")}`
      +` — ingestion and polling stopped; signed records preserved</small>`;
  }
  if(t==="key_rotation"){
    return `<div class="row warn"><span class="pill">key rotation</span> `
      +`<strong>issuer key retired</strong> — ${esc(String(p.previous_key||"").slice(0,12))}…`
      +` → ${esc(String(p.new_key||"").slice(0,12))}…</div>`
      +`<small>${esc(p.reason||"planned rotation")} — the signed pivot; `
      +`receipts before it verify under the retiring key</small>`;
  }
  if(t==="key_adoption"){
    const link=p.rotation_receipt||{};
    return `<div class="row ok"><span class="pill">key adoption</span> `
      +`<strong>successor countersigned</strong> — rotation ${esc(String(link.id||"").slice(0,12))}…</div>`
      +`<small>the new key holder consented — consent, not just a claim</small>`;
  }
  if(t==="key_revocation"){
    return `<div class="row bad"><span class="pill">key revoked</span> `
      +`<strong>issuer key declared suspect</strong> — ${esc(String(p.revoked_key||"").slice(0,12))}…</div>`
      +`<small>suspect for records after ${fmtLocal(p.suspect_after||"")}`
      +`${p.reason?" · "+esc(p.reason):""} — a trust annotation, never an erasure</small>`;
  }
  if(t==="case_export"){
    const n2=Object.keys(p.receipt_hashes||{}).length;
    return `<div class="row ok"><span class="pill">export</span> `
      +`<strong>case export</strong> — signed manifest naming ${n2} record(s)</div>`;
  }
  if(t==="verification_report"){
    const s=p.summary||{};const checks=p.checks||[];
    const cls=c=>c==="pass"?"ok":c==="fail"?"bad":c==="warn"?"warn":"muted";
    const rows=checks.map(c=>
      `<div class="row ${cls(c.status)}"><span class="pill">${esc(c.status||"?")}</span> `
      +`${esc(c.check||"")}`
      +(c.detail?` <small class="muted">— ${esc(String(c.detail)).slice(0,160)}</small>`:"")
      +`</div>`
    ).join("");
    return `<div class="row ok"><span class="pill">verification</span> `
      +`<strong>signed verify-live report</strong> — ${fmtLocal(p.generated_at||"")}</div>`
      +`<small>against <code>${esc(p.base_url||"")}</code> · `
      +`${esc(s.pass||0)} pass · ${esc(s.fail||0)} fail · ${esc(s.warn||0)} warn `
      +`· ${esc(s.skip||0)} skip</small>`
      +rows
      +`<div class="row muted"><small>each result is what the API actually returned`
      +` — a FAIL is an honest fail, not a test error</small></div>`;
  }
  return `<div class="row ok"><span class="pill">${esc(t)}</span> <strong>${esc(t)}</strong></div>`;
}
async function renderIndex(){
  const meta=JSON.parse(d64(document.getElementById("packmeta").textContent));
  document.getElementById("site").textContent=
    "Attest case record — "+(meta.site&&meta.site.name||meta.site_id||"site");
  document.getElementById("meta").innerHTML=
    "Generated "+(meta.generated_at?fmtLocal(meta.generated_at):"(unknown)")
    +" · issuer key "+esc(String(meta.issuer_key||"").slice(0,16))+"…";
  const cards=document.getElementById("cards");
  const verdict=document.getElementById("verdict");
  let key=null,anyBad=false,n=0,declared=0;
  _checked=0;_engWc=0;_engJs=0; /* same per-run reset verifyFiles does — a
    re-render must not inherit a previous pass's engine/progress counts */
  const rows=[];const actual=Object.create(null);const payloads=[];
  /* Rotation receipts ride as inlined attestation tags — build the trusted
     issuer set (both directions from the declared issuer) BEFORE checking
     bundles, so a pack exported across a key rotation verifies. */
  const rotNodes=[];
  for(const tag of document.querySelectorAll("script.attestation")){
    const aN=parseKeep(d64(tag.textContent));
    const art=((toJS(aN)||{}).payload||{}).record_type;
    if(art==="key_rotation"||art==="key_adoption"||art==="key_revocation")rotNodes.push(aN);
  }
  const trusted=meta.issuer_key&&rotNodes.length
    ?new Set([
        ...(await trustedKeys(meta.issuer_key,rotNodes)),
        ...(await descendantKeys(meta.issuer_key,rotNodes)),
      ])
    :null;
  const revoked=await revokedKeys(rotNodes,meta.issuer_key||"");let suspectTotal=0;
  for(const tag of document.querySelectorAll("script.bundle")){
    const root=parseKeep(d64(tag.textContent));
    const js=toJS(root)||{};
    const oNode=get(root,"original");
    if(!key)key=toJS(get(oNode,"public_key"));
    const c=await checkBundle(root,trusted||key);
    if(!c.ok)anyBad=true;
    n++;
    const bRev=get(root,"reviews");
    suspectTotal+=suspectRecords(
      [oNode].concat((bRev&&bRev.t==="arr"?bRev.v:[]).map(en=>get(en,"receipt"))),
      revoked).length;
    actual[tag.dataset.vid]=(js.original||{}).payload_hash;
    const p=(js.original||{}).payload||{};
    if(c.ok)payloads.push(p);
    const stance=deriveStance(js);
    const ds=digests((js.original||{}).payload||{});declared+=ds.length;
    const cls=c.ok?(STATE_CLS[p.state]||"ok"):"bad";
    const win=p.schedule
      ?fmtRange(p.schedule.window_start||"",p.schedule.window_end||"")
      :"unscheduled";
    rows.push(
      `<div class="card" id="v-${esc(tag.dataset.vid)}"><div class="row ${cls}">`
      +`<span class="pill">${esc(p.state||"?")}</span> `
      +`<strong>${esc(tag.dataset.vid)}</strong>`
      +` <a class="plink" href="#v-${esc(tag.dataset.vid)}" `
      +`title="link to this record" aria-label="link to record ${esc(tag.dataset.vid)}">#</a>`
      +(p.scheduled_worker?` · worker ${esc(p.scheduled_worker.name||"")}`:"")
      +(stance!=="no_statement"?` · statement: ${esc(stance)}`:"")
      +` — ${esc(c.why)}</div>`
      /* a FAILED bundle's narrative is untrusted — render only the verdict
         row; tabs/statements/plain view stay hidden so tampered content can't
         present itself as a verified account. */
      +(c.ok
        ?`<span class="view-toggle" role="group" aria-label="record view">`
         +`<button type="button" class="view-tab on" data-view="tech" aria-pressed="true">`
         +`technical</button>`
         +`<button type="button" class="view-tab" data-view="plain" aria-pressed="false">`
         +`plain language (family)</button></span>`
         +`<div class="tech">`+voicesHTML(js)
         +`<small>${win} · ${ds.length} media digest(s)</small>`
         +anchorsHTML(oNode,js.original||{},p)
         +timelineSVG(p)+corroborationHTML(p)+statementsHTML(js)+`</div>`
         +`<div class="plain" style="display:none">${plainHTML(p,js)}</div>`
        :"")
      +`</div>`);
  }
  const wk=weekSVG(payloads);
  if(wk)rows.unshift(
    `<div class="card"><div class="row ok"><span class="pill">week</span> `
    +`<strong>the exported window at a glance</strong> `
    +`<small class="muted">— assembled only from verified signed payloads</small>`
    +`<button type="button" class="print-btn">print this record</button></div>`
    +wk+`</div>`);
  cards.innerHTML=rows.join("");
  cards.onclick=e=>{
    /* Delegated chrome: the week strip's print button and each card's
       technical/plain segmented toggle. Views flip by display only — the
       verified DOM stays intact, and @media print re-shows .plain. */
    if(e.target.closest(".print-btn")){window.print();return;}
    const b=e.target.closest(".view-tab");if(!b)return;
    const card=b.closest(".card");if(!card)return;
    const t=card.querySelector(".tech"),pl=card.querySelector(".plain");
    if(!t||!pl)return;
    const showPlain=b.dataset.view==="plain";
    pl.style.display=showPlain?"":"none";t.style.display=showPlain?"none":"";
    for(const tb of card.querySelectorAll(".view-tab")){
      tb.classList.toggle("on",tb===b);
      tb.setAttribute("aria-pressed",tb===b?"true":"false");}
  };
  let mLine="";
  const mtag=document.getElementById("packmanifest");
  if(mtag&&mtag.textContent){
    const mNode=parseKeep(d64(mtag.textContent));
    const mc=await checkManifestNode(mNode,trusted||key);
    if(!mc.ok)anyBad=true;
    mLine=`<div class="row ${mc.ok?"ok":"bad"}">manifest: ${esc(mc.why)}</div>`;
    const listedVids=new Set();
    const _mArr=x=>Array.isArray(x)?x:[];  /* non-list manifest sections never iterate */
    for(const v of _mArr((toJS(mNode)||{}).visits)){
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
    const alist=Object.create(null);
    for(const a of _mArr((toJS(mNode)||{}).attestations))alist[a.receipt_id]=a;
    const present=new Set();
    for(const tag of document.querySelectorAll("script.attestation")){
      present.add(tag.dataset.rid);
      const aNode=parseKeep(d64(tag.textContent));const rjs=toJS(aNode)||{};
      const listed=alist[tag.dataset.rid];
      const rid=esc(tag.dataset.rid);
      const aOut=trusted?!trusted.has(rjs.public_key):(key&&rjs.public_key!==key);
      if(aOut){
        anyBad=true;
        mLine+=`<div class="row bad">attestation ${rid}: key outside the trusted issuer chain</div>`;
        continue;}
      const rc=await checkReceipt(aNode);
      if(!rc.ok){
        anyBad=true;mLine+=`<div class="row bad">attestation ${rid}: ${esc(rc.why)}</div>`;continue;}
      if(rjs.id!==tag.dataset.rid){
        anyBad=true;
        mLine+=`<div class="row bad">attestation ${rid}: filename disagrees with the signed receipt id</div>`;
        continue;}
      if(!listed||listed.payload_hash!==rjs.payload_hash||listed.visit_id!==rjs.visit_id){
        anyBad=true;
        mLine+=`<div class="row bad">attestation ${rid}: not in the signed manifest</div>`;continue;}
      mLine+=`<div class="row ok">attestation ${esc(listed.record_type||"record")}: signed and intact</div>`;
      cards.innerHTML+=`<div class="card">${attestationHTML(rjs.payload||{})}</div>`;
    }
    for(const a of (toJS(mNode)||{}).attestations||[]){
      if(!present.has(a.receipt_id)){
        anyBad=true;
        mLine+=`<div class="row bad">attestation ${esc(a.receipt_id)}: listed but not inlined</div>`;}
    }
  }
  verdict.innerHTML=anyBad
    ?'<div class="row stamp bad">FAILED — '+n
     +" record(s), at least one does not verify. Do not rely on this pack.</div>"+mLine
    :`<div class="row stamp ok">VERIFIED — ${n} record(s), chains intact under issuer key `
     +esc(String(key||"").slice(0,16))+"…"
     +(_engWc&&_engJs?" · signatures via WebCrypto Ed25519 + BigInt fallback"
       :_engWc?" · signatures via WebCrypto Ed25519"
       :_engJs?" · signatures via pure-JS BigInt Ed25519":"")+"</div>"+mLine
     +(suspectTotal
       ?`<div class="row warn">${suspectTotal} record(s) signed by a revoked issuer `
        +"inside its suspect window</div>":"")
     /* A rotation signed by a key later declared suspect means the handoff
        itself may be attacker-authored — the lineage carries the doubt. */
     +(suspectRecords(rotNodes,revoked).length
       ?`<div class="row warn">${suspectRecords(rotNodes,revoked).length} `
        +"key-lifecycle receipt(s) signed inside a suspect window — the trust "
        +"pivot itself is qualified</div>":"")
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

    Each visit's bundle.json text is inlined base64-encoded inside inert
    ``type="text/plain"`` script tags — immune to ``</script>`` breakout inside
    signed statement text, decoded back to the exact bytes so ``parseKeep``
    still canonicalizes the original literal spellings, and never executed as
    script (a bare ``<script>`` would log a console error per tag). ``meta``
    (site, generated_at, issuer_key) and the raw ``manifest.json`` text — so
    the signed export receipt is verified too — are inlined the same way.
    Everything else — Ed25519, canonicalization, the timeline — is the shared
    ``_JS_LIB``, so the browser *is* the verifier.

    Attribute order is contractual: ``data-vid``/``data-rid``/``id`` stay last
    before ``>`` — tests and the node-side drivers match
    ``data-vid="…">``, ``class="attestation" data-rid="…">`` and
    ``id="packmeta">`` literally.
    """
    import base64
    import json as _json
    from html import escape as _hesc

    enc = lambda s: base64.b64encode(s.encode()).decode()  # noqa: E731
    tags = "".join(
        f'<script type="text/plain" class="bundle" data-vid="{_hesc(vid, quote=True)}">{enc(text)}</script>\n'
        for vid, text in bundles
    )
    tags += "".join(
        f'<script type="text/plain" class="attestation" data-rid="{_hesc(rid, quote=True)}">'
        f"{enc(text)}</script>\n"
        for rid, text in attestations
    )
    meta_tag = f'<script type="text/plain" id="packmeta">{enc(_json.dumps(meta))}</script>\n'
    if manifest_text:
        meta_tag += f'<script type="text/plain" id="packmanifest">{enc(manifest_text)}</script>\n'
    return (
        _HEAD.replace("<title>Attest pack verifier</title>", "<title>Attest case record</title>")
        + '<main id="main">\n'
        + _INDEX_BODY
        + meta_tag
        + tags
        + _JS_OPEN
        + _JS_LIB
        + _INDEX_DRIVER
        + "</script>\n</main>\n</body>\n</html>\n"
    )


if __name__ == "__main__":  # pragma: no cover - developer tool
    import sys

    sys.stdout.write(VERIFY_HTML)
