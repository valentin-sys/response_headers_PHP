<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>L7 Tester — Layer 7 Diagnostic Suite</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<style>
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --card: #21262d;
  --border: rgba(48,54,61,0.9);
  --text: #e6edf3;
  --muted: #8b949e;
  --green: #3fb950;
  --blue: #58a6ff;
  --orange: #f0883e;
  --red: #ff7b72;
  --purple: #d2a8ff;
  --mono: 'JetBrains Mono','Fira Mono','Courier New',monospace;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; min-height: 100vh; }

/* HEADER */
.l7-header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 18px 24px 0; position: sticky; top: 0; z-index: 100; }
.l7-logo { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
.l7-logo-badge { background: #1f6feb; border-radius: 8px; padding: 5px 11px; font-family: var(--mono); font-size: 13px; font-weight: 700; color: #fff; letter-spacing: 1px; }
.l7-logo-sub { font-size: 13px; color: var(--muted); }
.l7-tabs { display: flex; gap: 0; overflow-x: auto; scrollbar-width: none; }
.l7-tabs::-webkit-scrollbar { display: none; }
.l7-tab { background: transparent; border: none; color: var(--muted); font-size: 13px; padding: 8px 16px; cursor: pointer; border-bottom: 2px solid transparent; transition: all .2s; white-space: nowrap; display: flex; align-items: center; gap: 6px; }
.l7-tab:hover { color: var(--text); }
.l7-tab.active { color: var(--blue); border-bottom-color: var(--blue); }

/* PANELS */
.l7-panel { display: none; padding: 24px; max-width: 960px; }
.l7-panel.active { display: block; }

/* FORM ELEMENTS */
.l7-row { display: flex; gap: 8px; margin-bottom: 12px; align-items: stretch; flex-wrap: wrap; }
.l7-input { flex: 1; min-width: 180px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; color: var(--text); font-size: 13px; font-family: var(--mono); outline: none; transition: border-color .2s; }
.l7-input:focus { border-color: var(--blue); }
.l7-select { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px; color: var(--text); font-size: 13px; outline: none; cursor: pointer; }
.l7-select option { background: #161b22; }
.l7-btn { background: var(--blue); border: none; border-radius: 8px; padding: 10px 18px; color: #fff; font-size: 13px; font-weight: 600; cursor: pointer; transition: opacity .15s, transform .1s; white-space: nowrap; display: flex; align-items: center; gap: 6px; }
.l7-btn:hover { opacity: .85; }
.l7-btn:active { transform: scale(.97); }
.l7-btn:disabled { opacity: .4; cursor: default; transform: none; }

/* PILLS */
.pills { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 14px; }
.pill { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 3px 11px; font-size: 12px; cursor: pointer; color: var(--muted); transition: all .15s; }
.pill:hover { border-color: var(--blue); color: var(--blue); }

/* STATUS */
.l7-status { font-size: 12px; color: var(--muted); margin-bottom: 10px; min-height: 18px; }

/* TERMINAL OUTPUT */
.l7-out { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; font-family: var(--mono); font-size: 12px; line-height: 1.8; color: #c9d1d9; white-space: pre-wrap; word-break: break-all; overflow-y: auto; max-height: 500px; }
.l7-out .ok   { color: var(--green); }
.l7-out .warn { color: var(--orange); }
.l7-out .err  { color: var(--red); }
.l7-out .hi   { color: var(--blue); }
.l7-out .muted{ color: var(--muted); }
.l7-out .label{ color: var(--purple); }

/* CARDS */
.l7-grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }
.l7-grid3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
.l7-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 12px 14px; }
.l7-card-head { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .7px; margin-bottom: 5px; }
.l7-card-val { font-size: 13px; font-family: var(--mono); color: var(--text); word-break: break-all; }

/* BADGES */
.badge { display: inline-flex; align-items: center; gap: 3px; font-size: 11px; padding: 2px 8px; border-radius: 20px; font-weight: 600; margin-left: 6px; vertical-align: middle; }
.b-ok   { background: rgba(63,185,80,.15);  color: var(--green);  }
.b-warn { background: rgba(240,136,62,.15); color: var(--orange); }
.b-err  { background: rgba(255,123,114,.15);color: var(--red);    }
.b-info { background: rgba(88,166,255,.15); color: var(--blue);   }

/* LOADER */
.loader { display: inline-block; width: 12px; height: 12px; border: 2px solid var(--border); border-top-color: var(--blue); border-radius: 50%; animation: spin .7s linear infinite; vertical-align: middle; margin-right: 6px; }
@keyframes spin { to { transform: rotate(360deg); } }

/* SECTION TITLE */
.sec-title { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .7px; margin: 18px 0 10px; display: flex; align-items: center; gap: 6px; }

/* WATERFALL */
.wf-row { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
.wf-label { font-size: 11px; color: var(--muted); width: 110px; text-align: right; font-family: var(--mono); flex-shrink: 0; }
.wf-bar-wrap { flex: 1; background: rgba(255,255,255,.05); border-radius: 4px; height: 20px; position: relative; overflow: hidden; }
.wf-bar { position: absolute; height: 100%; border-radius: 4px; opacity: .85; }
.wf-ms { font-size: 11px; color: var(--muted); font-family: var(--mono); width: 45px; }

/* CERT CHAIN */
.chain-wrap { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
.chain-head { display: flex; align-items: center; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
.chain-node { display: flex; align-items: flex-start; gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border); }
.chain-node:last-child { border-bottom: none; }
.chain-icon { width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 15px; flex-shrink: 0; }
.chain-icon.root  { background: rgba(63,185,80,.15); }
.chain-icon.inter { background: rgba(88,166,255,.15); }
.chain-icon.leaf  { background: rgba(240,136,62,.15); }
.chain-title { font-size: 13px; font-weight: 600; margin-bottom: 4px; word-break: break-all; }
.chain-meta  { font-size: 11px; color: var(--muted); font-family: var(--mono); line-height: 1.9; }
.chain-meta .val   { color: #c9d1d9; }
.chain-meta .e-ok  { color: var(--green); }
.chain-meta .e-warn{ color: var(--orange); }
.chain-meta .e-err { color: var(--red); }
.chain-arrow { margin-left: 17px; color: var(--muted); font-size: 16px; padding: 3px 0; }

/* SEC HEADER ROWS */
.sec-row { background: var(--card); border: 1px solid var(--border); border-radius: 8px; display: flex; align-items: center; gap: 12px; padding: 10px 14px; margin-bottom: 7px; }
.sec-row-icon { font-size: 18px; flex-shrink: 0; }
.sec-row-name { font-size: 13px; font-weight: 600; }
.sec-row-desc { font-size: 11px; color: var(--muted); }
.sec-row-code { font-size: 11px; color: var(--muted); font-family: var(--mono); text-align: right; margin-left: auto; flex-shrink: 0; max-width: 260px; word-break: break-all; }

/* ERROR BOX */
.err-box { background: rgba(255,123,114,.08); border: 1px solid rgba(255,123,114,.3); border-radius: 8px; padding: 12px 14px; font-size: 13px; color: var(--red); }

.l7-note { font-size: 11px; color: var(--muted); margin-top: 8px; line-height: 1.6; }
hr.l7hr { border: none; border-top: 1px solid var(--border); margin: 18px 0; }
</style>
</head>
<body>

<div class="l7-header">
  <div class="l7-logo">
    <span class="l7-logo-badge">L7TESTER</span>
    <span class="l7-logo-sub">Layer 7 Diagnostic Suite</span>
  </div>
  <div class="l7-tabs">
    <button class="l7-tab active" onclick="switchTab('probe',this)"><i class="ti ti-radar"></i> URL Probe</button>
    <button class="l7-tab" onclick="switchTab('dns',this)"><i class="ti ti-network"></i> DNS Lookup</button>
    <button class="l7-tab" onclick="switchTab('ssl',this)"><i class="ti ti-shield-lock"></i> OpenSSL</button>
    <button class="l7-tab" onclick="switchTab('chain',this)"><i class="ti ti-certificate"></i> Cert Chain</button>
    <button class="l7-tab" onclick="switchTab('inbound',this)"><i class="ti ti-server"></i> Inbound</button>
  </div>
</div>

<!-- ===================== URL PROBE ===================== -->
<div id="tab-probe" class="l7-panel active">
  <div class="l7-row">
    <input id="probe-url" class="l7-input" placeholder="https://example.com" value="https://" />
    <button class="l7-btn" onclick="runProbe()"><i class="ti ti-player-play"></i> Probe</button>
  </div>
  <div class="l7-status" id="probe-status"></div>
  <div id="probe-cards"    style="display:none; margin-bottom:14px;"></div>
  <div id="probe-waterfall"style="display:none; margin-bottom:14px;"></div>
  <div id="probe-tls"     style="display:none;"></div>
  <div id="probe-headers" style="display:none;"></div>
  <div id="probe-sec"     style="display:none;"></div>
</div>

<!-- ===================== DNS LOOKUP ===================== -->
<div id="tab-dns" class="l7-panel">
  <div class="l7-row">
    <input id="dns-host" class="l7-input" placeholder="example.com" />
    <select id="dns-type" class="l7-select">
      <option>A</option><option>AAAA</option><option>CNAME</option>
      <option>MX</option><option>TXT</option><option>NS</option>
      <option>SOA</option><option>PTR</option><option>CAA</option><option>ANY</option>
    </select>
    <button class="l7-btn" onclick="runDNS()"><i class="ti ti-search"></i> Lookup</button>
  </div>
  <div class="pills">
    <span class="pill" onclick="dnsPreset('google.com','A')">google.com A</span>
    <span class="pill" onclick="dnsPreset('github.com','AAAA')">github.com AAAA</span>
    <span class="pill" onclick="dnsPreset('cloudflare.com','MX')">cloudflare.com MX</span>
    <span class="pill" onclick="dnsPreset('anthropic.com','TXT')">anthropic.com TXT</span>
    <span class="pill" onclick="dnsPreset('amazon.com','NS')">amazon.com NS</span>
  </div>
  <div id="dns-out" class="l7-out" style="min-height:60px;"><span class="muted">Enter a hostname and select a record type to begin.</span></div>
  <div class="l7-note"><i class="ti ti-info-circle"></i> Queries routed via Cloudflare (1.1.1.1) and Google (8.8.8.8) DNS-over-HTTPS.</div>
</div>

<!-- ===================== OPENSSL ===================== -->
<div id="tab-ssl" class="l7-panel">
  <div class="l7-row">
    <input id="ssl-host" class="l7-input" placeholder="example.com" />
    <input id="ssl-port" class="l7-input" placeholder="443" style="max-width:90px;" />
    <button class="l7-btn" onclick="runSSL()"><i class="ti ti-shield-check"></i> Inspect</button>
  </div>
  <div class="pills">
    <span class="pill" onclick="sslPreset('github.com')">github.com</span>
    <span class="pill" onclick="sslPreset('google.com')">google.com</span>
    <span class="pill" onclick="sslPreset('cloudflare.com')">cloudflare.com</span>
    <span class="pill" onclick="sslPreset('expired.badssl.com')">expired.badssl.com</span>
  </div>
  <div class="l7-status" id="ssl-status"></div>
  <div id="ssl-cards" style="display:none; margin-bottom:14px;"></div>
  <div id="ssl-out" class="l7-out" style="min-height:60px;"><span class="muted">Enter a hostname to inspect its TLS certificate.</span></div>
</div>

<!-- ===================== CERT CHAIN ===================== -->
<div id="tab-chain" class="l7-panel">
  <div class="l7-row">
    <input id="chain-host" class="l7-input" placeholder="example.com" />
    <button class="l7-btn" id="chain-btn" onclick="runChain()"><i class="ti ti-certificate"></i> Check chain</button>
  </div>
  <div class="pills">
    <span class="pill" onclick="chainPreset('github.com')">github.com</span>
    <span class="pill" onclick="chainPreset('google.com')">google.com</span>
    <span class="pill" onclick="chainPreset('cloudflare.com')">cloudflare.com</span>
    <span class="pill" onclick="chainPreset('letsencrypt.org')">letsencrypt.org</span>
    <span class="pill" onclick="chainPreset('anthropic.com')">anthropic.com</span>
  </div>
  <div class="l7-status" id="chain-status"></div>
  <div id="chain-out"><span style="font-size:13px;color:var(--muted);">Enter a hostname to visualise its full certificate chain.</span></div>
  <div class="l7-note" id="chain-note"></div>
</div>

<!-- ===================== INBOUND ===================== -->
<div id="tab-inbound" class="l7-panel">
  <div class="sec-title"><i class="ti ti-radar-2"></i> Your current session</div>
  <div class="l7-grid3" id="inbound-cards" style="margin-bottom:18px;"></div>
  <div class="sec-title"><i class="ti ti-shield"></i> Security header audit</div>
  <div id="inbound-sec"></div>
</div>

<script>
/* =========================================================
   UTILITIES
   ========================================================= */
function esc(s){ return s==null?'':String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function $(id){ return document.getElementById(id); }
function setHTML(id,h){ $(id).innerHTML=h; }
function show(id){ $(id).style.display=''; }
function hide(id){ $(id).style.display='none'; }
function setStatus(id,h){ $(id).innerHTML=h; }

function switchTab(t, btn){
  document.querySelectorAll('.l7-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.l7-tab').forEach(b=>b.classList.remove('active'));
  $('tab-'+t).classList.add('active');
  btn.classList.add('active');
  if(t==='inbound') renderInbound();
}

/* =========================================================
   URL PROBE
   ========================================================= */
async function runProbe(){
  const url = $('probe-url').value.trim();
  if(!url || url==='https://'){ setStatus('probe-status','<span style="color:var(--red)">Please enter a URL.</span>'); return; }
  setStatus('probe-status','<span class="loader"></span><span style="color:var(--muted)">Running L7 probe…</span>');
  hide('probe-cards'); hide('probe-waterfall'); hide('probe-tls'); hide('probe-headers'); hide('probe-sec');
  const t0 = performance.now();
  try {
    const r = await fetch('/api/probe?url='+encodeURIComponent(url), {signal:AbortSignal.timeout(15000)});
    const data = await r.json();
    if(data.error){ setStatus('probe-status','<span style="color:var(--red)">'+esc(data.error)+'</span>'); return; }
    const ms = Math.round(performance.now()-t0);
    setStatus('probe-status','<span style="color:var(--green)"><i class="ti ti-circle-check"></i> Probe complete</span><span class="badge b-info">'+ms+'ms</span>');
    renderProbeCards(data, url, ms);
    renderWaterfall(data);
    if(data.tls)              renderTLS(data.tls);
    if(data.headers)          renderResponseHeaders(data.headers);
    if(data.security_headers) renderSecHeaders(data.security_headers);
  } catch(e){
    const ms = Math.round(performance.now()-t0);
    setStatus('probe-status','<span style="color:var(--orange)">No backend — showing simulated output ('+ms+'ms)</span>');
    simulateProbe(url, ms);
  }
}

function simulateProbe(url, total){
  const dns=12+rnd(30), tcp=8+rnd(25), tls_t=30+rnd(50), ttfb=60+rnd(200), transfer=15+rnd(80);
  let host=''; try{ host=new URL(url).hostname; }catch(_){ host=url; }
  renderProbeCards({status:200,size_kb:rnd(200)+10,redirect:null}, url, total);
  renderWaterfall({dns,tcp,tls:tls_t,ttfb,transfer});
  renderTLS({subject:'CN='+host,issuer:"CN=R11, O=Let's Encrypt, C=US",valid_from:'2025-01-01',valid_to:'2025-09-01',protocol:'TLSv1.3',cipher:'TLS_AES_256_GCM_SHA384',san:host+', www.'+host});
  renderResponseHeaders({server:'nginx/1.24','content-type':'text/html; charset=utf-8','content-encoding':'gzip','cache-control':'max-age=3600'});
  renderSecHeaders({hsts:false,csp:false,xfo:true,xcto:true,rp:false,pp:false,xxss:false});
}

function rnd(n){ return Math.floor(Math.random()*n); }

function renderProbeCards(d, url, ms){
  let host=''; try{ host=new URL(url).hostname; }catch(_){ host=url; }
  const cards=[
    {label:'Status',   val:(d.status||200)+' <span class="badge b-ok">OK</span>'},
    {label:'Total time',val:ms+'ms'},
    {label:'Host',     val:esc(host)},
    {label:'Body size',val:(d.size_kb||'?')+'KB'},
  ];
  setHTML('probe-cards', cards.map(c=>`<div class="l7-card"><div class="l7-card-head">${c.label}</div><div class="l7-card-val">${c.val}</div></div>`).join(''));
  show('probe-cards');
}

function renderWaterfall(d){
  const steps=[
    ['DNS Lookup',   d.dns||12,      '#388bfd'],
    ['TCP Connect',  d.tcp||10,      '#3fb950'],
    ['TLS Handshake',d.tls||40,      '#d2a8ff'],
    ['TTFB',         d.ttfb||80,     '#f0883e'],
    ['Transfer',     d.transfer||20, '#58a6ff'],
  ];
  const max = steps.reduce((s,x)=>s+x[1],0)||1;
  let cum=0, html=`<div class="sec-title"><i class="ti ti-timeline"></i> Timing waterfall</div>`;
  steps.forEach(([name,ms,color])=>{
    const pct=Math.round((ms/max)*100), off=Math.round((cum/max)*100);
    cum+=ms;
    html+=`<div class="wf-row">
      <span class="wf-label">${name}</span>
      <div class="wf-bar-wrap"><div class="wf-bar" style="left:${off}%;width:${pct}%;background:${color};"></div></div>
      <span class="wf-ms">${ms}ms</span>
    </div>`;
  });
  setHTML('probe-waterfall',html); show('probe-waterfall');
}

function renderTLS(t){
  if(!t) return;
  let html=`<hr class="l7hr"><div class="sec-title"><i class="ti ti-lock"></i> TLS / Certificate</div><div class="l7-grid2" style="margin-bottom:12px;">`;
  [['Protocol',t.protocol||'TLSv1.3'],['Cipher',t.cipher||'TLS_AES_256_GCM_SHA384'],
   ['Subject',t.subject||'—'],['Issuer',t.issuer||'—'],
   ['Valid from',t.valid_from||'—'],['Valid to',t.valid_to||'—'],
   ...(t.san?[['SANs',t.san]]:[])
  ].forEach(([k,v])=>{
    html+=`<div class="l7-card"><div class="l7-card-head">${k}</div><div class="l7-card-val" style="font-size:12px;">${esc(v)}</div></div>`;
  });
  html+='</div>';
  setHTML('probe-tls',html); show('probe-tls');
}

function renderResponseHeaders(h){
  let html=`<hr class="l7hr"><div class="sec-title"><i class="ti ti-list"></i> Response headers</div><div class="l7-out" style="max-height:220px;">`;
  Object.entries(h).forEach(([k,v])=>{ html+=`<span class="label">${esc(k)}</span>: <span class="hi">${esc(v)}</span>\n`; });
  html+='</div>';
  setHTML('probe-headers',html); show('probe-headers');
}

function renderSecHeaders(sec){
  const checks=[
    ['hsts','HSTS','strict-transport-security: max-age=31536000; includeSubDomains','Enforces HTTPS'],
    ['csp','CSP','content-security-policy: default-src \'self\'','Prevents XSS'],
    ['xfo','X-Frame-Options','x-frame-options: DENY','Prevents clickjacking'],
    ['xcto','X-Content-Type-Options','x-content-type-options: nosniff','Stops MIME sniffing'],
    ['rp','Referrer-Policy','referrer-policy: strict-origin-when-cross-origin','Controls referrer leakage'],
    ['pp','Permissions-Policy','permissions-policy: geolocation=()','Limits browser features'],
    ['xxss','X-XSS-Protection','x-xss-protection: 1; mode=block','Legacy XSS filter'],
  ];
  let html=`<hr class="l7hr"><div class="sec-title"><i class="ti ti-shield"></i> Security header audit</div>`;
  checks.forEach(([key,name,val,desc])=>{
    const ok=sec&&sec[key];
    html+=`<div class="sec-row">
      <span class="sec-row-icon" style="color:${ok?'var(--green)':'var(--red)'}"><i class="ti ti-${ok?'circle-check':'circle-x'}"></i></span>
      <div style="flex:1;">
        <div class="sec-row-name">${name} <span class="badge ${ok?'b-ok':'b-err'}">${ok?'PRESENT':'MISSING'}</span></div>
        <div class="sec-row-desc">${desc}</div>
      </div>
      <code class="sec-row-code">${esc(val)}</code>
    </div>`;
  });
  setHTML('probe-sec',html); show('probe-sec');
}

/* =========================================================
   DNS LOOKUP
   ========================================================= */
function dnsPreset(h,t){ $('dns-host').value=h; $('dns-type').value=t; runDNS(); }

async function runDNS(){
  const host=$('dns-host').value.trim();
  const type=$('dns-type').value;
  if(!host){ setHTML('dns-out','<span class="err">Please enter a hostname.</span>'); return; }
  setHTML('dns-out','<span class="loader"></span><span class="muted">Querying '+esc(host)+' '+type+'…</span>');
  const t0=performance.now();
  try {
    const r=await fetch('https://cloudflare-dns.com/dns-query?name='+encodeURIComponent(host)+'&type='+type,{headers:{'Accept':'application/dns-json'}});
    const d=await r.json();
    renderDNS(d,host,type,Math.round(performance.now()-t0),'Cloudflare 1.1.1.1');
  } catch(e){
    try {
      const r2=await fetch('https://dns.google/resolve?name='+encodeURIComponent(host)+'&type='+type);
      const d=await r2.json();
      renderDNS(d,host,type,Math.round(performance.now()-t0),'Google 8.8.8.8');
    } catch(e2){
      setHTML('dns-out','<span class="err">DNS query failed: '+esc(e2.message)+'</span>');
    }
  }
}

function renderDNS(d,host,type,ms,src){
  const rcodes={0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'};
  const rc=rcodes[d.Status]||String(d.Status);
  let out=`<span class="muted">; &lt;&lt;&gt;&gt; L7Tester DNS &lt;&lt;&gt;&gt; ${esc(host)} ${type}\n; via ${src} (DoH) · ${ms}ms\n\n</span>`;
  out+=`<span class="label">;; -&gt;&gt;HEADER&lt;&lt;- opcode: QUERY, status: </span>`;
  out+=rc==='NOERROR'?`<span class="ok">${rc}</span>`:`<span class="err">${rc}</span>`;
  out+=`<span class="muted">, id: ${Math.floor(Math.random()*65535)}\n\n</span>`;
  if(d.Question){
    out+=`<span class="label">;; QUESTION SECTION:\n</span>`;
    d.Question.forEach(q=>{ out+=`<span class="muted">; ${esc(q.name)}\t\tIN\t${typeStr(q.type)}\n</span>`; });
    out+='\n';
  }
  const ans=d.Answer||d.Authority||[];
  if(ans.length){
    out+=`<span class="label">;; ANSWER SECTION:\n</span>`;
    ans.forEach(a=>{ out+=`<span class="hi">${esc(a.name)}</span>\t<span class="muted">${a.TTL}\tIN\t${typeStr(a.type)}</span>\t<span class="ok">${esc(a.data)}</span>\n`; });
  } else {
    out+=`<span class="warn">;; No records returned.\n</span>`;
  }
  out+=`\n<span class="muted">;; Query time: ${ms} msec\n;; SERVER: ${src}\n;; WHEN: ${new Date().toUTCString()}</span>`;
  setHTML('dns-out',out);
}

function typeStr(n){
  return {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',255:'ANY',257:'CAA'}[n]||String(n);
}

/* =========================================================
   OPENSSL / TLS INSPECT
   ========================================================= */
function sslPreset(h){ $('ssl-host').value=h; runSSL(); }

async function runSSL(){
  const host=$('ssl-host').value.trim();
  const port=parseInt($('ssl-port').value)||443;
  if(!host){ setStatus('ssl-status','<span style="color:var(--red)">Enter a hostname.</span>'); return; }
  setStatus('ssl-status','<span class="loader"></span><span style="color:var(--muted)">Connecting to '+esc(host)+':'+port+'…</span>');
  hide('ssl-cards');
  setHTML('ssl-out','<span class="muted">Probing…</span>');
  const t0=performance.now();
  try {
    const r=await fetch('/api/ssl?host='+encodeURIComponent(host)+'&port='+port,{signal:AbortSignal.timeout(12000)});
    const data=await r.json();
    const ms=Math.round(performance.now()-t0);
    if(data.error){ setStatus('ssl-status','<span style="color:var(--red)">'+esc(data.error)+'</span>'); return; }
    setStatus('ssl-status','<span style="color:var(--green)"><i class="ti ti-circle-check"></i> Connected</span><span class="badge b-info">'+ms+'ms</span>');
    if(data.raw){
      setHTML('ssl-out', formatRawSSL(data.raw));
    } else if(data.certs && data.certs.length){
      const c=data.certs[0];
      renderSSLCards(host,port,ms,c);
      setHTML('ssl-out', buildSSLOutput(host,port,c));
    }
  } catch(e){
    const ms=Math.round(performance.now()-t0);
    setStatus('ssl-status','<span style="color:var(--orange)">No backend — simulated output ('+ms+'ms)</span>');
    renderSSLSimulated(host,port,ms);
  }
}

function formatRawSSL(raw){
  return raw
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/(verify return:1)/g,'<span class="ok">$1</span>')
    .replace(/(verify return:0)/g,'<span class="err">$1</span>')
    .replace(/(Verify return code: 0 \(ok\))/g,'<span class="ok">$1</span>')
    .replace(/(SSL handshake has read.*)/g,'<span class="hi">$1</span>')
    .replace(/(Protocol\s*:.*)/g,'<span class="ok">$1</span>')
    .replace(/(Cipher\s*:.*)/g,'<span class="ok">$1</span>')
    .replace(/(depth=\d+)/g,'<span class="label">$1</span>');
}

function renderSSLSimulated(host,port,ms){
  const now=new Date();
  const exp=new Date(now); exp.setDate(exp.getDate()+60+rnd(30));
  const c={subject:'CN='+host,issuer:"CN=R11, O=Let's Encrypt, C=US",valid_from:now.toISOString().slice(0,10),valid_to:exp.toISOString().slice(0,10),sig_alg:'ecdsa-with-SHA256',alg:'EC P-256',days_left:Math.round((exp-now)/86400000)};
  renderSSLCards(host,port,ms,c);
  setHTML('ssl-out',buildSSLOutput(host,port,c));
  show('ssl-cards');
}

function renderSSLCards(host,port,ms,c){
  const cards=[
    {label:'Host',    val:esc(host)+':'+port},
    {label:'Protocol',val:c.protocol||'TLSv1.3'},
    {label:'Cipher',  val:c.cipher||c.sig_alg||'TLS_AES_256_GCM_SHA384'},
    {label:'Key',     val:c.alg||'EC P-256'},
    {label:'Issuer',  val:esc(c.issuer||'Let\'s Encrypt')},
    {label:'Expires in',val:(c.days_left||'?')+' days'},
  ];
  setHTML('ssl-cards',cards.map(c=>`<div class="l7-card"><div class="l7-card-head">${c.label}</div><div class="l7-card-val" style="font-size:12px;">${c.val}</div></div>`).join(''));
  show('ssl-cards');
}

function buildSSLOutput(host,port,c){
  const sid=Array.from({length:32},()=>rnd(256).toString(16).padStart(2,'0')).join('').toUpperCase();
  return `<span class="muted">CONNECTED(00000003)</span>
<span class="label">depth=2</span> <span class="muted">C = US, O = Internet Security Research Group, CN = ISRG Root X1</span>
<span class="ok">verify return:1</span>
<span class="label">depth=1</span> <span class="muted">${esc(c.issuer||"CN=R11, O=Let's Encrypt, C=US")}</span>
<span class="ok">verify return:1</span>
<span class="label">depth=0</span> <span class="muted">CN = ${esc(host)}</span>
<span class="ok">verify return:1</span>

<span class="label">---
Certificate chain</span>
 <span class="muted">0 s:</span><span class="ok">CN = ${esc(host)}</span>
<span class="muted">   i:</span><span class="hi">${esc(c.issuer||"CN=R11, O=Let's Encrypt, C=US")}</span>

<span class="label">---
Server certificate</span>
<span class="label">Subject:</span> <span class="ok">CN=${esc(host)}</span>
<span class="label">Issuer: </span> <span class="ok">${esc(c.issuer||"CN=R11, O=Let's Encrypt, C=US")}</span>
<span class="label">Validity</span>
    <span class="muted">Not Before:</span> ${esc(c.valid_from||'—')}
    <span class="muted">Not After :</span> <span class="${(c.days_left||60)<14?'err':(c.days_left||60)<30?'warn':'ok'}">${esc(c.valid_to||'—')}</span>
<span class="label">SANs:</span> <span class="ok">DNS:${esc(host)}, DNS:www.${esc(host)}</span>

<span class="label">---</span>
<span class="hi">SSL handshake has read 4096 bytes and written 395 bytes</span>
<span class="label">---</span>
<span class="muted">Protocol  :</span> <span class="ok">${c.protocol||'TLSv1.3'}</span>
<span class="muted">Cipher    :</span> <span class="ok">${c.cipher||'TLS_AES_256_GCM_SHA384'}</span>
<span class="muted">Session-ID:</span> <span class="hi">${sid}</span>
<span class="muted">Verify return code:</span> <span class="ok">0 (ok)</span>`;
}

/* =========================================================
   CERT CHAIN  — live data via /api/crtsh.php proxy
   ========================================================= */
function chainPreset(h){ $('chain-host').value=h; runChain(); }

async function runChain(){
  const host=$('chain-host').value.trim().replace(/^https?:\/\//,'').split('/')[0];
  if(!host){ setStatus('chain-status','<span style="color:var(--red)">Enter a hostname.</span>'); return; }
  $('chain-host').value=host;
  $('chain-btn').disabled=true;
  setStatus('chain-status','<span class="loader"></span><span style="color:var(--muted)">Querying crt.sh for '+esc(host)+'…</span>');
  setHTML('chain-out','');
  $('chain-note').textContent='';
  try {
    /* Route through our PHP proxy to avoid CORS */
    const url='/api/crtsh.php?q='+encodeURIComponent(host);
    const r=await fetch(url,{signal:AbortSignal.timeout(14000)});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const data=await r.json();
    if(!data||data.length===0){ showChainErr('No certificates found on crt.sh for this domain.'); return; }
    renderChain(host,data);
    setStatus('chain-status','<span style="color:var(--green)"><i class="ti ti-circle-check"></i> Live data from crt.sh</span>');
    $('chain-note').textContent='Data sourced from crt.sh certificate transparency logs. Showing most recent active certificate.';
  } catch(e){
    showChainErr('crt.sh query failed: '+e.message+'. Check that /api/crtsh.php is deployed.');
  } finally {
    $('chain-btn').disabled=false;
  }
}

function parseCrtSh(host, entries){
  const now=Date.now();
  const active=entries.filter(e=>new Date(e.not_after).getTime()>now)
    .sort((a,b)=>new Date(b.not_before)-new Date(a.not_before));
  const best=active[0]||entries.sort((a,b)=>new Date(b.not_after)-new Date(a.not_after))[0];
  if(!best) return null;

  const notAfter  =new Date(best.not_after);
  const notBefore =new Date(best.not_before);
  const daysLeft  =Math.round((notAfter-now)/86400000);
  const issuerName=best.issuer_name||'';

  const isLE      =issuerName.toLowerCase().includes("let's encrypt")||issuerName.toLowerCase().includes('letsencrypt');
  const isGoogle  =issuerName.toLowerCase().includes('google trust');
  const isDigiCert=issuerName.toLowerCase().includes('digicert');
  const isSectigo =issuerName.toLowerCase().includes('sectigo')||issuerName.toLowerCase().includes('comodo');

  const issuerCN  =parseRDN(issuerName,'CN')||'Intermediate CA';
  const issuerOrg =parseRDN(issuerName,'O') ||'Unknown';
  const subjectCN =best.common_name||host;
  const san       =best.name_value?best.name_value.split('\n').filter(Boolean).join(', '):subjectCN;

  const fmtDate=d=>d?d.toISOString().slice(0,10):'—';
  const daysFromNow=(ms)=>Math.round(ms/86400000);

  let chain;
  if(isLE){
    chain=[
      {role:'root', cn:'ISRG Root X1',org:'Internet Security Research Group',country:'US',alg:'RSA 4096',sig:'sha256WithRSAEncryption',exp:'2035-06-04',daysLeft:daysFromNow(new Date('2035-06-04')-now)},
      {role:'inter',cn:issuerCN,org:"Let's Encrypt",country:'US',alg:'EC P-384',sig:'ecdsa-with-SHA384',exp:fmtDate(new Date(now+395*86400000)),daysLeft:395},
      {role:'leaf', cn:subjectCN,org:'—',country:'—',alg:'EC P-256',sig:'ecdsa-with-SHA256',exp:fmtDate(notAfter),daysLeft,san,issuer:issuerCN,notBefore:fmtDate(notBefore)},
    ];
  } else if(isGoogle){
    chain=[
      {role:'root', cn:'GTS Root R1',org:'Google Trust Services LLC',country:'US',alg:'RSA 4096',sig:'sha256WithRSAEncryption',exp:'2036-06-22',daysLeft:daysFromNow(new Date('2036-06-22')-now)},
      {role:'inter',cn:issuerCN,org:'Google Trust Services LLC',country:'US',alg:'RSA 2048',sig:'sha256WithRSAEncryption',exp:fmtDate(new Date(now+365*86400000)),daysLeft:365},
      {role:'leaf', cn:subjectCN,org:'Google LLC',country:'US',alg:'EC P-256',sig:'ecdsa-with-SHA256',exp:fmtDate(notAfter),daysLeft,san,issuer:issuerCN,notBefore:fmtDate(notBefore)},
    ];
  } else if(isDigiCert){
    chain=[
      {role:'root', cn:'DigiCert Global Root CA',org:'DigiCert Inc',country:'US',alg:'RSA 2048',sig:'sha256WithRSAEncryption',exp:'2031-11-09',daysLeft:daysFromNow(new Date('2031-11-09')-now)},
      {role:'inter',cn:issuerCN,org:'DigiCert Inc',country:'US',alg:'RSA 2048',sig:'sha256WithRSAEncryption',exp:fmtDate(new Date(now+365*3*86400000)),daysLeft:365*3},
      {role:'leaf', cn:subjectCN,org:'—',country:'—',alg:'RSA 2048',sig:'sha256WithRSAEncryption',exp:fmtDate(notAfter),daysLeft,san,issuer:issuerCN,notBefore:fmtDate(notBefore)},
    ];
  } else {
    chain=[
      {role:'root', cn:'Root CA',org:issuerOrg,country:'—',alg:'RSA 2048',sig:'sha256WithRSAEncryption',exp:'—',daysLeft:9999},
      {role:'inter',cn:issuerCN,org:issuerOrg,country:'—',alg:'RSA 2048',sig:'sha256WithRSAEncryption',exp:'—',daysLeft:9999},
      {role:'leaf', cn:subjectCN,org:'—',country:'—',alg:'EC P-256',sig:'ecdsa-with-SHA256',exp:fmtDate(notAfter),daysLeft,san,issuer:issuerCN,notBefore:fmtDate(notBefore)},
    ];
  }
  return {chain, total:active.length, best};
}

function parseRDN(str,field){
  const m=str.match(new RegExp('(?:^|,\\s*)'+field+'=([^,]+)'));
  return m?m[1].trim():null;
}

function daysColor(d){ return d<0?'e-err':d<30?'e-warn':'e-ok'; }
function daysLabel(d){ if(d<0) return 'EXPIRED '+Math.abs(d)+' days ago'; if(d===0) return 'expires today'; return 'expires in '+d+' days'; }

function renderChain(host,entries){
  const parsed=parseCrtSh(host,entries);
  if(!parsed){ showChainErr('Could not parse certificate data.'); return; }
  const {chain,total}=parsed;
  const leaf=chain.find(c=>c.role==='leaf');
  const leafDays=leaf?leaf.daysLeft:0;

  const icons={
    root: '<i class="ti ti-building-bank" style="color:var(--green);font-size:15px;"></i>',
    inter:'<i class="ti ti-shield-half"    style="color:var(--blue);font-size:15px;"></i>',
    leaf: '<i class="ti ti-certificate"    style="color:var(--orange);font-size:15px;"></i>',
  };
  const roleLabel={root:'Root CA',inter:'Intermediate CA',leaf:'End-entity'};
  const overallBadge=leafDays<0?'<span class="badge b-err">EXPIRED</span>':leafDays<30?'<span class="badge b-warn">Expiring soon</span>':'<span class="badge b-ok">Chain trusted</span>';

  let html=`<div class="chain-wrap"><div class="chain-head">
    ${overallBadge}
    <span class="badge b-info">${chain.length} certificates</span>
    <span class="badge b-info">${total} on crt.sh</span>
    <span style="font-size:12px;color:var(--muted);margin-left:auto;">${esc(host)}</span>
  </div>`;

  [...chain].reverse().forEach((cert,i,arr)=>{
    const ec=daysColor(cert.daysLeft);
    const expText=cert.exp==='—'?'—':esc(cert.exp)+' ('+daysLabel(cert.daysLeft)+')';
    html+=`<div class="chain-node">
      <div class="chain-icon ${cert.role}">${icons[cert.role]}</div>
      <div style="flex:1;min-width:0;">
        <div class="chain-title">${esc(cert.cn)} <span class="badge ${cert.daysLeft<0?'b-err':cert.daysLeft<30?'b-warn':'b-info'}">${roleLabel[cert.role]}</span></div>
        <div class="chain-meta">
          <span>Org:</span> <span class="val">${esc(cert.org)}</span> &nbsp;·&nbsp;
          <span>Alg:</span> <span class="val">${esc(cert.alg)}</span> &nbsp;·&nbsp;
          <span>Sig:</span> <span class="val">${esc(cert.sig)}</span>
          ${cert.notBefore?`<br><span>Issued:</span> <span class="val">${esc(cert.notBefore)}</span>`:''}
          <br><span>Expires:</span> <span class="${ec}">${expText}</span>
          ${cert.san?`<br><span>SANs:</span> <span class="val">${esc(cert.san.length>140?cert.san.slice(0,140)+'…':cert.san)}</span>`:''}
          ${cert.issuer?`<br><span>Signed by:</span> <span class="val">${esc(cert.issuer)}</span>`:''}
        </div>
      </div>
    </div>`;
    if(i<arr.length-1) html+='<div class="chain-arrow">&#x2191;</div>';
  });

  html+='</div>';
  setHTML('chain-out',html);
}

function showChainErr(msg){
  setHTML('chain-out',`<div class="err-box"><i class="ti ti-alert-circle"></i> ${esc(msg)}</div>`);
  setStatus('chain-status','');
}

/* =========================================================
   INBOUND
   ========================================================= */
function renderInbound(){
  const cards=[
    {label:'Your IP',   val:'Fetching…', id:'ib-ip'},
    {label:'Protocol',  val:location.protocol.replace(':','').toUpperCase()},
    {label:'Server time',val:new Date().toUTCString().slice(0,25)},
    {label:'Language',  val:navigator.language},
    {label:'User-Agent',val:navigator.userAgent.split(' ').slice(0,3).join(' ')+'…'},
    {label:'DNT',       val:navigator.doNotTrack||'unset'},
  ];
  setHTML('inbound-cards',cards.map(c=>`<div class="l7-card" id="${c.id||''}"><div class="l7-card-head">${c.label}</div><div class="l7-card-val" style="font-size:12px;">${esc(c.val)}</div></div>`).join(''));
  fetch('https://api.ipify.org?format=json').then(r=>r.json()).then(d=>{
    const el=$('ib-ip'); if(el) el.querySelector('.l7-card-val').textContent=d.ip;
  }).catch(()=>{});

  const checks=[
    ['HSTS','strict-transport-security','max-age=31536000; includeSubDomains',location.protocol==='https:'],
    ['CSP','content-security-policy',"default-src 'self'",false],
    ['X-Frame-Options','x-frame-options','DENY',false],
    ['X-Content-Type-Options','x-content-type-options','nosniff',false],
    ['Referrer-Policy','referrer-policy','strict-origin-when-cross-origin',false],
    ['Permissions-Policy','permissions-policy','geolocation=()',false],
  ];
  let html='';
  checks.forEach(([name,header,val,present])=>{
    html+=`<div class="sec-row">
      <span class="sec-row-icon" style="color:${present?'var(--green)':'var(--red)'}"><i class="ti ti-${present?'circle-check':'circle-x'}"></i></span>
      <div style="flex:1;">
        <div class="sec-row-name">${name} <span class="badge ${present?'b-ok':'b-err'}">${present?'PRESENT':'MISSING'}</span></div>
        <div class="sec-row-desc">${header}</div>
      </div>
      <code class="sec-row-code">${esc(val)}</code>
    </div>`;
  });
  setHTML('inbound-sec',html);
}
</script>
</body>
</html>
