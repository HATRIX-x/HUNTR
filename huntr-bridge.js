/* HUNTR LIVE BRIDGE — injected by huntr-server at runtime; edit here, never inside huntr-ui.html */
/* ── HUNTR LIVE BRIDGE ── makes the premium workbench fire the real engine when served locally ── */
(function(){
  if(location.hostname!=='127.0.0.1' && location.hostname!=='localhost') return;
  const API=location.origin+'/api';
  window.__HUNTR_LIVE=true;
  async function jpost(p,b){const r=await fetch(API+p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});return r.json();}
  function curTarget(){ try{ if(window.V&&V.target&&V.target!=='all') return V.target; if(window.WB&&WB.ep){const s=sessions.find(x=>x.id===WB.ep.huntId); if(s)return (s.program&&s.program.trim())||s.scope;} }catch(e){} return 'default'; }
  function urlFor(f){const host=f.host;return (/^https?:/.test(host)?host:'https://'+host)+f.n.label;}
  window.HUNTR_ENGINE='http';  // 'http' = curl via scope-guard · 'cdp' = real Chrome
  // real Send (routes through the chosen exec engine)
  window.rpSend=async function(){ const f=nodeFor&&nodeFor(); if(!f)return; const out=document.getElementById('rp-out'); const cdp=window.HUNTR_ENGINE==='cdp';
    if(out)out.innerHTML='<div class="rp-hint">'+(cdp?'firing from your real Chrome…':'firing through scope-guard…')+'</div>';
    if(cdp){ const b=await jpost('/browser',{}); if(!b.up){ out.innerHTML='<div class="rp-verdict bad">No debuggable Chrome on :9222. Launch:<br><code>google-chrome --remote-debugging-port=9222 --user-data-dir="$HOME/.config/google-chrome"</code><br>open a tab on the target, then Send again.</div>'; return; } }
    const r=await jpost('/exec',{target:curTarget(),url:urlFor(f),method:'GET',engine:window.HUNTR_ENGINE,identity:(window.WB&&WB.rpid)||'session'});
    if(out)out.innerHTML='<div class="rp-resp"><div class="rp-resp-h"><span>response · '+(cdp?'real browser':'live')+'</span></div><div class="rp-resp-b">'+((r.out||'')+(r.err?'\n'+r.err:'')).replace(/</g,'&lt;')+'</div></div>'; };
  // real Diff (two identities → diff-oracle)
  window.rpDiff=async function(){ const f=nodeFor&&nodeFor(); if(!f)return; const out=document.getElementById('rp-out'); if(out)out.innerHTML='<div class="rp-hint">running as two identities…</div>';
    const r=await jpost('/exec',{target:curTarget(),url:urlFor(f),diff:'admin,low-priv',expect:'deny'});
    const txt=(r.out||'')+(r.err?'\n'+r.err:''); const bad=/VIOLATION|CROSS-USER|BOLA|BFLA/i.test(txt); const ok=/no access-control violation/i.test(txt);
    if(out)out.innerHTML='<div class="rp-resp"><div class="rp-resp-b">'+txt.replace(/</g,'&lt;')+'</div></div>'+(ok?'<div class="rp-verdict ok">✓ low-priv denied — no access bug on this pair.</div>':bad?'<div class="rp-verdict bad">⚠ access violation — confirm + escalate.</div>':''); };
  // Programs page: prepend a live "hunt now by $/hr" ROI board from /api/roi
  (function(){ const st=document.createElement('style'); st.textContent=
    '.roi-board{margin-bottom:6px}.roi-row{display:grid;grid-template-columns:auto 1fr auto;gap:14px;align-items:center;padding:13px 18px;border-bottom:1px solid var(--border)}.roi-row:last-child{border-bottom:none}'+
    '.roi-rank{width:24px;height:24px;border-radius:8px;display:grid;place-items:center;font-family:var(--mono);font-size:12px;font-weight:700;color:var(--accent);background:var(--accent2);border:1px solid var(--accent3)}'+
    '.roi-name{font-family:var(--sans);font-weight:700;color:var(--white);font-size:14px}.roi-sub{font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:3px}'+
    '.roi-hr{font-family:var(--mono);font-size:18px;font-weight:700;color:var(--gold);font-variant-numeric:tabular-nums}.roi-hr span{font-size:11px;color:var(--text3)}'+
    '.roi-hint{font-family:var(--sans);font-size:11.5px;color:var(--text3);margin:10px 2px 0}';
    document.head.appendChild(st); })();
  // Monitor page: prepend a live "scope radar" board (program scope/reward changes)
  const _rm=window.renderMonitor;
  window.renderMonitor=function(el){
    if(_rm) _rm(el);
    fetch(API+'/scope-changes').then(r=>r.json()).then(d=>{
      const C=((d&&d.changes)||[]).slice().reverse();
      let inner;
      if(!C.length){ inner='<div class="roi-hint">No program scope changes tracked yet. Baseline a program: <code>scope-radar.py --snapshot --program X</code>, then <code>--check</code> on a schedule.</div>'; }
      else { inner='<div class="table-glass">'+C.slice(0,8).map(c=>{
        const add=(c.added||[]).length, rw=c.reward||'';
        return `<div class="roi-row"><span class="roi-rank" style="${add?'color:var(--gold);border-color:rgba(231,201,131,.5);background:rgba(231,201,131,.12)':''}">${add||'~'}</span>`+
        `<div><div class="roi-name">${c.program}${add?' · '+add+' NEW asset'+(add>1?'s':''):''}</div>`+
        `<div class="roi-sub">${c.ts}${(c.added||[]).length?' · '+c.added.slice(0,3).join(', '):''}${(c.removed||[]).length?' · −'+c.removed.length+' removed':''}</div></div>`+
        `<div class="roi-hr" style="font-size:12px;color:${rw?'var(--gold)':'var(--text3)'}">${rw||'scope'}</div></div>`;}).join('')+'</div>'
        +'<div class="roi-hint">New scope = uncrowded = first-to-report money. It also floats to the top of Programs → Hunt now.</div>'; }
      const board=`<div style="margin-bottom:26px"><div class="section-label" style="margin-bottom:12px">Scope radar — program changes</div>${inner}</div>`;
      el.insertAdjacentHTML('afterbegin', board);
    }).catch(()=>{});
  };
  const SYM={USD:'$',EUR:'€',GBP:'£'};
  const money=(o)=>Object.keys(o||{}).length?Object.entries(o).map(([c,v])=>`${SYM[c]||c+' '}${Math.round(v).toLocaleString()}`).join(' · '):'—';
  const _rp=window.renderPrograms;
  window.renderPrograms=function(el){
    if(_rp) _rp(el);
    // earnings strip (the business ledger) — top of Programs
    fetch(API+'/earnings').then(r=>r.json()).then(e=>{
      const strip=`<div class="ck-bar" style="margin-bottom:22px">
        <div class="ck-money"><span class="ck-earn">${money(e.paid)}</span><span class="ck-earn-l">earned (paid)</span></div>
        <div class="ck-sep"></div>
        <div class="ck-money"><span class="ck-triage">${money(e.pending)}</span><span class="ck-earn-l">in triage</span></div>
        <div class="ck-sep"></div>
        <div class="ck-money"><span class="ck-triage">${money(e.ytd)}</span><span class="ck-earn-l">this year</span></div>
        <span style="margin-left:auto;font-family:var(--mono);font-size:10.5px;color:var(--text3)">${(e.counts&&e.counts.paid)||0} paid · ${(e.counts&&e.counts.programs)||0} programs · from your ledger</span>
      </div>`;
      el.insertAdjacentHTML('afterbegin', strip);
    }).catch(()=>{});
    fetch(API+'/roi').then(r=>r.json()).then(d=>{
      const P=(d&&d.programs)||[];
      let inner;
      if(!P.length){ inner='<div class="roi-hint">No ROI data yet. Add programs: <code>program-roi.py --add</code> (or <code>--seed</code>), then reopen.</div>'; }
      else { inner='<div class="table-glass roi-board">'+P.slice(0,6).map((p,i)=>
        `<div class="roi-row"><span class="roi-rank">${i+1}</span><div><div class="roi-name">${p.name}</div>`+
        `<div class="roi-sub">${p.platform} · fit ${(p.fit*100).toFixed(0)}% · dup ${(p.dup*100).toFixed(0)}% · ${p.reports_week}/wk${p.fresh?' · <b style="color:var(--gold)">NEW scope</b>':''} · ~$${p.roi_per_hunt}/hunt</div></div>`+
        `<div class="roi-hr">$${p.per_hr}<span>/hr</span></div></div>`).join('')+'</div>'
        +`<div class="roi-hint">Ranked by expected $/hour, tuned to your paid history — hunt #1 first.</div>`; }
      const board=`<div style="margin-bottom:26px"><div class="section-label" style="margin-bottom:12px">Hunt now — by ROI</div>${inner}</div>`;
      el.insertAdjacentHTML('afterbegin', board);
    }).catch(()=>{});
  };
  // live dup-probability chip on the report view (pre-submit gut check)
  function inferClass(f){const s=((f&&f.title||'')+' '+(f&&f.endpoint||'')).toLowerCase();
    const map=[['sqli','sql inj'],['idor','idor'],['idor','bola'],['authz','access control'],['bfla','privileg'],
      ['ssrf','ssrf'],['xss','xss'],['ssti','template inj'],['rce','rce'],['rce','code exec'],['cors','cors'],
      ['csrf','csrf'],['jwt','jwt'],['oauth','oauth'],['authbypass','auth bypass'],['authbypass','account takeover'],
      ['openredirect','open redirect'],['race','race'],['fileupload','upload'],['session','session'],['logic','logic']];
    for(const[c,kw]of map)if(s.includes(kw))return c; return 'misc';}
  const _render=window.render;
  window.render=function(){ if(_render)_render.apply(this,arguments);
    try{ if(V.page==='report-view'||V.page==='finding-report'){
      const s=(typeof getS==='function')?getS():null;
      let f=null,prog='';
      if(V.page==='report-view'&&s){f=s.findings[V.fi];prog=(s.program&&s.program.trim())||s.scope;}
      else if(typeof allFindingsFlat==='function'){f=allFindingsFlat()[V.fi];prog=(f&&(f.program||f.scope))||'';}
      if(f){ const tb=document.querySelector('.rv-toolbar');
        if(tb&&!document.getElementById('appeal-btn')){
          const ab=document.createElement('button'); ab.id='appeal-btn'; ab.className='btn-sm btn-sm-g'; ab.textContent='Appeal…';
          ab.title='Got a downgrade / N-A / dup? Draft a rebuttal.';
          ab.onclick=function(){ const reason=prompt("Paste the triager's closing reason (N/A, intended, duplicate, severity, NMI…):"); if(!reason)return;
            jpost('/appeal',{reason:reason,cls:inferClass(f),endpoint:f.endpoint||'',title:f.title||'',severity:({c:'critical',h:'high',m:'medium',l:'low',i:'info'})[f.sev]||''}).then(d=>{
              let host=document.getElementById('appeal-panel'); const rv=document.querySelector('.report-viewer')||tb.parentNode;
              if(!host){host=document.createElement('div');host.id='appeal-panel';host.style.cssText='margin:18px 0;padding:16px 18px;border-radius:12px;background:var(--glass);border:1px solid var(--border2)';rv.appendChild(host);}
              const col=d.decision==='DROP'?'var(--red)':d.decision==='PROVIDE-INFO'?'var(--amber)':'var(--green)';
              host.innerHTML=`<div style="font-family:var(--mono);font-size:12px;font-weight:700;color:${col};margin-bottom:8px">${d.decision} · ${d.pattern||''}</div>`+
                (d.decision==='DROP'?`<div style="color:var(--text2);font-size:13px;line-height:1.6">${(d.guidance||'').replace(/</g,'&lt;')}</div>`:
                `<textarea style="width:100%;min-height:220px;background:#0c0818;border:1px solid var(--border2);border-radius:10px;color:#d7d2ee;font-family:var(--mono);font-size:12px;line-height:1.6;padding:12px">${(d.draft||'').replace(/</g,'&lt;')}</textarea>`);
              host.scrollIntoView({behavior:'smooth',block:'center'});
            }).catch(()=>{});
          };
          tb.appendChild(ab);
        }
        if(tb&&!document.getElementById('dup-chip')){
        const chip=document.createElement('span'); chip.id='dup-chip'; chip.textContent='dup risk…';
        chip.style.cssText='margin-left:auto;font-family:var(--mono);font-size:11px;font-weight:700;padding:5px 11px;border-radius:8px;border:1px solid var(--border2);color:var(--text3)';
        tb.appendChild(chip);
        jpost('/dup',{cls:inferClass(f),endpoint:f.endpoint||'',title:f.title||'',program:prog}).then(d=>{
          if(d.prob==null){chip.textContent='dup risk n/a';return;}
          const col=d.verdict==='HOLD'?'var(--red)':d.verdict==='REVIEW'?'var(--amber)':'var(--green)';
          const bg=d.verdict==='HOLD'?'rgba(251,113,133,.12)':d.verdict==='REVIEW'?'rgba(251,191,36,.12)':'rgba(74,222,128,.1)';
          chip.style.color=col;chip.style.borderColor=col;chip.style.background=bg;
          chip.textContent=`dup risk ${d.prob}% · ${d.verdict}`;
          chip.title=(d.nearest||'')+' — '+JSON.stringify(d.factors||{});
        }).catch(()=>{chip.textContent='dup risk n/a';});
      } }
    } }catch(e){}
  };
  // ── Mobile APK/IPA surface ───────────────────────────────────────────────
  (function(){
    const st=document.createElement('style'); st.textContent=
      '.mob-drop{border:2px dashed rgba(167,139,250,.4);border-radius:18px;padding:56px 32px;text-align:center;cursor:pointer;transition:border-color .2s,background .2s;margin-bottom:24px}'+
      '.mob-drop.drag{border-color:var(--accent);background:rgba(167,139,250,.08)}'+
      '.mob-drop-ico{font-size:40px;margin-bottom:12px;opacity:.6}'+
      '.mob-drop-title{font-family:var(--sans);font-size:15px;font-weight:700;color:var(--white);margin-bottom:6px}'+
      '.mob-drop-sub{font-family:var(--mono);font-size:12px;color:var(--text3)}'+
      '.mob-path-row{display:flex;gap:10px;margin-bottom:24px;align-items:center}'+
      '.mob-path-inp{flex:1;background:#0c0818;border:1px solid var(--border2);border-radius:10px;color:var(--white);font-family:var(--mono);font-size:12px;padding:10px 14px;outline:none}'+
      '.mob-path-inp:focus{border-color:var(--accent3)}'+
      '.mob-btn{padding:10px 20px;border-radius:10px;border:none;font-family:var(--sans);font-size:13px;font-weight:700;cursor:pointer;transition:transform .12s}'+
      '.mob-btn.primary{background:linear-gradient(135deg,#A78BFA,#7C3AED);color:#fff;box-shadow:0 6px 18px -6px rgba(124,58,237,.8)}'+
      '.mob-btn.primary:hover{transform:translateY(-1px)}'+
      '.mob-btn.ghost{background:var(--glass);border:1px solid var(--border2);color:var(--text2)}'+
      '.mob-progress{font-family:var(--mono);font-size:12px;color:var(--accent);margin:16px 0;display:none}'+
      '.mob-hero{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}'+
      '.mob-tile{background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:16px 18px;position:relative;overflow:hidden}'+
      '.mob-tile-lbl{font-size:11px;font-weight:700;letter-spacing:.5px;color:var(--text3);text-transform:uppercase;margin-bottom:8px;font-family:var(--sans)}'+
      '.mob-tile-val{font-family:var(--mono);font-size:22px;font-weight:700;color:var(--white);font-variant-numeric:tabular-nums;line-height:1}'+
      '.mob-tile-sub{font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:5px}'+
      '.mob-tile.red .mob-tile-val{color:#FB7185}.mob-tile.amber .mob-tile-val{color:#FBBF24}.mob-tile.green .mob-tile-val{color:#4ADE80}.mob-tile.orchid .mob-tile-val{color:var(--accent)}'+
      '.mob-flag{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:8px;font-family:var(--mono);font-size:11px;font-weight:700;margin:4px 4px 0 0}'+
      '.mob-flag.warn{background:rgba(251,191,36,.14);color:#FBBF24;border:1px solid rgba(251,191,36,.35)}'+
      '.mob-flag.bad{background:rgba(251,113,133,.12);color:#FB7185;border:1px solid rgba(251,113,133,.35)}'+
      '.mob-flag.ok{background:rgba(74,222,128,.1);color:#4ADE80;border:1px solid rgba(74,222,128,.3)}'+
      '.mob-section{background:var(--glass);border:1px solid var(--border);border-radius:14px;margin-bottom:18px;overflow:hidden}'+
      '.mob-section-h{padding:13px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}'+
      '.mob-section-title{font-family:var(--sans);font-size:13px;font-weight:700;color:var(--white)}'+
      '.mob-section-ct{font-family:var(--mono);font-size:11px;color:var(--text3)}'+
      '.mob-item{padding:10px 18px;border-bottom:1px solid rgba(255,255,255,.05);font-family:var(--mono);font-size:12px;color:var(--text2);display:flex;align-items:flex-start;gap:10px;word-break:break-all}'+
      '.mob-item:last-child{border-bottom:none}'+
      '.mob-item-badge{flex-shrink:0;font-size:9px;font-weight:700;padding:2px 8px;border-radius:5px;margin-top:1px;letter-spacing:.4px}'+
      '.mob-item-badge.ep{background:rgba(167,139,250,.18);color:var(--accent);border:1px solid rgba(167,139,250,.35)}'+
      '.mob-item-badge.secret{background:rgba(251,113,133,.14);color:#FB7185;border:1px solid rgba(251,113,133,.35)}'+
      '.mob-item-badge.dl{background:rgba(74,222,128,.1);color:#4ADE80;border:1px solid rgba(74,222,128,.3)}'+
      '.mob-item-badge.comp{background:rgba(251,191,36,.12);color:#FBBF24;border:1px solid rgba(251,191,36,.35)}'+
      '.mob-item-badge.perm{background:rgba(96,165,250,.12);color:#60A5FA;border:1px solid rgba(96,165,250,.3)}'+
      '.mob-empty{padding:24px;text-align:center;font-family:var(--sans);font-size:12px;color:var(--text3)}';
    document.head.appendChild(st);
  })();

  window.renderMobile=function(el){
    el.innerHTML=`<div style="padding:24px 28px 40px">
      <div class="view-title">Mobile Surface</div>
      <div class="view-sub">Drop an APK or IPA — extract endpoints, secrets, deep links, and exported components.</div>
      <div class="mob-drop" id="mob-drop" onclick="document.getElementById('mob-file-inp').click()">
        <div class="mob-drop-ico">📱</div>
        <div class="mob-drop-title">Drop APK / IPA here</div>
        <div class="mob-drop-sub">or click to browse · uploads and analyzes via the local engine</div>
        <input type="file" id="mob-file-inp" accept=".apk,.ipa" style="display:none"/>
      </div>
      <div style="text-align:center;font-family:var(--mono);font-size:11px;color:var(--text3);margin:-14px 0 18px">— or paste a local file path —</div>
      <div class="mob-path-row">
        <input class="mob-path-inp" id="mob-path" placeholder="/home/user/downloads/app.apk  or  app.ipa"/>
        <label style="display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;color:var(--text3);cursor:pointer"><input type="checkbox" id="mob-deep" style="accent-color:var(--accent)"/> deep (jadx)</label>
        <button class="mob-btn primary" onclick="window._mobAnalyze()">Analyze</button>
      </div>
      <div class="mob-progress" id="mob-progress">⏳ analyzing… this can take 30–120s for deep mode</div>
      <div id="mob-results"></div>
    </div>`;

    // drag and drop
    const drop=document.getElementById('mob-drop');
    drop.addEventListener('dragover',e=>{e.preventDefault();drop.classList.add('drag');});
    drop.addEventListener('dragleave',()=>drop.classList.remove('drag'));
    drop.addEventListener('drop',e=>{e.preventDefault();drop.classList.remove('drag');const f=e.dataTransfer.files[0];if(f)_mobFile(f);});
    document.getElementById('mob-file-inp')?.addEventListener('change',e=>{const f=e.target.files[0];if(f)_mobFile(f);});

    function _mobFile(f){
      const prog=document.getElementById('mob-progress');
      if(prog){prog.textContent=`⏳ uploading ${f.name} (${(f.size/1024/1024).toFixed(1)} MB)…`;prog.style.display='block';}
      const reader=new FileReader();
      reader.onload=async ev=>{
        const b64=ev.target.result.split(',')[1];
        if(prog)prog.textContent=`⏳ analyzing ${f.name}…`;
        const deep=document.getElementById('mob-deep')?.checked||false;
        try{
          const r=await jpost('/mobile/upload',{filename:f.name,data_b64:b64,deep});
          if(prog)prog.style.display='none';
          _mobRender(r);
        }catch(e){if(prog){prog.textContent=`❌ ${e.message||e}`;}}
      };
      reader.readAsDataURL(f);
    }

    window._mobAnalyze=async function(){
      const fp=(document.getElementById('mob-path')?.value||'').trim();
      if(!fp)return;
      const prog=document.getElementById('mob-progress');
      if(prog){prog.textContent='⏳ analyzing…';prog.style.display='block';}
      const deep=document.getElementById('mob-deep')?.checked||false;
      try{
        const r=await fetch(API+'/mobile/analyze?file='+encodeURIComponent(fp)+(deep?'&deep=1':'')).then(x=>x.json());
        if(prog)prog.style.display='none';
        _mobRender(r);
      }catch(e){if(prog)prog.textContent=`❌ ${e.message||e}`;}
    };

    function _mobRender(r){
      if(r.error){document.getElementById('mob-results').innerHTML=`<div class="mob-empty" style="color:#FB7185">❌ ${r.error}<br><pre style="font-size:10px;color:var(--text3);margin-top:8px;text-align:left">${(r.raw||'').slice(0,600)}</pre></div>`;return;}
      const eps=r.endpoints||[]; const secs=r.secrets||[]; const dls=r.deep_links||r.url_schemes&&r.url_schemes.map(s=>({scheme:s}))||[];
      const comps=r.exported_components||[]; const perms=(r.permissions||[]).filter(p=>/CAMERA|MICROPHONE|LOCATION|CONTACT|STORAGE|SMS|PHONE|RECORD/i.test(p));
      const doms=r.domains||[]; const notes=r.notes||[];
      // flags
      const flagsHtml=[
        r.cert_pinning&&'<span class="mob-flag warn">📌 cert pinning</span>',
        r.debug_enabled&&'<span class="mob-flag bad">🐛 debuggable</span>',
        r.backup_enabled&&'<span class="mob-flag warn">💾 allowBackup</span>',
        r.webview_js&&'<span class="mob-flag warn">🌐 WebView JS</span>',
        r.root_detection&&'<span class="mob-flag ok">🛡 root detect</span>',
        (r.ats_exceptions&&r.ats_exceptions.length)&&'<span class="mob-flag bad">🔓 ATS disabled</span>',
        (r.firebase_config&&r.firebase_config.project_id)&&'<span class="mob-flag warn">🔥 Firebase</span>',
      ].filter(Boolean).join('');
      // hero tiles
      const heroHtml=`<div class="mob-hero">
        <div class="mob-tile orchid"><div class="mob-tile-lbl">Endpoints</div><div class="mob-tile-val">${eps.length}</div><div class="mob-tile-sub">API URLs found</div></div>
        <div class="mob-tile red"><div class="mob-tile-lbl">Secrets</div><div class="mob-tile-val">${secs.length}</div><div class="mob-tile-sub">hardcoded creds/keys</div></div>
        <div class="mob-tile amber"><div class="mob-tile-lbl">Exported</div><div class="mob-tile-val">${comps.length}</div><div class="mob-tile-sub">exported components</div></div>
        <div class="mob-tile green"><div class="mob-tile-lbl">Deep links</div><div class="mob-tile-val">${dls.length}</div><div class="mob-tile-sub">custom URL schemes</div></div>
      </div>`;
      // meta bar
      const id=r.package||r.bundle_id||'?'; const ver=r.version||'?';
      const metaHtml=`<div style="font-family:var(--mono);font-size:12px;color:var(--text2);margin-bottom:14px">
        <b style="color:var(--white)">${id}</b> v${ver} · ${r.type?.toUpperCase()||'?'} · SDK ${r.min_sdk||r.min_os||'?'}→${r.target_sdk||'?'}<br/>
        <div style="margin-top:8px">${flagsHtml}</div></div>`;
      // sections
      const epRows=eps.slice(0,40).map(e=>`<div class="mob-item"><span class="mob-item-badge ep">EP</span>${e}</div>`).join('');
      const secRows=secs.slice(0,30).map(s=>`<div class="mob-item"><span class="mob-item-badge secret">${s.type}</span>${s.redacted}</div>`).join('');
      const dlRows=dls.slice(0,20).map(d=>`<div class="mob-item"><span class="mob-item-badge dl">scheme</span>${d.scheme}:// ${d.component||d.sample||''}</div>`).join('');
      const compRows=comps.slice(0,20).map(c=>`<div class="mob-item"><span class="mob-item-badge comp">${c.kind}</span>${c.name}<span style="color:var(--text3);font-size:10px;margin-left:8px">${(c.actions||[]).join(', ').slice(0,60)}</span></div>`).join('');
      const permRows=perms.slice(0,15).map(p=>`<div class="mob-item"><span class="mob-item-badge perm">perm</span>${p}</div>`).join('');
      const domRows=doms.slice(0,20).map(d=>`<div class="mob-item"><span class="mob-item-badge ep">dom</span>${d}</div>`).join('');
      const noteRows=notes.map(n=>`<div class="mob-item"><span class="mob-item-badge warn">→</span>${n}</div>`).join('');

      const sec=function(title,ct,rows,extra=''){return rows?`<div class="mob-section"><div class="mob-section-h"><span class="mob-section-title">${title}</span><span class="mob-section-ct">${ct}</span></div>${rows}${extra?`<div style="padding:8px 18px;font-size:10px;color:var(--text3);font-family:var(--mono)">${extra}</div>`:''}</div>`:'';};
      document.getElementById('mob-results').innerHTML=heroHtml+metaHtml+
        sec('Endpoints',`${eps.length} found`,epRows||'<div class="mob-empty">None found</div>',eps.length>40?`+${eps.length-40} more`:'') +
        sec('Hardcoded Secrets',`${secs.length} found`,secRows||'<div class="mob-empty">None found</div>',secs.length>30?`+${secs.length-30} more`:'') +
        sec('Deep Links / URL Schemes',`${dls.length} found`,dlRows||'<div class="mob-empty">None found</div>') +
        sec('Exported Components',`${comps.length} found`,compRows||'<div class="mob-empty">None exported</div>') +
        sec('Dangerous Permissions',`${perms.length} dangerous`,permRows||'<div class="mob-empty">None flagged</div>') +
        sec('Domains',`${doms.length} found`,domRows||'<div class="mob-empty">None found</div>') +
        (noteRows?sec('Notes',`${notes.length}`,noteRows):'');
    }
  };

  // ── Earnings dashboard page ──────────────────────────────────────────────
  (function(){
    const st=document.createElement('style'); st.textContent=
      '.earn-hero{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}'+
      '.earn-tile{background:var(--glass,rgba(255,255,255,.06));border:1px solid var(--border,rgba(255,255,255,.1));border-radius:14px;padding:20px 22px}'+
      '.earn-tile-lbl{font-family:var(--sans);font-size:11px;font-weight:700;letter-spacing:.5px;color:var(--text3);text-transform:uppercase;margin-bottom:8px}'+
      '.earn-tile-val{font-family:var(--mono);font-size:26px;font-weight:700;color:var(--gold,#E7C983);font-variant-numeric:tabular-nums;line-height:1}'+
      '.earn-tile-sub{font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:5px}'+
      '.earn-tile.blue .earn-tile-val{color:#60A5FA}.earn-tile.green .earn-tile-val{color:#4ADE80}.earn-tile.orchid .earn-tile-val{color:var(--accent,#A78BFA)}'+
      '.earn-two{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px}'+
      '@media(max-width:720px){.earn-two{grid-template-columns:1fr}}'+
      '.earn-card{background:var(--glass,rgba(255,255,255,.06));border:1px solid var(--border,rgba(255,255,255,.1));border-radius:14px;padding:18px 20px}'+
      '.earn-card-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}'+
      '.earn-card-title{font-family:var(--sans);font-size:13px;font-weight:700;color:var(--white,#F3F1FB)}'+
      '.earn-row{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;padding:8px 0;border-bottom:1px solid var(--border,rgba(255,255,255,.07))}'+
      '.earn-row:last-child{border-bottom:none}'+
      '.earn-row-name{font-family:var(--sans);font-size:13px;color:var(--text2,#CCC9E8);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'+
      '.earn-row-amt{font-family:var(--mono);font-size:13px;font-weight:700;color:var(--gold,#E7C983);font-variant-numeric:tabular-nums;white-space:nowrap}'+
      '.earn-chart{margin-bottom:28px;background:var(--glass,rgba(255,255,255,.06));border:1px solid var(--border,rgba(255,255,255,.1));border-radius:14px;padding:18px 20px}'+
      '.earn-empty{font-family:var(--sans);font-size:13px;color:var(--text3);padding:20px 0;text-align:center}'+
      '.earn-tax-row{display:flex;align-items:center;gap:10px;margin-top:14px;flex-wrap:wrap}'+
      '.earn-tax-input{background:#0c0818;border:1px solid var(--border2,rgba(255,255,255,.15));border-radius:8px;color:var(--white,#F3F1FB);font-family:var(--mono);font-size:13px;padding:6px 10px;width:70px;text-align:center}'+
      '.earn-tax-lbl{font-family:var(--sans);font-size:12px;color:var(--text3)}'+
      '.earn-tax-result{font-family:var(--mono);font-size:14px;font-weight:700;color:var(--amber,#FBBF24)}'+
      '.earn-add-form{background:var(--glass,rgba(255,255,255,.06));border:1px solid var(--border,rgba(255,255,255,.1));border-radius:14px;padding:18px 20px;margin-bottom:28px}'+
      '.earn-add-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-top:12px}'+
      '.earn-field label{font-family:var(--sans);font-size:11px;font-weight:700;color:var(--text3);display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px}'+
      '.earn-field input,.earn-field select{width:100%;background:#0c0818;border:1px solid var(--border2,rgba(255,255,255,.15));border-radius:8px;color:var(--white,#F3F1FB);font-family:var(--mono);font-size:12px;padding:7px 10px;box-sizing:border-box}'+
      '.earn-field select option{background:#0c0818}'+
      '.earn-add-actions{display:flex;gap:10px;margin-top:14px}'+
      '.btn-earn{padding:8px 18px;border-radius:9px;border:none;font-family:var(--sans);font-size:12px;font-weight:700;cursor:pointer}'+
      '.btn-earn.primary{background:linear-gradient(135deg,#A78BFA,#7C3AED);color:#fff}'+
      '.btn-earn.ghost{background:transparent;border:1px solid rgba(255,255,255,.2);color:var(--text2)}'+
      '.earn-msg{font-family:var(--mono);font-size:12px;margin-top:8px;color:#4ADE80}'+
      '.earn-msg.err{color:#FB7185}'+
      '.sev-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}'+
      '.recent-row{display:grid;grid-template-columns:90px 1fr auto auto;gap:10px;align-items:center;padding:8px 0;border-bottom:1px solid var(--border,rgba(255,255,255,.07))}'+
      '.recent-row:last-child{border-bottom:none}'+
      '.recent-date{font-family:var(--mono);font-size:11px;color:var(--text3)}'+
      '.recent-title{font-family:var(--sans);font-size:13px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}'+
      '.recent-prog{font-family:var(--mono);font-size:10.5px;color:var(--text3);white-space:nowrap}'+
      '.recent-amt{font-family:var(--mono);font-size:13px;font-weight:700;font-variant-numeric:tabular-nums;white-space:nowrap}'+
      '.recent-amt.paid{color:#4ADE80}.recent-amt.pending{color:#FBBF24}.recent-amt.dispute{color:#FB7185}';
    document.head.appendChild(st);
  })();

  window.renderEarnings=function(el){
    el.innerHTML='<div class="earn-empty" style="margin-top:48px">Loading earnings…</div>';
    Promise.all([
      fetch(API+'/earnings').then(r=>r.json()).catch(()=>({paid:{},pending:{},ytd:{},counts:{}})),
      fetch(API+'/earnings/detail').then(r=>r.json()).catch(()=>({paid:{},pending:{},ytd:{},counts:{},by_program:{},by_platform:{},by_month:{},by_severity:{},recent:[]}))
    ]).then(([tots, full])=>{
      const paid=full.paid||tots.paid||{};
      const pend=full.pending||tots.pending||{};
      const ytd=full.ytd||tots.ytd||{};
      const counts=full.counts||tots.counts||{};
      const byProg=full.by_program||{};
      const byPlat=full.by_platform||{};
      const byMon=full.by_month||{};
      const bySev=full.by_severity||{};
      const recent=(full.recent||[]);

      // money formatter (same as top strip)
      const moneyStr=(o)=>Object.keys(o||{}).length
        ? Object.entries(o).map(([c,v])=>`${SYM[c]||c+' '}${Math.round(v).toLocaleString()}`).join(' · ')
        : '—';

      // hero tiles
      const heroHtml=`<div class="earn-hero">
        <div class="earn-tile"><div class="earn-tile-lbl">Total paid</div><div class="earn-tile-val">${moneyStr(paid)}</div><div class="earn-tile-sub">${counts.paid||0} payouts · ${counts.programs||0} programs</div></div>
        <div class="earn-tile blue"><div class="earn-tile-lbl">In triage</div><div class="earn-tile-val">${moneyStr(pend)}</div><div class="earn-tile-sub">${counts.pending||0} pending reports</div></div>
        <div class="earn-tile green"><div class="earn-tile-lbl">This year</div><div class="earn-tile-val">${moneyStr(ytd)}</div><div class="earn-tile-sub">${new Date().getFullYear()} YTD</div></div>
        <div class="earn-tile orchid"><div class="earn-tile-lbl">In dispute</div><div class="earn-tile-val">${moneyStr(Object.fromEntries(Object.entries(pend).map(([c])=>[c,0])))}</div><div class="earn-tile-sub">${counts.dispute||0} reports</div></div>
      </div>`;

      // bar chart (monthly trend, SVG)
      let chartHtml='';
      const mons=Object.entries(byMon);
      if(mons.length>0){
        const allAmts=mons.map(([,cv])=>Object.values(cv).reduce((a,b)=>a+b,0));
        const maxAmt=Math.max(...allAmts,1);
        const bw=Math.max(24, Math.min(60, Math.floor(560/mons.length)-8));
        const svgW=mons.length*(bw+8)+20; const svgH=100;
        const bars=mons.map(([m,cv],i)=>{
          const tot=Object.values(cv).reduce((a,b)=>a+b,0);
          const bh=Math.round((tot/maxAmt)*80);
          const x=10+i*(bw+8); const y=svgH-bh-14;
          const amt=moneyStr(cv);
          return `<g><rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="4" fill="rgba(167,139,250,.55)"/>`+
            `<text x="${x+bw/2}" y="${svgH-2}" font-size="8" text-anchor="middle" fill="#948CB6">${m.slice(5)}</text>`+
            `<title>${m}: ${amt}</title></g>`;
        }).join('');
        chartHtml=`<div class="earn-chart"><div class="earn-card-h"><span class="earn-card-title">Monthly trend</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">${mons.length} months</span></div>`+
          `<svg viewBox="0 0 ${svgW} ${svgH}" style="width:100%;max-height:130px;overflow:visible">${bars}</svg></div>`;
      }

      // program table (top 10)
      const progRows=Object.entries(byProg).slice(0,10).map(([name,cv])=>
        `<div class="earn-row"><span class="earn-row-name" title="${name}">${name}</span><span class="earn-row-amt">${moneyStr(cv)}</span></div>`).join('');
      const progHtml=`<div class="earn-card"><div class="earn-card-h"><span class="earn-card-title">Top programs</span></div>`+
        (progRows||'<div class="earn-empty">No paid entries yet.</div>')+`</div>`;

      // platform table
      const platRows=Object.entries(byPlat).map(([name,cv])=>
        `<div class="earn-row"><span class="earn-row-name">${name}</span><span class="earn-row-amt">${moneyStr(cv)}</span></div>`).join('');
      const platHtml=`<div class="earn-card"><div class="earn-card-h"><span class="earn-card-title">By platform</span></div>`+
        (platRows||'<div class="earn-empty">No paid entries yet.</div>')+`</div>`;

      // severity breakdown
      const sevColors={critical:'#FB7185',high:'#FB923C',medium:'#FBBF24',low:'#60A5FA',info:'#94A3B8'};
      const sevRows=Object.entries(bySev).map(([s,cv])=>
        `<div class="earn-row"><span class="earn-row-name"><span class="sev-dot" style="background:${sevColors[s]||'#948CB6'}"></span>${s}</span><span class="earn-row-amt">${moneyStr(cv)}</span></div>`).join('');
      const sevHtml=`<div class="earn-card"><div class="earn-card-h"><span class="earn-card-title">By severity</span></div>`+
        (sevRows||'<div class="earn-empty">No paid entries yet.</div>')+`</div>`;

      // tax estimator
      const taxHtml=`<div class="earn-card" style="margin-bottom:28px"><div class="earn-card-h"><span class="earn-card-title">Tax set-aside (estimate)</span><span style="font-family:var(--sans);font-size:11px;color:var(--text3)">always confirm with an accountant</span></div>`+
        `<div class="earn-tax-row"><input id="earn-tax-rate" class="earn-tax-input" type="number" min="0" max="60" step="1" value="25" title="Tax rate %"/><span class="earn-tax-lbl">% rate</span>`+
        `<span class="earn-tax-lbl">→</span><span class="earn-tax-result" id="earn-tax-result"></span></div></div>`;

      // quick-add form
      const addHtml=`<div class="earn-add-form"><div class="earn-card-h"><span class="earn-card-title">Log a payout</span></div>`+
        `<div class="earn-add-grid">`+
        `<div class="earn-field"><label>Program</label><input id="ea-prog" placeholder="Acme Corp"/></div>`+
        `<div class="earn-field"><label>Platform</label><input id="ea-plat" placeholder="HackerOne"/></div>`+
        `<div class="earn-field"><label>Amount</label><input id="ea-amt" type="number" placeholder="1500"/></div>`+
        `<div class="earn-field"><label>Currency</label><select id="ea-cur"><option>USD</option><option>EUR</option><option>GBP</option></select></div>`+
        `<div class="earn-field"><label>Severity</label><select id="ea-sev"><option value="">—</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select></div>`+
        `<div class="earn-field"><label>Status</label><select id="ea-status"><option>paid</option><option>pending</option><option>dispute</option></select></div>`+
        `<div class="earn-field" style="grid-column:span 2"><label>Title / description</label><input id="ea-title" placeholder="IDOR /api/orders/{id}"/></div>`+
        `<div class="earn-field"><label>Fee</label><input id="ea-fee" type="number" placeholder="0"/></div>`+
        `<div class="earn-field"><label>Date (YYYY-MM-DD)</label><input id="ea-date" placeholder="${new Date().toISOString().slice(0,10)}"/></div>`+
        `</div><div class="earn-add-actions">`+
        `<button class="btn-earn primary" onclick="window._earnAdd()">Log payout</button>`+
        `<button class="btn-earn ghost" onclick="window._earnReset()">Clear</button>`+
        `</div><div id="earn-msg" class="earn-msg" style="display:none"></div></div>`;

      // recent ledger
      const recentRows=recent.map(r=>{
        const st=r.status||'paid';
        const amtStr=`${SYM[r.currency]||r.currency+' '}${Math.round(r.amount||0).toLocaleString()}`;
        return `<div class="recent-row">`+
          `<span class="recent-date">${(r.date||'').slice(0,10)}</span>`+
          `<span class="recent-title" title="${r.title||''}">${r.title||'—'}</span>`+
          `<span class="recent-prog">${r.program||'?'}${r.platform&&r.platform!=='?'?' · '+r.platform:''}</span>`+
          `<span class="recent-amt ${st}">${amtStr} <span style="font-size:10px;opacity:.7">${st}</span></span>`+
          `</div>`;
      }).join('');
      const recentHtml=recent.length?`<div class="earn-card" style="margin-bottom:28px">`+
        `<div class="earn-card-h"><span class="earn-card-title">Recent entries</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">${recent.length} shown</span></div>`+
        recentRows+`</div>`:
        `<div class="earn-empty" style="margin-bottom:28px">No ledger entries yet. Log your first payout above.</div>`;

      el.innerHTML=`<div style="padding:24px 28px 40px">`+
        heroHtml+
        addHtml+
        chartHtml+
        `<div class="earn-two">${progHtml}${platHtml}</div>`+
        `<div class="earn-two">${sevHtml}${taxHtml}</div>`+
        recentHtml+
        `</div>`;

      // tax calculator wiring
      function calcTax(){
        const rate=parseFloat(document.getElementById('earn-tax-rate')?.value||'0');
        const res=document.getElementById('earn-tax-result'); if(!res)return;
        const parts=Object.entries(paid).map(([c,v])=>`${SYM[c]||c+' '}${Math.round(v*rate/100).toLocaleString()}`);
        res.textContent=parts.length?parts.join(' · '):'—';
      }
      calcTax();
      document.getElementById('earn-tax-rate')?.addEventListener('input',calcTax);

      // quick-add handler
      window._earnAdd=async function(){
        const prog=document.getElementById('ea-prog')?.value.trim()||'?';
        const plat=document.getElementById('ea-plat')?.value.trim()||'?';
        const amt=parseFloat(document.getElementById('ea-amt')?.value||'0');
        const cur=document.getElementById('ea-cur')?.value||'USD';
        const sev=document.getElementById('ea-sev')?.value||'';
        const status=document.getElementById('ea-status')?.value||'paid';
        const title=document.getElementById('ea-title')?.value.trim()||'';
        const fee=parseFloat(document.getElementById('ea-fee')?.value||'0');
        const date=document.getElementById('ea-date')?.value.trim()||new Date().toISOString().slice(0,10);
        const msg=document.getElementById('earn-msg');
        if(!prog||!amt){if(msg){msg.textContent='Program and amount are required.';msg.className='earn-msg err';msg.style.display='block';}return;}
        const r=await jpost('/earnings/add',{program:prog,platform:plat,amount:amt,currency:cur,sev,status,title,fee,date}).catch(()=>({ok:false,msg:'network error'}));
        if(msg){msg.textContent=r.msg||(r.ok?'Logged.':'Error logging entry.');msg.className='earn-msg'+(r.ok?'':' err');msg.style.display='block';}
        if(r.ok) setTimeout(()=>{ if(typeof renderEarnings==='function'){const c=document.getElementById('content');if(c)renderEarnings(c);} },600);
      };
      window._earnReset=function(){
        ['ea-prog','ea-plat','ea-amt','ea-title','ea-fee','ea-date'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
        const msg=document.getElementById('earn-msg');if(msg)msg.style.display='none';
      };
    }).catch(e=>{ el.innerHTML=`<div class="earn-empty" style="margin-top:48px;color:#FB7185">Failed to load earnings data: ${e.message||e}</div>`; });
  };

  // ── JS Diff / GraphQL / Report Scorer / GitHub / Nuclei ──────────────────
  (function(){
    const st=document.createElement('style'); st.textContent=
      '.tool-card{background:var(--glass);border:1px solid var(--border);border-radius:14px;padding:18px 20px;margin-bottom:18px}'+
      '.tool-card-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}'+
      '.tool-card-title{font-family:var(--sans);font-size:13px;font-weight:700;color:var(--white)}'+
      '.tool-row{display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap}'+
      '.tool-inp{flex:1;min-width:180px;background:#0c0818;border:1px solid var(--border2);border-radius:8px;color:var(--white);font-family:var(--mono);font-size:12px;padding:7px 11px;outline:none}'+
      '.tool-inp:focus{border-color:var(--accent3)}'+
      '.tool-btn{padding:7px 16px;border-radius:8px;border:none;font-family:var(--sans);font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap}'+
      '.tool-btn.pri{background:linear-gradient(135deg,#A78BFA,#7C3AED);color:#fff}'+
      '.tool-btn.ghost{background:var(--glass);border:1px solid var(--border2);color:var(--text2)}'+
      '.tool-out{font-family:var(--mono);font-size:11.5px;color:var(--text2);background:#07040f;border:1px solid var(--border);border-radius:10px;padding:12px 14px;max-height:320px;overflow-y:auto;margin-top:8px;white-space:pre-wrap;word-break:break-all}'+
      '.tool-out .hi{color:var(--gold)}.tool-out .crit{color:#FB7185}.tool-out .high{color:#FB923C}.tool-out .med{color:#FBBF24}.tool-out .ok{color:#4ADE80}'+
      '.score-bar{height:6px;border-radius:3px;background:rgba(255,255,255,.1);overflow:hidden;margin:10px 0}'+
      '.score-fill{height:100%;border-radius:3px;transition:width .4s}'+
      '.score-grid{display:grid;grid-template-columns:90px 1fr auto;gap:6px 10px;align-items:center;font-family:var(--mono);font-size:11px;color:var(--text3)}'+
      '.score-label{color:var(--text2)}.score-dim-bar{height:5px;border-radius:3px;background:rgba(167,139,250,.35)}'+
      '.score-dim-fill{height:100%;border-radius:3px;background:var(--accent)}'+
      '.score-tip{font-family:var(--sans);font-size:12px;color:var(--text3);padding:7px 0;border-bottom:1px solid var(--border);line-height:1.55}'+
      '.score-tip:last-child{border-bottom:none}';
    document.head.appendChild(st);
  })();

  // ── extend renderMonitor: append JS-diff, GraphQL, GitHub, Nuclei panels ─
  const _rmOld=window.renderMonitor;
  window.renderMonitor=function(el){
    if(_rmOld) _rmOld(el);

    // JS Diff panel
    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="jsdiff-card">
      <div class="tool-card-h"><span class="tool-card-title">JS surface watcher</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">track bundle changes for new endpoints/secrets</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="jsd-tgt" placeholder="target (e.g. acme)"/>
        <input class="tool-inp" id="jsd-url" placeholder="JS URL to track (optional)"/>
        <button class="tool-btn pri" onclick="window._jsdiff_check()">Check changes</button>
        <button class="tool-btn ghost" onclick="window._jsdiff_addurl()">+ Add URL</button>
        <button class="tool-btn ghost" onclick="window._jsdiff_report()">Report</button>
      </div>
      <div class="tool-out" id="jsd-out" style="display:none"></div>
    </div>`);

    // GraphQL panel
    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="gql-card">
      <div class="tool-card-h"><span class="tool-card-title">GraphQL surface mapper</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">introspect + map IDOR/upload/auth candidates</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="gql-url" placeholder="https://api.acme.com/graphql"/>
        <input class="tool-inp" id="gql-tok" placeholder="Bearer token (optional)"/>
        <button class="tool-btn pri" onclick="window._gql_probe()">Probe</button>
      </div>
      <div class="tool-out" id="gql-out" style="display:none"></div>
    </div>`);

    // GitHub Recon panel
    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="gh-card">
      <div class="tool-card-h"><span class="tool-card-title">GitHub recon</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">scan public org repos for secrets + staging URLs + CI issues</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="gh-org" placeholder="org name or full repo URL"/>
        <input class="tool-inp" id="gh-tok" placeholder="ghp_xxx token (optional, higher rate)"/>
        <button class="tool-btn pri" onclick="window._gh_scan()">Scan org</button>
        <button class="tool-btn ghost" onclick="window._gh_scan(true)">Scan repo</button>
      </div>
      <div class="tool-out" id="gh-out" style="display:none"></div>
    </div>`);

    // Nuclei panel
    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="nuc-card">
      <div class="tool-card-h"><span class="tool-card-title">Nuclei scanner</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">run templates against in-scope hosts</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="nuc-tgts" placeholder="https://api.acme.com, https://app.acme.com"/>
        <input class="tool-inp" id="nuc-sev" placeholder="severity: critical,high,medium" value="critical,high,medium"/>
        <input class="tool-inp" id="nuc-tags" placeholder="tags (optional): cves,misconfig"/>
        <button class="tool-btn pri" onclick="window._nuc_scan()">Run Nuclei</button>
      </div>
      <div class="tool-out" id="nuc-out" style="display:none"></div>
    </div>`);

    // ── Tier 3 tool cards ───────────────────────────────────────────────
    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="ssrf-card">
      <div class="tool-card-h"><span class="tool-card-title">SSRF probe</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">metadata · internal sweep · bypass variants · blind callback</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="ssrf-url" placeholder="https://api.acme.com/fetch"/>
        <input class="tool-inp" id="ssrf-param" placeholder="param: url" value="url"/>
        <input class="tool-inp" id="ssrf-cb" placeholder="callback domain (optional): xyz.oast.me"/>
        <button class="tool-btn pri" onclick="window._ssrf_probe()">Probe SSRF</button>
      </div>
      <div class="tool-out" id="ssrf-out" style="display:none"></div>
    </div>`);

    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="race-card">
      <div class="tool-card-h"><span class="tool-card-title">Race condition tester</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">gate-release × 25 threads · duplicate creation · balance diverge</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="race-url" placeholder="https://api.acme.com/v1/redeem"/>
        <input class="tool-inp" id="race-data" placeholder='POST body: {"code":"SAVE10"}' />
        <input class="tool-inp" id="race-tok" placeholder="Bearer token (optional)"/>
        <button class="tool-btn pri" onclick="window._race_fire()">Fire Race</button>
      </div>
      <div class="tool-out" id="race-out" style="display:none"></div>
    </div>`);

    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="ssti-card">
      <div class="tool-card-h"><span class="tool-card-title">SSTI probe</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">Jinja2 · Twig · Freemarker · Velocity · ERB · EL/OGNL · Go tmpl</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="ssti-url" placeholder="https://app.acme.com/render"/>
        <input class="tool-inp" id="ssti-param" placeholder="param: template"/>
        <button class="tool-btn pri" onclick="window._ssti_probe()">Probe SSTI</button>
      </div>
      <div class="tool-out" id="ssti-out" style="display:none"></div>
    </div>`);

    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="tko-card">
      <div class="tool-card-h"><span class="tool-card-title">Subdomain takeover</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">45+ service fingerprints: GitHub Pages · S3 · Netlify · Vercel · Heroku…</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="tko-hosts" placeholder="sub1.acme.com, sub2.acme.com  (or domain: acme.com)"/>
        <button class="tool-btn pri" onclick="window._tko_check()">Check takeover</button>
      </div>
      <div class="tool-out" id="tko-out" style="display:none"></div>
    </div>`);

    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="redir-card">
      <div class="tool-card-h"><span class="tool-card-title">Open redirect finder</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">15 bypass vectors · OAuth state-theft chain builder</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="redir-url" placeholder="https://acme.com/login"/>
        <input class="tool-inp" id="redir-param" placeholder="param: next"/>
        <input class="tool-inp" id="redir-oauth" placeholder="OAuth authorize URL (optional, for chain)"/>
        <button class="tool-btn pri" onclick="window._redir_test()">Test redirect</button>
      </div>
      <div class="tool-out" id="redir-out" style="display:none"></div>
    </div>`);

    // ── Tier 2 tool cards ───────────────────────────────────────────────
    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="sub-card">
      <div class="tool-card-h"><span class="tool-card-title">Subdomain enumeration</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">crt.sh · hackertarget · alienvault · brute</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="sub-domain" placeholder="target domain: acme.com"/>
        <label style="font-family:var(--mono);font-size:11px;color:var(--text3);display:flex;align-items:center;gap:6px;white-space:nowrap"><input type="checkbox" id="sub-brute" style="accent-color:var(--accent)"> brute</label>
        <label style="font-family:var(--mono);font-size:11px;color:var(--text3);display:flex;align-items:center;gap:6px;white-space:nowrap"><input type="checkbox" id="sub-seed"> seed coverage</label>
        <button class="tool-btn pri" onclick="window._sub_enum()">Enumerate</button>
      </div>
      <div class="tool-out" id="sub-out" style="display:none"></div>
    </div>`);

    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="cors-card">
      <div class="tool-card-h"><span class="tool-card-title">CORS tester</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">arbitrary · null · subdomain · pre-flight · downgrade</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="cors-url" placeholder="https://api.acme.com/v1/me"/>
        <input class="tool-inp" id="cors-tok" placeholder="Bearer token (optional)"/>
        <button class="tool-btn pri" onclick="window._cors_test()">Test CORS</button>
      </div>
      <div class="tool-out" id="cors-out" style="display:none"></div>
    </div>`);

    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="jwt-card">
      <div class="tool-card-h"><span class="tool-card-title">JWT attack suite</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">alg:none · weak secret · RS→HS confusion · kid traversal · jku SSRF</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="jwt-tok" placeholder="eyJ… (the token to attack)"/>
        <input class="tool-inp" id="jwt-url" placeholder="https://api.acme.com/v1/me"/>
        <button class="tool-btn pri" onclick="window._jwt_test()">Test JWT</button>
      </div>
      <div class="tool-out" id="jwt-out" style="display:none"></div>
    </div>`);

    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="param-card">
      <div class="tool-card-h"><span class="tool-card-title">Hidden parameter fuzzer</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">400-param differential sweep + IDOR enumeration</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="param-url" placeholder="https://api.acme.com/v1/me"/>
        <input class="tool-inp" id="param-tok" placeholder="Bearer token (optional)"/>
        <input class="tool-inp" id="param-idor" placeholder="IDOR field:base, e.g. id:1234"/>
        <button class="tool-btn pri" onclick="window._param_fuzz()">Fuzz Params</button>
      </div>
      <div class="tool-out" id="param-out" style="display:none"></div>
    </div>`);

    el.insertAdjacentHTML('beforeend',`<div class="tool-card" id="radar-card">
      <div class="tool-card-h"><span class="tool-card-title">Scope radar</span><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">snapshot + diff program scope/rewards on HackerOne · Bugcrowd · YesWeHack · Intigriti</span></div>
      <div class="tool-row">
        <input class="tool-inp" id="radar-slug" placeholder="h1:shopify · bc:acme · ywh:target · ing:company/slug"/>
        <button class="tool-btn pri" onclick="window._radar_snap()">Snapshot</button>
        <button class="tool-btn ghost" onclick="window._radar_diff()">Diff changes</button>
      </div>
      <div class="tool-out" id="radar-out" style="display:none"></div>
    </div>`);

    _wireMonitorTools();
  };

  function _wireMonitorTools(){
    // JS diff handlers
    window._jsdiff_check=async function(){
      const t=document.getElementById('jsd-tgt')?.value.trim()||'default';
      const o=document.getElementById('jsd-out'); if(!o)return;
      o.style.display='block'; o.textContent='checking…';
      try{
        const d=await fetch(API+'/js-diff/check?target='+encodeURIComponent(t)).then(r=>r.json());
        const c=(d.changes||[]);
        if(!c.length){o.innerHTML='<span class="ok">✓ no JS changes detected</span>';return;}
        o.innerHTML=c.map(ch=>{
          const ae=(ch.added_endpoints||[]).length, ns=(ch.new_secrets||[]).length;
          let s=`<span class="hi">${ch.url||ch.target}</span>\n`;
          if(ae)s+=`  <span class="ok">+${ae} new endpoints:</span> ${(ch.added_endpoints||[]).slice(0,4).join(', ')}\n`;
          if(ns)s+=`  <span class="crit">⚠ ${ns} new secret(s)!</span>\n`;
          return s;
        }).join('\n');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };
    window._jsdiff_addurl=async function(){
      const t=document.getElementById('jsd-tgt')?.value.trim()||'default';
      const u=document.getElementById('jsd-url')?.value.trim();
      const o=document.getElementById('jsd-out'); if(!o)return;
      if(!u){o.style.display='block';o.textContent='enter a URL to track';return;}
      o.style.display='block'; o.textContent='adding…';
      const d=await jpost('/js-diff/add-url',{target:t,url:u}).catch(e=>({ok:false,msg:String(e)}));
      o.textContent=d.msg||'done';
    };
    window._jsdiff_report=async function(){
      const t=document.getElementById('jsd-tgt')?.value.trim()||'default';
      const o=document.getElementById('jsd-out'); if(!o)return;
      o.style.display='block'; o.textContent='loading report…';
      try{
        const d=await fetch(API+'/js-diff/report?target='+encodeURIComponent(t)).then(r=>r.json());
        const c=(d.changes||[]);
        if(!c.length){o.textContent='no JS changes logged yet';return;}
        o.innerHTML=c.slice(-20).reverse().map(ch=>{
          const ae=(ch.added_endpoints||[]).length, ns=(ch.new_secrets||[]).length;
          return `<span style="color:var(--text3)">${ch.ts||''}</span>  <span class="hi">${(ch.url||ch.target||'').slice(0,60)}</span>`+
            (ae?`  <span class="ok">+${ae}ep</span>`:'')+(ns?`  <span class="crit">⚠SECRET</span>`:'');
        }).join('\n');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // GraphQL probe handler
    window._gql_probe=async function(){
      const url=document.getElementById('gql-url')?.value.trim();
      const tok=document.getElementById('gql-tok')?.value.trim();
      const o=document.getElementById('gql-out'); if(!o)return;
      if(!url){o.style.display='block';o.textContent='enter GraphQL endpoint URL';return;}
      o.style.display='block'; o.textContent='introspecting…';
      try{
        const d=await jpost('/graphql',{url,token:tok||undefined});
        if(!d.introspection){o.innerHTML=`<span class="med">introspection disabled</span>${d.probes&&d.probes.length?' — field probe results:\n'+d.probes.map(p=>`  ${p.query} → ${p.response}`).join('\n'):''}`;return;}
        const c=d.counts||{};
        const notes=(d.notes||[]).join('\n');
        const top=(d.priority_ops||[]).slice(0,15);
        o.innerHTML=`<span class="ok">✓ introspection OK</span>  queries:${c.queries||0} mutations:${c.mutations||0} subs:${c.subscriptions||0}`+
          (d.batch_support?`  <span class="hi">BATCH supported → rate-limit bypass</span>`:'')+
          (notes?'\n\n'+notes.replace(/⚠/g,'<span class="med">⚠</span>').replace(/✓/g,'<span class="ok">✓</span>'):'')+
          (top.length?'\n\nTop priority ops:\n'+top.map(op=>`  [${op.op.toUpperCase().padEnd(8)}] <span class="hi">${op.name.padEnd(30)}</span> ${op.classes.join(',')}`).join('\n'):'');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // GitHub recon handlers
    window._gh_scan=async function(isRepo){
      const val=document.getElementById('gh-org')?.value.trim();
      const tok=document.getElementById('gh-tok')?.value.trim();
      const o=document.getElementById('gh-out'); if(!o)return;
      if(!val){o.style.display='block';o.textContent='enter an org name or repo URL';return;}
      o.style.display='block'; o.textContent='cloning + scanning… this may take 30–120s';
      try{
        const body=isRepo||val.startsWith('http')?{repo:val,token:tok||undefined}:{org:val,token:tok||undefined};
        const d=await jpost('/github/recon',body);
        if(d.error){o.innerHTML=`<span class="crit">error: ${d.error}</span>`;return;}
        const top=(d.findings||[]).slice(0,20);
        o.innerHTML=`repos:${d.repos_scanned||0}  <span class="crit">crit:${d.critical||0}</span>  <span class="high">high:${d.high||0}</span>  total:${d.total_findings||0}`+
          (top.length?'\n\n'+top.map(f=>`  <span class="${f.severity==='critical'?'crit':f.severity==='high'?'high':'med'}">[${(f.severity||'?').toUpperCase().padEnd(8)}]</span> ${f.class.padEnd(20)} ${f.repo||''}:${(f.file||'').slice(0,35)}\n         ${(f.snippet||'').slice(0,90)}`).join('\n'):'\n<span class="ok">✓ no findings</span>');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // Nuclei handlers
    window._nuc_scan=async function(){
      const tgtsRaw=document.getElementById('nuc-tgts')?.value.trim()||'';
      const sev=document.getElementById('nuc-sev')?.value.trim()||'critical,high,medium';
      const tags=document.getElementById('nuc-tags')?.value.trim()||'';
      const o=document.getElementById('nuc-out'); if(!o)return;
      if(!tgtsRaw){o.style.display='block';o.textContent='enter at least one target URL';return;}
      const targets=tgtsRaw.split(/[,\n]+/).map(s=>s.trim()).filter(Boolean);
      o.style.display='block'; o.textContent=`launching nuclei against ${targets.length} target(s)… this may take several minutes`;
      try{
        const d=await jpost('/nuclei',{targets,severity:sev,tags:tags||undefined});
        if(d.error&&!d.total){o.innerHTML=`<span class="crit">error: ${d.error}</span>`;return;}
        const finds=(d.findings||[]);
        o.innerHTML=`nuclei ${d.nuclei_version||'?'}  <span class="crit">crit:${d.critical||0}</span>  <span class="high">high:${d.high||0}</span>  med:${d.medium||0}  total:${d.total||0}`+
          (finds.length?'\n\n'+finds.slice(0,25).map(f=>`  <span class="${f.severity==='critical'?'crit':f.severity==='high'?'high':f.severity==='medium'?'med':'ok'}">[${(f.severity||'?').toUpperCase().padEnd(8)}]</span> <span class="hi">${f.name.slice(0,40).padEnd(42)}</span> ${f.class}\n         ${(f.url||f.host||'').slice(0,70)}`).join('\n'):'\n<span class="ok">✓ no findings</span>');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // SSRF probe
    window._ssrf_probe=async function(){
      const url=document.getElementById('ssrf-url')?.value.trim();
      const param=document.getElementById('ssrf-param')?.value.trim()||'url';
      const cb=document.getElementById('ssrf-cb')?.value.trim();
      const o=document.getElementById('ssrf-out'); if(!o)return;
      if(!url){o.style.display='block';o.textContent='enter a URL';return;}
      o.style.display='block'; o.textContent=`probing ${url}?${param}=… (metadata + bypass variants${cb?' + blind callback':''})`;
      try{
        const body={url,param};
        if(cb) body.callback=cb;
        const d=await jpost('/ssrf',body);
        const f=(d.findings||[]);
        o.innerHTML=`findings:${f.length}  <span class="crit">crit:${d.critical||0}</span>  <span class="high">high:${d.high||0}</span>`+
          (f.length?'\n\n'+f.map(x=>`  <span class="${x.severity==='critical'?'crit':'high'}">[${x.severity.toUpperCase()}]</span> ${x.name}\n         target:${x.target}\n         ${(x.note||'').slice(0,100)}`).join('\n'):'\n\n<span class="ok">✓ no SSRF found with tested payloads</span>');
        if(cb&&!f.length) o.innerHTML+=`\n\n<span class="med">Blind SSRF payload sent to ${cb} — check DNS/HTTP logs</span>`;
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // Race condition
    window._race_fire=async function(){
      const url=document.getElementById('race-url')?.value.trim();
      const data=document.getElementById('race-data')?.value.trim();
      const tok=document.getElementById('race-tok')?.value.trim();
      const o=document.getElementById('race-out'); if(!o)return;
      if(!url){o.style.display='block';o.textContent='enter a URL';return;}
      o.style.display='block'; o.textContent='warming up + releasing 25 threads simultaneously…';
      try{
        const body={url,count:25};
        if(data) body.data=data;
        if(tok) body.token=tok;
        const d=await jpost('/race',body);
        const f=(d.findings||[]);
        const sc=d.status_counts||{};
        o.innerHTML=`threads:25  elapsed:${d.elapsed_ms||'?'}ms  success:${d.success_count||0}\n`+
          `status dist: `+Object.entries(sc).map(([s,n])=>`<span class="${+s<300?'ok':+s<500?'med':'crit'}">${s}×${n}</span>`).join('  ')+
          (f.length?'\n\n'+f.map(x=>`  <span class="${x.severity==='critical'?'crit':x.severity==='high'?'high':'med'}">[${(x.severity||'?').toUpperCase()}]</span> ${x.type}\n         ${(x.note||'').slice(0,100)}`).join('\n'):'\n\n<span class="ok">✓ endpoint appears idempotent</span>');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // SSTI probe
    window._ssti_probe=async function(){
      const url=document.getElementById('ssti-url')?.value.trim();
      const param=document.getElementById('ssti-param')?.value.trim();
      const o=document.getElementById('ssti-out'); if(!o)return;
      if(!url||!param){o.style.display='block';o.textContent='enter URL and param name';return;}
      o.style.display='block'; o.textContent=`probing ${param} for template injection (14 engines)…`;
      try{
        const d=await jpost('/ssti',{url,param});
        const f=(d.findings||[]);
        o.innerHTML=`reflects:${d.reflects?'yes':'no'}  engine:${d.engine||'none'}  findings:${f.length}`+
          (f.length?'\n\n'+f.map(x=>`  <span class="${x.severity==='critical'?'crit':x.severity==='high'?'high':'med'}">[${(x.severity||'?').toUpperCase()}]</span> ${x.label} (${x.engine||'?'})\n         payload: ${(x.payload||'').slice(0,50)}\n         ${(x.note||'').slice(0,100)}`).join('\n'):'\n\n<span class="ok">✓ no template injection found</span>');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // Subdomain takeover
    window._tko_check=async function(){
      const raw=document.getElementById('tko-hosts')?.value.trim();
      const o=document.getElementById('tko-out'); if(!o)return;
      if(!raw){o.style.display='block';o.textContent='enter subdomains or domain:acme.com';return;}
      o.style.display='block';
      // check if it's a domain: prefix or a list
      let body={};
      if(raw.startsWith('domain:')){body.domain=raw.slice(7).trim();}
      else{ body.hosts=raw.split(/[,\n]+/).map(s=>s.trim()).filter(Boolean); }
      o.textContent=`checking ${body.hosts?body.hosts.length+' hosts':'domain '+body.domain}… (CNAME resolution + fingerprinting)`;
      try{
        const d=await jpost('/takeover',body);
        const confirmed=(d.findings||[]).filter(f=>f.severity!=='info');
        const suspects=(d.findings||[]).filter(f=>f.severity==='info');
        o.innerHTML=`hosts:${d.hosts_checked||0}  <span class="crit">confirmed:${d.confirmed||0}</span>  suspects:${d.suspects||0}`+
          (confirmed.length?'\n\n'+confirmed.map(f=>`  <span class="${f.severity==='critical'?'crit':'high'}">[${f.severity.toUpperCase()}]</span> ${f.host}\n         CNAME→ ${f.cname}  service:${f.service}\n         ${f.note.slice(0,90)}`).join('\n'):'')+(suspects.length?`\n\n<span class="med">Unconfirmed (${suspects.length}):</span> ${suspects.slice(0,3).map(f=>f.host).join(', ')}`:'')
          ||'\n\n<span class="ok">✓ no dangling CNAMEs found</span>';
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // Open redirect
    window._redir_test=async function(){
      const url=document.getElementById('redir-url')?.value.trim();
      const param=document.getElementById('redir-param')?.value.trim();
      const oauth=document.getElementById('redir-oauth')?.value.trim();
      const o=document.getElementById('redir-out'); if(!o)return;
      if(!url||!param){o.style.display='block';o.textContent='enter URL and param name';return;}
      o.style.display='block'; o.textContent=`testing 15 redirect bypass vectors on ${param}…`;
      try{
        const body={url,param};
        if(oauth) body.oauth_url=oauth;
        const d=await jpost('/redirect',body);
        const f=(d.findings||[]);
        o.innerHTML=`findings:${f.length}  high:${d.high||0}  med:${d.medium||0}`+
          (f.length?'\n\n'+f.map(x=>`  <span class="${x.severity==='high'?'high':'med'}">[${(x.severity||'?').toUpperCase()}]</span> ${x.label||'oauth_chain'}\n         payload: ${(x.payload||x.chain||'').slice(0,70)}\n         ${(x.note||'').slice(0,100)}`).join('\n'):'\n\n<span class="ok">✓ no open redirect found</span>');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // Subdomain enumeration
    window._sub_enum=async function(){
      const domain=document.getElementById('sub-domain')?.value.trim();
      const brute=document.getElementById('sub-brute')?.checked;
      const seed=document.getElementById('sub-seed')?.checked;
      const o=document.getElementById('sub-out'); if(!o)return;
      if(!domain){o.style.display='block';o.textContent='enter a domain';return;}
      o.style.display='block'; o.textContent=`enumerating ${domain}… (crt.sh + hackertarget + alienvault${brute?' + brute':''})`;
      try{
        const params=new URLSearchParams({domain,target:'default'});
        if(brute) params.set('brute','1');
        if(seed) params.set('seed','1');
        const d=await fetch(API+'/subdomain?'+params).then(r=>r.json());
        if(d.error){o.innerHTML=`<span class="crit">error: ${d.error}</span>`;return;}
        const live=(d.results||[]).filter(r=>r.status);
        o.innerHTML=`found:${d.total_found||0}  <span class="ok">live:${d.live||0}</span>  dead:${d.dead||0}`+
          (seed&&d.seeded_cells?`  <span class="hi">+${d.seeded_cells} coverage cells</span>`:'')+
          (live.length?'\n\n'+live.slice(0,30).map(r=>`  <span class="${r.status<400?'ok':r.status<500?'med':'crit'}">[${r.status}]</span> ${r.host.padEnd(45)} ${(r.title||'').slice(0,40)}`).join('\n'):'\n<span class="med">no live subdomains</span>');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // CORS tester
    window._cors_test=async function(){
      const url=document.getElementById('cors-url')?.value.trim();
      const tok=document.getElementById('cors-tok')?.value.trim();
      const o=document.getElementById('cors-out'); if(!o)return;
      if(!url){o.style.display='block';o.textContent='enter a URL';return;}
      o.style.display='block'; o.textContent='testing 9 CORS vectors…';
      try{
        const d=await jpost('/cors',{url,token:tok||undefined});
        const f=(d.findings||[]);
        if(!f.length){o.innerHTML=`<span class="ok">✓ no CORS misconfiguration found</span>`;return;}
        o.innerHTML=`<span class="crit">⚠ ${f.length} CORS finding(s)</span>  crit:${d.critical||0}  med:${d.medium||0}\n\n`+
          f.map(x=>`  <span class="${x.severity==='critical'?'crit':'med'}">[${x.severity.toUpperCase()}]</span> ${x.label}\n`+
          `         ACAO=${x.acao}  ACAC=${x.acac}\n         ${x.note.slice(0,100)}`).join('\n');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // JWT attack suite
    window._jwt_test=async function(){
      const tok=document.getElementById('jwt-tok')?.value.trim();
      const url=document.getElementById('jwt-url')?.value.trim();
      const o=document.getElementById('jwt-out'); if(!o)return;
      if(!tok||!url){o.style.display='block';o.textContent='enter both a JWT and an endpoint URL';return;}
      o.style.display='block'; o.textContent='running JWT attack suite… (alg:none · weak secret · kid traversal · jku SSRF)';
      try{
        const d=await jpost('/jwt',{token:tok,url});
        const f=(d.findings||[]);
        o.innerHTML=`alg:${d.alg||'?'}  baseline:${d.baseline_status||'?'}  findings:${f.length}`+
          (f.length?'\n\n'+f.map(x=>`  <span class="${x.severity==='critical'?'crit':x.severity==='high'?'high':'med'}">[${(x.severity||'?').toUpperCase()}]</span> ${x.attack}\n         ${(x.note||'').slice(0,100)}`).join('\n'):'\n\n<span class="ok">✓ no JWT vulnerabilities found with tested patterns</span>');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // Hidden parameter fuzzer
    window._param_fuzz=async function(){
      const url=document.getElementById('param-url')?.value.trim();
      const tok=document.getElementById('param-tok')?.value.trim();
      const idorRaw=document.getElementById('param-idor')?.value.trim();
      const o=document.getElementById('param-out'); if(!o)return;
      if(!url){o.style.display='block';o.textContent='enter a URL';return;}
      o.style.display='block'; o.textContent='fuzzing ~400 hidden parameters…';
      const body={url,token:tok||undefined};
      if(idorRaw&&idorRaw.includes(':')){
        const [field,base]=idorRaw.split(':',2);
        body.idor_field=field.trim(); body.idor_base=base.trim();
      }
      try{
        const d=await jpost('/params',body);
        const f=(d.findings||[]);
        o.innerHTML=`tested:${d.params_tested||0}  findings:${f.length}`+
          (f.length?'\n\n'+f.map(x=>`  <span class="${x.type==='idor_candidate'?'crit':'med'}">[${(x.severity||'?').toUpperCase()}]</span> ${x.param||x.field||'?'}\n         ${(x.note||'').slice(0,100)}`).join('\n'):'\n\n<span class="ok">✓ no hidden parameters found</span>');
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };

    // Scope radar
    function _parseRadarSlug(raw){
      const body={};
      for(const part of raw.split(/[\s,]+/)){
        const [p,s]=(part+':').split(':',2);
        if(!s)continue;
        const v=s.trim();
        if(p==='h1') body.h1=v; else if(p==='bc') body.bc=v;
        else if(p==='ywh') body.ywh=v; else if(p==='ing') body.ing=v;
      }
      return body;
    }
    window._radar_snap=async function(){
      const raw=document.getElementById('radar-slug')?.value.trim();
      const o=document.getElementById('radar-out'); if(!o)return;
      if(!raw){o.style.display='block';o.textContent='enter a slug like h1:shopify or ywh:target';return;}
      o.style.display='block'; o.textContent='fetching + snapshotting…';
      const params=new URLSearchParams(_parseRadarSlug(raw));
      params.set('snapshot_only','1');
      try{
        const d=await fetch(API+'/scope-radar?'+params).then(r=>r.json());
        o.innerHTML=(d.results||[]).map(r=>r.first_run?`<span class="ok">✓ first snapshot stored: ${r.platform}:${r.slug} (${r.scope_count} scope items)</span>`:`<span class="med">snapshot updated: ${r.platform}:${r.slug}`).join('\n')||'done';
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };
    window._radar_diff=async function(){
      const raw=document.getElementById('radar-slug')?.value.trim();
      const o=document.getElementById('radar-out'); if(!o)return;
      if(!raw){o.style.display='block';o.textContent='enter a slug';return;}
      o.style.display='block'; o.textContent='diffing against stored snapshot…';
      const params=new URLSearchParams(_parseRadarSlug(raw));
      try{
        const d=await fetch(API+'/scope-radar?'+params).then(r=>r.json());
        if(!d.changes_found){o.innerHTML=`<span class="ok">✓ no scope or reward changes</span>`;return;}
        let out='';
        for(const r of (d.results||[])){
          if(r.first_run){out+=`first run — ${r.scope_count} items\n`;continue;}
          const a=(r.added||[]),rm=(r.removed||[]),bc=(r.bounty_changes||[]);
          if(a.length) out+=`<span class="ok">+${a.length} NEW:</span> `+a.slice(0,5).map(s=>s.identifier||s).join(', ')+'\n';
          if(rm.length) out+=`<span class="med">-${rm.length} removed:</span> `+rm.slice(0,3).map(s=>s.identifier||s).join(', ')+'\n';
          for(const b of bc) out+=`<span class="hi">bounty ${b.direction==='increase'?'↑':'↓'}</span> ${b.label}: ${b.old_max}→${b.new_max}\n`;
        }
        o.innerHTML=out||'changes detected';
      }catch(e){o.textContent=`error: ${e.message||e}`;}
    };
  }

  // ── Report scorer button in report-view toolbar ──────────────────────────
  const _renderOld2=window.render;
  window.render=function(){
    if(_renderOld2) _renderOld2.apply(this,arguments);
    try{
      if(V.page==='report-view'||V.page==='finding-report'){
        const tb=document.querySelector('.rv-toolbar');
        if(tb&&!document.getElementById('score-btn')){
          const sb=document.createElement('button'); sb.id='score-btn'; sb.className='btn-sm btn-sm-g'; sb.textContent='Score report';
          sb.title='Score this report 0–100 before submitting';
          sb.onclick=function(){
            let f=null;
            try{const s=(typeof getS==='function')?getS():null;if(s)f=s.findings[V.fi];if(!f&&typeof allFindingsFlat==='function')f=allFindingsFlat()[V.fi];}catch(e){}
            const panel=document.getElementById('score-panel')||document.createElement('div');
            panel.id='score-panel';
            panel.style.cssText='margin:18px 0;padding:16px 18px;border-radius:12px;background:var(--glass);border:1px solid var(--border2)';
            const rv=document.querySelector('.report-viewer')||tb.parentNode;
            if(!document.getElementById('score-panel'))rv.appendChild(panel);
            panel.innerHTML='<div style="font-family:var(--mono);font-size:12px;color:var(--text3)">scoring…</div>';
            const body={};
            if(f){
              if(f.title)body.title=f.title;
              if(f.endpoint)body.endpoint=f.endpoint;
              body.cls=inferClass(f);
              const sevMap={c:'critical',h:'high',m:'medium',l:'low',i:'info'};
              if(f.sev)body.sev=sevMap[f.sev]||f.sev;
              if(f.impact)body.impact=f.impact;
              if(f.repro||f.reproduction||f.steps)body.repro=(f.repro||f.reproduction||f.steps||'').slice(0,600);
              if(f.cvss)body.cvss=String(f.cvss);
              if(f.poc||f.request)body.has_poc=true;
              if(f.evidence||f.screenshot)body.has_evidence=true;
            }
            jpost('/report/score',body).then(d=>{
              const col=d.verdict==='SUBMIT'?'#4ADE80':d.verdict==='POLISH'?'#FBBF24':'#FB7185';
              const icon=d.verdict==='SUBMIT'?'✓':d.verdict==='POLISH'?'⚠':'✗';
              const scoreW=Math.min(100,d.score||0);
              const dims=d.dimensions||{};
              const dimRows=Object.entries(dims).map(([k,v])=>`
                <div class="score-label">${k}</div>
                <div class="score-bar" style="margin:0"><div class="score-dim-fill" style="width:${Math.round((v.score/v.max)*100)}%;height:5px;border-radius:3px;background:var(--accent)"></div></div>
                <div style="font-family:var(--mono);font-size:10px;color:var(--text3)">${v.score}/${v.max}</div>`).join('');
              const tips=(d.tips||[]).map(t=>`<div class="score-tip">${t}</div>`).join('');
              panel.innerHTML=`
                <div style="font-family:var(--mono);font-size:14px;font-weight:700;color:${col};margin-bottom:10px">${icon} ${d.verdict} · ${d.score}/100</div>
                <div class="score-bar"><div class="score-fill" style="width:${scoreW}%;background:${col}"></div></div>
                <div class="score-grid" style="margin-bottom:12px">${dimRows}</div>
                ${tips?`<div style="font-family:var(--sans);font-size:12px;font-weight:700;color:var(--text2);margin-bottom:6px">What to fix:</div>${tips}`:''}`;
              panel.scrollIntoView({behavior:'smooth',block:'center'});
            }).catch(()=>{ panel.innerHTML='<div style="font-family:var(--mono);font-size:12px;color:#FB7185">score failed — is the server running?</div>'; });
          };
          tb.appendChild(sb);
        }
      }
    }catch(e){}
  };

  // wire "Run pipeline" paste box to create a real server workspace via intake
  const _startHunt=window.startHunt;
  window.startHunt=function(){ try{ const paste=document.getElementById('mi-paste'); const tgt=document.getElementById('mi-target'); if(paste&&paste.value.trim()){ const name=(document.getElementById('mi-program')&&document.getElementById('mi-program').value.trim())|| (tgt&&tgt.value.trim())||'target'; jpost('/intake',{target:name,text:paste.value}); } }catch(e){} return _startHunt&&_startHunt.apply(this,arguments); };
  // subtle LIVE badge + exec-engine toggle (HTTP / Browser) in the topbar
  window.addEventListener('load',()=>{ setTimeout(()=>{ const tb=document.getElementById('tb-right'); if(!tb||document.getElementById('live-badge'))return;
    const b=document.createElement('span'); b.id='live-badge'; b.textContent='● LIVE'; b.title='connected to the local engine — Send/Diff fire real requests';
    b.style.cssText='font-family:var(--mono);font-size:10px;font-weight:700;color:#4ADE80;border:1px solid rgba(74,222,128,.4);background:rgba(74,222,128,.1);padding:4px 9px;border-radius:7px;margin-right:6px';
    const tog=document.createElement('span'); tog.id='exec-tog'; tog.title='exec engine: HTTP (curl via scope-guard) or Browser (real Chrome over CDP)';
    tog.style.cssText='font-family:var(--mono);font-size:10px;font-weight:700;border:1px solid rgba(255,255,255,.18);border-radius:8px;overflow:hidden;margin-right:8px;cursor:pointer;display:inline-flex';
    const paint=()=>{ const cdp=window.HUNTR_ENGINE==='cdp'; tog.innerHTML=`<span style="padding:4px 9px;${!cdp?'background:linear-gradient(135deg,#A78BFA,#7C3AED);color:#fff':'color:#948CB6'}">HTTP</span><span style="padding:4px 9px;${cdp?'background:linear-gradient(135deg,#A78BFA,#7C3AED);color:#fff':'color:#948CB6'}">Browser</span>`; };
    tog.onclick=()=>{ window.HUNTR_ENGINE=window.HUNTR_ENGINE==='cdp'?'http':'cdp'; paint(); }; paint();
    tb.insertBefore(b, tb.firstChild); tb.insertBefore(tog, tb.firstChild); },400); });
})();
