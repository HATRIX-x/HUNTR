/* ============================================================
   HUNTR — shared site behaviors (all pages)
   Depends on (optional) GSAP + ScrollTrigger + Lenis if present.
   ============================================================ */
(function(){
  "use strict";
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  window.HUNTR = window.HUNTR || {};
  window.HUNTR.reduce = reduce;

  // Paste a Formspree endpoint to collect emails, e.g. "https://formspree.io/f/abcwxyz".
  var FORM_ENDPOINT = "";

  function ready(fn){ if(document.readyState!=='loading') fn(); else document.addEventListener('DOMContentLoaded',fn); }

  ready(function(){
    var yr=document.getElementById('yr'); if(yr) yr.textContent=new Date().getFullYear();

    /* active nav link by path */
    (function(){
      var here=location.pathname.replace(/index\.html$/,'').replace(/\/$/,'')||'/';
      document.querySelectorAll('.nav-links a[data-path]').forEach(function(a){
        var p=a.getAttribute('data-path');
        if(p===here || (p!=='/'&&here.indexOf(p)===0)) a.classList.add('active');
      });
    })();

    /* scroll progress + ambient parallax */
    (function(){
      var sp=document.getElementById('sprog'), amb=document.querySelector('.ambient'), de=document.documentElement;
      function onScroll(){
        var max=de.scrollHeight-de.clientHeight;
        var p=max>0?(de.scrollTop||window.scrollY||0)/max:0;
        if(sp) sp.style.width=(Math.min(1,Math.max(0,p))*100)+'%';
        if(amb&&!reduce) amb.style.transform='translateY('+(-(de.scrollTop||window.scrollY||0)*0.04)+'px)';
      }
      addEventListener('scroll',onScroll,{passive:true}); onScroll();
    })();

    /* boot intro (once per session) */
    (function(){
      var boot=document.getElementById('boot'); if(!boot) return;
      var done=function(){ boot.classList.add('done'); setTimeout(function(){ try{boot.remove();}catch(e){} },600); };
      var seen=false; try{ seen=sessionStorage.getItem('huntr_boot')==='1'; }catch(e){}
      if(reduce||seen){ done(); return; }
      try{ sessionStorage.setItem('huntr_boot','1'); }catch(e){}
      var log=document.getElementById('b-log'), bar=document.getElementById('b-bar');
      var steps=[[8,'Initializing operator…'],[34,'Loading surface map…'],[62,'Arming class matrix…'],[90,'<b>● System online</b>'],[100,'Target ready']];
      var i=0; (function go(){ if(i>=steps.length){ setTimeout(done,320); return; }
        var s=steps[i++]; if(bar)bar.style.width=s[0]+'%'; if(log)log.innerHTML=s[1];
        setTimeout(go, 280+Math.random()*160); })();
      setTimeout(done, 3000);
    })();

    /* custom crosshair cursor + magnetic CTAs */
    (function(){
      if(reduce || !window.matchMedia || !matchMedia('(pointer:fine)').matches) return;
      var cur=document.getElementById('cursor'), dot=document.getElementById('cursor-dot'); if(!cur||!dot) return;
      document.documentElement.classList.add('cursor-on');
      var x=innerWidth/2,y=innerHeight/2,dx=x,dy=y;
      addEventListener('pointermove',function(e){x=e.clientX;y=e.clientY; dot.style.transform='translate('+x+'px,'+y+'px) translate(-50%,-50%)';});
      (function t(){ dx+=(x-dx)*0.2; dy+=(y-dy)*0.2; cur.style.transform='translate('+dx+'px,'+dy+'px) translate(-50%,-50%)'; requestAnimationFrame(t); })();
      document.querySelectorAll('a,button,input,.btn,.faq-q,[data-wl]').forEach(function(el){
        el.addEventListener('pointerenter',function(){cur.classList.add('hot');}); el.addEventListener('pointerleave',function(){cur.classList.remove('hot');}); });
      document.querySelectorAll('.btn-primary').forEach(function(b){
        b.addEventListener('pointermove',function(e){var r=b.getBoundingClientRect();b.style.transform='translate('+(e.clientX-(r.left+r.width/2))*0.18+'px,'+(e.clientY-(r.top+r.height/2))*0.3+'px)';});
        b.addEventListener('pointerleave',function(){b.style.transform='';}); });
    })();

    /* smooth scroll (Lenis) */
    (function(){ if(reduce||typeof Lenis==='undefined') return;
      try{ var lenis=new Lenis({duration:1.05,smoothWheel:true}); (function raf(t){lenis.raf(t);requestAnimationFrame(raf);})(performance.now());
        document.querySelectorAll('a[href^="#"]').forEach(function(a){a.addEventListener('click',function(e){var id=a.getAttribute('href'); if(id.length>1){var el=document.querySelector(id); if(el){e.preventDefault(); lenis.scrollTo(el,{offset:-20});}}});});
        if(window.gsap&&window.ScrollTrigger) lenis.on('scroll',ScrollTrigger.update);
      }catch(e){}
    })();

    /* scroll reveal — IntersectionObserver driven, visible-by-default safe.
       Content is never hidden unless we can guarantee we'll reveal it:
       we only hide after confirming IO + (gsap|transition) are available,
       and a failsafe timer force-reveals everything regardless. */
    (function(){
      var groups=[].slice.call(document.querySelectorAll('.reveal-group'));
      var singles=[].slice.call(document.querySelectorAll('[data-reveal]'));
      var hasGsap = (typeof gsap!=='undefined');
      // Build unit list: each group is one unit (stagger children); each single is a unit.
      var units=[];
      groups.forEach(function(g){ units.push({el:g, items:[].slice.call(g.children)}); });
      singles.forEach(function(el){ units.push({el:el, items:[el]}); });
      if(!units.length) return;

      var canAnimate = !reduce && typeof IntersectionObserver!=='undefined';
      function show(items){
        items.forEach(function(el,i){
          if(hasGsap){ gsap.to(el,{y:0,opacity:1,duration:.7,ease:'power3.out',delay:i*0.07}); }
          else { el.style.transition='opacity .6s ease, transform .6s ease'; el.style.opacity=1; el.style.transform='none'; }
          el.setAttribute('data-shown','1');
        });
      }
      if(!canAnimate){ units.forEach(function(u){ u.items.forEach(function(el){el.style.opacity=1;}); }); return; }

      // hide (now that we know we can reveal)
      units.forEach(function(u){ u.items.forEach(function(el){
        if(hasGsap){ gsap.set(el,{y:24,opacity:0}); } else { el.style.opacity=0; el.style.transform='translateY(24px)'; }
      }); });

      var map=new WeakMap(); units.forEach(function(u){ map.set(u.el,u); });
      var io=new IntersectionObserver(function(es){ es.forEach(function(e){
        if(e.isIntersecting){ var u=map.get(e.target); if(u){ show(u.items); io.unobserve(e.target); } }
      }); },{threshold:0.12, rootMargin:'0px 0px -6% 0px'});
      units.forEach(function(u){ io.observe(u.el); });

      // failsafe: nothing stays invisible — reveal all after 3s no matter what
      setTimeout(function(){ units.forEach(function(u){ if(!u.items[0] || u.items[0].getAttribute('data-shown')!=='1'){ show(u.items); try{io.unobserve(u.el);}catch(e){} } }); }, 3000);
    })();

    /* count-up — IntersectionObserver with failsafe */
    (function(){
      var nums=[].slice.call(document.querySelectorAll('[data-count]'));
      if(!nums.length) return;
      var render=function(el,val){ var sfx=el.dataset.suffix||''; el.innerHTML=Math.round(val)+(sfx?'<span class="sfx">'+sfx+'</span>':''); };
      if(reduce||typeof IntersectionObserver==='undefined'){ nums.forEach(function(el){render(el,+el.dataset.count);}); return; }
      nums.forEach(function(el){render(el,0);});
      var run=function(el){ if(el.getAttribute('data-ran')==='1') return; el.setAttribute('data-ran','1');
        var end=+el.dataset.count, dur=1100, t0=performance.now();
        if(end===0){ render(el,0); return; }
        (function step(t){ var p=Math.min(1,(t-t0)/dur); var e=1-Math.pow(1-p,3); render(el, end*e); if(p<1) requestAnimationFrame(step); })(t0); };
      var io=new IntersectionObserver(function(es){es.forEach(function(e){ if(e.isIntersecting){ run(e.target); io.unobserve(e.target); } });},{threshold:.35});
      nums.forEach(function(el){io.observe(el);});
      setTimeout(function(){ nums.forEach(run); }, 3200);
    })();

    /* FAQ accordion */
    document.querySelectorAll('.faq-list .faq-q').forEach(function(q){
      q.addEventListener('click', function(){
        var panel=q.nextElementSibling;
        var open=q.getAttribute('aria-expanded')==='true';
        var list=q.closest('.faq-list');
        list.querySelectorAll('.faq-q').forEach(function(o){ o.setAttribute('aria-expanded','false'); if(o.nextElementSibling) o.nextElementSibling.style.maxHeight='0px'; });
        if(!open){ q.setAttribute('aria-expanded','true'); panel.style.maxHeight=panel.scrollHeight+'px'; }
      });
    });

    /* waitlist forms */
    var valid=function(v){return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);};
    document.querySelectorAll('form[data-wl]').forEach(function(form){
      var email=form.querySelector('input[type=email]');
      var btn=form.querySelector('button[type=submit]');
      var msg=form.parentElement.querySelector('.wl-msg') || form.nextElementSibling;
      form.addEventListener('submit', async function(e){
        e.preventDefault(); if(msg) msg.className='wl-msg';
        if(!valid((email.value||'').trim())){ if(msg){msg.textContent='→ enter a valid email address.'; msg.classList.add('err');} return; }
        if(!FORM_ENDPOINT){ if(msg){msg.textContent='→ waitlist opens soon — follow for the launch.'; msg.classList.add('ok');} return; }
        btn.disabled=true; var label=btn.textContent; btn.textContent='Sending…';
        try{ var r=await fetch(FORM_ENDPOINT,{method:'POST',headers:{'Accept':'application/json','Content-Type':'application/json'},body:JSON.stringify({email:email.value.trim(),source:'huntr.run'})});
          if(r.ok){ if(msg){msg.textContent='✓ you\'re on the list. we\'ll be in touch.'; msg.classList.add('ok');} form.reset(); } else throw 0;
        }catch(err){ if(msg){msg.textContent='→ something went wrong — try again.'; msg.classList.add('err');} }
        finally{ btn.disabled=false; btn.textContent=label; }
      });
    });
  });
})();
