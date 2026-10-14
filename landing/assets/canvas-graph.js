/* ============================================================
   HUNTR — 3D attack-surface graph (home hero)
   three.js (r128 UMD global THREE). Custom point shader:
   crisp core + additive glow halo, depth fade, a 3D "hunt
   wavefront" that classifies nodes (tested/validated/noise),
   live spokes, slow drift + pointer parallax.
   Self-inits on #scene-graph inside a .stage.
   ============================================================ */
(function(){
  "use strict";
  if (typeof THREE === 'undefined') return;
  var canvas = document.getElementById('scene-graph');
  if (!canvas) return;
  var stage = canvas.closest('.stage') || canvas.parentElement;
  var reduce = (window.HUNTR && window.HUNTR.reduce) || (window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);

  var BG = 0x0A0B0D;
  var COL = { idle:[0.22,0.25,0.32], tested:[0.62,0.66,0.73], val:[0.655,0.545,0.98], noise:[0.33,0.36,0.43], op:[0.29,0.87,0.50] };

  var renderer = new THREE.WebGLRenderer({ canvas:canvas, antialias:true, alpha:true, powerPreference:'high-performance' });
  renderer.setClearColor(0x000000, 0);
  var scene = new THREE.Scene();
  var camera = new THREE.PerspectiveCamera(55, 1, 0.1, 100);

  var group = new THREE.Group(); scene.add(group);

  /* ---- soft radial sprite for glow ---- */
  function sprite(){
    var c=document.createElement('canvas'); c.width=c.height=64;
    var g=c.getContext('2d'); var grd=g.createRadialGradient(32,32,0,32,32,32);
    grd.addColorStop(0,'rgba(255,255,255,0.95)'); grd.addColorStop(0.22,'rgba(255,255,255,0.40)');
    grd.addColorStop(0.55,'rgba(255,255,255,0.08)'); grd.addColorStop(1,'rgba(255,255,255,0)');
    g.fillStyle=grd; g.fillRect(0,0,64,64);
    var t=new THREE.Texture(c); t.needsUpdate=true; return t;
  }
  var TEX = sprite();

  /* ---- build nodes: flattened ellipsoid cloud (a "surface" with depth) ---- */
  var N = 120, R = 9;
  var pos = new Float32Array(N*3), col = new Float32Array(N*3), siz = new Float32Array(N), alp = new Float32Array(N);
  var nodes = [];
  for (var i=0;i<N;i++){
    var u=Math.random(), v=Math.random();
    var theta=u*Math.PI*2, phi=Math.acos(2*v-1);
    var rad = R*(0.30 + Math.pow(Math.random(),0.7)*0.70);
    var x=Math.sin(phi)*Math.cos(theta)*rad*1.35;
    var y=Math.sin(phi)*Math.sin(theta)*rad*0.98;
    var z=Math.cos(phi)*rad*0.60;
    pos[i*3]=x; pos[i*3+1]=y; pos[i*3+2]=z;
    nodes.push({ i:i, x:x,y:y,z:z, d:Math.sqrt(x*x+y*y+z*z), state:'idle', seen:false, pulse:0, base:1.4+Math.random()*1.7 });
  }
  nodes.sort(function(a,b){return a.d-b.d;});
  function setColor(i,c){ col[i*3]=c[0]; col[i*3+1]=c[1]; col[i*3+2]=c[2]; }
  nodes.forEach(function(n){ setColor(n.i,COL.idle); siz[n.i]=n.base; alp[n.i]=0.7; });

  var geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(pos,3));
  geo.setAttribute('aColor', new THREE.BufferAttribute(col,3));
  geo.setAttribute('aSize', new THREE.BufferAttribute(siz,1));
  geo.setAttribute('aAlpha', new THREE.BufferAttribute(alp,1));

  var vert = [
    'attribute float aSize; attribute vec3 aColor; attribute float aAlpha;',
    'uniform float uSizeMul; uniform float uPix; uniform float uFadeNear; uniform float uFadeFar;',
    'varying vec3 vColor; varying float vAlpha;',
    'void main(){',
    '  vColor=aColor;',
    '  vec4 mv = modelViewMatrix * vec4(position,1.0);',
    '  float d = -mv.z;',
    '  float fade = 1.0 - smoothstep(uFadeNear, uFadeFar, d);',
    '  vAlpha = aAlpha * clamp(fade,0.08,1.0);',
    '  gl_PointSize = aSize * uSizeMul * uPix * (70.0 / d);',
    '  gl_Position = projectionMatrix * mv;',
    '}'
  ].join('\n');
  var frag = [
    'uniform sampler2D uTex; varying vec3 vColor; varying float vAlpha;',
    'void main(){ vec4 t=texture2D(uTex, gl_PointCoord); gl_FragColor=vec4(vColor, t.a*vAlpha); }'
  ].join('\n');

  function mkMat(sizeMul, alphaMul, additive){
    return new THREE.ShaderMaterial({
      uniforms:{ uTex:{value:TEX}, uSizeMul:{value:sizeMul}, uPix:{value:1}, uFadeNear:{value:R*1.2}, uFadeFar:{value:R*3.4} },
      vertexShader:vert.replace('aAlpha;','aAlpha;') ,
      fragmentShader:frag.replace('t.a*vAlpha','t.a*vAlpha*'+alphaMul.toFixed(2)),
      transparent:true, depthWrite:false, depthTest:false,
      blending: additive?THREE.AdditiveBlending:THREE.NormalBlending
    });
  }
  var halo = new THREE.Points(geo, mkMat(3.0, 0.32, true));   // subtle additive glow
  var core = new THREE.Points(geo, mkMat(0.9, 1.0, false));   // crisp defined dot
  group.add(halo); group.add(core);

  /* ---- operator core (center) ---- */
  var opGeo=new THREE.BufferGeometry();
  opGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array([0,0,0]),3));
  opGeo.setAttribute('aColor', new THREE.BufferAttribute(new Float32Array(COL.op),3));
  opGeo.setAttribute('aSize', new THREE.BufferAttribute(new Float32Array([4.2]),1));
  opGeo.setAttribute('aAlpha', new THREE.BufferAttribute(new Float32Array([1]),1));
  var opHalo=new THREE.Points(opGeo, mkMat(3.2,0.5,true));
  var opCore=new THREE.Points(opGeo, mkMat(1.0,1.0,false));
  group.add(opHalo); group.add(opCore);

  /* ---- spokes (center -> ~half of nodes) + a few neighbor links ---- */
  var spokeNodes = nodes.filter(function(_,k){return k%2===0;});
  var eCount = spokeNodes.length;
  var ePos = new Float32Array(eCount*2*3), eCol = new Float32Array(eCount*2*3), eAlp = new Float32Array(eCount*2);
  var edges=[];
  spokeNodes.forEach(function(n,k){
    ePos[k*6+3]=n.x; ePos[k*6+4]=n.y; ePos[k*6+5]=n.z;
    edges.push({ node:n, k:k, lit:0 });
  });
  var eGeo=new THREE.BufferGeometry();
  eGeo.setAttribute('position', new THREE.BufferAttribute(ePos,3));
  eGeo.setAttribute('aColor', new THREE.BufferAttribute(eCol,3));
  eGeo.setAttribute('aAlpha', new THREE.BufferAttribute(eAlp,1));
  var eVert=[
    'attribute vec3 aColor; attribute float aAlpha; varying vec3 vColor; varying float vAlpha;',
    'void main(){ vColor=aColor; vAlpha=aAlpha; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);} '
  ].join('\n');
  var eFrag=['varying vec3 vColor; varying float vAlpha; void main(){ gl_FragColor=vec4(vColor, vAlpha);} '].join('\n');
  var eMat=new THREE.ShaderMaterial({ vertexShader:eVert, fragmentShader:eFrag, transparent:true, depthWrite:false, depthTest:false, blending:THREE.AdditiveBlending });
  var lines=new THREE.LineSegments(eGeo, eMat); group.add(lines);
  function edgeColor(k,c,a){ for(var s=0;s<2;s++){ eCol[k*6+s*3]=c[0]; eCol[k*6+s*3+1]=c[1]; eCol[k*6+s*3+2]=c[2]; eAlp[k*2+s]=a; } }
  edges.forEach(function(e){ edgeColor(e.k, COL.idle, 0.05); });

  /* ---- faint concentric rings (ground plane feel) ---- */
  function ring(r, a){
    var seg=96, p=new Float32Array((seg+1)*3);
    for(var j=0;j<=seg;j++){ var t=j/seg*Math.PI*2; p[j*3]=Math.cos(t)*r; p[j*3+1]=Math.sin(t)*r; p[j*3+2]=0; }
    var g=new THREE.BufferGeometry(); g.setAttribute('position',new THREE.BufferAttribute(p,3));
    var m=new THREE.LineBasicMaterial({ color:0xA78BFA, transparent:true, opacity:a });
    var l=new THREE.Line(g,m); l.rotation.x=Math.PI*0.5*0.0; return l;
  }
  var ringGrp=new THREE.Group();
  [0.5,0.75,1.0].forEach(function(f){ ringGrp.add(ring(R*f, 0.05)); });
  group.add(ringGrp);

  /* ---- telemetry ---- */
  var elT=document.getElementById('t-tested'), elV=document.getElementById('t-val'),
      elN=document.getElementById('t-noise'), elC=document.getElementById('t-cov'), elB=document.getElementById('t-bar');
  var counts={tested:0,val:0,noise:0};
  function tel(){
    var total=N; var done=counts.tested+counts.val+counts.noise;
    if(elT)elT.textContent=counts.tested+counts.val;
    if(elV)elV.textContent=counts.val;
    if(elN)elN.textContent=counts.noise;
    var cov=Math.round(done/total*100);
    if(elC)elC.textContent=cov+'%'; if(elB)elB.style.width=cov+'%';
  }
  function activate(n){
    n.seen=true; var r=Math.random();
    if(r<0.11){ n.state='val'; counts.val++; setColor(n.i,COL.val); siz[n.i]=n.base+1.4; alp[n.i]=1.0; }
    else if(r<0.36){ n.state='noise'; counts.noise++; setColor(n.i,COL.noise); alp[n.i]=0.9; }
    else { n.state='tested'; counts.tested++; setColor(n.i,COL.tested); alp[n.i]=0.9; }
    n.pulse=1;
    var e=edges.find(function(x){return x.node===n;});
    if(e){ e.lit=1; edgeColor(e.k, n.state==='val'?COL.val:COL.tested, n.state==='val'?0.6:0.22); }
    tel();
  }
  function resetScan(){
    nodes.forEach(function(n){ n.seen=false; n.state='idle'; n.pulse=0; setColor(n.i,COL.idle); siz[n.i]=n.base; alp[n.i]=0.7; });
    edges.forEach(function(e){ e.lit=0; edgeColor(e.k, COL.idle, 0.05); });
    counts={tested:0,val:0,noise:0}; tel();
  }

  /* ---- interaction ---- */
  var mx=0,my=0,tmx=0,tmy=0;
  if(!reduce){
    addEventListener('pointermove', function(e){
      var r=stage.getBoundingClientRect();
      mx=((e.clientX-r.left)/r.width-0.5)*2; my=((e.clientY-r.top)/r.height-0.5)*2;
    },{passive:true});
  }

  /* ---- sizing ---- */
  var DPR=Math.min(window.devicePixelRatio||1, 2);
  function resize(){
    var r=stage.getBoundingClientRect(); var w=Math.max(1,r.width), h=Math.max(1,r.height);
    renderer.setPixelRatio(DPR); renderer.setSize(w,h,false);
    camera.aspect=w/h; camera.updateProjectionMatrix();
    // fit camera distance so the cloud comfortably fills frame
    var narrow = w/h < 0.95;
    camera.position.set(0,0, R* (narrow ? 3.5 : 2.75));
    camera.lookAt(0,0,0);
    // weight the cloud to the right of the hero copy on wide screens
    group.position.x = narrow ? 0 : R*0.52;
    group.position.y = narrow ? R*0.28 : 0;
    halo.material.uniforms.uPix.value = Math.min(DPR,2);
    core.material.uniforms.uPix.value = Math.min(DPR,2);
    opHalo.material.uniforms.uPix.value = Math.min(DPR,2);
    opCore.material.uniforms.uPix.value = Math.min(DPR,2);
  }
  try{ new ResizeObserver(resize).observe(stage); }catch(e){ addEventListener('resize',resize); }

  /* ---- loop ---- */
  var scanR=0, opPulse=0, t0=performance.now(), last=t0, raf=null;
  group.rotation.x=-0.28;
  function frame(now){
    var dt=Math.min(now-last,50); last=now; var t=(now-t0)*0.001;
    // drift + parallax
    tmx+=(mx-tmx)*0.05; tmy+=(my-tmy)*0.05;
    group.rotation.y = t*0.055 + tmx*0.35;
    group.rotation.x = -0.28 + (-tmy)*0.22 + Math.sin(t*0.3)*0.02;
    ringGrp.rotation.z = t*0.02;

    // hunt wavefront
    if(!reduce){
      scanR += dt*0.0023*R;
      if(scanR > R*1.25){ scanR=0; resetScan(); }
      for(var q=0;q<nodes.length;q++){ var n=nodes[q]; if(!n.seen && n.d<=scanR) activate(n); }
    }

    // per-node pulse → size bump decays
    for(var k=0;k<nodes.length;k++){ var nn=nodes[k];
      if(nn.pulse>0.01){ nn.pulse*=0.93; siz[nn.i]= (nn.state==='val'? nn.base+1.4 : nn.base) + nn.pulse*2.2; }
    }
    // operator breathing
    opPulse = 0.5+0.5*Math.sin(t*2.0);
    opGeo.attributes.aSize.array[0] = 4.0 + opPulse*0.8; opGeo.attributes.aSize.needsUpdate=true;

    geo.attributes.aColor.needsUpdate=true; geo.attributes.aSize.needsUpdate=true; geo.attributes.aAlpha.needsUpdate=true;
    eGeo.attributes.aColor.needsUpdate=true; eGeo.attributes.aAlpha.needsUpdate=true;

    renderer.render(scene,camera);
    raf=requestAnimationFrame(frame);
  }

  resize();
  // reduced-motion: paint one representative frame, no loop
  if(reduce){
    nodes.forEach(function(n){ var r=Math.random(); if(r<0.11){n.state='val';counts.val++;setColor(n.i,COL.val);siz[n.i]=n.base+1.4;alp[n.i]=1;} else if(r<0.33){n.state='noise';counts.noise++;setColor(n.i,COL.noise);alp[n.i]=0.9;} else {n.state='tested';counts.tested++;setColor(n.i,COL.tested);alp[n.i]=0.9;} n.seen=true; var e=edges.find(function(x){return x.node===n;}); if(e)edgeColor(e.k, n.state==='val'?COL.val:COL.tested, n.state==='val'?0.6:0.22); });
    geo.attributes.aColor.needsUpdate=geo.attributes.aSize.needsUpdate=geo.attributes.aAlpha.needsUpdate=true;
    eGeo.attributes.aColor.needsUpdate=eGeo.attributes.aAlpha.needsUpdate=true;
    tel(); renderer.render(scene,camera);
  } else {
    var start=function(){ if(!raf){ last=performance.now(); raf=requestAnimationFrame(frame); } };
    var stop=function(){ if(raf){ cancelAnimationFrame(raf); raf=null; } };
    try{
      var io=new IntersectionObserver(function(es){es.forEach(function(e){ e.isIntersecting?start():stop(); });},{threshold:0.01});
      io.observe(stage);
    }catch(e){ start(); }
    document.addEventListener('visibilitychange',function(){ document.hidden?stop():start(); });
  }
})();
