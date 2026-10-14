/* ============================================================
   HUNTR — cinematic data-stream (platform hero)
   three.js. Light streaks (tests, verdicts) flow through 3D
   space, converging into a focal "lock" — the operator.
   Purple = testing · green = validated · grey = dropped.
   Self-inits on #scene-stream inside a .stage.
   ============================================================ */
(function(){
  "use strict";
  if (typeof THREE === 'undefined') return;
  var canvas = document.getElementById('scene-stream');
  if (!canvas) return;
  var stage = canvas.closest('.stage') || canvas.parentElement;
  var reduce = (window.HUNTR && window.HUNTR.reduce) || (window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);

  var renderer=new THREE.WebGLRenderer({canvas:canvas,antialias:true,alpha:true,powerPreference:'high-performance'});
  renderer.setClearColor(0x000000,0);
  var scene=new THREE.Scene();
  var camera=new THREE.PerspectiveCamera(60,1,0.1,200); camera.position.set(0,0,8);
  var group=new THREE.Group(); scene.add(group);

  var COL={ test:[0.62,0.51,0.97], val:[0.29,0.87,0.50], drop:[0.40,0.43,0.52] };
  var Z_FAR=-70, Z_END=5, BASER=12;
  var N = Math.max(300, Math.min(520, Math.round((stage.getBoundingClientRect().width||1200)/2.6)));

  var P=[];
  function spawn(p, fresh){
    p.ang=Math.random()*Math.PI*2;
    p.r=BASER*(0.25+Math.random()*0.85);
    p.z=fresh? (Z_FAR*Math.random()) : Z_FAR - Math.random()*10;
    p.speed=22+Math.random()*34;
    p.len=4.0+Math.random()*9.0;
    var r=Math.random(); p.type = r<0.12?'val' : (r<0.30?'drop':'test');
  }
  for(var i=0;i<N;i++){ var p={}; spawn(p,true); P.push(p); }

  var pos=new Float32Array(N*2*3), col=new Float32Array(N*2*3), alp=new Float32Array(N*2);
  var geo=new THREE.BufferGeometry();
  geo.setAttribute('position',new THREE.BufferAttribute(pos,3));
  geo.setAttribute('aColor',new THREE.BufferAttribute(col,3));
  geo.setAttribute('aAlpha',new THREE.BufferAttribute(alp,1));
  var vert=['attribute vec3 aColor; attribute float aAlpha; varying vec3 vC; varying float vA;',
    'void main(){ vC=aColor; vA=aAlpha; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);} '].join('\n');
  var frag=['varying vec3 vC; varying float vA; void main(){ gl_FragColor=vec4(vC, vA);} '].join('\n');
  var mat=new THREE.ShaderMaterial({vertexShader:vert,fragmentShader:frag,transparent:true,depthWrite:false,depthTest:false,blending:THREE.AdditiveBlending});
  var streaks=new THREE.LineSegments(geo,mat); group.add(streaks);

  /* focal lock: pulsing rings + crosshair */
  function ringLine(r){
    var seg=80, a=new Float32Array((seg+1)*3);
    for(var j=0;j<=seg;j++){var t=j/seg*Math.PI*2; a[j*3]=Math.cos(t)*r; a[j*3+1]=Math.sin(t)*r; a[j*3+2]=0;}
    var g=new THREE.BufferGeometry(); g.setAttribute('position',new THREE.BufferAttribute(a,3));
    return new THREE.Line(g,new THREE.LineBasicMaterial({color:0x4ADE80,transparent:true,opacity:0.5}));
  }
  var lock=new THREE.Group();
  var r1=ringLine(1.5), r2=ringLine(2.4); lock.add(r1); lock.add(r2);
  var chGeo=new THREE.BufferGeometry();
  chGeo.setAttribute('position',new THREE.BufferAttribute(new Float32Array([-3.2,0,0,-1.8,0,0, 1.8,0,0,3.2,0,0, 0,-3.2,0,0,-1.8,0, 0,1.8,0,0,3.2,0]),3));
  lock.add(new THREE.LineSegments(chGeo,new THREE.LineBasicMaterial({color:0x4ADE80,transparent:true,opacity:0.35})));
  // operator glow sprite
  (function(){ var c=document.createElement('canvas');c.width=c.height=64;var g=c.getContext('2d');
    var gr=g.createRadialGradient(32,32,0,32,32,32);gr.addColorStop(0,'rgba(120,255,170,0.9)');gr.addColorStop(0.3,'rgba(74,222,128,0.35)');gr.addColorStop(1,'rgba(74,222,128,0)');
    g.fillStyle=gr;g.fillRect(0,0,64,64);var t=new THREE.Texture(c);t.needsUpdate=true;
    var sp=new THREE.Sprite(new THREE.SpriteMaterial({map:t,transparent:true,blending:THREE.AdditiveBlending,depthWrite:false,depthTest:false}));
    sp.scale.set(6,6,1); lock.add(sp);
  })();
  group.add(lock);

  function setV(i, head, tail, c, a){
    pos[i*6]=head[0];pos[i*6+1]=head[1];pos[i*6+2]=head[2];
    pos[i*6+3]=tail[0];pos[i*6+4]=tail[1];pos[i*6+5]=tail[2];
    col[i*6]=col[i*6+3]=c[0]; col[i*6+1]=col[i*6+4]=c[1]; col[i*6+2]=col[i*6+5]=c[2];
    alp[i*2]=a; alp[i*2+1]=a*0.15;
  }
  function ease(t){return t*t*(3-2*t);}

  var mx=0,my=0,tmx=0,tmy=0;
  if(!reduce) addEventListener('pointermove',function(e){var r=stage.getBoundingClientRect();mx=((e.clientX-r.left)/r.width-0.5)*2;my=((e.clientY-r.top)/r.height-0.5)*2;},{passive:true});

  var DPR=Math.min(window.devicePixelRatio||1,2);
  function resize(){ var r=stage.getBoundingClientRect(),w=Math.max(1,r.width),h=Math.max(1,r.height);
    renderer.setPixelRatio(DPR); renderer.setSize(w,h,false); camera.aspect=w/h; camera.updateProjectionMatrix();
    camera.position.z = (w/h<0.9)?12:8;
  }
  try{ new ResizeObserver(resize).observe(stage);}catch(e){ addEventListener('resize',resize); }

  var last=performance.now(), t0=last, raf=null;
  function step(now){ var dt=Math.min((now-last)/1000,0.05); last=now; var t=(now-t0)*0.001;
    tmx+=(mx-tmx)*0.04; tmy+=(my-tmy)*0.04;
    group.rotation.y = tmx*0.12 + Math.sin(t*0.15)*0.03;
    group.rotation.x = -tmy*0.1;
    var pulse=0.5+0.5*Math.sin(t*2.2); lock.scale.setScalar(1+pulse*0.04); r1.material.opacity=0.35+pulse*0.25;
    for(var i=0;i<N;i++){ var p=P[i];
      if(!reduce) p.z += p.speed*dt;
      if(p.z>Z_END){ spawn(p,false); }
      var prog=Math.min(1,Math.max(0,(p.z-Z_FAR)/(Z_END-Z_FAR)));
      var cr=p.r*(1-ease(prog)*0.5);
      var hx=Math.cos(p.ang)*cr, hy=Math.sin(p.ang)*cr;
      var tr=p.r*(1-ease(Math.max(0,(p.z-p.len-Z_FAR)/(Z_END-Z_FAR)))*0.5);
      var tx=Math.cos(p.ang)*tr, ty=Math.sin(p.ang)*tr;
      var a = ease(Math.min(1,prog*2.4)) * (1-ease(Math.max(0,(prog-0.86)/0.14)));
      var c = p.type==='val'?COL.val : (p.type==='drop'?COL.drop:COL.test);
      var am = p.type==='val'?1.3 : (p.type==='drop'?0.7:1.05);
      setV(i,[hx,hy,p.z],[tx,ty,p.z-p.len], c, Math.min(1,a*am*1.5));
    }
    geo.attributes.position.needsUpdate=true; geo.attributes.aColor.needsUpdate=true; geo.attributes.aAlpha.needsUpdate=true;
    renderer.render(scene,camera);
    raf=requestAnimationFrame(step);
  }

  resize();
  if(reduce){ for(var k=0;k<N;k++){var p=P[k]; p.z=Z_FAR+Math.random()*(Z_END-Z_FAR);} last=performance.now(); step(last); if(raf){cancelAnimationFrame(raf);raf=null;} }
  else {
    var start=function(){ if(!raf){last=performance.now();raf=requestAnimationFrame(step);} };
    var stop=function(){ if(raf){cancelAnimationFrame(raf);raf=null;} };
    try{ var io=new IntersectionObserver(function(es){es.forEach(function(e){e.isIntersecting?start():stop();});},{threshold:0.01}); io.observe(stage);}catch(e){ start(); }
    document.addEventListener('visibilitychange',function(){document.hidden?stop():start();});
  }
})();
