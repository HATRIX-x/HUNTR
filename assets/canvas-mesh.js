/* ============================================================
   HUNTR — shader gradient mesh (benchmark / access hero)
   three.js fullscreen plane + GLSL: domain-warped fbm noise,
   brand purple->green blooms drifting on near-black, grain +
   vignette. `data-intensity` on the canvas tunes strength.
   Self-inits on #scene-mesh inside a .stage.
   ============================================================ */
(function(){
  "use strict";
  if (typeof THREE === 'undefined') return;
  var canvas = document.getElementById('scene-mesh');
  if (!canvas) return;
  var stage = canvas.closest('.stage') || canvas.parentElement;
  var reduce = (window.HUNTR && window.HUNTR.reduce) || (window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
  var intensity = parseFloat(canvas.getAttribute('data-intensity')||'1') || 1;

  var renderer=new THREE.WebGLRenderer({canvas:canvas,antialias:false,alpha:true,powerPreference:'high-performance'});
  renderer.setClearColor(0x000000,0);
  var scene=new THREE.Scene();
  var camera=new THREE.OrthographicCamera(-1,1,1,-1,0,1);

  var frag=[
    'precision highp float;',
    'varying vec2 vUv;',
    'uniform vec2 uRes; uniform float uTime; uniform float uInt;',
    'float hash(vec2 p){ p=fract(p*vec2(123.34,456.21)); p+=dot(p,p+45.32); return fract(p.x*p.y); }',
    'float noise(vec2 p){ vec2 i=floor(p),f=fract(p); vec2 u=f*f*(3.0-2.0*f);',
    ' float a=hash(i),b=hash(i+vec2(1.0,0.0)),c=hash(i+vec2(0.0,1.0)),d=hash(i+vec2(1.0,1.0));',
    ' return mix(mix(a,b,u.x),mix(c,d,u.x),u.y); }',
    'float fbm(vec2 p){ float v=0.0,amp=0.5; mat2 m=mat2(1.6,1.2,-1.2,1.6);',
    ' for(int i=0;i<5;i++){ v+=amp*noise(p); p=m*p; amp*=0.5; } return v; }',
    'void main(){',
    ' vec2 uv=vUv; uv.x*=uRes.x/uRes.y;',
    ' vec2 p=uv*2.1; float t=uTime*0.05;',
    ' vec2 q=vec2(fbm(p+vec2(0.0,t)), fbm(p+vec2(5.2,-t)));',
    ' vec2 r=vec2(fbm(p+q*1.8+vec2(1.7,9.2)+t*0.5), fbm(p+q*1.8+vec2(8.3,2.8)-t*0.5));',
    ' float f=fbm(p+r*1.8);',
    ' vec3 bg=vec3(0.039,0.043,0.051);',
    ' vec3 purple=vec3(0.655,0.545,0.98);',
    ' vec3 green=vec3(0.29,0.87,0.50);',
    ' vec3 col=bg;',
    ' col=mix(col, purple, smoothstep(0.45,0.98,f)*0.55*uInt);',
    ' col=mix(col, green, smoothstep(0.58,0.95,r.x)*0.16*uInt);',
    ' col+=purple*pow(f,3.0)*0.45*uInt;',
    ' float vig=smoothstep(1.35,0.15,length(vUv-0.5)*1.7);',
    ' col*=mix(0.45,1.0,vig);',
    ' col+=(hash(vUv*uRes+t)-0.5)*0.022;',
    ' gl_FragColor=vec4(col,1.0);',
    '}'
  ].join('\n');
  var vert=['varying vec2 vUv; void main(){ vUv=uv; gl_Position=vec4(position,1.0);} '].join('\n');

  var uni={ uRes:{value:new THREE.Vector2(1,1)}, uTime:{value:0}, uInt:{value:intensity} };
  var mat=new THREE.ShaderMaterial({uniforms:uni,vertexShader:vert,fragmentShader:frag});
  var mesh=new THREE.Mesh(new THREE.PlaneGeometry(2,2),mat); scene.add(mesh);

  var DPR=Math.min(window.devicePixelRatio||1,1.5);
  function resize(){ var r=stage.getBoundingClientRect(),w=Math.max(1,r.width),h=Math.max(1,r.height);
    renderer.setPixelRatio(DPR); renderer.setSize(w,h,false); uni.uRes.value.set(w*DPR,h*DPR); }
  try{ new ResizeObserver(resize).observe(stage);}catch(e){ addEventListener('resize',resize); }

  var t0=performance.now(), raf=null;
  function step(now){ uni.uTime.value=(now-t0)*0.001; renderer.render(scene,camera); raf=requestAnimationFrame(step); }
  resize();
  if(reduce){ uni.uTime.value=12.0; renderer.render(scene,camera); }
  else{
    var start=function(){ if(!raf){t0=performance.now()-uni.uTime.value*1000; raf=requestAnimationFrame(step);} };
    var stop=function(){ if(raf){cancelAnimationFrame(raf);raf=null;} };
    try{ var io=new IntersectionObserver(function(es){es.forEach(function(e){e.isIntersecting?start():stop();});},{threshold:0.01}); io.observe(stage);}catch(e){ start(); }
    document.addEventListener('visibilitychange',function(){document.hidden?stop():start();});
  }
})();
