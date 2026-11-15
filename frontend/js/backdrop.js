// The background: the knowledge graph drawn as 9,000 dots with three.js (loaded from a CDN, no install).
// Each colour is one layer of the chain: bugs (CVE) on the outer shell, attacker actions (ATT&CK) at the core.
import * as THREE from "https://cdn.jsdelivr.net/npm/three@0.169.0/build/three.module.js";

const LAYERS = [
  { color: "#f59e0b", share: 0.46, shell: 2.15, column: -2.7 }, // CVE: specific bugs
  { color: "#ec4899", share: 0.2, shell: 1.6, column: -0.9 },   // CWE: the coding mistakes
  { color: "#8b5cf6", share: 0.17, shell: 1.1, column: 0.9 },   // CAPEC: how attacks work
  { color: "#14b8a6", share: 0.17, shell: 0.62, column: 2.7 },  // ATT&CK: what attackers do
];
const COUNT = 9000;

// Two positions for every dot: on its sphere shell, and in its column of the left-to-right chain
function buildShapes() {
  const sphere = new Float32Array(COUNT * 3), chain = new Float32Array(COUNT * 3);
  const colors = new Float32Array(COUNT * 3), seeds = new Float32Array(COUNT);
  const golden = Math.PI * (3 - Math.sqrt(5)); // spreads points evenly over a sphere
  let i = 0;
  LAYERS.forEach((layer, li) => {
    const n = li === LAYERS.length - 1 ? COUNT - i : Math.round(COUNT * layer.share);
    const c = new THREE.Color(layer.color);
    for (let k = 0; k < n; k++, i++) {
      const y = 1 - (k / (n - 1)) * 2;
      const r = Math.sqrt(1 - y * y) * layer.shell;
      sphere.set([Math.cos(golden * k) * r, y * layer.shell, Math.sin(golden * k) * r], i * 3);
      const a = Math.random() * Math.PI * 2, d = Math.sqrt(Math.random()) * (0.55 + layer.share * 1.6);
      chain.set([layer.column + (Math.random() - 0.5) * 0.18, Math.sin(a) * d, Math.cos(a) * d], i * 3);
      colors.set([c.r, c.g, c.b], i * 3);
      seeds[i] = Math.random();
    }
  });
  return { sphere, chain, colors, seeds };
}

// Runs on the graphics card for every dot: blends sphere -> chain and adds a gentle wobble
const VERTEX = `
uniform float uTime, uMorph, uPixel;
attribute vec3 aChain;
attribute float aSeed;
varying vec3 vColor;
void main() {
  float m = smoothstep(aSeed * 0.35, 0.65 + aSeed * 0.35, uMorph);
  vec3 p = mix(position, aChain, m);
  p += 0.035 * vec3(sin(uTime * 0.8 + aSeed * 40.0), cos(uTime * 0.7 + aSeed * 31.0), sin(uTime * 0.6 + aSeed * 23.0));
  vec4 mv = modelViewMatrix * vec4(p, 1.0);
  gl_Position = projectionMatrix * mv;
  gl_PointSize = uPixel * (2.2 + aSeed * 2.4) * (6.0 / -mv.z);
  vColor = color;
}`;
const FRAGMENT = `
varying vec3 vColor;
void main() {
  float d = length(gl_PointCoord - 0.5);
  if (d > 0.5) discard;
  gl_FragColor = vec4(vColor, smoothstep(0.5, 0.15, d) * 0.8);
}`;

// Draws the dots into `el`. scroll: true turns the sphere into the chain as the page scrolls.
export function startBackdrop(el, { scroll = false } = {}) {
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  } catch {
    return; // no WebGL on this computer: keep only the CSS gradient
  }
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  el.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 50);
  const { sphere, chain, colors, seeds } = buildShapes();
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.BufferAttribute(sphere, 3));
  geometry.setAttribute("aChain", new THREE.BufferAttribute(chain, 3));
  geometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  geometry.setAttribute("aSeed", new THREE.BufferAttribute(seeds, 1));
  const uniforms = { uTime: { value: 0 }, uMorph: { value: 0 }, uPixel: { value: renderer.getPixelRatio() } };
  const dots = new THREE.Points(geometry, new THREE.ShaderMaterial({
    uniforms, vertexShader: VERTEX, fragmentShader: FRAGMENT, transparent: true, depthWrite: false, vertexColors: true,
  }));
  scene.add(dots);

  function resize() {
    renderer.setSize(innerWidth, innerHeight, false);
    camera.aspect = innerWidth / innerHeight;
    camera.position.z = innerWidth < 700 ? 10.5 : 7; // further back on phones so it fits
    camera.updateProjectionMatrix();
  }

  // Where the animation should go; each frame moves a little toward these (smooth easing)
  const goal = { tiltX: 0, turnY: 0, morph: 0 };
  let scale = 2.4; // starts spread out, gathers into the sphere
  addEventListener("pointermove", (e) => {
    goal.tiltX = (e.clientY / innerHeight - 0.5) * 0.35;
    goal.turnY = (e.clientX / innerWidth - 0.5) * 0.6;
  });
  if (scroll) addEventListener("scroll", () => { goal.morph = Math.min(1, scrollY / (innerHeight * 1.2)); });
  addEventListener("resize", resize);

  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const clock = new THREE.Clock();
  function tick() {
    const t = clock.getElapsedTime();
    scale += (1 - scale) * 0.04;
    dots.scale.setScalar(still ? 1 : scale);
    dots.rotation.x += (goal.tiltX - dots.rotation.x) * 0.05;
    dots.rotation.y += (t * 0.06 + goal.turnY - dots.rotation.y) * 0.05;
    uniforms.uMorph.value += (goal.morph - uniforms.uMorph.value) * 0.06;
    uniforms.uTime.value = t;
    renderer.render(scene, camera);
    if (!still) requestAnimationFrame(tick);
  }
  resize();
  tick();
}
