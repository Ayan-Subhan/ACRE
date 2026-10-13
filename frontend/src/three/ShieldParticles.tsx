import { useMemo, useRef } from 'react'
import { useFrame, useThree } from '@react-three/fiber'
import * as THREE from 'three'
import { ZONES, HERO_TARGET } from './layout'

/**
 * One particle cloud with two homes: a breathing 3D shield (hero) and the zone
 * platforms of the architecture. `progress.current` (0..1, scroll-driven)
 * bursts the shield apart and re-gathers the particles onto the network floor.
 */

const vert = /* glsl */ `
uniform float uTime;
uniform float uMorph;
uniform vec2 uPointer;
uniform float uSize;
uniform float uPixelRatio;
attribute vec3 aShield;
attribute vec3 aArch;
attribute vec4 aRand;
attribute vec3 aColor;
varying vec3 vColor;
varying float vAlpha;

mat3 rotY(float a){ float c=cos(a), s=sin(a); return mat3(c,0.,-s, 0.,1.,0., s,0.,c); }
mat3 rotX(float a){ float c=cos(a), s=sin(a); return mat3(1.,0.,0., 0.,c,s, 0.,-s,c); }

void main(){
  // hero: shield, breathing + slow turn + pointer tilt
  vec3 s = aShield;
  s += normalize(s + vec3(0.0001)) * sin(uTime * 1.4 + aRand.x * 6.2831) * 0.035;
  s = rotY(sin(uTime * 0.35) * 0.45 + uPointer.x * 0.5) * rotX(-uPointer.y * 0.3) * s;
  vec3 p0 = s + vec3(${HERO_TARGET[0].toFixed(2)}, ${HERO_TARGET[1].toFixed(2)}, ${HERO_TARGET[2].toFixed(2)});

  // architecture: zone floor dust, gentle shimmer
  vec3 p1 = aArch + vec3(0.0, sin(uTime * 0.8 + aRand.y * 20.0) * 0.03, 0.0);

  // staggered morph with a burst in the middle
  float m = smoothstep(aRand.y * 0.35, 0.65 + aRand.y * 0.35, uMorph);
  vec3 dir = normalize(aRand.xyz * 2.0 - 1.0 + vec3(0.0, 0.35, 0.0));
  vec3 p = mix(p0, p1, m) + dir * sin(m * 3.14159) * (4.0 + aRand.w * 7.0);

  vec4 mv = modelViewMatrix * vec4(p, 1.0);
  gl_Position = projectionMatrix * mv;
  float twinkle = 0.65 + 0.35 * sin(uTime * 2.0 + aRand.z * 40.0);
  float size = uSize * mix(1.0, 0.75 * twinkle, m) * (0.6 + aRand.w * 0.8);
  gl_PointSize = size * uPixelRatio * (12.0 / -mv.z);

  vec3 shieldCol = mix(vec3(0.13, 0.83, 0.93), vec3(0.55, 0.36, 0.96), clamp(aShield.y * 0.25 + 0.5, 0.0, 1.0));
  shieldCol = mix(shieldCol, vec3(1.0, 0.42, 0.17), step(0.94, aRand.z)); // a few hostile embers
  vColor = mix(shieldCol, aColor, m);
  vAlpha = mix(0.95, 0.55, m);
}
`

const frag = /* glsl */ `
varying vec3 vColor;
varying float vAlpha;
void main(){
  vec2 c = gl_PointCoord - 0.5;
  float d = length(c);
  if (d > 0.5) discard;
  float a = smoothstep(0.5, 0.0, d);
  gl_FragColor = vec4(vColor * (0.9 + a * 1.6), a * a * vAlpha);
}
`

function shieldHalfWidth(y: number) {
  const W = 1.7
  if (y > 0.3) return W * (1 - 0.04 * (y - 0.3))
  const k = (y + 2.3) / 2.6
  return k <= 0 ? 0 : W * Math.pow(k, 0.62)
}

function sampleShield(rand: () => number): [number, number, number] {
  const r = rand()
  // 22% outline rim, 10% emblem pulse line, rest surface
  if (r < 0.22) {
    const t = rand()
    let x: number, y: number
    if (t < 0.18) { x = (rand() * 2 - 1) * 1.62; y = 2.0 - 0.12 * Math.cos(x * 1.9) }
    else {
      y = 2.0 - rand() * 4.3
      x = shieldHalfWidth(y) * (rand() < 0.5 ? -1 : 1)
    }
    const z = 0.55 * (1 - Math.min(1, (x / 1.7) ** 2)) + 0.06
    return [x, y, z]
  }
  if (r < 0.32) {
    // pulse emblem: flat - spike - flat
    const pts = [[-1.0, 0], [-0.4, 0], [-0.2, 0.6], [0.15, -0.7], [0.4, 0.25], [0.55, 0], [1.0, 0]]
    const i = Math.floor(rand() * (pts.length - 1))
    const k = rand()
    const x = pts[i][0] + (pts[i + 1][0] - pts[i][0]) * k
    const y = 0.15 + pts[i][1] + (pts[i + 1][1] - pts[i][1]) * k
    return [x, y, 0.62 + (rand() - 0.5) * 0.04]
  }
  for (;;) {
    const x = (rand() * 2 - 1) * 1.7
    const y = 2.0 - rand() * 4.3
    if (Math.abs(x) <= shieldHalfWidth(y)) {
      const z = 0.55 * (1 - (x / 1.7) ** 2) + (rand() - 0.5) * 0.08
      return [x, y, z]
    }
  }
}

function sampleArch(rand: () => number): { p: [number, number, number]; c: THREE.Color } {
  // weight zones by area; 35% on outlines for crisp edges
  const areas = ZONES.map((z) => (z.x1 - z.x0) * (z.z1 - z.z0))
  const total = areas.reduce((a, b) => a + b, 0)
  let pick = rand() * total
  let zi = 0
  while (pick > areas[zi]) { pick -= areas[zi]; zi++ }
  const z = ZONES[zi]
  const c = new THREE.Color(z.color)
  if (rand() < 0.35) {
    const per = 2 * ((z.x1 - z.x0) + (z.z1 - z.z0))
    let d = rand() * per
    const w = z.x1 - z.x0, h = z.z1 - z.z0
    let x: number, zz: number
    if (d < w) { x = z.x0 + d; zz = z.z0 } else if ((d -= w) < h) { x = z.x1; zz = z.z0 + d }
    else if ((d -= h) < w) { x = z.x1 - d; zz = z.z1 } else { d -= w; x = z.x0; zz = z.z1 - d }
    return { p: [x, 0.07, zz], c: c.clone().multiplyScalar(1.4) }
  }
  return { p: [z.x0 + rand() * (z.x1 - z.x0), 0.05 + rand() * 0.04, z.z0 + rand() * (z.z1 - z.z0)], c: c.clone().multiplyScalar(0.55) }
}

function mulberry32(a: number) {
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export default function ShieldParticles({ count, progress, pointer }: {
  count: number
  progress: React.MutableRefObject<number>
  pointer: React.MutableRefObject<[number, number]>
}) {
  const gl = useThree((s) => s.gl)
  const matRef = useRef<THREE.ShaderMaterial>(null)

  const geom = useMemo(() => {
    const rand = mulberry32(7)
    const shield = new Float32Array(count * 3)
    const arch = new Float32Array(count * 3)
    const rnd = new Float32Array(count * 4)
    const col = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      shield.set(sampleShield(rand), i * 3)
      const a = sampleArch(rand)
      arch.set(a.p, i * 3)
      col.set([a.c.r, a.c.g, a.c.b], i * 3)
      rnd.set([rand(), rand(), rand(), rand()], i * 4)
    }
    const g = new THREE.BufferGeometry()
    g.setAttribute('position', new THREE.BufferAttribute(arch, 3))
    g.setAttribute('aShield', new THREE.BufferAttribute(shield, 3))
    g.setAttribute('aArch', new THREE.BufferAttribute(arch, 3))
    g.setAttribute('aRand', new THREE.BufferAttribute(rnd, 4))
    g.setAttribute('aColor', new THREE.BufferAttribute(col, 3))
    g.boundingSphere = new THREE.Sphere(new THREE.Vector3(0, 0, 0), 60)
    return g
  }, [count])

  const uniforms = useMemo(() => ({
    uTime: { value: 0 },
    uMorph: { value: 0 },
    uPointer: { value: new THREE.Vector2() },
    uSize: { value: 2.4 },
    uPixelRatio: { value: Math.min(gl.getPixelRatio(), 2) },
  }), [gl])

  useFrame((_, dt) => {
    const u = matRef.current?.uniforms
    if (!u) return
    u.uTime.value += Math.min(dt, 0.05)
    u.uMorph.value = progress.current
    const pv = u.uPointer.value as THREE.Vector2
    pv.x += (pointer.current[0] - pv.x) * 0.05
    pv.y += (pointer.current[1] - pv.y) * 0.05
  })

  return (
    <points geometry={geom} frustumCulled={false}>
      <shaderMaterial
        ref={matRef}
        vertexShader={vert}
        fragmentShader={frag}
        uniforms={uniforms}
        transparent
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </points>
  )
}
