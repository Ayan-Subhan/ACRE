import { useMemo, useRef } from 'react'
import { useFrame } from '@react-three/fiber'
import { Html, Line } from '@react-three/drei'
import * as THREE from 'three'
import { DEPLOY, WALLS, ZONES, node } from './layout'

/** Glass zone slabs with glowing outlines and corner labels. */
export function ZonePlatforms({ appear, labelsVisible }: { appear: React.MutableRefObject<number>; labelsVisible: React.MutableRefObject<number> }) {
  const mats = useRef<(THREE.MeshBasicMaterial | null)[]>([])
  const lines = useRef<({ material: THREE.Material } | null)[]>([])
  const labels = useRef<(HTMLDivElement | null)[]>([])
  useFrame((state) => {
    const a = THREE.MathUtils.clamp((appear.current - 0.45) / 0.4, 0, 1)
    const t = state.clock.elapsedTime
    ZONES.forEach((_, i) => {
      const m = mats.current[i]
      if (m) m.opacity = a * 0.07
      const l = lines.current[i]?.material as THREE.Material & { opacity: number } | undefined
      if (l) l.opacity = a * (0.55 + 0.25 * Math.sin(t * 1.6 + i))
      const el = labels.current[i]
      if (el) el.style.opacity = String(a * labelsVisible.current)
    })
  })
  return (
    <group>
      {ZONES.map((z, i) => {
        const w = z.x1 - z.x0, d = z.z1 - z.z0
        const cx = (z.x0 + z.x1) / 2, cz = (z.z0 + z.z1) / 2
        const y = 0.02
        const outline: [number, number, number][] = [[z.x0, y, z.z0], [z.x1, y, z.z0], [z.x1, y, z.z1], [z.x0, y, z.z1], [z.x0, y, z.z0]]
        return (
          <group key={z.id}>
            <mesh position={[cx, 0, cz]} rotation={[-Math.PI / 2, 0, 0]}>
              <planeGeometry args={[w, d]} />
              <meshBasicMaterial ref={(m) => { mats.current[i] = m }} color={z.color} transparent opacity={0} depthWrite={false} toneMapped={false} />
            </mesh>
            <Line ref={(l) => { lines.current[i] = l as unknown as { material: THREE.Material } }} points={outline} color={z.color} lineWidth={1.6} transparent opacity={0} toneMapped={false} />
            <Html position={[z.x0 + 0.15, 0.05, z.z0 + 0.1]} zIndexRange={[10, 0]} style={{ pointerEvents: 'none' }}>
              <div ref={(el) => { labels.current[i] = el }} className="zone-label" style={{ opacity: 0, color: z.color }}>
                <b>{z.label}</b><span>{z.sub}</span>
              </div>
            </Html>
          </group>
        )
      })}
    </group>
  )
}

const wallVert = /* glsl */ `
varying vec2 vUv;
void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }
`
const wallFrag = /* glsl */ `
uniform vec3 uColor; uniform float uTime; uniform float uOpacity;
varying vec2 vUv;
void main(){
  float base = pow(1.0 - vUv.y, 2.2);
  float scan = smoothstep(0.0, 0.02, abs(fract(vUv.y * 1.0 - uTime * 0.35) - 0.5) - 0.47);
  float bars = 0.5 + 0.5 * step(0.5, fract(vUv.x * 40.0));
  float a = (base * 0.55 + (1.0 - scan) * 0.25 * (1.0 - vUv.y)) * mix(0.75, 1.0, bars);
  gl_FragColor = vec4(uColor * 1.6, a * uOpacity);
}
`

/** Pulsing segregation walls between network zones. */
export function SegregationWalls({ appear }: { appear: React.MutableRefObject<number> }) {
  const mats = useRef<(THREE.ShaderMaterial | null)[]>([])
  const uniforms = useMemo(() => WALLS.map((w) => ({ uColor: { value: new THREE.Color(w.color) }, uTime: { value: 0 }, uOpacity: { value: 0 } })), [])
  useFrame((state) => {
    const a = THREE.MathUtils.clamp((appear.current - 0.6) / 0.3, 0, 1)
    mats.current.forEach((m, i) => {
      if (!m) return
      m.uniforms.uTime.value = state.clock.elapsedTime + i * 0.7
      m.uniforms.uOpacity.value = a * (0.75 + 0.25 * Math.sin(state.clock.elapsedTime * 2 + i))
    })
  })
  return (
    <group>
      {WALLS.map((w, i) => {
        const [ax, az] = w.a, [bx, bz] = w.b
        const len = Math.hypot(bx - ax, bz - az)
        const angle = Math.atan2(bz - az, bx - ax)
        return (
          <mesh key={i} position={[(ax + bx) / 2, 0.6, (az + bz) / 2]} rotation={[0, -angle, 0]}>
            <planeGeometry args={[len, 1.2]} />
            <shaderMaterial ref={(m) => { mats.current[i] = m }} vertexShader={wallVert} fragmentShader={wallFrag} uniforms={uniforms[i]}
              transparent depthWrite={false} side={THREE.DoubleSide} blending={THREE.AdditiveBlending} />
          </mesh>
        )
      })}
    </group>
  )
}

/** Dashed arcs from the offline zone to the gates they configure. */
export function DeployLinks({ appear }: { appear: React.MutableRefObject<number> }) {
  const refs = useRef<({ material: THREE.Material & { dashOffset: number; opacity: number } } | null)[]>([])
  const curves = useMemo(() => DEPLOY.map((d) => {
    const a = node(d.from).pos, b = node(d.to).pos
    const mid = new THREE.Vector3((a[0] + b[0]) / 2, 2.6, (a[2] + b[2]) / 2)
    return new THREE.QuadraticBezierCurve3(new THREE.Vector3(a[0], 0.4, a[2]), mid, new THREE.Vector3(b[0], 0.4, b[2])).getPoints(50)
  }), [])
  useFrame((_, dt) => {
    const a = THREE.MathUtils.clamp((appear.current - 0.75) / 0.25, 0, 1)
    refs.current.forEach((r) => {
      if (!r) return
      r.material.dashOffset -= dt * 0.8
      r.material.opacity = a * 0.7
    })
  })
  return (
    <group>
      {curves.map((pts, i) => (
        <Line key={i} ref={(l) => { refs.current[i] = l as unknown as { material: THREE.Material & { dashOffset: number; opacity: number } } }}
          points={pts} color="#a78bfa" lineWidth={1.4} dashed dashSize={0.25} gapSize={0.18} transparent opacity={0} toneMapped={false} />
      ))}
    </group>
  )
}
