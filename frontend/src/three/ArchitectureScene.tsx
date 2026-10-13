import { Suspense, useEffect, useMemo, useRef } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { Grid, Html, AdaptiveDpr } from '@react-three/drei'
import { EffectComposer, Bloom, Vignette } from '@react-three/postprocessing'
import * as THREE from 'three'
import { rectEvents } from './events'
import gsap from 'gsap'
import ShieldParticles from './ShieldParticles'
import ArchNode from './ArchNode'
import FlowParticles, { type FlowRates, type Kind, type Outcome } from './FlowParticles'
import { ZonePlatforms, SegregationWalls, DeployLinks } from './Zones'
import { ARCH_TARGET, EIDS_MODELS, HERO_TARGET, NODES, ZONES, node, type NodeDef } from './layout'
import { MODEL_COLOR } from '../lib/theme'

export interface SceneHandles {
  progress: React.MutableRefObject<number>
  pointer: React.MutableRefObject<[number, number]>
  rates: React.MutableRefObject<FlowRates>
  tally: React.MutableRefObject<Record<Kind, Record<Outcome, number>>>
  labelsVisible: React.MutableRefObject<number>
}

const zoneColor = (id: string) => ZONES.find((z) => z.id === id)?.color ?? '#22d3ee'
const nodeColor = (d: NodeDef) =>
  d.id === 'blocked' ? '#ef4444' : d.id === 'alert' ? '#e879f9' : d.id === 'quarantine' ? '#facc15' : zoneColor(d.zone)

const ease = (k: number) => k * k * (3 - 2 * k)

/**
 * Camera without OrbitControls: interpolates hero -> architecture view from the
 * scroll progress, sways slowly, follows horizontal drags, and flies into a
 * node when one is selected.
 */
function CameraRig({ progress, mobile, focus, reduced }: {
  progress: React.MutableRefObject<number>
  mobile: boolean
  focus: React.MutableRefObject<{ k: number; pos: THREE.Vector3 }>
  reduced: boolean
}) {
  const { camera, gl } = useThree()
  const drag = useRef({ az: 0, vel: 0, down: false, x: 0 })
  const target = useMemo(() => new THREE.Vector3(), [])
  const heroT = useMemo(() => new THREE.Vector3(...HERO_TARGET), [])
  const archT = useMemo(() => new THREE.Vector3(...ARCH_TARGET), [])

  useEffect(() => {
    const el = gl.domElement.parentElement!
    const down = (e: PointerEvent) => { drag.current.down = true; drag.current.x = e.clientX }
    const move = (e: PointerEvent) => {
      if (!drag.current.down || progress.current < 0.98) return
      const dx = e.clientX - drag.current.x
      drag.current.x = e.clientX
      drag.current.vel = dx * -0.004
      drag.current.az += drag.current.vel
    }
    const up = () => { drag.current.down = false }
    el.addEventListener('pointerdown', down)
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
    return () => { el.removeEventListener('pointerdown', down); window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up) }
  }, [gl, progress])

  useFrame((state, dt) => {
    const d = drag.current
    if (!d.down) { d.az += d.vel; d.vel *= 0.94 }
    d.az = THREE.MathUtils.clamp(d.az, -1.1, 1.1)
    const m = ease(THREE.MathUtils.clamp(progress.current, 0, 1))
    const t = state.clock.elapsedTime
    // hero: frame the shield off-centre so it clears the headline
    const aspect = state.size.width / state.size.height
    const portrait = aspect < 0.9
    const heroShift = aspect > 1 ? new THREE.Vector3(-Math.min(3.2, 1.1 * aspect), 0, 0) : new THREE.Vector3(0, -2.6, 0)
    target.lerpVectors(heroT.clone().add(heroShift), archT, m)
    const sway = reduced ? 0 : Math.sin(t * 0.12) * 0.22 * m
    // portrait: look along the flow so it runs bottom (untrusted) to top (LAN)
    const az = (portrait ? -1.32 : -0.38) * m + sway + d.az * m
    const polar = THREE.MathUtils.lerp(portrait ? 1.3 : 1.48, portrait ? 0.82 : mobile ? 0.95 : 1.0, m)
    const radius = THREE.MathUtils.lerp(portrait ? 13 : 8.5, portrait ? 41 : mobile ? 36 : 25.5, m)
    const pos = new THREE.Vector3(
      target.x + radius * Math.sin(polar) * Math.sin(az),
      target.y + radius * Math.cos(polar),
      target.z + radius * Math.sin(polar) * Math.cos(az),
    )
    // fly-in to a selected node
    const f = focus.current
    if (f.k > 0) {
      const fk = ease(f.k)
      const fp = f.pos.clone().add(new THREE.Vector3(0, 0.8, 0))
      target.lerp(fp, fk)
      pos.lerp(fp.clone().add(new THREE.Vector3(1.5, 3.2, 5.5)), fk)
    }
    camera.position.lerp(pos, Math.min(1, dt * 6))
    camera.lookAt(target)
  })
  return null
}

/** Three model chips orbiting the EIDS node. */
function EidsSatellites({ appear }: { appear: React.MutableRefObject<number> }) {
  const g = useRef<THREE.Group>(null)
  const labels = useRef<(HTMLSpanElement | null)[]>([])
  const p = node('eids').pos
  useFrame((state) => {
    if (!g.current) return
    g.current.rotation.y = state.clock.elapsedTime * 0.6
    const a = THREE.MathUtils.clamp((appear.current - 0.9) / 0.1, 0, 1)
    g.current.scale.setScalar(Math.max(0.0001, a))
    labels.current.forEach((l) => { if (l) l.style.opacity = String(a) })
  })
  return (
    <group ref={g} position={[p[0], 1.3, p[2]]}>
      {EIDS_MODELS.map((m, i) => {
        const a = (i / EIDS_MODELS.length) * Math.PI * 2
        return (
          <group key={m} position={[Math.cos(a) * 1.75, Math.sin(a * 2) * 0.25, Math.sin(a) * 1.75]}>
            <mesh>
              <octahedronGeometry args={[0.17, 0]} />
              <meshBasicMaterial color={MODEL_COLOR[m]} toneMapped={false} />
            </mesh>
            <Html center zIndexRange={[15, 0]} style={{ pointerEvents: 'none' }}>
              <span ref={(el) => { labels.current[i] = el }} className="sat-label" style={{ color: MODEL_COLOR[m], opacity: 0 }}>{m}</span>
            </Html>
          </group>
        )
      })}
    </group>
  )
}

function SceneContent({ handles, mobile, reduced, onSelect, onHover, particleCount, flowCount }: {
  handles: SceneHandles; mobile: boolean; reduced: boolean
  onSelect: (d: NodeDef) => void; onHover: (d: NodeDef | null) => void
  particleCount: number; flowCount: number
}) {
  const pulse = useRef<Record<string, number>>({})
  const focus = useRef({ k: 0, pos: new THREE.Vector3() })

  const select = (d: NodeDef) => {
    if (handles.progress.current < 0.95) return
    focus.current.pos.set(...d.pos)
    gsap.to(focus.current, { k: 1, duration: reduced ? 0.01 : 0.85, ease: 'power3.inOut', onComplete: () => onSelect(d) })
  }

  return (
    <>
      <color attach="background" args={['#000000']} />
      <fog attach="fog" args={['#000000', 26, 62]} />
      <ambientLight intensity={0.35} />
      <directionalLight position={[6, 12, 8]} intensity={1.1} color="#bfefff" />
      <pointLight position={[-8, 3, 1]} intensity={12} distance={12} color="#ff6a2b" />
      <pointLight position={[7, 3, 1]} intensity={10} distance={12} color="#8b5cf6" />

      <CameraRig progress={handles.progress} mobile={mobile} focus={focus} reduced={reduced} />

      <Grid position={[0, -0.01, 0]} args={[80, 80]} cellSize={0.6} cellThickness={0.6} cellColor="#0b2530"
        sectionSize={3} sectionThickness={1} sectionColor="#0f4a5c" fadeDistance={48} fadeStrength={1.6} infiniteGrid />

      <ShieldParticles count={particleCount} progress={handles.progress} pointer={handles.pointer} />
      <ZonePlatforms appear={handles.progress} labelsVisible={handles.labelsVisible} />
      <SegregationWalls appear={handles.progress} />
      <DeployLinks appear={handles.progress} />
      <Suspense fallback={null}>
        {NODES.map((d) => (
          <ArchNode key={d.id} def={d} color={nodeColor(d)} appear={handles.progress} pulse={pulse}
            onSelect={select} onHover={onHover} labelsVisible={handles.labelsVisible} />
        ))}
      </Suspense>
      <EidsSatellites appear={handles.progress} />
      <FlowParticles count={flowCount} rates={handles.rates} appear={handles.progress} pulse={pulse} tally={handles.tally} paused={reduced} />

      <EffectComposer multisampling={0}>
        <Bloom mipmapBlur intensity={mobile ? 0.9 : 1.15} luminanceThreshold={0.22} luminanceSmoothing={0.3} radius={0.75} />
        <Vignette eskil={false} offset={0.2} darkness={0.85} />
      </EffectComposer>
    </>
  )
}

export default function ArchitectureCanvas(props: {
  handles: SceneHandles; mobile: boolean; reduced: boolean
  onSelect: (d: NodeDef) => void; onHover: (d: NodeDef | null) => void
}) {
  const { mobile } = props
  return (
    <Canvas
      dpr={[1, mobile ? 1.5 : 2]}
      camera={{ fov: 42, near: 0.1, far: 200, position: [HERO_TARGET[0], HERO_TARGET[1], HERO_TARGET[2] + 8.5] }}
      gl={{ antialias: true, powerPreference: 'high-performance' }}
      onPointerMissed={() => (document.body.style.cursor = '')}
      events={rectEvents}
    >
      <AdaptiveDpr pixelated={false} />
      <SceneContent {...props} particleCount={mobile ? 7000 : 16000} flowCount={mobile ? 110 : 240} />
    </Canvas>
  )
}
