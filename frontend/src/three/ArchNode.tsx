import { useRef, useState } from 'react'
import { useFrame } from '@react-three/fiber'
import { Billboard, Html, Image } from '@react-three/drei'
import * as THREE from 'three'
import type { NodeDef } from './layout'

/**
 * A component of the architecture: hex plinth, glowing ring, billboarded
 * isometric icon. Grows in with `appear` (0..1), springs up on hover.
 */
export default function ArchNode({ def, color, appear, pulse, onSelect, onHover, labelsVisible }: {
  def: NodeDef
  color: string
  appear: React.MutableRefObject<number>
  pulse?: React.MutableRefObject<Record<string, number>>
  onSelect: (d: NodeDef) => void
  onHover: (d: NodeDef | null) => void
  labelsVisible: React.MutableRefObject<number>
}) {
  const group = useRef<THREE.Group>(null)
  const ring = useRef<THREE.MeshBasicMaterial>(null)
  const label = useRef<HTMLDivElement>(null)
  const [hovered, setHovered] = useState(false)
  const size = def.size ?? 1
  const seed = useRef(Math.random() * 10)
  const cur = useRef(0)

  useFrame((state, dt) => {
    const g = group.current
    if (!g) return
    const t = state.clock.elapsedTime
    // staggered grow-in by x position so the network "builds" left to right
    const delay = (def.pos[0] + 12) / 30 * 0.45
    const a = THREE.MathUtils.clamp((appear.current - 0.55 - delay) / 0.25, 0, 1)
    const target = a * (hovered ? 1.22 : 1)
    cur.current += (target - cur.current) * Math.min(1, dt * 9)
    const s = cur.current * size
    g.scale.setScalar(Math.max(0.0001, s))
    g.position.y = def.pos[1] + Math.sin(t * 1.1 + seed.current) * 0.06 + (hovered ? 0.18 : 0)
    if (ring.current) {
      const p = pulse?.current[def.id] ?? 0
      ring.current.opacity = (def.dim ? 0.35 : 0.85) + (hovered ? 0.15 : 0)
      ring.current.color.set(color).multiplyScalar(1.2 + p * 2.5 + (hovered ? 1.2 : 0))
      if (pulse && p > 0) pulse.current[def.id] = Math.max(0, p - dt * 2.2)
    }
    if (label.current) label.current.style.opacity = String(a * labelsVisible.current)
  })

  return (
    <group
      ref={group}
      position={def.pos}
      onPointerOver={(e) => { e.stopPropagation(); setHovered(true); onHover(def); document.body.style.cursor = 'pointer' }}
      onPointerOut={() => { setHovered(false); onHover(null); document.body.style.cursor = '' }}
      onClick={(e) => { e.stopPropagation(); onSelect(def) }}
    >
      {/* plinth */}
      <mesh position={[0, 0.12, 0]}>
        <cylinderGeometry args={[0.95, 1.05, 0.24, 6]} />
        <meshStandardMaterial color="#0b1118" metalness={0.6} roughness={0.35} emissive={color} emissiveIntensity={def.dim ? 0.03 : 0.08} />
      </mesh>
      <mesh position={[0, 0.25, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <ringGeometry args={[0.92, 1.0, 6]} />
        <meshBasicMaterial ref={ring} color={color} transparent toneMapped={false} side={THREE.DoubleSide} />
      </mesh>
      {/* hit area bigger than the mark */}
      <mesh position={[0, 1.1, 0]} visible={false}>
        <cylinderGeometry args={[1.15, 1.15, 2.4, 8]} />
        <meshBasicMaterial />
      </mesh>
      <Billboard position={[0, 1.15, 0]}>
        <Image url={def.icon} scale={[2.1, 2.1]} transparent toneMapped={false} opacity={def.dim ? 0.55 : 1} />
      </Billboard>
      <Html position={[0, -0.25, 0]} center zIndexRange={[20, 0]} style={{ pointerEvents: 'none' }}>
        <div ref={label} className={`node-label ${hovered ? 'hover' : ''} ${def.dim ? 'dim' : ''}`} style={{ opacity: 0 }}>
          <span className="node-label-name">{def.label}{def.badge && <em>{def.badge}</em>}</span>
          <span className="node-label-hint">{def.hint}</span>
        </div>
      </Html>
    </group>
  )
}
