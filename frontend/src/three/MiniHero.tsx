import { Suspense, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Billboard, Image } from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import * as THREE from 'three'
import { rectEvents } from './events'

function Orbit({ color, count = 900 }: { color: string; count?: number }) {
  const ref = useRef<THREE.Points>(null)
  const geom = useMemo(() => {
    const g = new THREE.BufferGeometry()
    const p = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      const ring = i % 3
      const a = Math.random() * Math.PI * 2
      const r = 1.9 + ring * 0.45 + (Math.random() - 0.5) * 0.18
      p.set([Math.cos(a) * r, (Math.random() - 0.5) * 0.12 + ring * 0.05, Math.sin(a) * r], i * 3)
    }
    g.setAttribute('position', new THREE.BufferAttribute(p, 3))
    return g
  }, [count])
  useFrame((s) => {
    if (!ref.current) return
    ref.current.rotation.y = s.clock.elapsedTime * 0.25
    ref.current.rotation.x = 0.35 + Math.sin(s.clock.elapsedTime * 0.4) * 0.06
  })
  return (
    <points ref={ref} geometry={geom}>
      <pointsMaterial color={color} size={0.035} sizeAttenuation transparent opacity={0.9} toneMapped={false} blending={THREE.AdditiveBlending} depthWrite={false} />
    </points>
  )
}

function Totem({ icon, color, dim }: { icon: string; color: string; dim?: boolean }) {
  const g = useRef<THREE.Group>(null)
  const plinth = useRef<THREE.Group>(null)
  const [hover, setHover] = useState(false)
  const s = useRef(0.2)
  useFrame((st, dt) => {
    s.current += ((hover ? 1.15 : 1) - s.current) * Math.min(1, dt * 5)
    if (g.current) {
      g.current.scale.setScalar(s.current)
      g.current.position.y = Math.sin(st.clock.elapsedTime * 1.2) * 0.08
    }
    if (plinth.current) plinth.current.rotation.y += dt * (hover ? 1.2 : 0.35)
  })
  return (
    <group ref={g} onPointerOver={() => setHover(true)} onPointerOut={() => setHover(false)}>
      <group ref={plinth} position={[0, -1.15, 0]}>
        <mesh>
          <cylinderGeometry args={[1.25, 1.4, 0.3, 6]} />
          <meshStandardMaterial color="#0b1118" metalness={0.7} roughness={0.3} emissive={color} emissiveIntensity={0.08} />
        </mesh>
        <mesh position={[0, 0.16, 0]} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[1.18, 1.27, 6]} />
          <meshBasicMaterial color={color} toneMapped={false} side={THREE.DoubleSide} />
        </mesh>
      </group>
      <Billboard>
        <Image url={icon} scale={[2.8, 2.8]} transparent toneMapped={false} opacity={dim ? 0.6 : 1} />
      </Billboard>
    </group>
  )
}

/** Rotating plinth + icon + orbiting particles, used in each page header. */
export default function MiniHero({ icon, color, dim }: { icon: string; color: string; dim?: boolean }) {
  return (
    <Canvas dpr={[1, 2]} camera={{ position: [0, 1.2, 6.2], fov: 40 }} gl={{ antialias: true, alpha: true }} style={{ touchAction: 'pan-y' }} events={rectEvents}>
      <ambientLight intensity={0.5} />
      <directionalLight position={[3, 5, 4]} intensity={1.2} />
      <pointLight position={[0, -1, 2]} color={color} intensity={6} distance={6} />
      <Suspense fallback={null}>
        <Totem icon={icon} color={color} dim={dim} />
      </Suspense>
      <Orbit color={color} />
      <EffectComposer multisampling={0}>
        <Bloom mipmapBlur intensity={0.9} luminanceThreshold={0.25} radius={0.7} />
      </EffectComposer>
    </Canvas>
  )
}
