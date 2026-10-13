import { lazy, Suspense, useEffect } from 'react'
import { Route, Routes, useLocation } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import Lenis from 'lenis'
import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import NavBar from './components/NavBar'
import Footer from './components/Footer'
import { prefersReducedMotion } from './lib/motion'

gsap.registerPlugin(ScrollTrigger)

const Home = lazy(() => import('./pages/Home'))
const Validator = lazy(() => import('./pages/Validator'))
const IDS = lazy(() => import('./pages/IDS'))
const Discriminator = lazy(() => import('./pages/Discriminator'))
const Adversary = lazy(() => import('./pages/Adversary'))
const BasePaper = lazy(() => import('./pages/BasePaper'))
const Pipeline = lazy(() => import('./pages/Pipeline'))

export default function App() {
  const location = useLocation()

  // smooth scroll (skipped under reduced motion), driven by the GSAP ticker
  useEffect(() => {
    if (prefersReducedMotion()) return
    const lenis = new Lenis({ lerp: 0.1, smoothWheel: true })
    lenis.on('scroll', ScrollTrigger.update)
    const tick = (t: number) => lenis.raf(t * 1000)
    gsap.ticker.add(tick)
    gsap.ticker.lagSmoothing(0)
    ;(window as unknown as { __lenis?: Lenis }).__lenis = lenis
    return () => { gsap.ticker.remove(tick); lenis.destroy() }
  }, [])

  useEffect(() => {
    const lenis = (window as unknown as { __lenis?: Lenis }).__lenis
    if (lenis) lenis.scrollTo(0, { immediate: true })
    else window.scrollTo(0, 0)
  }, [location.pathname])

  return (
    <>
      <a className="sr-only sr-only-focusable btn" href="#main" style={{ position: 'fixed', top: 8, left: 8, zIndex: 100 }}>Skip to content</a>
      <NavBar />
      <AnimatePresence mode="wait">
        <motion.main
          id="main"
          key={location.pathname}
          // opacity only: a filter/transform on <main> would re-anchor the fixed 3D stage
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0, transition: { duration: 0.2 } }}
          transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
          onAnimationComplete={() => ScrollTrigger.refresh()}
        >
          <Suspense fallback={<div style={{ minHeight: '100vh' }} />}>
            <Routes location={location}>
              <Route path="/" element={<Home />} />
              <Route path="/validator" element={<Validator />} />
              <Route path="/ids" element={<IDS />} />
              <Route path="/discriminator" element={<Discriminator />} />
              <Route path="/adversary" element={<Adversary />} />
              <Route path="/base-paper" element={<BasePaper />} />
              <Route path="/pipeline" element={<Pipeline />} />
              <Route path="*" element={<Home />} />
            </Routes>
          </Suspense>
          {location.pathname !== '/' && <Footer />}
        </motion.main>
      </AnimatePresence>
    </>
  )
}
