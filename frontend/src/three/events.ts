import { events as defaultEvents, type RootState } from '@react-three/fiber'

type Store = Parameters<typeof defaultEvents>[0]

/**
 * Pointer events computed from clientX/Y and the canvas rect instead of
 * offsetX/Y, so picking stays correct under CSS zoom/transform scaling.
 */
export function rectEvents(store: Store) {
  return {
    ...defaultEvents(store),
    compute(event: { clientX: number; clientY: number }, state: RootState) {
      const r = state.gl.domElement.getBoundingClientRect()
      state.pointer.set(((event.clientX - r.left) / r.width) * 2 - 1, -((event.clientY - r.top) / r.height) * 2 + 1)
      state.raycaster.setFromCamera(state.pointer, state.camera)
    },
  }
}
