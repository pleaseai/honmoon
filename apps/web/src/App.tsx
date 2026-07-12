import { useRef } from 'react'
import { useReveal } from './hooks/useReveal'
import { Barrier } from './sections/Barrier'
import { Cta } from './sections/Cta'
import { Footer } from './sections/Footer'
import { Hero } from './sections/Hero'
import { HowItWorks } from './sections/HowItWorks'
import { Membrane } from './sections/Membrane'
import { Modes } from './sections/Modes'
import { OpenCore } from './sections/OpenCore'
import { Policy } from './sections/Policy'
import { Threat } from './sections/Threat'
import { TopNav } from './sections/TopNav'

export default function App() {
  const landingRef = useRef<HTMLDivElement>(null)
  useReveal(landingRef)

  return (
    <>
      <a className="skip-link" href="#content">Skip to content</a>
      {/* 우주 — 페이지 전체를 덮는 고정 배경(경계 없는 연속 별필드 + 결계 문) */}
      <Membrane />

      <TopNav />

      <main id="content" tabIndex={-1} style={{ outline: 'none' }}>
        <Hero />
        <Barrier />

        <div className="landing" ref={landingRef}>
          <Threat />
          <HowItWorks />
          <Policy />
          <Modes />
          <OpenCore />
          <Cta />
        </div>
      </main>

      <Footer />
    </>
  )
}
