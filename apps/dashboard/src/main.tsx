import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import { captureSession } from './session'
import './index.css'

// Before the first render: `/login` hands the session secret over in the URL
// fragment, and `App` routes on that same fragment (#188).
captureSession()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
