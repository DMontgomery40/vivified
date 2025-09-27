import React from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import App from './App.jsx'
import ThemeProvider from './theme/ThemeProvider.jsx'
import useBrand from './hooks/useBrand.js'

function Root(){
  const brand = useBrand()
  const traits = [] // TODO: fetch from /auth/me
  return (
    <ThemeProvider userTraits={traits} brand={brand}>
      <BrowserRouter>
        <Routes>
          <Route path="/*" element={<App/>} />
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  )
}

createRoot(document.getElementById('root')).render(<Root/>)
