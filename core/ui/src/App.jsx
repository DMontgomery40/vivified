import React from 'react'
import { Link, Routes, Route } from 'react-router-dom'

function Home() {
  return (
    <div style={{padding:16}}>
      <h1>Vivified Admin Console</h1>
      <p>Welcome. Use the nav to explore.</p>
      <ul>
        <li><Link to="/brand">Brand Settings</Link></li>
        <li><Link to="/schemas">Canonical Schemas</Link></li>
      </ul>
    </div>
  )
}

function Placeholder({ title }){
  return <div style={{padding:16}}><h1>{title}</h1><p>Coming soon.</p></div>
}

export default function App(){
  return (
    <Routes>
      <Route path="/" element={<Home/>} />
      <Route path="/brand" element={<Placeholder title="Brand Settings"/>} />
      <Route path="/schemas" element={<Placeholder title="Canonical Schemas"/>} />
    </Routes>
  )
}

