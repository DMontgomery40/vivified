import React, { useEffect, useState, createContext, useContext } from 'react'
import { Link, Routes, Route, useNavigate } from 'react-router-dom'
import BrandSettings from './pages/BrandSettings.jsx'
import Schemas from './pages/Schemas.jsx'
import { devLogin, authMe } from './lib/api.js'

const UserCtx = createContext({ traits: [], ready:false })
const useUser = ()=> useContext(UserCtx)

function RequireTraits({ traits, children }){
  const { traits: userTraits, ready } = useUser()
  if (!ready) return null
  const allowed = userTraits.includes('admin') || traits.some(t=>userTraits.includes(t))
  if (!allowed) return <div style={{padding:16}}><h1>Not Authorized</h1></div>
  return children
}

function Home() {
  const { traits } = useUser()
  const canBrand = traits.includes('admin') || traits.includes('config_manager')
  const canSchemas = traits.includes('admin')
  return (
    <div style={{padding:16}}>
      <h1>Vivified Admin Console</h1>
      <p>Welcome. Use the nav to explore.</p>
      <ul>
        {canBrand && <li><Link to="/brand">Brand Settings</Link></li>}
        {canSchemas && <li><Link to="/schemas">Canonical Schemas</Link></li>}
      </ul>
    </div>
  )
}

function Placeholder({ title }){
  return <div style={{padding:16}}><h1>{title}</h1><p>Coming soon.</p></div>
}

export default function App(){
  const [user,setUser] = useState({ traits:[], ready:false })
  const navigate = useNavigate()
  useEffect(()=>{
    (async ()=>{
      try{
        const me = await authMe()
        setUser({ traits: me?.traits||[], ready:true })
      }catch(e){ setUser({ traits:[], ready:true }) }
    })()
  },[])

  const doDevLogin = async ()=>{
    try{
      const r = await devLogin()
      localStorage.setItem('vivi_token', r.token)
      const me = await authMe()
      setUser({ traits: me?.traits||[], ready:true })
      navigate('/')
    }catch(e){ alert('Login failed') }
  }

  return (
    <UserCtx.Provider value={user}>
      <div style={{padding:12, borderBottom:'1px solid #e5e7eb', display:'flex', justifyContent:'space-between', alignItems:'center'}}>
        <div><Link to="/">Home</Link></div>
        <div>
          {user?.traits?.length ? (
            <span style={{fontSize:12, color:'#6b7280'}}>traits: {user.traits.join(', ')}</span>
          ) : (
            <button onClick={doDevLogin} style={{padding:'6px 10px'}}>Dev Login</button>
          )}
        </div>
      </div>
      <Routes>
        <Route path="/" element={<Home/>} />
        <Route path="/brand" element={<RequireTraits traits={["config_manager"]}><BrandSettings/></RequireTraits>} />
        <Route path="/schemas" element={<RequireTraits traits={["admin"]}><Schemas/></RequireTraits>} />
      </Routes>
    </UserCtx.Provider>
  )
}
