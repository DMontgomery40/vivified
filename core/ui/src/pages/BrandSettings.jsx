import React, { useEffect, useState } from 'react'
import { getEffectiveConfig, setConfig } from '../lib/api.js'

export default function BrandSettings(){
  const [title,setTitle] = useState('Vivified')
  const [primary,setPrimary] = useState('#6D28D9')
  const [accent,setAccent] = useState('#22D3EE')
  const [logoData,setLogoData] = useState(null)

  useEffect(()=>{
    (async ()=>{
      try{
        const cfg = await getEffectiveConfig({})
        const b = cfg?.['ui.brand'] || {}
        setTitle(b.title || 'Vivified')
        setPrimary(b.primary || '#6D28D9')
        setAccent(b.accent || '#22D3EE')
        setLogoData(b.logoData || null)
        if (b.title) document.title = b.title
      }catch(e){ /* noop */ }
    })()
  },[])

  const onFile = async (e)=>{
    const f = e.target.files?.[0]
    if(!f) return
    const reader = new FileReader()
    reader.onload = () => setLogoData(reader.result)
    reader.readAsDataURL(f)
  }

  const save = async ()=>{
    const payload = { key:'ui.brand', value:{ title, primary, accent, logoData }, is_sensitive:false, reason:'branding update' }
    await setConfig(payload)
    alert('Brand settings saved')
  }

  return (
    <div style={{padding:16}}>
      <h1>Brand Settings</h1>
      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:12, maxWidth:800}}>
        <label>App Title<input style={input} value={title} onChange={e=>setTitle(e.target.value)} /></label>
        <label>Primary<input style={input} value={primary} onChange={e=>setPrimary(e.target.value)} /></label>
        <label>Accent<input style={input} value={accent} onChange={e=>setAccent(e.target.value)} /></label>
        <label>Logo <input type="file" onChange={onFile} /></label>
        <div style={{gridColumn:'1 / -1'}}>
          <div style={{padding:12, border:'1px solid #e5e7eb', borderRadius:8}}>
            <div style={{display:'flex', alignItems:'center', gap:12}}>
              <div style={{width:48,height:48,background:primary,borderRadius:8}} />
              <div>
                <div style={{fontSize:18, fontWeight:600, color:primary}}>{title}</div>
                <div style={{fontSize:12, color:accent}}>accent sample</div>
              </div>
              {logoData && <img src={logoData} alt="Logo" style={{height:48}} />}
            </div>
          </div>
        </div>
        <div style={{gridColumn:'1 / -1'}}>
          <button onClick={save} style={btn}>Save</button>
        </div>
      </div>
    </div>
  )
}

const input = { width:'100%', padding:'8px 10px', border:'1px solid #e5e7eb', borderRadius:6, display:'block'}
const btn = { padding:'8px 12px', background:'#111827', color:'#fff', borderRadius:6, border:'none' }
