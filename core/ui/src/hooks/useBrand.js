import { useEffect, useState } from 'react'
import { getEffectiveConfig } from '../lib/api.js'

export default function useBrand(){
  const [brand,setBrand] = useState({ title:'Vivified', primary:'#6D28D9', accent:'#22D3EE', logoData:null })
  useEffect(()=>{
    (async ()=>{
      try{
        const cfg = await getEffectiveConfig({})
        const b = cfg?.['ui.brand'] || {}
        setBrand({ title: b.title || 'Vivified', primary: b.primary || '#6D28D9', accent: b.accent || '#22D3EE', logoData: b.logoData || null })
        if (b.title) document.title = b.title
      }catch(e){}
    })()
  },[])
  return brand
}

