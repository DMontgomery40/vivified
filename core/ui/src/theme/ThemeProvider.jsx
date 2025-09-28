import React, { createContext, useContext, useMemo } from 'react'

const ThemeCtx = createContext({ mode:'business', colors:{ primary:'#6D28D9', accent:'#22D3EE' }})
export function useTheme(){ return useContext(ThemeCtx) }

export default function ThemeProvider({ children, userTraits=[], brand={} }){
  const isHIPAA = userTraits.includes('hipaa_compliant')
  const theme = useMemo(()=>{
    const primary = brand.primary || '#6D28D9'
    const accent  = brand.accent  || '#22D3EE'
    const palette = isHIPAA ? { primary:'#1E40AF', accent:'#22D3EE', bg:'#F8FAFF', text:'#0F172A' }
                             : { primary, accent, bg:'#F8FAFC', text:'#0F172A' }
    document.documentElement.style.setProperty('--color-primary', palette.primary)
    document.documentElement.style.setProperty('--color-accent',  palette.accent)
    document.body.style.backgroundColor = palette.bg
    document.body.style.color = palette.text
    return { mode: isHIPAA ? 'hipaa' : 'business', colors: palette }
  }, [isHIPAA, brand.primary, brand.accent])
  return <ThemeCtx.Provider value={theme}>{children}</ThemeCtx.Provider>
}

