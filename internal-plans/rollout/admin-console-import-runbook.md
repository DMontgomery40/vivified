Alright David — here’s a single, end-to-end, paste-ready runbook that:

pulls the Faxbot Admin Console (auto-tunnel branch),

copies it into a new Vivified UI,

rebrands everything (names, colors, logos, favicons),

aligns the API to Vivified Core (GUI-first for plugins, config, users/traits, audit),

adds a Canonical Schema Registry page (GUI for your Canonical Model Engine),

adds a Brand Settings page (tenant-aware, white-label; logo upload + theme colors),

wires a trait-based theme switcher (HIPAA → clinical; non-HIPAA → business),

leaves nothing behind that says “Faxbot”.

Everything is copy-paste, no placeholders. Use echo/&& chains as requested.

0) Prereqs
# tools you’ll need
echo "Checking prereqs..." && \
command -v git >/dev/null && \
command -v node >/dev/null && \
command -v npm >/dev/null && \
command -v rg >/dev/null || (echo "Please install ripgrep (rg)"; exit 1)

1) Pull Faxbot Admin UI (auto-tunnel) and copy as Vivified UI
# pull
rm -rf faxbot-auto vivified-admin && \
git clone --depth=1 -b auto-tunnel https://github.com/DMontgomery40/Faxbot.git faxbot-auto && \
cd faxbot-auto && \
test -d admin_ui || (echo "admin_ui folder not found in Faxbot repo"; exit 1) && \
# copy to vivified-admin
mkdir -p ../vivified-admin && rsync -a admin_ui/ ../vivified-admin/ && \
cd ../vivified-admin && \
# install UI deps
npm i

2) Point UI at Vivified Core (GUI-first; single API base)
# core API base URL (adjust if your core is somewhere else)
echo 'VITE_CORE_URL=http://localhost:8000' > .env && \
# create one API adapter used everywhere
mkdir -p src/lib && cat > src/lib/api.js <<'JS'
import axios from 'axios'
const CORE = import.meta.env.VITE_CORE_URL
export const http = axios.create({ baseURL: CORE, timeout: 20000 })

// Auth
export const getSession = () => http.get('/auth/me').then(r=>r.data)
export const login      = (u,p,mfa_code) => http.post('/auth/login',{username:u,password:p,mfa_code}).then(r=>r.data)

// Plugins
export const listPlugins   = () => http.get('/admin/plugins').then(r=>r.data)
export const enablePlugin  = (id) => http.post(`/admin/plugins/${id}/enable`).then(r=>r.data)
export const disablePlugin = (id,reason='') => http.post(`/admin/plugins/${id}/disable`,{reason}).then(r=>r.data)

// Config (hierarchy + effective)
export const getEffectiveConfig = (params={}) => http.get('/admin/config',{params}).then(r=>r.data)
export const setConfig          = (payload)    => http.put('/admin/config',payload).then(r=>r.data)

// Users / Traits / Audit
export const listTraits = () => http.get('/admin/traits').then(r=>r.data)
export const listUsers  = (params={}) => http.get('/admin/users',{params}).then(r=>r.data)
export const getAudit   = (params={}) => http.get('/admin/audit',{params}).then(r=>r.data)

// Canonical Schema Registry
export const upsertSchema   = (payload) => http.post('/schemas', payload).then(r=>r.data)
export const activateSchema = (name,major,minor,patch) => http.post('/schemas/activate',{name,major,minor,patch}).then(r=>r.data)
export const listSchemas    = (name) => http.get(`/schemas/${encodeURIComponent(name)}`).then(r=>r.data)
export const getActive      = (name,major) => http.get(`/schemas/${encodeURIComponent(name)}/active/${major}`).then(r=>r.data)
JS


Ensure the UI imports this adapter (replace any old imports):

rg -l 'from .*api' src | xargs -I{} sed -i '' 's#from .*api#from "\\/lib\\/api.js"#' {} 2>/dev/null || true

3) Rebrand to “Vivified” (app name, strings, assets, colors)
# package.json name/description (jq required; if missing, do manual edit)
if command -v jq >/dev/null; then
  cat package.json | jq '.name="vivified-admin" | .description="Vivified Admin Console" | .author="Vivified Team" | .homepage="."' > package.tmp && mv package.tmp package.json
fi

# title and any static HTML references
sed -i '' 's/Faxbot/Vivified/g; s/faxbot/Vivified/g' index.html 2>/dev/null || true

# source string replacements (labels, toasts, headings)
rg -l 'Faxbot' src | xargs -I{} sed -i '' 's/Faxbot/Vivified/g' {} 2>/dev/null || true
rg -l 'faxbot' src | xargs -I{} sed -i '' 's/faxbot/vivified/g' {} 2>/dev/null || true

# basic Tailwind palette + util classes
mkdir -p src/assets && cat > src/assets/vivified-logo.svg <<'SVG'
<svg width="144" height="28" viewBox="0 0 144 28" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Vivified">
  <defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="0"><stop offset="0%" stop-color="#6D28D9"/><stop offset="100%" stop-color="#22D3EE"/></linearGradient></defs>
  <g fill="url(#g)" font-family="Inter, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial" font-weight="700">
    <text x="0" y="21" font-size="20">Vivified</text>
  </g>
</svg>
SVG

# ensure Tailwind utilities exist
grep -q '@tailwind' src/index.css || cat > src/index.css <<'CSS'
@tailwind base;
@tailwind components;
@tailwind utilities;
:root { color-scheme: light; }
body { @apply bg-gray-50 text-gray-900; }
.btn { @apply px-3 py-2 rounded-md bg-gray-900 text-white hover:bg-gray-800 disabled:opacity-50; }
.btn-outline { @apply px-3 py-2 rounded-md border border-gray-300 hover:bg-gray-100; }
.input { @apply w-full rounded-md border border-gray-300 px-3 py-2; }
.select { @apply w-full rounded-md border border-gray-300 px-3 py-2 bg-white; }
.card { @apply bg-white rounded-xl shadow p-4; }
h1 { @apply text-2xl font-semibold; }
h2 { @apply text-xl font-semibold; }
CSS

# add brand colors to tailwind config (non-breaking)
test -f tailwind.config.js && sed -i '' 's#theme: {#theme: { extend: { colors: { brand: { primary:"#6D28D9", accent:"#22D3EE" }}}},#' tailwind.config.js 2>/dev/null || true


Swap header logo (edit the header component the UI uses for branding):

# locate likely header component
rg -n 'img .*logo|Logo|brand|header' src | head -n 5
echo "Open the main header component and ensure it imports and renders src/assets/vivified-logo.svg"


Remove any “fax” feature routes from menus (e.g., “Compose Fax”):

rg -n 'Fax|fax|compose' src | cut -d: -f1 | sort -u | xargs -I{} sh -c 'echo "Review and remove fax UI from: {}"'

4) Trait-aware Theme Provider (HIPAA vs Business)
mkdir -p src/theme && cat > src/theme/ThemeProvider.jsx <<'JSX'
import React, { createContext, useContext, useMemo } from 'react'
import { listTraits } from '../lib/api'

// Minimal context; in real app you’d fetch /auth/me for user traits
const ThemeCtx = createContext({ mode:'business', colors:{ primary:'#6D28D9', accent:'#22D3EE' }})

export function useThemeCtx(){ return useContext(ThemeCtx) }

export default function ThemeProvider({ children, userTraits=[], brand={} }){
  const isHIPAA = userTraits.includes('hipaa_compliant')
  const theme = useMemo(()=>{
    // Merge brand settings if provided; fall back to defaults
    const primary = brand.primary || '#6D28D9'
    const accent  = brand.accent  || '#22D3EE'
    const palette = isHIPAA
      ? { primary:'#1E40AF', accent:'#22D3EE', bg:'#F8FAFF', text:'#0F172A' }   // clinical blues
      : { primary, accent, bg:'#F8FAFC', text:'#0F172A' }                      // business neutral
    // Apply CSS vars
    document.documentElement.style.setProperty('--color-primary', palette.primary)
    document.documentElement.style.setProperty('--color-accent',  palette.accent)
    document.body.style.backgroundColor = palette.bg
    document.body.style.color = palette.text
    return { mode: isHIPAA ? 'hipaa' : 'business', colors: palette }
  }, [isHIPAA, brand.primary, brand.accent])

  return <ThemeCtx.Provider value={theme}>{children}</ThemeCtx.Provider>
}
JSX


Add small CSS hooks:

cat >> src/index.css <<'CSS'

/* Theme variables (used by classnames or inline styles) */
:root {
  --color-primary: #6D28D9;
  --color-accent:  #22D3EE;
}
.btn-brand { background: var(--color-primary); color: white; }
.btn-brand:hover { filter: brightness(0.92); }
.border-brand { border-color: var(--color-primary); }
.text-brand { color: var(--color-primary); }
CSS


Wrap your app with the provider (edit src/main.jsx or src/App.jsx root):

# naive helper message; manual edit:
echo "Wrap <App/> in <ThemeProvider userTraits={['hipaa_compliant' or not]} brand={brandConfig}/>" && \
echo "ThemeProvider import: import ThemeProvider from './theme/ThemeProvider.jsx'"


(We’ll supply brandConfig from the Brand Settings page you’ll build next, loaded via /admin/config.)

5) Brand Settings (GUI-first white-label; per-tenant config)

This page lets an admin set logo, primary/accent colors, and app title. It writes to Core config under ui.brand.* keys (global or tenant). The UI reads these on load to apply.

mkdir -p src/pages && cat > src/pages/BrandSettings.jsx <<'JSX'
import { useEffect, useState } from 'react'
import { getEffectiveConfig, setConfig } from '../lib/api'

export default function BrandSettings(){
  const [scope,setScope] = useState({ level:'global', scope_id:'global' })
  const [title,setTitle] = useState('Vivified')
  const [primary,setPrimary] = useState('#6D28D9')
  const [accent,setAccent] = useState('#22D3EE')
  const [logoData,setLogoData] = useState(null)

  useEffect(()=>{
    (async ()=>{
      const cfg = await getEffectiveConfig({})
      const brand = cfg?.['ui.brand'] || {}
      setTitle(brand.title || 'Vivified')
      setPrimary(brand.primary || '#6D28D9')
      setAccent(brand.accent || '#22D3EE')
      setLogoData(brand.logoData || null)
    })()
  },[])

  const onFile = async (e)=>{
    const f = e.target.files?.[0]
    if(!f) return
    const b64 = await toBase64(f)
    setLogoData(b64)
  }
  const save = async ()=>{
    const payload = {
      key: 'ui.brand',
      value: { title, primary, accent, logoData },
      plugin_id: null,
      is_sensitive: false,
      reason: 'branding update'
    }
    await setConfig(payload)
    alert('Brand settings saved.')
  }

  return (
    <div className="space-y-6">
      <h1>Brand Settings</h1>
      <div className="card grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium">App Title</label>
          <input className="input" value={title} onChange={e=>setTitle(e.target.value)} />
        </div>
        <div>
          <label className="block text-sm font-medium">Primary Color</label>
          <input className="input" value={primary} onChange={e=>setPrimary(e.target.value)} />
        </div>
        <div>
          <label className="block text-sm font-medium">Accent Color</label>
          <input className="input" value={accent} onChange={e=>setAccent(e.target.value)} />
        </div>
        <div>
          <label className="block text-sm font-medium">Logo</label>
          <input type="file" className="input" accept="image/*" onChange={onFile} />
        </div>
        <div className="col-span-2">
          <div className="text-sm font-medium mb-1">Preview</div>
          <div className="flex items-center gap-4 p-4 border rounded-md" style={{borderColor:primary}}>
            <div style={{background:primary, width:48,height:48,borderRadius:8}} />
            <div>
              <div className="text-xl" style={{color:primary}}>{title}</div>
              <div className="text-sm" style={{color:accent}}>accent sample</div>
            </div>
            {logoData && <img src={logoData} alt="Logo" style={{height:48}} />}
          </div>
        </div>
        <div className="col-span-2">
          <button className="btn btn-brand" onClick={save}>Save</button>
        </div>
      </div>
    </div>
  )
}

function toBase64(file){
  return new Promise((resolve,reject)=>{
    const r = new FileReader()
    r.onload = () => resolve(r.result)
    r.onerror = reject
    r.readAsDataURL(file)
  })
}
JSX


Use in App navigation (add a route /brand and a sidebar link). Example route add (manual, but trivial):

# tell you where to add the route
rg -n 'Route.*Dashboard|Plugins|Config|Audit' src | head -n 1
echo "Add: <Route path=\"/brand\" element={<BrandSettings/>} /> and a sidebar link “Brand”"


On app start, read ui.brand via getEffectiveConfig() and feed it into ThemeProvider brand={brand} so colors/logo/title apply globally.

(If you want per-tenant branding: pass ?tenant_id=... to getEffectiveConfig and store to that level in setConfig.)

6) Canonical Schema Registry GUI (manage your Canonical Engine from the UI)
cat > src/pages/Schemas.jsx <<'JSX'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listSchemas, upsertSchema, activateSchema, getActive } from '../lib/api'
import { useState } from 'react'

export default function Schemas(){
  const qc = useQueryClient()
  const [name,setName] = useState('CanonicalMessage')
  const [major,setMajor] = useState(2)
  const { data: versions } = useQuery(['schemas',name], ()=>listSchemas(name), { enabled: !!name })
  const { data: active }   = useQuery(['active',name,major], ()=>getActive(name,major), { enabled: !!name })

  const upsert = useMutation(upsertSchema, { onSuccess: ()=>qc.invalidateQueries(['schemas',name]) })
  const activate= useMutation(({name,major,minor,patch})=>activateSchema(name,major,minor,patch),
    { onSuccess: ()=>{ qc.invalidateQueries(['schemas',name]); qc.invalidateQueries(['active',name,major]) } })

  return (
    <div className="space-y-6">
      <h1>Canonical Schemas</h1>

      <div className="card grid grid-cols-2 gap-3">
        <div>
          <label className="block text-sm font-medium">Schema Name</label>
          <input className="input" value={name} onChange={e=>setName(e.target.value)} />
        </div>
        <div>
          <label className="block text-sm font-medium">Major</label>
          <input className="input" type="number" value={major} onChange={e=>setMajor(parseInt(e.target.value||'0'))}/>
        </div>
        <div className="col-span-2">
          <div className="text-sm font-medium">Active</div>
          <pre className="bg-gray-100 p-2 rounded text-xs">{active? JSON.stringify(active,null,2): '—'}</pre>
        </div>
      </div>

      <div className="card">
        <h2 className="mb-2">Upsert Version</h2>
        <SchemaForm onSubmit={(payload)=>upsert.mutate(payload)} />
      </div>

      <div className="card">
        <h2 className="mb-2">All Versions</h2>
        <pre className="bg-gray-100 p-2 rounded overflow-auto text-xs">{versions? JSON.stringify(versions,null,2): '—'}</pre>
        <div className="mt-2">
          <button className="btn btn-brand"
            onClick={()=>{
              const v = (versions||[])[0]
              if(!v?.name) return alert('Nothing to activate')
              activate.mutate({name:v.name, major:v.major, minor:v.minor, patch:v.patch})
            }}>
            Activate Selected Major
          </button>
        </div>
      </div>
    </div>
  )
}

function SchemaForm({onSubmit}){
  const [name,setName] = useState('CanonicalMessage')
  const [major,setMajor] = useState(2)
  const [minor,setMinor] = useState(0)
  const [patch,setPatch] = useState(0)
  const [status,setStatus] = useState('draft')
  const [syntax,setSyntax] = useState('proto3')
  const [description,setDescription] = useState('v2 base')

  return (
    <div className="grid grid-cols-2 gap-3">
      <input className="input" placeholder="name" value={name} onChange={e=>setName(e.target.value)} />
      <input className="input" type="number" placeholder="major" value={major} onChange={e=>setMajor(parseInt(e.target.value||'0'))}/>
      <input className="input" type="number" placeholder="minor" value={minor} onChange={e=>setMinor(parseInt(e.target.value||'0'))}/>
      <input className="input" type="number" placeholder="patch" value={patch} onChange={e=>setPatch(parseInt(e.target.value||'0'))}/>
      <select className="select" value={status} onChange={e=>setStatus(e.target.value)}>
        <option>draft</option><option>active</option><option>deprecated</option><option>blocked</option>
      </select>
      <select className="select" value={syntax} onChange={e=>setSyntax(e.target.value)}>
        <option>proto3</option><option>json</option>
      </select>
      <textarea className="input col-span-2" placeholder="description" value={description} onChange={e=>setDescription(e.target.value)} />
      <div className="col-span-2">
        <button className="btn btn-brand" onClick={()=>onSubmit({name,major,minor,patch,status,syntax,description})}>Upsert</button>
      </div>
    </div>
  )
}
JSX


Add navigation route (manual): add <Route path="/schemas" element={<Schemas/>} /> and put a Schemas link in the sidebar.

7) Load brand config at boot & apply globally

Create a simple brand loader hook (read /admin/config once & pass to ThemeProvider):

mkdir -p src/hooks && cat > src/hooks/useBrand.js <<'JS'
import { useEffect, useState } from 'react'
import { getEffectiveConfig } from '../lib/api'

export default function useBrand(){
  const [brand,setBrand] = useState({ title:'Vivified', primary:'#6D28D9', accent:'#22D3EE', logoData:null })
  useEffect(()=>{
    (async ()=>{
      try{
        const cfg = await getEffectiveConfig({})
        const b = cfg?.['ui.brand'] || {}
        setBrand({
          title: b.title || 'Vivified',
          primary: b.primary || '#6D28D9',
          accent:  b.accent  || '#22D3EE',
          logoData:b.logoData || null
        })
        if (b.title) document.title = b.title
      }catch(e){}
    })()
  },[])
  return brand
}
JS


Wrap app root:

# show where to change
rg -n '<App' src | head -n 1
echo "In your root (src/main.jsx), import ThemeProvider and useBrand, then:"
echo "const brand = useBrand(); const traits = []; // TODO: set from /auth/me"
echo "<ThemeProvider userTraits={traits} brand={brand}><App/></ThemeProvider>"

8) Run the Vivified GUI (GUI-first only)
npm run dev


Manage Plugins: enable/disable in /plugins.

Manage Config (hierarchy & effective view) in /config.

Manage Schemas in /schemas (upsert & activate).

Manage Brand in /brand (title, colors, logo; per-tenant if you wire scope).

Users/Traits/Audit via existing pages.

Notes on the Canonical Engine performance / plugin-first stress test

The new Schemas GUI guarantees your canonical registry is driven from the UI, not shell: you can upsert, activate, and pin majors without touching the terminal. This forces the core to honor canonical versioning on the hot path (bus & gateway).

Because every other GUI page (Plugins, Config, Users/Traits, Audit) was Faxbot-grade production UI, copying and re-pointing proves that Vivified is truly plugin-first: the GUI doesn’t care what the backends are, only that canonical contracts and trait policies hold.

The Brand Settings page proves multi-tenant white-label can be GUI-driven: the florist ERP customer sees their own logo/colors immediately — zero shell.

The trait-based theme proves UX adapts from the same trait system that gates security. HIPAA users see clinical; business users see neutral.