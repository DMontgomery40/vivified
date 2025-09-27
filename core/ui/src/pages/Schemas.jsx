import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient, QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { listSchemas, upsertSchema, activateSchema, getActive } from '../lib/api.js'

const qc = new QueryClient()

export default function Schemas(){
  return (
    <QueryClientProvider client={qc}>
      <SchemasInner/>
    </QueryClientProvider>
  )
}

function SchemasInner(){
  const [name,setName] = useState('CanonicalMessage')
  const [major,setMajor] = useState(1)
  const { data: versions } = useQuery({ queryKey:['schemas',name], queryFn: ()=>listSchemas(name), enabled: !!name })
  const { data: active } = useQuery({ queryKey:['active',name,major], queryFn: ()=>getActive(name,major), enabled: !!name })
  const upsert = useMutation({ mutationFn: upsertSchema, onSuccess: ()=>qc.invalidateQueries({queryKey:['schemas',name]}) })
  const activate= useMutation({ mutationFn: ({name,major,minor,patch})=>activateSchema(name,major,minor,patch), onSuccess: ()=>{
    qc.invalidateQueries({queryKey:['schemas',name]}); qc.invalidateQueries({queryKey:['active',name,major]})
  }})

  return (
    <div style={{padding:16}}>
      <h1>Canonical Schemas</h1>
      <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:12, maxWidth:900}}>
        <label>Schema Name<input style={input} value={name} onChange={e=>setName(e.target.value)} /></label>
        <label>Major<input style={input} type="number" value={major} onChange={e=>setMajor(parseInt(e.target.value||'0'))}/></label>
        <div style={{gridColumn:'1 / -1'}}>
          <div style={panel}><div style={{fontWeight:600, marginBottom:8}}>Active</div>
            <pre style={pre}>{active? JSON.stringify(active,null,2): '—'}</pre>
          </div>
        </div>
      </div>

      <div style={panel}>
        <h2>Upsert Version</h2>
        <SchemaForm onSubmit={(payload)=>upsert.mutate(payload)} />
      </div>

      <div style={panel}>
        <h2>All Versions</h2>
        <pre style={pre}>{versions? JSON.stringify(versions,null,2): '—'}</pre>
        <div style={{marginTop:8}}>
          <button style={btn} onClick={()=>{
            const v = (versions||[])[0];
            if(!v?.name) return alert('Nothing to activate')
            activate.mutate({name:v.name, major:v.major, minor:v.minor, patch:v.patch})
          }}>Activate Selected Major</button>
        </div>
      </div>
    </div>
  )
}

function SchemaForm({onSubmit}){
  const [name,setName] = useState('CanonicalMessage')
  const [major,setMajor] = useState(1)
  const [minor,setMinor] = useState(0)
  const [patch,setPatch] = useState(0)
  const [status,setStatus] = useState('draft')
  const [syntax,setSyntax] = useState('proto3')
  const [description,setDescription] = useState('v1 base')
  return (
    <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:12}}>
      <input style={input} placeholder="name" value={name} onChange={e=>setName(e.target.value)} />
      <input style={input} type="number" placeholder="major" value={major} onChange={e=>setMajor(parseInt(e.target.value||'0'))}/>
      <input style={input} type="number" placeholder="minor" value={minor} onChange={e=>setMinor(parseInt(e.target.value||'0'))}/>
      <input style={input} type="number" placeholder="patch" value={patch} onChange={e=>setPatch(parseInt(e.target.value||'0'))}/>
      <select style={input} value={status} onChange={e=>setStatus(e.target.value)}>
        <option>draft</option><option>active</option><option>deprecated</option><option>blocked</option>
      </select>
      <select style={input} value={syntax} onChange={e=>setSyntax(e.target.value)}>
        <option>proto3</option><option>json</option>
      </select>
      <textarea style={{...input, gridColumn:'1 / -1'}} placeholder="description" value={description} onChange={e=>setDescription(e.target.value)} />
      <div style={{gridColumn:'1 / -1'}}>
        <button style={btn} onClick={()=>onSubmit({name,major,minor,patch,status,syntax,description})}>Upsert</button>
      </div>
    </div>
  )
}

const input = { width:'100%', padding:'8px 10px', border:'1px solid #e5e7eb', borderRadius:6, display:'block'}
const btn = { padding:'8px 12px', background:'#111827', color:'#fff', borderRadius:6, border:'none' }
const pre = { background:'#f3f4f6', padding:12, borderRadius:8, overflow:'auto', fontSize:12 }
const panel = { background:'#fff', border:'1px solid #e5e7eb', borderRadius:8, padding:12, marginTop:12 }

