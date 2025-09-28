import axios from 'axios'

const CORE = import.meta.env.VITE_CORE_URL || 'http://localhost:8000'
export const http = axios.create({ baseURL: CORE, timeout: 20000 })

// Attach Authorization token from localStorage if present
http.interceptors.request.use((config)=>{
  try{
    const t = localStorage.getItem('vivi_token')
    if (t) config.headers['Authorization'] = `Bearer ${t}`
  }catch(e){ /* noop */ }
  return config
})

export const getEffectiveConfig = (params={}) => http.get('/admin/config',{params}).then(r=>r.data)
export const setConfig = (payload) => http.put('/admin/config', payload).then(r=>r.data)
export const listSchemas = (name) => http.get(`/schemas/${encodeURIComponent(name)}`).then(r=>r.data)
export const upsertSchema = (payload) => http.post('/schemas', payload).then(r=>r.data)
export const activateSchema = (name,major,minor,patch) => http.post('/schemas/activate',{name,major,minor,patch}).then(r=>r.data)
export const getActive = (name,major) => http.get(`/schemas/${encodeURIComponent(name)}/active/${major}`).then(r=>r.data)
export const devLogin = () => http.post('/auth/dev-login', {enabled:true}).then(r=>r.data)
export const authMe = () => http.get('/auth/me').then(r=>r.data)
