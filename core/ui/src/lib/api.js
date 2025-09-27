import axios from 'axios'

const CORE = import.meta.env.VITE_CORE_URL || 'http://localhost:8000'
export const http = axios.create({ baseURL: CORE, timeout: 20000 })

export const getEffectiveConfig = (params={}) => http.get('/admin/config',{params}).then(r=>r.data)
export const setConfig = (payload) => http.put('/admin/config', payload).then(r=>r.data)
export const listSchemas = (name) => http.get(`/schemas/${encodeURIComponent(name)}`).then(r=>r.data)
export const upsertSchema = (payload) => http.post('/schemas', payload).then(r=>r.data)
export const activateSchema = (name,major,minor,patch) => http.post('/schemas/activate',{name,major,minor,patch}).then(r=>r.data)
export const getActive = (name,major) => http.get(`/schemas/${encodeURIComponent(name)}/active/${major}`).then(r=>r.data)

