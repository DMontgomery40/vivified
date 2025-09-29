import { useState } from 'react';
import { Box, Paper, Typography, TextField, Button, Alert, Stack, MenuItem, Select, InputLabel, FormControl, Divider } from '@mui/material';
import HelpTip from './common/HelpTip';
import AdminAPIClient from '../api/client';

type Props = { client: AdminAPIClient };

const TEMPLATE = `{
  "user_to_canonical": {
    "attributes.department": "profile.dept"
  },
  "user_from_canonical": {},
  "message_to_canonical": {
    "content": "body.text"
  },
  "message_from_canonical": {},
  "event_to_canonical": {
    "payload": { "system": "vivified" }
  },
  "event_from_canonical": {}
}`;

export default function CanonicalTransforms({ client }: Props) {
  const [source, setSource] = useState('plugin.src');
  const [target, setTarget] = useState('plugin.dest');
  const [jsonText, setJsonText] = useState<string>(TEMPLATE);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [plugins, setPlugins] = useState<string[]>([]);
  const [entity, setEntity] = useState<'user'|'message'|'event'>('user');
  const [sample, setSample] = useState<string>('{}');
  const [preview, setPreview] = useState<any | null>(null);

  const load = async () => {
    try {
      setError(null); setNote(null);
      const res = await client.getCanonicalTransforms(source, target);
      setJsonText(JSON.stringify(res.mappings || {}, null, 2));
    } catch (e: any) {
      setError(e?.message || 'Failed to load transforms');
    }
  };

  const save = async () => {
    try {
      setError(null); setNote(null);
      let obj: any = {};
      try { obj = JSON.parse(jsonText); }
      catch { setError('Transforms must be valid JSON'); return; }
      await client.setCanonicalTransforms({ source, target, mappings: obj });
      setNote('Transforms saved');
    } catch (e: any) {
      setError(e?.message || 'Failed to save transforms');
    }
  };

  const reset = () => {
    setJsonText(TEMPLATE);
    setError(null); setNote(null);
  };

  const loadPlugins = async () => {
    try {
      const res = await client.listPlugins();
      const ids = (res.items || []).map((p:any) => p?.manifest?.id || p?.id).filter(Boolean);
      setPlugins(ids);
    } catch {}
  };

  const runPreview = async () => {
    try {
      setError(null); setNote(null); setPreview(null);
      let data: any = {};
      try { data = JSON.parse(sample || '{}'); } catch { setError('Sample must be valid JSON'); return; }
      let res: any = null;
      if (entity === 'user') {
        res = await client.normalizeUser({ user_data: data, source_plugin: source, target_plugin: target });
      } else if (entity === 'message') {
        const r = await fetch(`${(client as any).baseURL}/canonical/normalize/message`, {
          method: 'POST', headers: { 'Authorization': `Bearer ${(client as any).apiKey}`, 'X-API-Key': (client as any).apiKey, 'Content-Type': 'application/json' },
          body: JSON.stringify({ message_data: data, source_plugin: source, target_plugin: target })
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        res = await r.json();
      } else {
        const r = await fetch(`${(client as any).baseURL}/canonical/normalize/event`, {
          method: 'POST', headers: { 'Authorization': `Bearer ${(client as any).apiKey}`, 'X-API-Key': (client as any).apiKey, 'Content-Type': 'application/json' },
          body: JSON.stringify({ event_data: data, source_plugin: source, target_plugin: target })
        });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        res = await r.json();
      }
      setPreview(res);
    } catch (e:any) {
      setError(e?.message || 'Preview failed');
    }
  };

  const flattenKeys = (obj: any, prefix = ''): string[] => {
    let res: string[] = [];
    if (obj && typeof obj === 'object') {
      for (const k of Object.keys(obj)) {
        const key = prefix ? `${prefix}.${k}` : k;
        res.push(key);
        res = res.concat(flattenKeys(obj[k], key));
      }
    }
    return res;
  };

  if (plugins.length === 0) { loadPlugins(); }

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h5" fontWeight={600}>Canonical Transforms</Typography>
        <HelpTip topic="canonical" />
      </Box>
      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={()=>setError(null)}>{error}</Alert>}
      {note && <Alert severity="success" sx={{ mb: 2 }} onClose={()=>setNote(null)}>{note}</Alert>}

      <Paper variant="outlined" sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
          <FormControl size="small" fullWidth>
            <InputLabel>Source Plugin</InputLabel>
            <Select value={source} label="Source Plugin" onChange={e=>setSource(e.target.value as string)}>
              {(plugins.length ? plugins : [source]).map(id => (<MenuItem key={id} value={id}>{id}</MenuItem>))}
            </Select>
          </FormControl>
          <FormControl size="small" fullWidth>
            <InputLabel>Target Plugin</InputLabel>
            <Select value={target} label="Target Plugin" onChange={e=>setTarget(e.target.value as string)}>
              {(plugins.length ? plugins : [target]).map(id => (<MenuItem key={id} value={id}>{id}</MenuItem>))}
            </Select>
          </FormControl>
          <Button variant="outlined" onClick={load}>Load</Button>
          <Button variant="text" onClick={reset}>Reset Template</Button>
        </Stack>
      </Paper>

      <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
        <Typography variant="subtitle2" gutterBottom>Transforms JSON</Typography>
        <TextField
          value={jsonText}
          onChange={(e)=>setJsonText(e.target.value)}
          fullWidth
          multiline
          minRows={10}
          placeholder={TEMPLATE}
          InputProps={{ sx: { fontFamily: 'monospace', fontSize: '0.85rem' } }}
        />
        <Box mt={2}>
          <Button variant="contained" onClick={save}>Save</Button>
        </Box>
      </Paper>

      <Divider sx={{ my: 3 }} />
      <Typography variant="h6" gutterBottom>Preview</Typography>
      <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
        <Stack direction={{ xs: 'column', lg: 'row' }} spacing={2}>
          <Box flex={1}>
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 1 }}>
              <FormControl size="small" sx={{ minWidth: 200 }}>
                <InputLabel>Entity</InputLabel>
                <Select value={entity} label="Entity" onChange={e=>setEntity(e.target.value as any)}>
                  <MenuItem value="user">User</MenuItem>
                  <MenuItem value="message">Message</MenuItem>
                  <MenuItem value="event">Event</MenuItem>
                </Select>
              </FormControl>
              <Button variant="outlined" onClick={runPreview}>Run Preview</Button>
            </Stack>
            <TextField label="Sample JSON" value={sample} onChange={e=>setSample(e.target.value)} fullWidth multiline minRows={8} InputProps={{ sx: { fontFamily: 'monospace', fontSize: '0.85rem' } }} />
            <Box mt={1}>
              <Typography variant="caption" color="text.secondary">Suggested keys:</Typography>
              <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mt: 0.5 }}>
                {flattenKeys((()=>{ try { return JSON.parse(sample || '{}'); } catch { return {}; } })()).slice(0, 50).map(k => (
                  <Button size="small" key={k} onClick={()=>setJsonText(jsonText + `\n// ${k}`)} sx={{ textTransform: 'none' }}>{k}</Button>
                ))}
              </Box>
            </Box>
          </Box>
          <Box flex={1}>
            <Typography variant="subtitle2" gutterBottom>Result</Typography>
            <pre style={{ margin: 0, fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}>{preview ? JSON.stringify(preview, null, 2) : 'No preview yet.'}</pre>
          </Box>
        </Stack>
      </Paper>
    </Box>
  );
}
