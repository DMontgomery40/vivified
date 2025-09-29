import { useEffect, useState } from 'react';
import { Box, Paper, Typography, Stack, Button, Alert, TextField, Divider } from '@mui/material';
import AdminAPIClient from '../api/client';
import HelpTip from './common/HelpTip';

export default function ManifestEditor({ client }: { client: AdminAPIClient }) {
  const [schema, setSchema] = useState<any | null>(null);
  const [jsonText, setJsonText] = useState<string>(`{
  "id": "example.plugin",
  "name": "Example Plugin",
  "version": "1.0.0",
  "contracts": ["GeneralPlugin"],
  "traits": ["communication_plugin"],
  "allowed_domains": ["api.example.com"],
  "endpoints": { "ping": "/ping" },
  "security": { "authentication": "none" },
  "compliance": { "hipaa_controls": [], "audit_level": "standard" }
}`);
  const [error, setError] = useState<string>('');
  const [note, setNote] = useState<string>('');
  const [result, setResult] = useState<any | null>(null);
  const [caller, setCaller] = useState<string>('plugin.caller');
  const [target, setTarget] = useState<string>('');
  const [inboxOk, setInboxOk] = useState<boolean>(true);
  const [inboxSuggest, setInboxSuggest] = useState<string>('');

  useEffect(() => {
    const load = async () => {
      try { setSchema(await client.getPluginManifestSchema()); } catch {}
    };
    load();
  }, [client]);

  const validate = async () => {
    try {
      setError(''); setNote(''); setResult(null);
      const obj = JSON.parse(jsonText || '{}');
      if (!target && obj?.id) setTarget(String(obj.id));
      // Inline inbox endpoint validation
      const eps = (obj?.endpoints && typeof obj.endpoints === 'object') ? obj.endpoints : {};
      const possibleKeys = ['message.receive','messages.receive','inbox','message'];
      const foundKey = possibleKeys.find(k => typeof eps?.[k] === 'string' && eps[k]);
      const ok = Boolean(foundKey);
      setInboxOk(ok);
      if (!ok) {
        setInboxSuggest('message.receive');
      } else {
        setInboxSuggest(foundKey || '');
      }
      const res = await client.validatePluginManifest(obj);
      setResult(res);
      setNote(res.ok ? 'Manifest is valid' : 'Manifest has validation issues');
    } catch (e: any) {
      setError(e?.message || 'Validation failed');
    }
  };

  const applyAllowlist = async () => {
    try {
      setError(''); setNote('');
      const obj = JSON.parse(jsonText || '{}');
      if (!obj.id) { setError('Manifest must include id'); return; }
      if (!result?.suggestions?.allowlist) { setError('No allowlist suggestions to apply'); return; }
      await client.setGatewayAllowlist({ plugin_id: obj.id, allowlist: result.suggestions.allowlist });
      setNote(`Applied allowlist for ${obj.id}`);
    } catch (e: any) {
      setError(e?.message || 'Apply allowlist failed');
    }
  };

  const register = async () => {
    try {
      setError(''); setNote('');
      const obj = JSON.parse(jsonText || '{}');
      const res = await client.registerPlugin(obj);
      setNote(`Registered plugin ${res?.id || obj.id || ''}`);
    } catch (e: any) { setError(e?.message || 'Register failed'); }
  };

  const generateOperatorAllowlist = async () => {
    try {
      setError(''); setNote('');
      const obj = JSON.parse(jsonText || '{}');
      const ops: string[] = (result?.suggestions?.operations && Array.isArray(result.suggestions.operations))
        ? result.suggestions.operations
        : (obj?.endpoints ? Object.keys(obj.endpoints) : []);
      const tgt = target || obj.id;
      if (!caller || !tgt) { setError('Caller and Target plugin ids are required'); return; }
      await client.setOperatorAllowlist({ caller, target: tgt, operations: ops });
      setNote(`Operator allowlist set: ${caller} -> ${tgt} (${ops.length} ops)`);
    } catch (e: any) { setError(e?.message || 'Generate operator allowlist failed'); }
  };

  const insertInboxEndpoint = () => {
    try {
      setError(''); setNote('');
      const obj = JSON.parse(jsonText || '{}');
      const eps = (obj.endpoints && typeof obj.endpoints === 'object') ? obj.endpoints : {};
      const key = inboxSuggest || 'message.receive';
      if (!eps[key]) {
        eps[key] = '/inbox';
      }
      obj.endpoints = eps;
      setJsonText(JSON.stringify(obj, null, 2));
      setNote(`Added inbox endpoint: ${key} -> /inbox`);
      setInboxOk(true);
    } catch (e: any) {
      setError(e?.message || 'Failed to insert inbox endpoint');
    }
  };

  return (
    <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h5" fontWeight={600}>Manifest Editor</Typography>
        <HelpTip topic="manifest-editor" />
      </Box>
      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>}
      {note && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setNote('')}>{note}</Alert>}
      <Stack spacing={2}>
        <TextField label="Manifest JSON" value={jsonText} onChange={(e)=>setJsonText(e.target.value)} fullWidth multiline minRows={10} sx={{ '& .MuiOutlinedInput-root': { fontFamily: 'monospace' } }} />
        <Typography variant="caption" color="text.secondary">
          Paste your manifest here and click Validate. Fix required fields and enum values as reported. Use “Apply Suggested Allowlist” and “Generate Operator Allowlist” to seed policies before Registering.
        </Typography>
        {!inboxOk && (
          <Alert severity="warning" onClose={()=>setInboxOk(true)}>
            Recommended: Add an inbox endpoint key (e.g., <code>message.receive</code>) pointing to your handler path (e.g., <code>/inbox</code>).
            <Box sx={{ mt: 1 }}>
              <Button size="small" variant="outlined" onClick={insertInboxEndpoint}>Insert inbox endpoint</Button>
            </Box>
          </Alert>
        )}
        <Stack direction="row" spacing={1}>
          <Button variant="contained" onClick={validate}>Validate</Button>
          <Button variant="outlined" onClick={applyAllowlist}>Apply Suggested Allowlist</Button>
          <Button variant="text" onClick={register}>Register Plugin</Button>
        </Stack>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
          <TextField label="Caller Plugin (operator)" value={caller} onChange={(e)=>setCaller(e.target.value)} fullWidth />
          <TextField label="Target Plugin" value={target} onChange={(e)=>setTarget(e.target.value)} fullWidth placeholder="defaults to manifest.id" />
          <Button variant="outlined" onClick={generateOperatorAllowlist}>Generate Operator Allowlist</Button>
        </Stack>
        <Divider />
        {schema && (
          <Box>
            <Typography variant="subtitle2">Schema (summary)</Typography>
            <pre style={{ whiteSpace: 'pre-wrap', maxHeight: 220, overflow: 'auto' }}>{JSON.stringify(schema?.properties || {}, null, 2)}</pre>
          </Box>
        )}
        {result && (
          <Box>
            <Typography variant="subtitle2">Validation Result</Typography>
            <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(result, null, 2)}</pre>
          </Box>
        )}
      </Stack>
    </Paper>
  );
}
