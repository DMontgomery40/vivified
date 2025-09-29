import { useEffect, useState } from 'react';
import { Box, Paper, Typography, Stack, Button, TextField, Chip, FormGroup, FormControlLabel, Checkbox, Divider, Switch } from '@mui/material';
import AdminAPIClient from '../api/client';

type Props = { client: AdminAPIClient; readOnly?: boolean };

export default function AIStudio({ client, readOnly = false }: Props) {
  const [status, setStatus] = useState<{ docs_indexed: number; last_trained_ts?: number | null; backend?: string } | null>(null);
  const [query, setQuery] = useState('Vivified');
  const [results, setResults] = useState<Array<{ id: string; title: string; path?: string }>>([]);
  const [prompt, setPrompt] = useState('Summarize Vivified core.');
  const [agentRes, setAgentRes] = useState<string>('');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');
  const [sources, setSources] = useState<{ docs: boolean; plans: boolean; code: boolean; all: boolean }>({ docs: true, plans: true, code: true, all: false });
  const [conn, setConn] = useState<{ openai: { base_url?: string; default_model?: string; api_key?: string }; agent: { tool_calling: boolean } }>({ openai: {}, agent: { tool_calling: false } });

  const refresh = async () => {
    try {
      const st = await client.aiStatus();
      setStatus(st);
    } catch { /* ignore */ }
  };

  useEffect(() => { (async () => { await refresh(); try { const c = await client.aiConnectorsGet(); setConn({ openai: c.openai || {}, agent: c.agent || { tool_calling: false } }); } catch {} })(); }, []);

  const train = async () => {
    try {
      setBusy(true);
      setNote('');
      let selected: string[] = [];
      if (sources.all) {
        selected = ['.'];
      } else {
        if (sources.docs) selected.push('docs');
        if (sources.plans) selected.push('internal-plans');
        if (sources.code) selected.push('core', 'plugins', 'sdk', 'tools', 'tests', 'scripts', 'k8s');
        if (selected.length === 0) selected = ['docs'];
      }
      const res = await client.aiTrain(selected);
      setNote(`Indexed ${res.indexed} documents (total ${res.total}).`);
      await refresh();
    } catch (e: any) {
      setNote(e?.message || 'Training failed');
    } finally { setBusy(false); }
  };

  const runQuery = async () => {
    try {
      setBusy(true);
      const res = await client.aiQuery(query);
      setResults(res.items || []);
    } catch { setResults([]); }
    finally { setBusy(false); }
  };

  const runAgent = async () => {
    try {
      setBusy(true);
      setAgentRes('');
      const r = await client.aiAgentRun(prompt);
      setAgentRes(r?.result || '');
    } catch (e: any) { setAgentRes(e?.message || 'Agent failed'); }
    finally { setBusy(false); }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>AI Studio</Typography>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Train an internal RAG index from local docs and run simple queries. Agent run uses internal context and optional tool-calling.
      </Typography>

      <Paper sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ xs: 'stretch', sm: 'center' }}>
          <Chip label={`Docs indexed: ${status?.docs_indexed ?? 0}`} />
          {status?.last_trained_ts ? <Chip variant="outlined" label={`Last trained: ${new Date((status.last_trained_ts || 0) * 1000).toLocaleString()}`} /> : null}
          {status?.backend ? <Chip color="secondary" variant="outlined" label={`Backend: ${status.backend}`} /> : null}
          <Button variant="contained" onClick={train} disabled={busy || readOnly} sx={{ borderRadius: 2 }}>
            {busy ? 'Training…' : 'Train from Docs'}
          </Button>
          {note && <Chip color="info" variant="outlined" label={note} />}
        </Stack>
        <Box sx={{ mt: 2 }}>
          <FormGroup row>
            <FormControlLabel control={<Checkbox checked={sources.docs} onChange={(e) => setSources(s => ({ ...s, docs: e.target.checked }))} />} label="docs/" />
            <FormControlLabel control={<Checkbox checked={sources.plans} onChange={(e) => setSources(s => ({ ...s, plans: e.target.checked }))} />} label="internal-plans/" />
            <FormControlLabel control={<Checkbox checked={sources.code} onChange={(e) => setSources(s => ({ ...s, code: e.target.checked }))} />} label="Include code (core/plugins/sdk/tools/tests)" />
            <FormControlLabel control={<Checkbox checked={sources.all} onChange={(e) => setSources(s => ({ ...s, all: e.target.checked }))} />} label="Index entire repo (.)" />
          </FormGroup>
          <Typography variant="caption" color="text.secondary">Uses .ragignore and .gitignore to skip irrelevant files.</Typography>
        </Box>
      </Paper>

      <Paper sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Typography variant="h6" gutterBottom>Query RAG</Typography>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }}>
          <TextField fullWidth value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search terms" />
          <Button variant="outlined" onClick={runQuery} disabled={busy} sx={{ borderRadius: 2 }}>Search</Button>
        </Stack>
        <Box sx={{ mt: 2 }}>
          {(results || []).map((r) => (
            <Box key={r.id} sx={{ mb: 1 }}>
              <Typography variant="body2">{r.title}</Typography>
            </Box>
          ))}
        </Box>
      </Paper>

      <Paper sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Typography variant="h6" gutterBottom>Agent Run (stub)</Typography>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }}>
          <TextField fullWidth value={prompt} onChange={(e) => setPrompt(e.target.value)} placeholder="Ask a question" />
          <Button variant="outlined" onClick={runAgent} disabled={busy} sx={{ borderRadius: 2 }}>Run</Button>
        </Stack>
        {agentRes && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>{agentRes}</Typography>
          </Box>
        )}
      </Paper>

      <Paper sx={{ p: 2, borderRadius: 2 }}>
        <Typography variant="h6" gutterBottom>Connectors (OpenAI)</Typography>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} sx={{ mb: 1 }}>
          <TextField fullWidth label="Base URL" placeholder="https://api.openai.com" value={conn.openai.base_url || ''} onChange={(e) => setConn(c => ({ ...c, openai: { ...c.openai, base_url: e.target.value } }))} />
          <TextField fullWidth label="Default Model" placeholder="gpt-4o-mini" value={conn.openai.default_model || ''} onChange={(e) => setConn(c => ({ ...c, openai: { ...c.openai, default_model: e.target.value } }))} />
        </Stack>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} alignItems={{ xs: 'stretch', sm: 'center' }}>
          <TextField fullWidth type="password" label="API Key" placeholder="sk-..." value={conn.openai.api_key || ''} onChange={(e) => setConn(c => ({ ...c, openai: { ...c.openai, api_key: e.target.value } }))} />
          <FormControlLabel control={<Switch checked={!!conn.agent.tool_calling} onChange={(e) => setConn(c => ({ ...c, agent: { ...c.agent, tool_calling: e.target.checked } }))} />} label="Enable tool-calling" />
          <Button variant="outlined" disabled={busy || readOnly} onClick={async () => {
            setBusy(true);
            try {
              await client.aiConnectorsPut({ openai: conn.openai, agent: { tool_calling: !!conn.agent.tool_calling } });
            } catch { /* ignore */ } finally { setBusy(false); }
          }}>Save</Button>
        </Stack>
        <Divider sx={{ mt: 2, mb: 1 }} />
        <Typography variant="caption" color="text.secondary">Values are stored in ConfigService; API keys are encrypted when configured.</Typography>
      </Paper>
    </Box>
  );
}
