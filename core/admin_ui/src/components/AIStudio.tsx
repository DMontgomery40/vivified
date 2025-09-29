import { useEffect, useState } from 'react';
import { Box, Paper, Typography, Stack, Button, TextField, Chip, FormGroup, FormControlLabel, Checkbox, Alert } from '@mui/material';
import AdminAPIClient from '../api/client';

type Props = { client: AdminAPIClient; readOnly?: boolean };

export default function AIStudio({ client, readOnly = false }: Props) {
  const [status, setStatus] = useState<{ docs_indexed: number; last_trained_ts?: number | null; backend?: string } | null>(null);
  const [query, setQuery] = useState('Vivified');
  const [results, setResults] = useState<Array<{ id: string; title: string; path?: string }>>([]);
  const [prompt, setPrompt] = useState('Summarize Vivified core.');
  const [agentRes, setAgentRes] = useState<string>('');
  const [toolsUsed, setToolsUsed] = useState<Array<{ name?: string; args?: any; content?: string }>>([]);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');
  const [sources, setSources] = useState<{ docs: boolean; plans: boolean; code: boolean; all: boolean }>({ docs: true, plans: true, code: true, all: false });
  const [cfg, setCfg] = useState<{ provider?: string; model?: string; base_url?: string; api_key_present: boolean } | null>(null);
  const [cfgEditing, setCfgEditing] = useState<{ provider?: string; model?: string; base_url?: string; openai_api_key?: string }>({});
  const [cfgMsg, setCfgMsg] = useState<string>('');
  const [rulesRequired, setRulesRequired] = useState<string>('{}');
  const [rulesClass, setRulesClass] = useState<string>('{}');
  const [rulesMsg, setRulesMsg] = useState<string>('');

  const refresh = async () => {
    try {
      const st = await client.aiStatus();
      setStatus(st);
    } catch { /* ignore */ }
  };

  useEffect(() => { (async () => {
    await refresh();
    try { const c = await client.getAiConfig(); setCfg(c?.llm || { api_key_present: false }); } catch {}
    try {
      const rr = await client.getAiRagRules();
      setRulesRequired(JSON.stringify(rr.required_traits || {}, null, 2));
      setRulesClass(JSON.stringify(rr.classification || {}, null, 2));
    } catch {}
  })(); }, []);

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
      setToolsUsed(Array.isArray((r as any)?.tools_used) ? (r as any).tools_used : []);
    } catch (e: any) { setAgentRes(e?.message || 'Agent failed'); }
    finally { setBusy(false); }
  };

  const saveConfig = async () => {
    try {
      setBusy(true);
      setCfgMsg('');
      const payload: any = {};
      if (cfgEditing.provider !== undefined) payload.provider = cfgEditing.provider;
      if (cfgEditing.model !== undefined) payload.model = cfgEditing.model;
      if (cfgEditing.base_url !== undefined) payload.base_url = cfgEditing.base_url;
      if (cfgEditing.openai_api_key) payload.openai_api_key = cfgEditing.openai_api_key;
      const res = await client.setAiConfig(payload);
      setCfgMsg(`Saved (${(res.changed || []).join(', ') || 'no changes'})`);
      const c = await client.getAiConfig();
      setCfg(c?.llm || { api_key_present: false });
      setCfgEditing({});
    } catch (e: any) {
      setCfgMsg(e?.message || 'Failed to save');
    } finally {
      setBusy(false);
    }
  };

  const saveRules = async () => {
    try {
      setBusy(true);
      setRulesMsg('');
      const required = JSON.parse(rulesRequired || '{}');
      const classification = JSON.parse(rulesClass || '{}');
      const res = await client.setAiRagRules({ required_traits: required, classification });
      setRulesMsg(res.ok ? 'Saved' : 'Failed');
    } catch (e: any) {
      setRulesMsg(e?.message || 'Invalid JSON or failed to save');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>AI Studio</Typography>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Train an internal RAG index from local docs and run simple queries. Agent run uses internal context and optional tool-calling.
      </Typography>

      <Paper sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Typography variant="h6" gutterBottom>LLM Configuration</Typography>
        {cfg?.api_key_present ? (
          <Chip label="API key present" color="success" size="small" sx={{ mb: 1 }} />
        ) : (
          <Alert severity="warning" sx={{ mb: 1 }}>No API key set. The agent will fall back to a local stub.</Alert>
        )}
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} sx={{ mb: 1 }}>
          <TextField label="Provider" size="small" sx={{ flex: 1 }}
            value={cfgEditing.provider ?? cfg?.provider ?? 'openai'}
            onChange={e => setCfgEditing(v => ({ ...v, provider: e.target.value }))}
            disabled={busy || readOnly}
          />
          <TextField label="Model" size="small" sx={{ flex: 1 }}
            value={cfgEditing.model ?? cfg?.model ?? 'gpt-5-mini'}
            onChange={e => setCfgEditing(v => ({ ...v, model: e.target.value }))}
            disabled={busy || readOnly}
          />
          <TextField label="Base URL" size="small" sx={{ flex: 1 }}
            placeholder="https://api.openai.com"
            value={cfgEditing.base_url ?? cfg?.base_url ?? ''}
            onChange={e => setCfgEditing(v => ({ ...v, base_url: e.target.value }))}
            disabled={busy || readOnly}
          />
        </Stack>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} alignItems={{ xs: 'stretch', sm: 'center' }}>
          <TextField fullWidth type="password" label="OpenAI API Key" placeholder="sk-..."
            value={cfgEditing.openai_api_key ?? ''}
            onChange={(e) => setCfgEditing(v => ({ ...v, openai_api_key: e.target.value }))}
            disabled={busy || readOnly}
          />
          <Button variant="contained" onClick={saveConfig} disabled={busy || readOnly} sx={{ borderRadius: 2 }}>Save</Button>
          {cfgMsg && <Chip label={cfgMsg} color="info" variant="outlined" />}
        </Stack>
      </Paper>

      {/* Ingestion Rules */}
      <Paper sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Typography variant="h6" gutterBottom>Ingestion Rules (Traits & Classification)</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Map path globs to required traits and classification labels. Queries only return docs whose required traits
          are a subset of the current user's traits.
        </Typography>
        <Stack spacing={2} direction={{ xs: 'column', sm: 'row' }}>
          <TextField label="required_traits (JSON)" value={rulesRequired} onChange={e => setRulesRequired(e.target.value)}
            multiline minRows={6} fullWidth size="small" />
          <TextField label="classification (JSON)" value={rulesClass} onChange={e => setRulesClass(e.target.value)}
            multiline minRows={6} fullWidth size="small" />
        </Stack>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} sx={{ mt: 1 }}>
          <Button variant="outlined" onClick={saveRules} disabled={busy || readOnly} sx={{ borderRadius: 2 }}>Save Rules</Button>
          {rulesMsg && <Chip label={rulesMsg} color="info" variant="outlined" />}
        </Stack>
      </Paper>

      <Paper sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ xs: 'stretch', sm: 'center' }}>
          <Chip label={`Docs indexed: ${status?.docs_indexed ?? 0}`} />
          {status?.last_trained_ts ? <Chip variant="outlined" label={`Last trained: ${new Date((status.last_trained_ts || 0) * 1000).toLocaleString()}`} /> : null}
          {status?.backend ? <Chip color="secondary" variant="outlined" label={`Backend: ${status.backend}`} /> : null}
          <Button variant="contained" onClick={train} disabled={busy || readOnly} sx={{ borderRadius: 2 }}>
            {busy ? 'Training…' : 'Train from Docs'}
          </Button>
          <Button variant="outlined" onClick={async () => { setBusy(true); setNote(''); try { const res = await client.aiTrain(['.']); setNote(`Indexed ${res.indexed} documents (total ${res.total}).`); await refresh(); } catch (e: any) { setNote(e?.message || 'Training failed'); } finally { setBusy(false); } }} disabled={busy || readOnly} sx={{ borderRadius: 2 }}>
            Train Everything (.)
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

      {toolsUsed && toolsUsed.length > 0 && (
        <Paper sx={{ p: 2, borderRadius: 2, mt: 2 }}>
          <Typography variant="h6" gutterBottom>Tools Used</Typography>
          {toolsUsed.map((t, idx) => (
            <Box key={idx} sx={{ mb: 1 }}>
              <Typography variant="body2"><b>{t.name || 'tool'}</b> {t.args ? `(${JSON.stringify(t.args)})` : ''}</Typography>
              {t.content && <Typography variant="caption" sx={{ whiteSpace: 'pre-wrap' }} color="text.secondary">{typeof t.content === 'string' ? t.content.slice(0, 400) : JSON.stringify(t.content).slice(0, 400)}</Typography>}
            </Box>
          ))}
        </Paper>
      )}

      <Paper sx={{ p: 2, borderRadius: 2 }}>
        <Typography variant="caption" color="text.secondary">Values are stored in ConfigService; API keys are encrypted when configured.</Typography>
      </Paper>
    </Box>
  );
}
