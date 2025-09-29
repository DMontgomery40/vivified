import { useEffect, useState } from 'react';
import { Box, Paper, Typography, Stack, Button, TextField, Chip, FormGroup, FormControlLabel, Checkbox, Alert, Switch } from '@mui/material';
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
  const [embedModel, setEmbedModel] = useState<string>('');
  const [cfgEditing, setCfgEditing] = useState<{ provider?: string; model?: string; base_url?: string; embeddings_model?: string; openai_api_key?: string }>({});
  const [cfgMsg, setCfgMsg] = useState<string>('');
  const [rulesRequired, setRulesRequired] = useState<string>('{}');
  const [rulesClass, setRulesClass] = useState<string>('{}');
  const [rulesMsg, setRulesMsg] = useState<string>('');
  const [connOpenai, setConnOpenai] = useState<{ base_url?: string; default_model?: string; api_key?: string }>({});
  const [connAnth, setConnAnth] = useState<{ base_url?: string; default_model?: string; api_key?: string }>({});
  const [toolCalling, setToolCalling] = useState<boolean>(false);
  const [connMsg, setConnMsg] = useState<string>('');
  const [userTraits, setUserTraits] = useState<string[]>([]);

  const refresh = async () => {
    try {
      const st = await client.aiStatus();
      setStatus(st);
    } catch { /* ignore */ }
  };

  useEffect(() => { (async () => {
    await refresh();
    try { const c = await client.getAiConfig(); setCfg(c?.llm || { api_key_present: false }); setEmbedModel(c?.embeddings?.model || 'text-embedding-3-small'); } catch {}
    try {
      const rr = await client.getAiRagRules();
      setRulesRequired(JSON.stringify(rr.required_traits || {}, null, 2));
      setRulesClass(JSON.stringify(rr.classification || {}, null, 2));
    } catch {}
    try {
      const cx = await client.aiConnectorsGet();
      setConnOpenai(cx.openai || {});
      setConnAnth(cx.anthropic || {});
      setToolCalling(Boolean(cx.agent?.tool_calling));
    } catch {}
    try {
      const ut = await client.getUserTraits();
      setUserTraits(ut?.traits || []);
    } catch {}
  })(); }, []);


  // Defaults prefilled when config missing
  useEffect(() => { (async () => {
    try {
      const cx = await client.aiConnectorsGet();
      const wantsProvider = !cx?.provider;
      const wantsOpenaiBase = !cx?.openai?.base_url;
      const wantsAnthBase = !cx?.anthropic?.base_url;
      if (wantsProvider || wantsOpenaiBase || wantsAnthBase) {
        await client.aiConnectorsPut({
          provider: cx?.provider || 'openai',
          openai: { base_url: cx?.openai?.base_url || 'https://api.openai.com', default_model: cx?.openai?.default_model || 'gpt-4o-mini' },
          anthropic: { base_url: cx?.anthropic?.base_url || 'https://api.anthropic.com', default_model: cx?.anthropic?.default_model || 'claude-3-haiku-20240307' },
        });
        setConnMsg('Defaults applied');
      }
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
      if (cfgEditing.embeddings_model !== undefined) payload.embeddings_model = cfgEditing.embeddings_model;
      if (cfgEditing.openai_api_key) payload.openai_api_key = cfgEditing.openai_api_key;
      const res = await client.setAiConfig(payload);
      setCfgMsg(`Saved (${(res.changed || []).join(', ') || 'no changes'})`);
      const c = await client.getAiConfig();
      setCfg(c?.llm || { api_key_present: false });
      setEmbedModel(c?.embeddings?.model || 'text-embedding-3-small');
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

  const saveConnectors = async () => {
    try {
      setBusy(true);
      setConnMsg('');
      const res = await client.aiConnectorsPut({ openai: connOpenai, anthropic: connAnth, agent: { tool_calling: toolCalling } });
      setConnMsg(res.ok ? 'Saved' : 'Failed');
    } catch (e: any) {
      setConnMsg(e?.message || 'Failed to save');
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
          <TextField label="Provider" size="small" sx={{ flex: 1 }} select
            value={cfgEditing.provider ?? cfg?.provider ?? 'openai'}
            onChange={e => setCfgEditing(v => ({ ...v, provider: e.target.value }))}
            disabled={busy || readOnly}
          >
            {providerOptions.map(p => (<MenuItem key={p} value={p}>{p}</MenuItem>))}
          </TextField>
          {modelOptions.length > 0 ? (
            <TextField label="Model" size="small" sx={{ flex: 1 }} select
              value={cfgEditing.model ?? cfg?.model ?? ''}
              onChange={e => setCfgEditing(v => ({ ...v, model: e.target.value }))}
              disabled={busy || readOnly}
            >
              {modelOptions.map(m => (<MenuItem key={m} value={m}>{m}</MenuItem>))}
            </TextField>
          ) : (
            <TextField label="Model" size="small" sx={{ flex: 1 }} placeholder="model name"
              value={cfgEditing.model ?? cfg?.model ?? ''}
              onChange={e => setCfgEditing(v => ({ ...v, model: e.target.value }))}
              disabled={busy || readOnly}
            />
          )}
          <TextField label="Base URL" size="small" sx={{ flex: 1 }}
            placeholder="https://api.openai.com"
            value={cfgEditing.base_url ?? cfg?.base_url ?? ''}
            onChange={e => setCfgEditing(v => ({ ...v, base_url: e.target.value }))}
            disabled={busy || readOnly}
          />
        </Stack>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} sx={{ mb: 1 }}>
          {embedOptions.length > 0 ? (
            <TextField label="Embeddings Model" size="small" sx={{ flex: 1 }} select
              value={cfgEditing.embeddings_model ?? embedModel}
              onChange={(e) => setCfgEditing(v => ({ ...v, embeddings_model: e.target.value }))}
              disabled={busy || readOnly}
            >
              {embedOptions.map(m => (<MenuItem key={m} value={m}>{m}</MenuItem>))}
            </TextField>
          ) : (
            <TextField label="Embeddings Model" size="small" sx={{ flex: 1 }} placeholder="text-embedding-3-small"
              value={cfgEditing.embeddings_model ?? embedModel}
              onChange={(e) => setCfgEditing(v => ({ ...v, embeddings_model: e.target.value }))}
              disabled={busy || readOnly}
            />
          )}
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

      {/* Trait Visibility (TBAC) */}
      <Paper sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Typography variant="h6" gutterBottom>Access Traits (TBAC)</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Queries only return documents whose required traits are a subset of your traits. Traits shown below reflect
          the current rules configuration and your user profile.
        </Typography>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} sx={{ mb: 1 }}>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle2">Your Traits</Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
              {(userTraits || []).length ? userTraits.map(t => (<Chip key={t} label={t} size="small" />)) : <Chip label="(none)" size="small" />}
            </Box>
          </Box>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle2">Required Traits in Rules</Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
              {(() => {
                try {
                  const obj = JSON.parse(rulesRequired || '{}') as Record<string, string[]>;
                  const uniq = new Set<string>();
                  Object.values(obj || {}).forEach(arr => (arr || []).forEach(v => uniq.add(String(v))));
                  return Array.from(uniq).map(t => (<Chip key={t} label={t} size="small" color={userTraits.includes(t) ? 'success' as any : 'default'} />));
                } catch { return [<Chip key="invalid" label="Invalid JSON" color="warning" size="small" />]; }
              })()}
            </Box>
          </Box>
          <Box sx={{ flex: 1 }}>
            <Typography variant="subtitle2">Blocked (Missing)</Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
              {(() => {
                try {
                  const obj = JSON.parse(rulesRequired || '{}') as Record<string, string[]>;
                  const req = new Set<string>();
                  Object.values(obj || {}).forEach(arr => (arr || []).forEach(v => req.add(String(v))));
                  const missing = Array.from(req).filter(t => !userTraits.includes(t));
                  return missing.length ? missing.map(t => (<Chip key={t} label={t} size="small" color="error" />)) : [<Chip key="none" label="(none)" size="small" />];
                } catch { return [<Chip key="invalid2" label="Invalid JSON" color="warning" size="small" />]; }
              })()}
            </Box>
          </Box>
        </Stack>
      </Paper>

      {/* Connectors (OpenAI / Anthropic) */}
      <Paper sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Typography variant="h6" gutterBottom>Connectors</Typography>
        <Typography variant="subtitle2" sx={{ mt: 1 }}>OpenAI</Typography>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} sx={{ mb: 1 }}>
          <TextField label="Base URL" size="small" sx={{ flex: 1 }} placeholder="https://api.openai.com"
            value={connOpenai.base_url || ''}
            onChange={e => setConnOpenai(v => ({ ...v, base_url: e.target.value }))}
            disabled={busy || readOnly}
          />
          <TextField label="Default Model" size="small" sx={{ flex: 1 }} placeholder="gpt-5-mini"
            value={connOpenai.default_model || ''}
            onChange={e => setConnOpenai(v => ({ ...v, default_model: e.target.value }))}
            disabled={busy || readOnly}
          />
          <TextField label="API Key" type="password" size="small" sx={{ flex: 1 }} placeholder="sk-..."
            value={connOpenai.api_key || ''}
            onChange={e => setConnOpenai(v => ({ ...v, api_key: e.target.value }))}
            disabled={busy || readOnly}
          />
        </Stack>
        <Typography variant="subtitle2" sx={{ mt: 2 }}>Anthropic</Typography>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} sx={{ mb: 1 }}>
          <TextField label="Base URL" size="small" sx={{ flex: 1 }} placeholder="https://api.anthropic.com"
            value={connAnth.base_url || ''}
            onChange={e => setConnAnth(v => ({ ...v, base_url: e.target.value }))}
            disabled={busy || readOnly}
          />
          <TextField label="Default Model" size="small" sx={{ flex: 1 }} placeholder="claude-3-opus-20240229"
            value={connAnth.default_model || ''}
            onChange={e => setConnAnth(v => ({ ...v, default_model: e.target.value }))}
            disabled={busy || readOnly}
          />
          <TextField label="API Key" type="password" size="small" sx={{ flex: 1 }} placeholder="sk-ant-..."
            value={connAnth.api_key || ''}
            onChange={e => setConnAnth(v => ({ ...v, api_key: e.target.value }))}
            disabled={busy || readOnly}
          />
        </Stack>
        <Typography variant="subtitle2" sx={{ mt: 2 }}>Local</Typography>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} sx={{ mb: 1 }}>
          <TextField label="Base URL" size="small" sx={{ flex: 1 }} placeholder="http://localhost:11434" disabled value={'http://localhost:11434'} />
          <TextField label="Default Model" size="small" sx={{ flex: 1 }} placeholder="llama3.1:8b" disabled value={'llama3.1:8b'} />
        </Stack>
        <Alert severity="info" sx={{ mb: 1 }}>Set Provider=local above to use your local LLM (e.g., Ollama). Allowlist is applied automatically when you save connectors.</Alert>
        <Stack spacing={1} direction={{ xs: 'column', sm: 'row' }} alignItems={{ xs: 'stretch', sm: 'center' }}>
          <FormControlLabel control={<Switch checked={toolCalling} onChange={(e) => setToolCalling(e.target.checked)} />} label="Enable tool-calling" />
          <Button variant="outlined" onClick={saveConnectors} disabled={busy || readOnly} sx={{ borderRadius: 2 }}>Save Connectors</Button>
          <Button variant="outlined" onClick={async()=>{ setBusy(true); setConnMsg(''); try { await client.aiConnectorsPut({ provider: (cfgEditing.provider || cfg?.provider || 'openai'), openai: { base_url: connOpenai.base_url || 'https://api.openai.com' }, anthropic: { base_url: connAnth.base_url || 'https://api.anthropic.com' }, local: { base_url: 'http://localhost:11434' } }); setConnMsg('Default allowlist applied'); } catch(e:any){ setConnMsg(e?.message || 'Failed'); } finally { setBusy(false); } }} disabled={busy || readOnly} sx={{ borderRadius: 2 }}>Apply Default AI Allowlist</Button>
          {connMsg && <Chip label={connMsg} color="info" variant="outlined" />}
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
          <Button variant="outlined" onClick={async () => { setBusy(true); setNote(''); try { const res = await client.aiTrain(['/workspace']); setNote(`Indexed ${res.indexed} documents (total ${res.total}).`); await refresh(); } catch (e: any) { setNote(e?.message || 'Training failed'); } finally { setBusy(false); } }} disabled={busy || readOnly} sx={{ borderRadius: 2 }}>
            Train Full Repo (/workspace)
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
