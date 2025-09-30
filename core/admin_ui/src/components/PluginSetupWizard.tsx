import { useEffect, useMemo, useState } from 'react';
import { Box, Paper, Typography, Stack, Button, TextField, Chip, Switch, FormControlLabel, MenuItem, Alert } from '@mui/material';
import AdminAPIClient from '../api/client';

type Props = { client: AdminAPIClient; readOnly?: boolean };

const COMMON_TRAITS = [
  'admin', 'plugin_manager', 'config_manager', 'audit_viewer', 'analytics_viewer', 'dba_viewer',
];

const PLUGIN_TYPES = [
  { id: 'llm-oss', label: 'LLM (Local/Ollama/GPT-OSS)' },
  { id: 'rag-db', label: 'RAG DB Backend (pgvector/Elastic/etc.)' },
  { id: 'notifier', label: 'Notifier (Apprise/Pushover/etc.)' },
  { id: 'storage', label: 'Storage Provider' },
  { id: 'other', label: 'Other' },
];

export default function PluginSetupWizard({ client, readOnly = false }: Props) {
  const [aiAssist, setAiAssist] = useState<boolean>(true);
  const [pluginType, setPluginType] = useState<string>('llm-oss');
  const [hipaa, setHipaa] = useState<boolean>(false);
  const [traits, setTraits] = useState<string[]>(['plugin_manager']);
  const [pluginId, setPluginId] = useState<string>('my-plugin');
  const [pluginName, setPluginName] = useState<string>('My Plugin');
  const [pluginVersion, setPluginVersion] = useState<string>('0.1.0');
  const [manifest, setManifest] = useState<string>('');
  const [suggestions, setSuggestions] = useState<{ operations: string[]; allowlist: Record<string, { allowed_methods: string[]; allowed_paths: string[] }> } | null>(null);
  const [busy, setBusy] = useState<boolean>(false);
  const [msg, setMsg] = useState<string>('');
  const [err, setErr] = useState<string>('');

  const defaultManifest = useMemo(() => {
    const m: any = {
      id: pluginId,
      name: pluginName,
      version: pluginVersion,
      contracts: [],
      traits,
      allowed_domains: [],
      endpoints: pluginType === 'rag-db' ? { rag_index: '/rag/index', rag_query: '/rag/query' }
               : pluginType === 'llm-oss' ? { chat: '/chat', embeddings: '/embeddings' }
               : {},
      security: { scopes: [] },
      compliance: { hipaa_controls: hipaa ? ["164.312(a)"] : [], audit_level: hipaa ? 'detailed' : 'standard' },
    };
    return JSON.stringify(m, null, 2);
  }, [pluginId, pluginName, pluginVersion, pluginType, traits, hipaa]);

  useEffect(() => {
    if (!manifest) setManifest(defaultManifest);
  }, [defaultManifest]);

  const askAIForManifest = async () => {
    try {
      setBusy(true); setErr(''); setMsg('');
      const prompt = [
        'You are assisting with a Vivified plugin manifest. Output only valid JSON for the manifest (no markdown).',
        `Plugin type: ${pluginType}. HIPAA: ${hipaa}. Traits: ${traits.join(', ') || '(none)'}.`,
        'Required fields: id, name, version, contracts (array), traits (array), allowed_domains (array), endpoints (object), security (object), compliance (object).',
        pluginType === 'rag-db'
          ? 'For RAG DB: add endpoints rag_index:/rag/index and rag_query:/rag/query.'
          : (pluginType === 'llm-oss'
              ? 'For LLM OSS: add endpoints chat:/chat and embeddings:/embeddings.'
              : (pluginType === 'notifier' ? 'For Notifier: add endpoint send:/send.' : '')),
        `Use id="${pluginId}", name="${pluginName}", version="${pluginVersion}".`,
      ].filter(Boolean).join('\n');

      const extractJson = (text: string): any => {
        try {
          const m1 = text.match(/```json\s*([\s\S]*?)```/i);
          if (m1) return JSON.parse(m1[1]);
          const m2 = text.match(/```\s*([\s\S]*?)```/);
          if (m2) return JSON.parse(m2[1]);
          const start = text.indexOf('{');
          const end = text.lastIndexOf('}');
          if (start !== -1 && end !== -1 && end > start) return JSON.parse(text.slice(start, end + 1));
        } catch { /* ignore */ }
        return null;
      };

      const templateManifest = () => {
        const m: any = {
          id: pluginId,
          name: pluginName,
          version: pluginVersion,
          contracts: [],
          traits,
          allowed_domains: [],
          endpoints: {},
          security: { scopes: [] },
          compliance: { hipaa_controls: hipaa ? ["164.312(a)"] : [], audit_level: hipaa ? 'detailed' : 'standard' },
        };
        if (pluginType === 'rag-db') m.endpoints = { rag_index: '/rag/index', rag_query: '/rag/query' };
        if (pluginType === 'llm-oss') m.endpoints = { chat: '/chat', embeddings: '/embeddings' };
        if (pluginType === 'notifier') m.endpoints = { send: '/send' };
        if ((pluginType === 'notifier') && (pluginName.toLowerCase().includes('pushover') || pluginId.toLowerCase().includes('pushover'))) {
          m.allowed_domains = [ 'api.pushover.net' ];
        }
        return m;
      };

      const aiPromise = client.aiAgentRun([{ role: "user", content: prompt }], true);
      const timeoutPromise = new Promise<{ result?: string }>((resolve) => setTimeout(() => resolve({ result: '' }), 20000));
      const r = await Promise.race([aiPromise as any, timeoutPromise]);
      const out = (r?.result || '').trim();
      const parsed = out ? extractJson(out) : null;
      const finalObj = parsed && typeof parsed === 'object' ? parsed : templateManifest();
      setManifest(JSON.stringify(finalObj, null, 2));
      setMsg(parsed ? 'AI generated a draft manifest. Validate before registering.' : 'AI timed out or returned invalid JSON. Inserted a safe template manifest. Validate before registering.');
    } catch (e:any) {
      setErr(e?.message || 'AI assistance failed; inserted a safe template.');
      setManifest(JSON.stringify({ id: pluginId, name: pluginName, version: pluginVersion, contracts: [], traits, allowed_domains: [], endpoints: {}, security: { scopes: [] }, compliance: { hipaa_controls: hipaa ? ["164.312(a)"] : [], audit_level: hipaa ? 'detailed' : 'standard' } }, null, 2));
    } finally { setBusy(false); }
  };

  const validate = async () => {
    try {
      setBusy(true); setErr(''); setMsg(''); setSuggestions(null);
      const parsed = JSON.parse(manifest || '{}');
      const v = await client.validatePluginManifest(parsed);
      if (!v.ok) setErr(`Schema errors: ${v.errors.map(e=>e.message).join('; ')}`);
      setSuggestions({ operations: v.suggestions.operations || [], allowlist: v.suggestions.allowlist || {} });
      setMsg('Validated. Suggestions are ready below.');
    } catch (e:any) { setErr(e?.message || 'Validation failed'); }
    finally { setBusy(false); }
  };

  const applyPolicies = async () => {
    try {
      setBusy(true); setErr(''); setMsg('');
      const parsed = JSON.parse(manifest || '{}');
      const pid = String(parsed.id || pluginId);
      if (suggestions?.allowlist && Object.keys(suggestions.allowlist).length) {
        await client.setGatewayAllowlist({ plugin_id: pid, allowlist: suggestions.allowlist });
      }
      // If this is a RAG backend, allow ai-core to call rag ops
      const ops = suggestions?.operations || [];
      const defaultOps = pluginType === 'rag-db' ? ['rag_index','rag_query'] : [];
      const unionOps = Array.from(new Set([...(ops||[]), ...defaultOps]));
      if (unionOps.length) {
        await client.setOperatorAllowlist({ caller: 'ai-core', target: pid, operations: unionOps });
      }
      setMsg('Policies applied (gateway + operator).');
    } catch (e:any) { setErr(e?.message || 'Failed to apply policies'); }
    finally { setBusy(false); }
  };

  const register = async () => {
    try {
      setBusy(true); setErr(''); setMsg('');
      const parsed = JSON.parse(manifest || '{}');
      const r = await client.registerPlugin(parsed);
      setMsg(`Registered plugin ${r?.plugin_id || parsed.id}. Token issued.`);
    } catch (e:any) { setErr(e?.message || 'Register failed'); }
    finally { setBusy(false); }
  };

  const downloadScaffold = async () => {
    try {
      setBusy(true); setErr(''); setMsg('');
      const template = pluginType === 'rag-db' ? 'rag-db-pgvector' : (pluginType === 'llm-oss' ? 'llm-oss' : '');
      const blob = await client.scaffoldPlugin({ id: pluginId, name: pluginName, version: pluginVersion, language: 'python', traits, template });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `${pluginId}_scaffold.zip`; a.click();
      URL.revokeObjectURL(url);
      setMsg('Scaffold downloaded.');
    } catch (e:any) { setErr(e?.message || 'Scaffold failed'); }
    finally { setBusy(false); }
  };

  const toggleTrait = (t: string) => setTraits((prev) => prev.includes(t) ? prev.filter(x => x !== t) : prev.concat([t]));

  return (
    <Paper sx={{ p: 2, borderRadius: 2 }}>
      <Box display='flex' alignItems='center' justifyContent='space-between'>
        <Typography variant='h6'>Plugin Setup Wizard</Typography>
        <FormControlLabel control={<Switch checked={aiAssist} onChange={(e)=>setAiAssist(e.target.checked)} />} label="Use AI Assistance" />
      </Box>
      <Alert severity='info' sx={{ mb: 2, borderRadius: 2 }}>
        This guided flow scaffolds, validates, applies policies, and registers a plugin. When AI Assistance is on, the embedded model drafts a manifest based on your selections. It never applies changes without your clicks. Every step is auditable and reversible.
      </Alert>
      {err && <Alert severity='error' sx={{ mb: 1, borderRadius: 2 }} onClose={()=>setErr('')}>{err}</Alert>}
      {msg && <Alert severity='success' sx={{ mb: 1, borderRadius: 2 }} onClose={()=>setMsg('')}>{msg}</Alert>}
      <Stack spacing={2}>
        <Stack direction={{ xs:'column', sm:'row' }} spacing={2}>
          <TextField size='small' label='Plugin ID' sx={{ flex: 1 }} value={pluginId} onChange={e=>setPluginId(e.target.value)} disabled={busy||readOnly} />
          <TextField size='small' label='Name' sx={{ flex: 1 }} value={pluginName} onChange={e=>setPluginName(e.target.value)} disabled={busy||readOnly} />
          <TextField size='small' label='Version' sx={{ width: 160 }} value={pluginVersion} onChange={e=>setPluginVersion(e.target.value)} disabled={busy||readOnly} />
        </Stack>
        <Stack direction={{ xs:'column', sm:'row' }} spacing={2}>
          <TextField size='small' label='Plugin Type' select sx={{ flex: 1 }} value={pluginType} onChange={e=>setPluginType(e.target.value)} disabled={busy||readOnly}>
            {PLUGIN_TYPES.map(t => (<MenuItem key={t.id} value={t.id}>{t.label}</MenuItem>))}
          </TextField>
          <FormControlLabel control={<Switch checked={hipaa} onChange={(e)=>setHipaa(e.target.checked)} />} label="Requires HIPAA?" />
        </Stack>
        <Alert severity='info' sx={{ borderRadius: 2 }}>
          If HIPAA is enabled, the wizard marks compliance metadata in your manifest. Access to PHI is controlled by TBAC traits: by default, content labeled <code>phi</code> requires the user trait <code>hipaa_cleared</code>. You manage those traits in Admin → Users. You can override the classification→trait mapping in Config.
        </Alert>
        <Box>
          <Typography variant='subtitle2'>Traits</Typography>
          <Typography variant='body2' color='text.secondary'>
            Traits are string labels assigned to users and used by policy to authorize actions and data access. The assistant will use your selected traits in the manifest. You can add custom traits anytime.
          </Typography>
        </Box>
        <Box>
          <Typography variant='subtitle2' sx={{ mt: 1 }}>Select Common Traits</Typography>
          <Box sx={{ display:'flex', gap: 1, flexWrap:'wrap', mt: 1 }}>
            {COMMON_TRAITS.map(t => (
              <Chip key={t} label={t} size='small' clickable color={traits.includes(t)?'success':'default'} onClick={()=>toggleTrait(t)} />
            ))}
          </Box>
          <TextField size='small' fullWidth sx={{ mt: 1 }} label='Custom traits (comma-separated)' placeholder='e.g., internal_docs, analytics_viewer' onBlur={(e)=>{
            const parts = (e.target.value||'').split(',').map(s=>s.trim()).filter(Boolean);
            if (parts.length) setTraits(prev => Array.from(new Set([...prev, ...parts])));
            e.target.value='';
          }} disabled={busy||readOnly} />
        </Box>
        <Box>
          <Typography variant='subtitle2'>Manifest</Typography>
          <Alert severity='info' sx={{ mb: 1, borderRadius: 2 }}>
            The manifest defines your plugin’s identity and endpoints. AI Assistance will propose one based on your inputs. You can edit it before validating and registering. No changes are applied until you click the buttons below.
          </Alert>
          <TextField value={manifest} onChange={e=>setManifest(e.target.value)} fullWidth multiline minRows={8} size='small' inputProps={{ style: { fontFamily: 'monospace' } }} />
        </Box>
        <Stack direction={{ xs:'column', sm:'row' }} spacing={1}>
          {aiAssist && <Button variant='outlined' onClick={askAIForManifest} disabled={busy||readOnly} sx={{ borderRadius: 2 }}>Ask AI to Generate Manifest</Button>}
          <Button variant='outlined' onClick={validate} disabled={busy||readOnly} sx={{ borderRadius: 2 }}>Validate</Button>
          <Button variant='outlined' onClick={applyPolicies} disabled={busy||readOnly || !suggestions} sx={{ borderRadius: 2 }}>Apply Suggested Policies</Button>
          <Button variant='contained' onClick={register} disabled={busy||readOnly} sx={{ borderRadius: 2 }}>Register Plugin</Button>
          <Button variant='text' onClick={downloadScaffold} disabled={busy||readOnly} sx={{ borderRadius: 2 }}>Download Scaffold</Button>
        </Stack>
        <Alert severity='info' sx={{ borderRadius: 2 }}>
          What happens next: Validate checks schema and suggests Gateway and Operator allowlists. Apply Suggested Policies writes those to Config (audited). Register stores your manifest and issues a plugin token—no code is executed on your infra until you deploy your plugin container.
        </Alert>
        {suggestions && (
          <Paper sx={{ p: 2, borderRadius: 2 }}>
            <Typography variant='subtitle2'>Suggestions</Typography>
            <Typography variant='body2' sx={{ mt: 1 }}>Operations: {(suggestions.operations||[]).join(', ') || '(none)'}</Typography>
            <Typography variant='body2' sx={{ mt: 1 }}>Allowlist Hosts: {Object.keys(suggestions.allowlist||{}).join(', ') || '(none)'}</Typography>
          </Paper>
        )}
      </Stack>
    </Paper>
  );
}
