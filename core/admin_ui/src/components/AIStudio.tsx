import { useEffect, useState } from 'react';
import { Box, Paper, Typography, Stack, Button, TextField, Chip } from '@mui/material';
import AdminAPIClient from '../api/client';

type Props = { client: AdminAPIClient; readOnly?: boolean };

export default function AIStudio({ client, readOnly = false }: Props) {
  const [status, setStatus] = useState<{ docs_indexed: number; last_trained_ts?: number | null } | null>(null);
  const [query, setQuery] = useState('Vivified');
  const [results, setResults] = useState<Array<{ id: string; title: string; path?: string }>>([]);
  const [prompt, setPrompt] = useState('Summarize Vivified core.');
  const [agentRes, setAgentRes] = useState<string>('');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');

  const refresh = async () => {
    try {
      const st = await client.aiStatus();
      setStatus(st);
    } catch { /* ignore */ }
  };

  useEffect(() => { refresh(); }, []);

  const train = async () => {
    try {
      setBusy(true);
      setNote('');
      const res = await client.aiTrain([ 'docs', 'internal-plans' ]);
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
        Train an internal RAG index from local docs and run simple queries. Agent run is stubbed but includes context from top RAG hits.
      </Typography>

      <Paper sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems={{ xs: 'stretch', sm: 'center' }}>
          <Chip label={`Docs indexed: ${status?.docs_indexed ?? 0}`} />
          <Button variant="contained" onClick={train} disabled={busy || readOnly} sx={{ borderRadius: 2 }}>
            {busy ? 'Training…' : 'Train from Docs'}
          </Button>
          {note && <Chip color="info" variant="outlined" label={note} />}
        </Stack>
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

      <Paper sx={{ p: 2, borderRadius: 2 }}>
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
    </Box>
  );
}

