import { useEffect, useState } from 'react';
import { Box, Paper, Typography, TextField, Button, Grid, Alert } from '@mui/material';
import AdminAPIClient from '../api/client';

interface Props {
  client: AdminAPIClient;
}

export default function MessagingConsole({ client }: Props) {
  const [stats, setStats] = useState<any>(null);
  const [eventType, setEventType] = useState('demo.event');
  const [sourcePlugin, setSourcePlugin] = useState('admin-ui');
  const [payload, setPayload] = useState(`{
  "hello": "world"
}`);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);

  const refresh = async () => {
    try {
      setStats(await client.getMessagingStats());
    } catch (e: any) {
      setError(e?.message || 'Failed to load stats');
    }
  };

  useEffect(() => { refresh(); }, []);

  const publish = async () => {
    setError(null);
    setResult(null);
    let data: Record<string, any> = {};
    try { data = payload ? JSON.parse(payload) : {}; } catch { setError('Payload must be JSON'); return; }
    try {
      const res = await client.publishEvent({ event_type: eventType, data, source_plugin: sourcePlugin });
      setResult(res);
      await refresh();
    } catch (e: any) {
      setError(e?.message || 'Publish failed');
    }
  };

  return (
    <Paper elevation={0} sx={{ p: 2 }}>
      <Typography variant="h6" sx={{ mb: 2 }}>Messaging / Event Bus</Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} sm={4}>
          <TextField label="Event Type" value={eventType} onChange={e=>setEventType(e.target.value)} fullWidth />
        </Grid>
        <Grid item xs={12} sm={4}>
          <TextField label="Source Plugin" value={sourcePlugin} onChange={e=>setSourcePlugin(e.target.value)} fullWidth />
        </Grid>
        <Grid item xs={12}>
          <TextField label="Payload (JSON)" value={payload} onChange={e=>setPayload(e.target.value)} fullWidth multiline minRows={3} />
        </Grid>
        <Grid item xs={12}>
          <Button variant="contained" onClick={publish}>Publish Event</Button>
          <Button variant="outlined" sx={{ ml: 1 }} onClick={refresh}>Refresh Stats</Button>
        </Grid>
      </Grid>
      {error && <Alert sx={{ mt: 2 }} severity="error">{error}</Alert>}
      {result && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle1">Publish Result</Typography>
          <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(result, null, 2)}</pre>
        </Box>
      )}
      {stats && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle1">Stats</Typography>
          <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(stats, null, 2)}</pre>
        </Box>
      )}
    </Paper>
  );
}
