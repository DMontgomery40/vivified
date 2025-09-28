import { useEffect, useState } from 'react';
import { Box, Paper, Typography, TextField, Button, Grid, Alert } from '@mui/material';
import AdminAPIClient from '../api/client';

interface Props {
  client: AdminAPIClient;
}

export default function CanonicalTools({ client }: Props) {
  const [stats, setStats] = useState<any>(null);
  const [source, setSource] = useState('plugin.src');
  const [target, setTarget] = useState('plugin.dest');
  const [userData, setUserData] = useState('{
  "id": "u_123",
  "name": "Jane Doe",
  "email": "jane@example.com"
}');
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);

  const refresh = async () => {
    try { setStats(await client.getCanonicalStats()); } catch (e: any) { setError(e?.message || 'Failed to load stats'); }
  };
  useEffect(()=>{ refresh(); }, []);

  const normalize = async () => {
    setError(null);
    setResult(null);
    let data: Record<string, any> = {};
    try { data = JSON.parse(userData); } catch { setError('User data must be JSON'); return; }
    try {
      const res = await client.normalizeUser({ user_data: data, source_plugin: source, target_plugin: target });
      setResult(res);
      await refresh();
    } catch (e: any) { setError(e?.message || 'Normalization failed'); }
  };

  return (
    <Paper elevation={0} sx={{ p: 2 }}>
      <Typography variant="h6" sx={{ mb: 2 }}>Canonical Tools</Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} sm={4}>
          <TextField label="Source Plugin" value={source} onChange={e=>setSource(e.target.value)} fullWidth />
        </Grid>
        <Grid item xs={12} sm={4}>
          <TextField label="Target Plugin" value={target} onChange={e=>setTarget(e.target.value)} fullWidth />
        </Grid>
        <Grid item xs={12}>
          <TextField label="User Data (JSON)" value={userData} onChange={e=>setUserData(e.target.value)} fullWidth multiline minRows={3} />
        </Grid>
        <Grid item xs={12}>
          <Button variant="contained" onClick={normalize}>Normalize User</Button>
          <Button variant="outlined" sx={{ ml: 1 }} onClick={refresh}>Refresh Stats</Button>
        </Grid>
      </Grid>
      {error && <Alert sx={{ mt: 2 }} severity="error">{error}</Alert>}
      {result && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle1">Result</Typography>
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

