import { useState } from 'react';
import { Box, Paper, Typography, TextField, Button, Alert } from '@mui/material';
import HelpTip from './common/HelpTip';
import AdminAPIClient from '../api/client';

interface Props { client: AdminAPIClient; }

const sampleManifest = `{
  "id": "example.plugin",
  "name": "Example Plugin",
  "version": "0.1.0",
  "description": "Local test plugin",
  "contracts": [],
  "traits": ["communication_plugin"],
  "security": {"allowed_domains": []},
  "compliance": {}
}`;

export default function PluginRegister({ client }: Props) {
  const [manifest, setManifest] = useState(sampleManifest);
  const [res, setRes] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setError(null); setRes(null);
    let data: Record<string, any> = {};
    try { data = JSON.parse(manifest); } catch { setError('Manifest must be JSON'); return; }
    try { setRes(await client.registerPlugin(data)); } catch (e: any) { setError(e?.message || 'Registration failed'); }
  };

  return (
    <Paper elevation={0} sx={{ p: 2 }}>
      <Box display="flex" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
        <Typography variant="h6">Register Plugin</Typography>
        <HelpTip topic="register" />
      </Box>
      <TextField fullWidth label="Manifest (JSON)" value={manifest} onChange={e=>setManifest(e.target.value)} multiline minRows={8} />
      <Box sx={{ mt: 2 }}>
        <Button variant="contained" onClick={submit}>Register</Button>
      </Box>
      {error && <Alert sx={{ mt: 2 }} severity="error">{error}</Alert>}
      {res && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle1">Result</Typography>
          <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(res, null, 2)}</pre>
        </Box>
      )}
    </Paper>
  );
}
