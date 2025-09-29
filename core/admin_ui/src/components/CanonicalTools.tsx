import { useEffect, useState } from 'react';
import { Box, Paper, Typography, TextField, Button, Grid, Alert, Stack } from '@mui/material';
import HelpTip from './common/HelpTip';
import AdminAPIClient from '../api/client';

interface Props {
  client: AdminAPIClient;
}

export default function CanonicalTools({ client }: Props) {
  const [stats, setStats] = useState<any>(null);
  const [source, setSource] = useState('plugin.src');
  const [target, setTarget] = useState('plugin.dest');
  const [userData, setUserData] = useState(`{
  "id": "u_123",
  "name": "Jane Doe",
  "email": "jane@example.com"
}`);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);
  const [schemaName, setSchemaName] = useState('User');
  const [schemaVersion, setSchemaVersion] = useState('1.0.0');
  const [schemaJson, setSchemaJson] = useState(`{
  "type": "object",
  "properties": {"id": {"type": "string"}}
}`);
  const [activeMajor, setActiveMajor] = useState('1');
  const [schemaNote, setSchemaNote] = useState<string | null>(null);

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
      <Box display="flex" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h6">Canonical Tools</Typography>
        <HelpTip topic="canonical" />
      </Box>
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
      <Box sx={{ mt: 3 }}>
        <Typography variant="subtitle1">Schema Registry</Typography>
        <Grid container spacing={2} sx={{ mt: 1 }}>
          <Grid item xs={12} sm={3}>
            <TextField label="Schema Name" value={schemaName} onChange={e=>setSchemaName(e.target.value)} fullWidth />
          </Grid>
          <Grid item xs={6} sm={3}>
            <TextField label="Version (x.y.z)" value={schemaVersion} onChange={e=>setSchemaVersion(e.target.value)} fullWidth />
          </Grid>
          <Grid item xs={6} sm={2}>
            <TextField label="Activate Major" value={activeMajor} onChange={e=>setActiveMajor(e.target.value)} fullWidth />
          </Grid>
          <Grid item xs={12}>
            <TextField label="Schema JSON" value={schemaJson} onChange={e=>setSchemaJson(e.target.value)} fullWidth multiline minRows={3} />
          </Grid>
          <Grid item xs={12}>
            <Stack direction="row" spacing={1}>
              <Button variant="outlined" onClick={async () => {
                try {
                  setError(null); setSchemaNote(null);
                  const [maj, min, pat] = (schemaVersion || '1.0.0').split('.').map(v=>parseInt(v,10)||0);
                  const sj = JSON.parse(schemaJson || '{}');
                  await client.upsertSchema({ name: schemaName, major: maj, minor: min, patch: pat, schema_data: sj });
                  setSchemaNote(`Upserted ${schemaName} ${schemaVersion}`);
                } catch (e: any) { setError(e?.message || 'Upsert failed'); }
              }}>Upsert</Button>
              <Button variant="contained" onClick={async () => {
                try {
                  setError(null); setSchemaNote(null);
                  const [maj, min, pat] = (schemaVersion || '1.0.0').split('.').map(v=>parseInt(v,10)||0);
                  await client.activateSchema({ name: schemaName, major: maj, minor: min, patch: pat });
                  setSchemaNote(`Activated ${schemaName} ${schemaVersion}`);
                } catch (e: any) { setError(e?.message || 'Activate failed'); }
              }}>Activate</Button>
              <Button variant="text" onClick={async () => {
                try {
                  const res = await client.listSchemas(schemaName);
                  setSchemaNote(`Versions: ${JSON.stringify(res.versions)}`);
                } catch (e: any) { setError(e?.message || 'List failed'); }
              }}>List Versions</Button>
              <Button variant="text" onClick={async () => {
                try {
                  const res = await client.getActiveSchema(schemaName, parseInt(activeMajor||'1',10)||1);
                  setSchemaNote(`Active: ${JSON.stringify(res.active)}`);
                } catch (e: any) { setError(e?.message || 'Active lookup failed'); }
              }}>Get Active</Button>
            </Stack>
          </Grid>
        </Grid>
        {schemaNote && <Alert sx={{ mt: 2 }} severity="success" onClose={()=>setSchemaNote(null)}>{schemaNote}</Alert>}
      </Box>
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
