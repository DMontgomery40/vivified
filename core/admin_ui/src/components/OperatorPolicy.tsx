import { useState } from 'react';
import { Box, Paper, Typography, TextField, Button, Alert, Stack, Chip } from '@mui/material';
import AdminAPIClient from '../api/client';
import HelpTip from './common/HelpTip';

export default function OperatorPolicy({ client }: { client: AdminAPIClient }) {
  const [caller, setCaller] = useState('');
  const [target, setTarget] = useState('');
  const [opsCsv, setOpsCsv] = useState('');
  const [operations, setOperations] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const refresh = async () => {
    try {
      setError(null); setNote(null);
      if (!caller || !target) return;
      const res = await client.getOperatorAllowlist(caller, target);
      setOperations(res.operations || []);
      setOpsCsv((res.operations || []).join(','));
    } catch (e: any) { setError(e?.message || 'Failed to load'); }
  };

  const save = async () => {
    try {
      setError(null); setNote(null);
      const ops = (opsCsv || '').split(',').map(s=>s.trim()).filter(Boolean);
      await client.setOperatorAllowlist({ caller, target, operations: ops });
      setNote('Saved');
      setOperations(ops);
    } catch (e: any) { setError(e?.message || 'Failed to save'); }
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h5" fontWeight={600}>Operator Policy</Typography>
        <HelpTip topic="operator-policy" />
      </Box>
      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={()=>setError(null)}>{error}</Alert>}
      {note && <Alert severity="success" sx={{ mb: 2 }} onClose={()=>setNote(null)}>{note}</Alert>}
      <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
          <TextField label="Caller Plugin" value={caller} onChange={e=>setCaller(e.target.value)} size="small" fullWidth />
          <TextField label="Target Plugin" value={target} onChange={e=>setTarget(e.target.value)} size="small" fullWidth />
          <Button variant="outlined" onClick={refresh}>Load</Button>
        </Stack>
        <Box mt={2}>
          <TextField label="Allowed Operations (CSV)" value={opsCsv} onChange={e=>setOpsCsv(e.target.value)} size="small" fullWidth />
          <Button variant="contained" sx={{ mt: 1 }} onClick={save}>Save</Button>
        </Box>
        <Box mt={2}>
          <Typography variant="subtitle2">Current</Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            {(operations || []).map(op => (<Chip key={op} label={op} size="small" />))}
          </Stack>
        </Box>
      </Paper>
    </Box>
  );
}
