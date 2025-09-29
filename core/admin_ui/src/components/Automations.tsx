import { useEffect, useState } from 'react';
import { Box, Typography, Paper, Stack, TextField, Button, Table, TableHead, TableRow, TableCell, TableBody, IconButton, Select, MenuItem } from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import HelpTip from './common/HelpTip';
import type { AdminAPIClient } from '../api/client';

interface Props { client: AdminAPIClient; readOnly?: boolean; }

export default function Automations({ client, readOnly }: Props) {
  const [rules, setRules] = useState<any[]>([]);
  const [error, setError] = useState<string>('');
  const [form, setForm] = useState<any>({ enabled: true, event_type: 'EmployeeTerminated', action: { type: 'set_user_roles', roles: ['viewer'] } });

  const refresh = async () => {
    try { const res = await client.listAutomationRules(); setRules(res.items || []); }
    catch (e:any) { setError(e?.message || 'Failed to load rules'); }
  };
  useEffect(()=>{ refresh(); },[]);

  const save = async () => {
    try { await client.upsertAutomationRule(form); setForm({ ...form, id: undefined }); await refresh(); }
    catch (e:any) { setError(e?.message || 'Failed to save rule'); }
  };

  const del = async (id: string) => {
    try { await client.deleteAutomationRule(id); await refresh(); }
    catch (e:any) { setError(e?.message || 'Failed to delete'); }
  };

  const ActionEditor = () => (
    <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mt: 2 }}>
      <Select size="small" value={form.action?.type || ''} onChange={(e)=>setForm({ ...form, action: { ...form.action, type: e.target.value } })} sx={{ minWidth: 220 }}>
        <MenuItem value="set_user_roles">Set User Roles</MenuItem>
      </Select>
      {form.action?.type === 'set_user_roles' && (
        <TextField label="Roles (comma‑sep)" size="small" value={(form.action?.roles || []).join(', ')} onChange={e=>setForm({ ...form, action: { ...form.action, roles: e.target.value.split(',').map((s:string)=>s.trim()).filter(Boolean) } })} sx={{ minWidth: 260 }} />
      )}
    </Stack>
  );

  return (
    <Box>
      <Box display="flex" alignItems="center" justifyContent="space-between">
        <Typography variant="h6" gutterBottom>Automations</Typography>
        <HelpTip topic="automations" />
      </Box>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Build GUI‑friendly flows: pick an event and an action. For example, when an HR or CRM plugin emits <code>EmployeeTerminated</code>, set the user’s roles to restrict access while keeping necessary self‑service.
      </Typography>
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
          <TextField label="Event Type" size="small" value={form.event_type || ''} onChange={e=>setForm({ ...form, event_type: e.target.value })} sx={{ minWidth: 220 }} />
          <ActionEditor />
          <Button variant="contained" onClick={save} disabled={readOnly}>Save Rule</Button>
        </Stack>
        {error && <Typography sx={{ mt:1 }} color="error.main">{error}</Typography>}
      </Paper>

      <Paper variant="outlined" sx={{ p: 0 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Enabled</TableCell>
              <TableCell>Event</TableCell>
              <TableCell>Action</TableCell>
              <TableCell></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(rules || []).map(r => (
              <TableRow key={r.id}>
                <TableCell>{String(Boolean(r.enabled))}</TableCell>
                <TableCell>{r.event_type}</TableCell>
                <TableCell>{r.action?.type} {r.action?.roles ? `→ ${r.action.roles.join(', ')}` : ''}</TableCell>
                <TableCell><IconButton onClick={()=>del(r.id)} disabled={readOnly} size="small"><DeleteIcon fontSize="small" /></IconButton></TableCell>
              </TableRow>
            ))}
            {(!rules || rules.length === 0) && (
              <TableRow><TableCell colSpan={4}><Typography sx={{ p: 2 }} color="text.secondary">No automations defined.</Typography></TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>
    </Box>
  );
}

