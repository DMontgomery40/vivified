import { useEffect, useState } from 'react';
import { Box, Typography, Paper, Stack, TextField, Button, Table, TableHead, TableRow, TableCell, TableBody, IconButton, Chip, MenuItem, Select } from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import type { AdminAPIClient } from '../api/client';
import HelpTip from './common/HelpTip';

interface Props { client: AdminAPIClient; readOnly?: boolean; }

export default function NotificationsRules({ client, readOnly }: Props) {
  const [rules, setRules] = useState<any[]>([]);
  const [error, setError] = useState<string>('');
  const [form, setForm] = useState<any>({ enabled: true, event_type: 'FaxReceived', channel: 'pushover', template: { title: 'New Fax', body: 'A fax was received.' }, audience: { mode: 'traits', traits: ['sales'], scope: 'tenant' } });

  const refresh = async () => {
    try { const res = await client.listNotificationRules(); setRules(res.items || []); } catch (e:any) { setError(e?.message || 'Failed to load rules'); }
  };
  useEffect(()=>{ refresh(); },[]);

  const save = async () => {
    try { await client.upsertNotificationRule(form); setForm({ ...form, id: undefined }); await refresh(); }
    catch (e:any) { setError(e?.message || 'Failed to save rule'); }
  };
  const del = async (id: string) => {
    try { await client.deleteNotificationRule(id); await refresh(); }
    catch (e:any) { setError(e?.message || 'Failed to delete'); }
  };

  return (
    <Box>
      <Box display="flex" alignItems="center" justifyContent="space-between">
        <Typography variant="subtitle1" gutterBottom>Notification Rules</Typography>
        <HelpTip topic="notifications-rules" />
      </Box>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Define event-driven rules to send notifications via configured channels. Audience can be trait-based (e.g., all users with trait ‘sales’ in tenant).
      </Typography>
      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack spacing={2} direction={{ xs: 'column', md: 'row' }}>
          <TextField label="Event Type" value={form.event_type || ''} onChange={e=>setForm({ ...form, event_type: e.target.value })} size="small" sx={{ minWidth: 220 }} />
          <TextField label="Title" value={form.template?.title || ''} onChange={e=>setForm({ ...form, template: { ...form.template, title: e.target.value } })} size="small" sx={{ minWidth: 220 }} />
          <TextField label="Body" value={form.template?.body || ''} onChange={e=>setForm({ ...form, template: { ...form.template, body: e.target.value } })} size="small" fullWidth />
        </Stack>
        <Stack spacing={2} direction={{ xs: 'column', md: 'row' }} sx={{ mt: 2 }}>
          <Select size="small" value={form.channel || ''} onChange={(e)=>setForm({ ...form, channel: e.target.value })} displayEmpty sx={{ minWidth: 180 }}>
            <MenuItem value=""><em>channel (optional)</em></MenuItem>
            <MenuItem value="pushover">pushover</MenuItem>
            <MenuItem value="apprise">apprise</MenuItem>
          </Select>
          <TextField label="Audience Traits (comma‑sep)" value={(form.audience?.traits || []).join(', ')} size="small" onChange={e=>setForm({ ...form, audience: { ...form.audience, mode: 'traits', traits: e.target.value.split(',').map((s:string)=>s.trim()).filter(Boolean) } })} sx={{ minWidth: 300 }} />
          <Select size="small" value={form.audience?.scope || 'tenant'} onChange={(e)=>setForm({ ...form, audience: { ...form.audience, scope: e.target.value } })}>
            <MenuItem value="tenant">tenant</MenuItem>
            <MenuItem value="org">org</MenuItem>
          </Select>
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
              <TableCell>Channel</TableCell>
              <TableCell>Audience</TableCell>
              <TableCell>Template</TableCell>
              <TableCell></TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(rules || []).map(r => (
              <TableRow key={r.id}>
                <TableCell>{String(Boolean(r.enabled))}</TableCell>
                <TableCell>{r.event_type}</TableCell>
                <TableCell>{r.channel || ''}</TableCell>
                <TableCell>
                  {(r.audience?.traits || []).map((t:string)=> (<Chip key={t} label={t} size="small" sx={{ mr: 0.5 }} />))}
                </TableCell>
                <TableCell>{(r.template?.title || '')} — {(r.template?.body || '').slice(0,60)}</TableCell>
                <TableCell>
                  <IconButton onClick={()=>del(r.id)} disabled={readOnly} size="small"><DeleteIcon fontSize="small" /></IconButton>
                </TableCell>
              </TableRow>
            ))}
            {(!rules || rules.length === 0) && (
              <TableRow><TableCell colSpan={6}><Typography sx={{ p: 2 }} color="text.secondary">No rules defined.</Typography></TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>
    </Box>
  );
}
