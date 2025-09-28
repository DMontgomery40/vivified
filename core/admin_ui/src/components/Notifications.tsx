import { useEffect, useMemo, useState } from 'react';
import { Box, Typography, Paper, TextField, Button, Stack, Divider, Link, Chip, Table, TableHead, TableRow, TableCell, TableBody } from '@mui/material';
import SendIcon from '@mui/icons-material/Send';
import HelpIcon from '@mui/icons-material/Help';
import type { AdminAPIClient } from '../api/client';

interface Props {
  client: AdminAPIClient;
  readOnly?: boolean;
}

export default function NotificationsPanel({ client, readOnly }: Props) {
  const [inbox, setInbox] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('Test notification from Admin Console');
  const [targets, setTargets] = useState('');
  const [note, setNote] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [help, setHelp] = useState<Record<string, string>>({});
  const [settings, setSettings] = useState<Record<string, any>>({});

  const refresh = async () => {
    try {
      const res = await client.getNotificationsInbox(50, 0);
      setInbox(res.items || []);
    } catch (e: any) {
      setError(e?.message || 'Failed to load inbox');
    }
  };

  useEffect(() => {
    refresh();
    (async () => {
      try { const h = await client.getNotificationsHelp(); setHelp(h?.links || {}); } catch {}
      try { const s = await client.getNotificationsSettings(); setSettings(s || {}); } catch {}
    })();
  }, []);

  const onSend = async () => {
    setLoading(true); setError(''); setNote('');
    try {
      const t = (targets || '').split(',').map(s => s.trim()).filter(Boolean);
      const res = await client.sendNotification({ title: title || undefined, body, targets: t.length ? t : undefined });
      setNote(`Queued status=${res.status} id=${res.notification_id}`);
      setTitle('');
      setBody('Test notification from Admin Console');
      setTargets('');
      setTimeout(refresh, 300);
    } catch (e: any) {
      setError(e?.message || 'Send failed');
    } finally {
      setLoading(false);
    }
  };

  const onToggleDryRun = async () => {
    try {
      const newVal = !Boolean(settings?.dry_run);
      const ns = await client.setNotificationsSettings({ dry_run: newVal });
      setSettings(ns);
    } catch (e: any) {
      setError(e?.message || 'Failed to update settings');
    }
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>Notifications</Typography>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Send test notifications and view the inbox. Plugins with trait <code>handles_notifications</code> will receive NotificationRequest events. Use Gateway Allowlist for external services.
      </Typography>

      <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems="center">
          <TextField label="Title" value={title} onChange={(e)=>setTitle(e.target.value)} size="small" sx={{ minWidth: 220 }} />
          <TextField label="Body" value={body} onChange={(e)=>setBody(e.target.value)} size="small" fullWidth />
          <TextField label="Targets (comma‑sep)" value={targets} onChange={(e)=>setTargets(e.target.value)} size="small" sx={{ minWidth: 240 }} placeholder="mailto://you@ex.com, slack://..." />
          <Button variant="contained" startIcon={<SendIcon />} onClick={onSend} disabled={loading || !!readOnly}>Send</Button>
        </Stack>
        <Stack direction="row" spacing={2} alignItems="center" sx={{ mt: 2 }}>
          <Chip label={`dry_run=${String(Boolean(settings?.dry_run))}`} size="small" onClick={onToggleDryRun} color={settings?.dry_run ? 'warning' : 'success'} clickable />
          {help?.apprise && (
            <Link href={help.apprise} target="_blank" rel="noreferrer" underline="hover"><HelpIcon sx={{ fontSize: 18, mr: 0.5 }} />Apprise docs</Link>
          )}
          {help?.pushover && (
            <Link href={help.pushover} target="_blank" rel="noreferrer" underline="hover"><HelpIcon sx={{ fontSize: 18, mr: 0.5 }} />Pushover API</Link>
          )}
        </Stack>
        {note && <Typography sx={{ mt: 1 }} color="success.main">{note}</Typography>}
        {error && <Typography sx={{ mt: 1 }} color="error.main">{error}</Typography>}
      </Paper>

      <Typography variant="subtitle1" gutterBottom>Inbox</Typography>
      <Paper variant="outlined" sx={{ p: 0 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>When</TableCell>
              <TableCell>ID</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Plugin</TableCell>
              <TableCell>Targets</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(inbox || []).map((it) => {
              const p = it?.payload || {};
              const when = new Date(it?.ts || Date.now()).toLocaleString();
              const targets = (p?.details?.targets || []).join(', ');
              return (
                <TableRow key={it.id}>
                  <TableCell>{when}</TableCell>
                  <TableCell>{p?.notification_id || it?.id}</TableCell>
                  <TableCell>{p?.status || ''}</TableCell>
                  <TableCell>{p?.plugin || ''}</TableCell>
                  <TableCell>{targets}</TableCell>
                </TableRow>
              );
            })}
            {(!inbox || inbox.length === 0) && (
              <TableRow><TableCell colSpan={5}><Typography color="text.secondary">No notifications yet.</Typography></TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>
    </Box>
  );
}

