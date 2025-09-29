import { useEffect, useState } from 'react';
import { Box, Typography, Paper, TextField, Button, Stack, Link, Chip, Table, TableHead, TableRow, TableCell, TableBody, Tabs, Tab } from '@mui/material';
import NotificationsRules from './NotificationsRules';
import SendIcon from '@mui/icons-material/Send';
import HelpIcon from '@mui/icons-material/Help';
import HelpTip from './common/HelpTip';
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
  const [tab, setTab] = useState<number>(0); // 0: Inbox, 1: Send, 2: Rules, 3: Settings, 4: Learn more
  const [limit] = useState<number>(50);
  const [offset, setOffset] = useState<number>(0);

  const refresh = async (nextOffset: number = offset) => {
    try {
      const res = await client.getNotificationsInbox(limit, nextOffset);
      setInbox(res.items || []);
      setOffset(nextOffset);
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

  const [audTraits, setAudTraits] = useState<string>('');

  const onSend = async () => {
    setLoading(true); setError(''); setNote('');
    try {
      const t = (targets || '').split(',').map(s => s.trim()).filter(Boolean);
      const audience = (audTraits || '').split(',').map(s=>s.trim()).filter(Boolean);
      const metadata: any = audience.length ? { audience: { mode: 'traits', traits: audience, scope: 'tenant' } } : undefined;
      const res = await client.sendNotification({ title: title || undefined, body, targets: t.length ? t : undefined, metadata });
      setNote(`Queued status=${res.status} id=${res.notification_id}`);
      setTitle('');
      setBody('Test notification from Admin Console');
      setTargets('');
      setAudTraits('');
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
      <Box display="flex" alignItems="center" justifyContent="space-between">
        <Typography variant="h6" gutterBottom>Notifications</Typography>
        <HelpTip topic="notifications" />
      </Box>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Send, manage, and review notifications. Trait <code>ui.notifications</code> controls access; actions are read‑only for non‑admins.
      </Typography>

      <Paper variant="outlined" sx={{ p: 0 }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tab} onChange={(_, v) => setTab(v)} variant="scrollable" scrollButtons="auto">
            <Tab label="Inbox" />
            <Tab label="Send" />
            <Tab label="Rules" />
            <Tab label="Settings" />
            <Tab label="Learn more" />
          </Tabs>
        </Box>

        <Box sx={{ p: 2 }} hidden={tab !== 0}>
          <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
            <Button variant="outlined" onClick={() => refresh(Math.max(0, offset - limit))} disabled={offset === 0}>Prev</Button>
            <Button variant="outlined" onClick={() => refresh(offset + limit)}>Next</Button>
          </Stack>
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
                const t = (p?.details?.targets || []).join(', ');
                return (
                  <TableRow key={it.id}>
                    <TableCell>{when}</TableCell>
                    <TableCell>{p?.notification_id || it?.id}</TableCell>
                    <TableCell>{p?.status || ''}</TableCell>
                    <TableCell>{p?.plugin || ''}</TableCell>
                    <TableCell>{t}</TableCell>
                  </TableRow>
                );
              })}
              {(!inbox || inbox.length === 0) && (
                <TableRow><TableCell colSpan={5}><Typography color="text.secondary">No notifications yet.</Typography></TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </Box>

        <Box sx={{ p: 2 }} hidden={tab !== 1}>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems="center">
            <TextField label="Title" value={title} onChange={(e)=>setTitle(e.target.value)} size="small" sx={{ minWidth: 220 }} />
            <TextField label="Body" value={body} onChange={(e)=>setBody(e.target.value)} size="small" fullWidth />
            <TextField label="Targets (comma‑sep)" value={targets} onChange={(e)=>setTargets(e.target.value)} size="small" sx={{ minWidth: 240 }} placeholder="mailto://you@ex.com, slack://..." />
            <TextField label="Audience Traits (comma‑sep)" value={audTraits} onChange={(e)=>setAudTraits(e.target.value)} size="small" sx={{ minWidth: 240 }} placeholder="e.g. sales, customer_success" />
            <Button variant="contained" startIcon={<SendIcon />} onClick={onSend} disabled={loading || !!readOnly}>Send</Button>
          </Stack>
          {note && <Typography sx={{ mt: 2 }} color="success.main">{note}</Typography>}
          {error && <Typography sx={{ mt: 1 }} color="error.main">{error}</Typography>}
        </Box>

        <Box sx={{ p: 2 }} hidden={tab !== 2}>
          <NotificationsRules client={client} readOnly={readOnly} />
        </Box>

        <Box sx={{ p: 2 }} hidden={tab !== 3}>
          <Stack direction="row" spacing={2} alignItems="center">
            <Chip 
              label={`dry_run=${String(Boolean(settings?.dry_run))}`} 
              size="small" 
              onClick={readOnly ? undefined : onToggleDryRun} 
              color={settings?.dry_run ? 'warning' : 'success'} 
              clickable={!readOnly}
            />
          </Stack>
          {error && <Typography sx={{ mt: 1 }} color="error.main">{error}</Typography>}
        </Box>

        <Box sx={{ p: 2 }} hidden={tab !== 4}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            Helpful links for configuring notification channels:
          </Typography>
          <Stack direction="row" spacing={2} alignItems="center" sx={{ flexWrap: 'wrap' }}>
            {Object.entries(help || {}).map(([k, v]) => (
              <Link key={k} href={v} target="_blank" rel="noreferrer" underline="hover">
                <HelpIcon sx={{ fontSize: 18, mr: 0.5 }} />{k}
              </Link>
            ))}
            {(!help || Object.keys(help).length === 0) && (
              <Typography color="text.secondary">No help links available.</Typography>
            )}
          </Stack>
        </Box>
      </Paper>
    </Box>
  );
}
