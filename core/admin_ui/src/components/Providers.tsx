import { useCallback, useEffect, useMemo, useState } from 'react';
import { Box, Button, Chip, CircularProgress, Grid, Paper, Tooltip, Typography } from '@mui/material';
import HubIcon from '@mui/icons-material/Hub';
import LinkIcon from '@mui/icons-material/Link';
import LinkOffIcon from '@mui/icons-material/LinkOff';
import RefreshIcon from '@mui/icons-material/Refresh';
import ShieldIcon from '@mui/icons-material/GppGood';
import type { AdminAPIClient } from '../api/client';

type ProviderItem = { provider: string; name: string; connected: boolean; details?: { account_name?: string } };

export default function Providers({ client, canManage }: { client: AdminAPIClient; canManage: boolean }) {
  const [loading, setLoading] = useState<boolean>(false);
  const [items, setItems] = useState<Array<ProviderItem & { blocked?: boolean }>>([]);
  const [error, setError] = useState<string>('');

  const hipaaBlockedCount = useMemo(() => items.filter(i => i.blocked).length, [items]);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await client.listIntegrations();
      const base = (res?.items || []) as ProviderItem[];
      // Probe HIPAA block via status endpoint deterministically
      const probed = await Promise.all(base.map(async (it) => {
        try {
          await client.statusIntegration(it.provider);
          return { ...it, blocked: false };
        } catch (e: any) {
          try {
            const msg = String(e?.message || '');
            // Lightweight detection; server returns 403 with error.code=integration.not_allowed
            if (msg.includes('403')) {
              return { ...it, blocked: true, connected: false };
            }
          } catch {}
          return { ...it };
        }
      }));
      setItems(probed);
    } catch (e: any) {
      const msg: string = String(e?.message || '');
      if (msg.includes('503')) {
        setError('Integration service unavailable');
      } else {
        setError('Failed to load providers');
      }
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    const handler = (e: MessageEvent) => {
      if (typeof e.data === 'string' && e.data.startsWith('integrations:') && e.data.endsWith(':connected')) {
        refresh();
      }
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, [refresh]);

  useEffect(() => {
    const onMessage = (ev: MessageEvent) => {
      if (typeof ev.data === 'string' && ev.data === 'integrations:hubspot:connected') {
        refresh();
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [refresh]);

  const handleConnect = async (provider: string) => {
    try {
      const { url } = await client.connectIntegration(provider, true);
      if (url) {
        window.open(url, '_blank', 'noopener');
      }
    } catch (e) {
      // no-op; API will handle HIPAA blocks and errors
    }
  };

  const handleRevoke = async (provider: string) => {
    if (!window.confirm('Revoke connection for this provider?')) return;
    try {
      await client.revokeIntegration(provider);
      await refresh();
    } catch (e) {
      // ignore
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <HubIcon color="primary" />
        <Typography variant="h6">Providers</Typography>
        <Box sx={{ flex: 1 }} />
        <Button startIcon={<RefreshIcon />} onClick={refresh} disabled={loading} variant="outlined">Refresh</Button>
      </Box>
      {hipaaBlockedCount > 0 && (
        <Paper sx={{ p: 2, mb: 2, borderLeft: '4px solid', borderColor: 'warning.main' }}>
          <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ShieldIcon color="warning" /> Compliance mode is ON. Some providers are disabled by policy.
          </Typography>
        </Paper>
      )}
      {error && (
        <Paper sx={{ p: 2, mb: 2, borderLeft: '4px solid', borderColor: 'error.main' }}>
          <Typography color="error" variant="body2">{error}</Typography>
        </Paper>
      )}
      {loading ? (
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', py: 6 }}>
          <CircularProgress />
        </Box>
      ) : (
        <Grid container spacing={2}>
          {items.map((it) => (
            <Grid item xs={12} md={6} key={it.provider}>
              <Paper sx={{ p: 2, display: 'flex', alignItems: 'center', gap: 2 }}>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="subtitle1">{it.name}</Typography>
                  <Typography variant="body2" color="text.secondary">{it.provider}</Typography>
                  <Box sx={{ mt: 1 }}>
                    {it.blocked ? (
                      <Chip label="Disabled by policy" color="warning" size="small" />
                    ) : it.connected ? (
                      <Chip label={it.details?.account_name ? `Connected (${it.details.account_name})` : 'Connected'} color="success" size="small" />
                    ) : (
                      <Chip label="Not connected" variant="outlined" size="small" />
                    )}
                  </Box>
                </Box>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Tooltip title={it.blocked ? 'Disabled by compliance policy' : 'Open provider auth in a new tab'}>
                    <span>
                      <Button
                        size="small"
                        variant="contained"
                        startIcon={<LinkIcon />}
                        disabled={!canManage || !!it.blocked}
                        onClick={() => handleConnect(it.provider)}
                      >
                        Connect
                      </Button>
                    </span>
                  </Tooltip>
                  <Tooltip title={it.blocked ? 'Disabled by compliance policy' : 'Revoke connection'}>
                    <span>
                      <Button
                        size="small"
                        color="error"
                        variant="outlined"
                        startIcon={<LinkOffIcon />}
                        disabled={!canManage || !!it.blocked || !it.connected}
                        onClick={() => handleRevoke(it.provider)}
                      >
                        Revoke
                      </Button>
                    </span>
                  </Tooltip>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>
      )}
    </Box>
  );
}
