import { useEffect, useMemo, useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  IconButton,
  Stack,
  Alert,
  Divider,
  Chip,
} from '@mui/material';
import { Add as AddIcon, Save as SaveIcon, Delete as DeleteIcon, Refresh as RefreshIcon, Public as DomainIcon } from '@mui/icons-material';
import HelpTip from './common/HelpTip';
import AdminAPIClient from '../api/client';

type AllowRule = { allowed_methods: string[]; allowed_paths: string[] };

interface Props { client: AdminAPIClient }

function parseCSV(value: string): string[] {
  return value
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);
}

export default function GatewayAllowlist({ client }: Props) {
  const [pluginId, setPluginId] = useState('');
  const [items, setItems] = useState<Record<string, AllowRule>>({});
  const [domain, setDomain] = useState('');
  const [methods, setMethods] = useState('GET,POST');
  const [paths, setPaths] = useState('/*');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const canSave = useMemo(() => pluginId && Object.keys(items).length >= 0, [pluginId, items]);

  const handleAdd = () => {
    if (!domain) return;
    const next: Record<string, AllowRule> = { ...items };
    next[domain] = { allowed_methods: parseCSV(methods).map((m) => m.toUpperCase()), allowed_paths: parseCSV(paths) };
    setItems(next);
    setDomain('');
    setMethods('GET,POST');
    setPaths('/*');
  };

  const handleRemove = (d: string) => {
    const next = { ...items };
    delete next[d];
    setItems(next);
  };

  const fetchAllowlist = async () => {
    if (!pluginId) return;
    try {
      setLoading(true);
      setError(null);
      const res = await client.getGatewayAllowlist(pluginId);
      setItems(res.items || {});
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load allowlist');
    } finally {
      setLoading(false);
    }
  };

  const saveAllowlist = async () => {
    try {
      setError(null);
      setSaved(false);
      await client.setGatewayAllowlist({ plugin_id: pluginId, allowlist: items });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save allowlist');
    }
  };

  useEffect(() => {
    setItems({});
  }, [pluginId]);

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h5" fontWeight={600}>Gateway Allowlist</Typography>
        <Box display="flex" gap={1}>
          <HelpTip topic="gateway-allowlist" />
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={fetchAllowlist} disabled={!pluginId || loading} sx={{ borderRadius: 2 }}>Refresh</Button>
          <Button variant="contained" startIcon={<SaveIcon />} onClick={saveAllowlist} disabled={!canSave} sx={{ borderRadius: 2 }}>Save</Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>
      )}
      {saved && (
        <Alert severity="success" sx={{ mb: 2 }}>Saved</Alert>
      )}

      <Paper variant="outlined" sx={{ p: 2, borderRadius: 2, mb: 2 }}>
        <Typography variant="subtitle2" gutterBottom>Plugin</Typography>
        <TextField
          value={pluginId}
          onChange={(e) => setPluginId(e.target.value)}
          placeholder="plugin-uuid or name"
          size="small"
          fullWidth
          InputProps={{ startAdornment: <DomainIcon sx={{ mr: 1, color: 'text.secondary' }} /> as any }}
        />
      </Paper>

      <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
        <Typography variant="subtitle2" gutterBottom>Add Domain Rule</Typography>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
          <TextField label="Domain" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="api.example.com" size="small" fullWidth />
          <TextField label="Methods (CSV)" value={methods} onChange={(e) => setMethods(e.target.value)} placeholder="GET,POST" size="small" fullWidth />
          <TextField label="Paths (CSV)" value={paths} onChange={(e) => setPaths(e.target.value)} placeholder="/*,/v1/*" size="small" fullWidth />
          <Button variant="outlined" startIcon={<AddIcon />} onClick={handleAdd} sx={{ borderRadius: 2 }}>Add</Button>
        </Stack>
      </Paper>

      <Box mt={3}>
        <Typography variant="subtitle2" gutterBottom>Current Rules</Typography>
        {Object.keys(items).length === 0 ? (
          <Paper variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
            <Typography color="text.secondary">No rules. Add a domain above.</Typography>
          </Paper>
        ) : (
          <Stack spacing={2}>
            {Object.entries(items).map(([d, rule]) => (
              <Paper key={d} variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
                <Box display="flex" justifyContent="space-between" alignItems="center">
                  <Box>
                    <Typography variant="subtitle1" fontWeight={600}>{d}</Typography>
                    <Box mt={1}>
                      <Typography variant="caption" color="text.secondary">Allowed Methods</Typography>
                      <Box mt={0.5} sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {(rule.allowed_methods || []).map((m) => (<Chip key={m} size="small" label={m} />))}
                      </Box>
                    </Box>
                    <Box mt={1}>
                      <Typography variant="caption" color="text.secondary">Allowed Paths</Typography>
                      <Box mt={0.5} sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                        {(rule.allowed_paths || []).map((p) => (<Chip key={p} size="small" label={p} variant="outlined" />))}
                      </Box>
                    </Box>
                  </Box>
                  <IconButton color="error" onClick={() => handleRemove(d)} aria-label={`remove ${d}`}>
                    <DeleteIcon />
                  </IconButton>
                </Box>
                <Divider sx={{ mt: 2 }} />
              </Paper>
            ))}
          </Stack>
        )}
      </Box>
    </Box>
  );
}
