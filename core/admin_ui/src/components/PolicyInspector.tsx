import { useEffect, useState } from 'react';
import { Box, Paper, Typography, Chip } from '@mui/material';
import HelpTip from './common/HelpTip';
import AdminAPIClient from '../api/client';

interface Props { client: AdminAPIClient; }

export default function PolicyInspector({ client }: Props) {
  const [traits, setTraits] = useState<{ backend_traits: string[]; traits: string[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await client.getUserTraits();
        setTraits({ backend_traits: res.backend_traits || [], traits: res.traits || [] });
      } catch (e: any) { setError(e?.message || 'Failed to load traits'); }
    })();
  }, []);

  return (
    <Paper elevation={0} sx={{ p: 2 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h6">Policy / Trait Inspector</Typography>
        <HelpTip topic="policy" />
      </Box>
      {error && <Typography color="error">{error}</Typography>}
      {traits && (
        <Box>
          <Typography variant="subtitle1" sx={{ mt: 1 }}>Backend Traits</Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>
            {traits.backend_traits.map(t => <Chip key={t} label={t} size="small" />)}
          </Box>
          <Typography variant="subtitle1" sx={{ mt: 2 }}>UI Traits</Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>
            {traits.traits.map(t => <Chip key={t} label={t} color="primary" size="small" />)}
          </Box>
        </Box>
      )}
    </Paper>
  );
}
