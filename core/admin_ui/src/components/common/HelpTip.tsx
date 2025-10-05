//
import { IconButton, Tooltip, Dialog, DialogTitle, DialogContent, Tabs, Tab, Box, Button, Typography } from '@mui/material';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import { helpTopics, resolveDocHref } from '../../help/topics';
import { useEffect, useState } from 'react';

interface HelpTipProps {
  topic: string;
  docsBase?: string;
  size?: 'small' | 'medium';
}

export default function HelpTip({ topic, docsBase, size = 'small' }: HelpTipProps) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState(0);
  const [userTraits, setUserTraits] = useState<string[] | null>(null);
  const t = helpTopics[topic];
  const docHref = resolveDocHref(docsBase, topic);

  // Fetch user traits on first open to support trait-aware help variants
  useEffect(() => {
    if (!open || userTraits !== null) return;
    (async () => {
      try {
        const key = localStorage.getItem('vivified_admin_key') || localStorage.getItem('faxbot_admin_key') || '';
        const res = await fetch('/admin/user/traits', { headers: { 'Authorization': `Bearer ${key}`, 'X-API-Key': key } });
        if (res.ok) {
          const js = await res.json();
          setUserTraits(js?.traits || []);
        } else {
          setUserTraits([]);
        }
      } catch {
        setUserTraits([]);
      }
    })();
  }, [open, userTraits]);

  // Apply trait-based variant overrides if present
  const resolved = (() => {
    if (!t) return null;
    const variants = t.variants || [];
    let match: typeof variants[number] | undefined;
    const traits = new Set((userTraits || []) as string[]);
    for (const v of variants) {
      if (v.whenAllTraits && v.whenAllTraits.every(tr => traits.has(tr))) { match = v; break; }
      if (v.whenAnyTrait && v.whenAnyTrait.some(tr => traits.has(tr))) { match = v; }
    }
    if (!match) return t;
    return {
      ...t,
      eli5: match.eli5 || t.eli5,
      dev: match.dev || t.dev,
    };
  })();

  if (!resolved) return null;

  // Overlay highlighter: highlight help icons when overlay is enabled
  const [overlay, setOverlay] = useState<boolean>(document.documentElement.getAttribute('data-help-overlay') === '1');
  useEffect(() => {
    const handler = (e: any) => setOverlay(Boolean(e?.detail?.on ?? (document.documentElement.getAttribute('data-help-overlay') === '1')));
    window.addEventListener('help-overlay-changed', handler as any);
    return () => window.removeEventListener('help-overlay-changed', handler as any);
  }, []);

  return (
    <>
      <Tooltip title={`Help — ${resolved.title}`}>
        <IconButton
          size={size}
          onClick={() => setOpen(true)}
          aria-label={`help ${t.title}`}
          sx={overlay ? {
            boxShadow: (theme) => `0 0 0 3px ${theme.palette.info.light}`,
            animation: 'helpPulse 1.4s ease-in-out infinite',
            '@keyframes helpPulse': {
              '0%': { boxShadow: (theme) => `0 0 0 3px ${theme.palette.info.light}` },
              '50%': { boxShadow: (theme) => `0 0 0 6px ${theme.palette.info.main}` },
              '100%': { boxShadow: (theme) => `0 0 0 3px ${theme.palette.info.light}` },
            },
          } : undefined}
        >
          <HelpOutlineIcon fontSize={size === 'small' ? 'small' : 'medium'} />
        </IconButton>
      </Tooltip>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{resolved.title}</DialogTitle>
        <DialogContent>
          <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
            <Tab label="Overview" />
            <Tab label="Developer" />
          </Tabs>
          {tab === 0 && (
            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
              {resolved.eli5}
            </Typography>
          )}
          {tab === 1 && (
            <Box>
              {resolved.dev.map((line, idx) => (
                <Typography key={idx} variant="body2" sx={{ display: 'block', mb: 0.5 }}>
                  • {line}
                </Typography>
              ))}
            </Box>
          )}
          <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
            {docHref ? (
              <Button href={docHref} target="_blank" rel="noreferrer" variant="outlined">
                Learn more
              </Button>
            ) : (
              <Typography variant="caption" color="text.secondary">Docs coming soon</Typography>
            )}
          </Box>
        </DialogContent>
      </Dialog>
    </>
  );
}
