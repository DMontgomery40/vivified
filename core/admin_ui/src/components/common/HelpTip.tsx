import { useState } from 'react';
import { IconButton, Tooltip, Dialog, DialogTitle, DialogContent, Tabs, Tab, Box, Button, Typography } from '@mui/material';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import { helpTopics, resolveDocHref } from '../../help/topics';

interface HelpTipProps {
  topic: string;
  docsBase?: string;
  size?: 'small' | 'medium';
}

export default function HelpTip({ topic, docsBase, size = 'small' }: HelpTipProps) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState(0);
  const t = helpTopics[topic];
  const docHref = resolveDocHref(docsBase, topic);

  if (!t) return null;

  return (
    <>
      <Tooltip title={`Help — ${t.title}`}>
        <IconButton size={size} onClick={() => setOpen(true)} aria-label={`help ${t.title}`}>
          <HelpOutlineIcon fontSize={size === 'small' ? 'small' : 'medium'} />
        </IconButton>
      </Tooltip>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{t.title}</DialogTitle>
        <DialogContent>
          <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
            <Tab label="Overview" />
            <Tab label="Developer" />
          </Tabs>
          {tab === 0 && (
            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
              {t.eli5}
            </Typography>
          )}
          {tab === 1 && (
            <Box>
              {t.dev.map((line, idx) => (
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

