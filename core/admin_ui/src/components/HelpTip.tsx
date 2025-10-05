import { useState } from 'react';
import { IconButton, Tooltip, Dialog, DialogTitle, DialogContent, Typography } from '@mui/material';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';

export default function HelpTip({ title, content }: { title: string; content: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Tooltip title={title}>
        <IconButton size="small" onClick={() => setOpen(true)} aria-label={`help: ${title}`}>
          <InfoOutlinedIcon fontSize="small" />
        </IconButton>
      </Tooltip>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>{title}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>{content}</Typography>
        </DialogContent>
      </Dialog>
    </>
  );
}

