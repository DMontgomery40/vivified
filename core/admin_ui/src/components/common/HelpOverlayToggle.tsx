import { useEffect, useState } from 'react';
import { Fab, Tooltip } from '@mui/material';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';

export default function HelpOverlayToggle() {
  const [on, setOn] = useState(false);

  useEffect(() => {
    const current = document.documentElement.getAttribute('data-help-overlay') === '1';
    setOn(current);
  }, []);

  const toggle = () => {
    const next = !on;
    setOn(next);
    document.documentElement.setAttribute('data-help-overlay', next ? '1' : '0');
    window.dispatchEvent(new CustomEvent('help-overlay-changed', { detail: { on: next } }));
  };

  return (
    <Tooltip title={on ? 'Hide help hotspots' : 'Show help hotspots'}>
      <Fab
        color={on ? 'secondary' : 'default'}
        size="small"
        onClick={toggle}
        sx={{
          position: 'fixed',
          right: 16,
          bottom: 16,
          zIndex: (theme) => theme.zIndex.tooltip + 1,
        }}
      >
        <HelpOutlineIcon />
      </Fab>
    </Tooltip>
  );
}

