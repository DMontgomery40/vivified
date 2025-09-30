import { useState } from 'react';
import { Box, Paper, Typography, Button, TextField, Alert, Stack } from '@mui/material';
import HelpTip from './common/HelpTip';
import AdminAPIClient from '../api/client';

type Props = {
  client: AdminAPIClient;
  readOnly?: boolean;
};

export default function MFA({ client, readOnly }: Props) {
  const [totpCode, setTotpCode] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);

  const handleSetupTotp = async () => {
    setMessage(null); setError(null); setQr(null); setSecret(null); setBackupCodes(null);
    try {
      const res = await client.mfaSetup();
      setSecret(res.secret || null);
      setQr(res.qr_png || res.qr || res.qr_code || null);
      setBackupCodes(res.backup_codes || null);
      setMessage('TOTP setup initialized. Scan the QR code or enter the secret in your authenticator app.');
    } catch (e: any) {
      setError(e?.message || 'Failed to initialize TOTP');
    }
  };

  const handleEnableTotp = async () => {
    setMessage(null); setError(null);
    try {
      const res = await client.mfaEnable({ totp_code: totpCode });
      if (res?.enabled) setMessage(`MFA enabled (${res.method}).`);
      else setError('Failed to enable MFA.');
    } catch (e: any) {
      setError(e?.message || 'Failed to enable MFA');
    }
  };

  return (
    <Paper elevation={0} sx={{ p: { xs: 2, md: 3 }, borderRadius: 3, border: '1px solid', borderColor: 'divider' }}>
      <Box display="flex" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
        <Typography variant="h6">MFA & Passkeys</Typography>
        <HelpTip topic="mfa" />
      </Box>

      {message && <Alert severity="success" sx={{ mb: 2 }}>{message}</Alert>}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Box sx={{ mb: 3 }}>
        <Typography variant="subtitle1" sx={{ mb: 1 }}>Time-based One-Time Password (TOTP)</Typography>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems="flex-start">
          <Button variant="contained" onClick={handleSetupTotp} disabled={!!readOnly}>Setup TOTP</Button>
          <TextField
            label="TOTP Code"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value)}
            inputProps={{ inputMode: 'numeric', pattern: '[0-9]*' }}
          />
          <Button variant="outlined" onClick={handleEnableTotp} disabled={!!readOnly || !totpCode}>Enable</Button>
        </Stack>
        {secret && (
          <Alert severity="info" sx={{ mt: 2 }}>
            Secret: <code>{secret}</code>
          </Alert>
        )}
        {qr && (
          <Box sx={{ mt: 2 }}>
            <img src={qr.startsWith('data:') ? qr : `data:image/png;base64,${qr}`} alt="MFA QR" style={{ maxWidth: 240 }} />
          </Box>
        )}
        {backupCodes && backupCodes.length > 0 && (
          <Alert severity="info" sx={{ mt: 2 }}>
            Backup codes:
            <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{backupCodes.join('\n')}</pre>
          </Alert>
        )}
      </Box>

      <Box>
        <Typography variant="subtitle1" sx={{ mb: 1 }}>Passkeys (WebAuthn)</Typography>
        <Typography variant="body2" sx={{ mb: 2 }}>
          Passkey registration flows vary by browser and OS. This UI will be expanded with
          a full WebAuthn journey; for now, use the Diagnostics or Scripts & Tests to
          exercise the backend endpoints.
        </Typography>
        <Button variant="outlined" disabled>Register Passkey (coming soon)</Button>
      </Box>
    </Paper>
  );
}
