import { useState } from 'react';
import { Box, Paper, Typography, TextField, Button, Grid, Alert } from '@mui/material';
import AdminAPIClient from '../api/client';

interface Props {
  client: AdminAPIClient;
}

export default function GatewayTester({ client }: Props) {
  const [method, setMethod] = useState('GET');
  const [url, setUrl] = useState('https://httpbin.org/get');
  const [headers, setHeaders] = useState('{
  "accept": "application/json"
}');
  const [body, setBody] = useState('');
  const [pluginId, setPluginId] = useState('admin-ui');
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const send = async () => {
    setError(null);
    setResult(null);
    let hdrs: Record<string, string> = {};
    try {
      hdrs = headers ? JSON.parse(headers) : {};
    } catch (e) {
      setError('Headers must be valid JSON');
      return;
    }
    try {
      const res = await client.proxyRequest({
        plugin_id: pluginId,
        method,
        url,
        headers: hdrs,
        body,
      });
      setResult(res);
    } catch (e: any) {
      setError(e?.message || 'Proxy request failed');
    }
  };

  return (
    <Paper elevation={0} sx={{ p: 2 }}>
      <Typography variant="h6" sx={{ mb: 2 }}>Gateway Proxy Tester</Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} sm={2}>
          <TextField label="Method" value={method} onChange={e=>setMethod(e.target.value)} fullWidth />
        </Grid>
        <Grid item xs={12} sm={7}>
          <TextField label="URL" value={url} onChange={e=>setUrl(e.target.value)} fullWidth />
        </Grid>
        <Grid item xs={12} sm={3}>
          <TextField label="Plugin ID" value={pluginId} onChange={e=>setPluginId(e.target.value)} fullWidth />
        </Grid>
        <Grid item xs={12}>
          <TextField label="Headers (JSON)" value={headers} onChange={e=>setHeaders(e.target.value)} fullWidth multiline minRows={3} />
        </Grid>
        <Grid item xs={12}>
          <TextField label="Body" value={body} onChange={e=>setBody(e.target.value)} fullWidth multiline minRows={3} />
        </Grid>
        <Grid item xs={12}>
          <Button variant="contained" onClick={send}>Send</Button>
        </Grid>
      </Grid>
      {error && <Alert sx={{ mt: 2 }} severity="error">{error}</Alert>}
      {result && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle1">Response</Typography>
          <pre style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(result, null, 2)}</pre>
        </Box>
      )}
    </Paper>
  );
}

