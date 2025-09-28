import { useEffect, useState } from 'react';
import { Box, Paper, Typography, TextField, Button, Grid, Table, TableHead, TableRow, TableCell, TableBody } from '@mui/material';
import AdminAPIClient from '../api/client';

interface Props { client: AdminAPIClient }

export default function StorageBrowser({ client }: Props) {
  const [items, setItems] = useState<any[]>([]);
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [classification, setClassification] = useState('');

  const refresh = async () => {
    const data = await client.storageList(limit, offset, classification || undefined);
    setItems(data.items || []);
  };

  useEffect(() => { refresh(); }, []);

  const download = async (k: string) => {
    const blob = await client.storageDownload(k);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = k; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Paper elevation={0} sx={{ p: 2 }}>
      <Typography variant="h6" sx={{ mb: 2 }}>Storage Browser</Typography>
      <Grid container spacing={2} sx={{ mb: 2 }}>
        <Grid item xs={12} sm={3}><TextField label="Classification (phi/pii/...)" value={classification} onChange={e=>setClassification(e.target.value)} fullWidth /></Grid>
        <Grid item xs={6} sm={2}><TextField type="number" label="Limit" value={limit} onChange={e=>setLimit(Number(e.target.value))} fullWidth /></Grid>
        <Grid item xs={6} sm={2}><TextField type="number" label="Offset" value={offset} onChange={e=>setOffset(Number(e.target.value))} fullWidth /></Grid>
        <Grid item xs={12} sm={2}><Button variant="contained" onClick={refresh}>Refresh</Button></Grid>
      </Grid>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Key</TableCell>
            <TableCell>Class</TableCell>
            <TableCell>Provider</TableCell>
            <TableCell align="right">Size</TableCell>
            <TableCell>Created</TableCell>
            <TableCell>Expires</TableCell>
            <TableCell></TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {items.map((m) => (
            <TableRow key={m.object_key} hover>
              <TableCell>{m.object_key}</TableCell>
              <TableCell>{m.data_classification}</TableCell>
              <TableCell>{m.provider}</TableCell>
              <TableCell align="right">{m.size_bytes}</TableCell>
              <TableCell>{m.created_at}</TableCell>
              <TableCell>{m.expires_at || ''}</TableCell>
              <TableCell><Button size="small" onClick={()=>download(m.object_key)}>Download</Button></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Paper>
  );
}

