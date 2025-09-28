import { useEffect, useState } from 'react'
import { Typography, Paper, Alert, Table, TableHead, TableRow, TableCell, TableBody, TableContainer, TextField, Stack, Button, Box } from '@mui/material'
import HelpTip from './common/HelpTip'
import AdminAPIClient from '../api/client'

type Props = { client: AdminAPIClient }

export default function Audit({ client }: Props){
  const [items,setItems] = useState<any[]>([])
  const [error,setError] = useState('')
  const [limit,setLimit] = useState(100)
  const [offset,setOffset] = useState(0)

  const load = async ()=>{
    try{
      setError('')
      const res = await client.getAudit(limit, offset)
      setItems(res.items || [])
    }catch(e:any){ setError(e?.message || 'Failed to load audit') }
  }

  useEffect(()=>{ load() },[limit,offset])

  return (
    <Paper elevation={0} sx={{ p:{xs:2, md:3}, border:'1px solid', borderColor:'divider', borderRadius:2 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h6" gutterBottom>Audit Events</Typography>
        <HelpTip topic="audit" />
      </Box>
      {error && <Alert severity="warning" sx={{mb:2}}>{error}</Alert>}
      <Stack direction={{xs:'column', sm:'row'}} spacing={2} sx={{mb:2}}>
        <TextField size="small" label="Limit" type="number" value={limit} onChange={e=>setLimit(parseInt(e.target.value||'0')||100)} />
        <TextField size="small" label="Offset" type="number" value={offset} onChange={e=>setOffset(parseInt(e.target.value||'0')||0)} />
        <Button variant="outlined" onClick={()=>load()}>Refresh</Button>
      </Stack>
      <TableContainer>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Time</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Result</TableCell>
              <TableCell>Resource</TableCell>
              <TableCell>Details</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {items.map((it,idx)=> (
              <TableRow key={idx}>
                <TableCell>{it.ts || it.timestamp || ''}</TableCell>
                <TableCell>{it.type || it.event_type || ''}</TableCell>
                <TableCell>{it.action || ''}</TableCell>
                <TableCell>{it.result || ''}</TableCell>
                <TableCell>{[it.resource_type, it.resource_id].filter(Boolean).join(':')}</TableCell>
                <TableCell><code style={{fontSize:12}}>{JSON.stringify(it.details||{}, null, 0)}</code></TableCell>
              </TableRow>
            ))}
            {items.length===0 && (
              <TableRow><TableCell colSpan={6}><Typography variant="body2" color="text.secondary">No audit events.</Typography></TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Paper>
  )
}
