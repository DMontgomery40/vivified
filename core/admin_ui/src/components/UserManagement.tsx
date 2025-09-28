import { useEffect, useState } from 'react';
import { Box, Typography, Paper, Alert, Button, TextField, Table, TableHead, TableRow, TableCell, TableBody, Stack, FormControl, InputLabel, Select, MenuItem } from '@mui/material';
import HelpTip from './common/HelpTip';
import AdminAPIClient from '../api/client';

type Props = { client: AdminAPIClient };

type User = {
  id: string;
  username: string;
  display_name?: string | null;
  email?: string | null;
  is_active: boolean;
  created_at?: string | null;
  roles?: string[];
};

export default function UserManagement({ client }: Props) {
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [newUser, setNewUser] = useState<{ username: string; password: string; display_name?: string; email?: string; role?: string }>({ username: '', password: '' });
  const [roles, setRoles] = useState<Array<{ name: string }>>([])

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await client.listUsers();
      setUsers(res.users || []);
      try { const rr = await client.getRoles(); setRoles(rr.roles || []) } catch {}
    } catch (e: any) {
      setError('User API is not available yet or you lack permissions.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const create = async () => {
    try {
      await client.createUser({
        username: newUser.username,
        password: newUser.password,
        display_name: newUser.display_name,
        email: newUser.email,
      });
      // Assign role if selected
      if (newUser.role) {
        try {
          const created = (await client.listUsers()).users.find(u => u.username === newUser.username)
          if (created?.id) await client.setUserRoles(created.id, [newUser.role])
        } catch {}
      }
      setNewUser({ username: '', password: '' });
      await load();
    } catch (e: any) {
      setError('Failed to create user: ' + (e?.message || 'unknown error'));
    }
  };

  const toggleActive = async (u: User) => {
    try {
      await client.patchUser(u.id, { is_active: !u.is_active });
      await load();
    } catch (e: any) {
      setError('Failed to update user: ' + (e?.message || 'unknown error'));
    }
  };

  return (
    <Paper elevation={0} sx={{ p: { xs: 2, md: 3 }, border: '1px solid', borderColor: 'divider', borderRadius: 2 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h6" gutterBottom>User Management</Typography>
        <HelpTip topic="users" />
      </Box>
      {error && <Alert severity="warning" sx={{ mb: 2 }}>{error}</Alert>}

      <Box sx={{ mb: 3 }}>
        <Typography variant="subtitle1" gutterBottom>Create User</Typography>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
          <TextField label="Username" value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} size="small" />
          <TextField label="Password" type="password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} size="small" />
          <TextField label="Display Name" value={newUser.display_name || ''} onChange={(e) => setNewUser({ ...newUser, display_name: e.target.value })} size="small" />
          <TextField label="Email" value={newUser.email || ''} onChange={(e) => setNewUser({ ...newUser, email: e.target.value })} size="small" />
          <FormControl size="small" sx={{ minWidth: 160 }}>
            <InputLabel id="role-select-label">Role</InputLabel>
            <Select labelId="role-select-label" value={newUser.role || ''} label="Role" onChange={e=>setNewUser({ ...newUser, role: String(e.target.value) })}>
              <MenuItem value=""><em>None</em></MenuItem>
              {roles.map(r => <MenuItem key={r.name} value={r.name}>{r.name}</MenuItem>)}
            </Select>
          </FormControl>
          <Button variant="contained" onClick={create} disabled={!newUser.username || !newUser.password}>Create</Button>
        </Stack>
      </Box>

      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Username</TableCell>
            <TableCell>Display Name</TableCell>
            <TableCell>Email</TableCell>
            <TableCell>Roles</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {users.map((u) => (
            <TableRow key={u.id}>
              <TableCell>{u.username}</TableCell>
              <TableCell>{u.display_name || '-'}</TableCell>
              <TableCell>{u.email || '-'}</TableCell>
              <TableCell>{(u.roles||[]).join(', ') || '-'}</TableCell>
              <TableCell>{u.is_active ? 'Active' : 'Disabled'}</TableCell>
              <TableCell>
                <Button variant="outlined" size="small" onClick={() => toggleActive(u)}>
                  {u.is_active ? 'Disable' : 'Enable'}
                </Button>
              </TableCell>
            </TableRow>
          ))}
          {users.length === 0 && !loading && (
            <TableRow>
              <TableCell colSpan={5}>
                <Typography variant="body2" color="text.secondary">No users found.</Typography>
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </Paper>
  );
}
