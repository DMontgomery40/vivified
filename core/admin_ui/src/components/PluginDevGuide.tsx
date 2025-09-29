import { useState } from 'react';
import { Box, Typography, Paper, Stack, Alert, Button, Chip, Divider, TextField } from '@mui/material';
import HelpTip from './common/HelpTip';
import AdminAPIClient from '../api/client';

export default function PluginDevGuide({ client }: { client: AdminAPIClient }) {
  const [manifest, setManifest] = useState<string>(`{
  "id": "patient-record-manager",
  "name": "Patient Record Manager",
  "version": "1.0.0",
  "traits": ["communication_plugin", "handles_phi", "audit_required", "encryption_required"],
  "endpoints": { "get_record": "/api/patients/{patient_id}", "create_record": "/api/patients/{patient_id}/records" }
}`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h4" component="h1">Plugin Development Guide</Typography>
        <HelpTip topic="plugin-dev" />
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Follow these steps to build secure plugins. All features are trait-gated and audited. Use canonical models and avoid PHI in logs.
      </Typography>

      <Stack spacing={2}>
        <Paper sx={{ p: 2, borderRadius: 2 }}>
          <Typography variant="h6" gutterBottom>1) Plan & Design</Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Define capabilities, data handling, and compliance controls. Assign required traits like <code>handles_phi</code> and <code>audit_required</code>.
          </Typography>
          <TextField
            label="Plugin Manifest (JSON)"
            value={manifest}
            onChange={(e) => setManifest(e.target.value)}
            fullWidth
            multiline
            minRows={6}
            sx={{ '& .MuiOutlinedInput-root': { borderRadius: 2, fontFamily: 'monospace', fontSize: '0.875rem' } }}
          />
        </Paper>

        <Paper sx={{ p: 2, borderRadius: 2 }}>
          <Typography variant="h6" gutterBottom>2) Implement</Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Use the Python SDK decorators to define RPC endpoints and event handlers. Enforce traits at the policy layer.
          </Typography>
          <Paper variant="outlined" sx={{ p: 2, bgcolor: 'background.default' }}>
            <pre style={{ margin: 0, fontSize: '0.8rem' }}>{`from vivified_sdk import VivifiedPlugin, rpc_endpoint, require_traits, audit_log, track_metrics, SecurityContext

class PatientRecordManager(VivifiedPlugin):
    def __init__(self):
        super().__init__("manifest.json")

    @rpc_endpoint("/api/patients/{patient_id}")
    @require_traits(["handles_phi", "authenticated"]) 
    @audit_log("patient_record_access")
    @track_metrics("record_retrieval")
    async def get_patient_record(self, patient_id: str, context: SecurityContext) -> dict:
        return {"patient_id": patient_id, "records": []}
`}</pre>
          </Paper>
        </Paper>

        <Paper sx={{ p: 2, borderRadius: 2 }}>
          <Typography variant="h6" gutterBottom>3) Test & Validate</Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Run unit tests locally. Smoke test in Admin → Tools → Scripts & Tests. Ensure CI is green at each step.
          </Typography>
          <Stack direction="row" spacing={1}>
            <Chip label="Traits" size="small" />
            <Chip label="Audit" size="small" />
            <Chip label="Canonical" size="small" />
          </Stack>
        </Paper>

        <Alert severity="info" sx={{ borderRadius: 2 }}>
          Tip: Use the Plugins and Register tabs to manage manifests and gateway allowlists. All actions are logged.
        </Alert>

        <Divider />
        <Box>
          <Button
            variant="contained"
            disabled={busy}
            sx={{ borderRadius: 2 }}
            onClick={async () => {
              try {
                setBusy(true); setError(null);
                const mj = JSON.parse(manifest);
                const blob = await client.scaffoldPlugin({ id: mj.id || 'my-plugin', name: mj.name, version: mj.version, language: 'python', traits: mj.traits });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = `${mj.id || 'plugin'}_scaffold.zip`; a.click();
                URL.revokeObjectURL(url);
              } catch (e: any) {
                setError(e?.message || 'Failed to scaffold plugin');
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? 'Generating…' : 'Scaffold Plugin'}
          </Button>
          {error && (
            <Alert severity="error" sx={{ mt: 2, borderRadius: 2 }} onClose={() => setError(null)}>{error}</Alert>
          )}
        </Box>
      </Stack>
    </Box>
  );
}
