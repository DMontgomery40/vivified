import { useEffect, useState } from 'react';
import { useMediaQuery } from '@mui/material';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Alert,
  Paper,
  CircularProgress,
  Grid,
  Chip,
  List,
  ListItem,
  ListItemText,
  Switch,
  FormControlLabel,
  Stack,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  ContentCopy as ContentCopyIcon,
  Security as SecurityIcon,
  Cloud as CloudIcon,
  Storage as StorageIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Settings as SettingsIcon,
} from '@mui/icons-material';
import AdminAPIClient from '../api/client';
import type { Settings as SettingsType } from '../api/types';
import { useTraits } from '../hooks/useTraits';
import { ResponsiveSettingItem, ResponsiveSettingSection } from './common/ResponsiveSettingItem';
import HelpTip from './common/HelpTip';
import { ResponsiveTextField, ResponsiveFormSection } from './common/ResponsiveFormFields';
import TunnelSettings from './TunnelSettings';

interface SettingsProps {
  client: AdminAPIClient;
  readOnly?: boolean;
}

function Settings({ client, readOnly = false }: SettingsProps) {
  const [settings, setSettings] = useState<SettingsType | null>(null);
  const [envContent, setEnvContent] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [snack, setSnack] = useState<string | null>(null);
  const [form, setForm] = useState<any>({});
  const [restartHint, setRestartHint] = useState<boolean>(false);
  const [allowRestart, setAllowRestart] = useState<boolean>(false);
  const [persistedEnabled, setPersistedEnabled] = useState<boolean>(false);
  const [docsBase, setDocsBase] = useState<string>('');
  const [migrationBanner, setMigrationBanner] = useState<boolean>(false);
  const [importingEnv, setImportingEnv] = useState<boolean>(false);
  const [importResult, setImportResult] = useState<{discovered:number; prefixes:string[]} | null>(null);
  const [lastGeneratedSecret, setLastGeneratedSecret] = useState<string>('');
  const { hasTrait, active, traitValue } = useTraits();
  const handleForm = (field: string, value: any) => setForm((prev: any) => ({ ...prev, [field]: value }));
  const isSmall = useMediaQuery('(max-width:900px)');
  const ctlStyle: React.CSSProperties = { background: 'transparent', color: 'inherit', borderColor: '#444', padding: '6px', borderRadius: 6, width: isSmall ? '100%' : 'auto', maxWidth: isSmall ? '100%' : undefined };

  // Effective integration selections with hybrid fallback
  const effectiveOutbound = (form.outbound_backend || settings?.hybrid?.outbound_backend || settings?.backend?.type) as string | undefined;
  // const effectiveInbound = (form.inbound_backend || settings?.hybrid?.inbound_backend || settings?.backend?.type) as string | undefined;

  const fetchSettings = async () => {
    try {
      setError(null);
      setLoading(true);
      const data = await client.getSettings();
      setSettings(data);
      setForm({
        backend: data.backend?.type,
        require_api_key: data.security?.require_api_key,
        enforce_public_https: data.security?.enforce_https,
        public_api_url: data.security?.public_api_url,
        feature_v3_plugins: data.features?.v3_plugins,
        fax_disabled: data.backend?.disabled,
        inbound_enabled: data.inbound?.enabled,
        feature_plugin_install: data.features?.plugin_install,
        sinch_base_url: (data as any)?.sinch?.base_url || '',
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch settings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    (async () => {
      await fetchSettings();
      try {
        const cfg = await client.getConfig();
        setAllowRestart(!!cfg?.allow_restart);
        setPersistedEnabled(!!cfg?.persisted_settings_enabled);
        if (cfg?.branding?.docs_base) setDocsBase(cfg.branding.docs_base);
        if (cfg?.migration) setMigrationBanner(Boolean(cfg.migration.banner));
        setForm((prev: any) => ({ ...prev, enable_persisted_settings: !!cfg?.persisted_settings_enabled }));
      } catch {}
    })();
  }, []);

  const exportEnv = async () => {
    try {
      setError(null);
      setLoading(true);
      const data = await client.exportSettings();
      setEnvContent(data.env_content);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export settings');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const downloadText = (filename: string, text: string) => {
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getStatusIcon = (configured: boolean) => {
    return configured ? (
      <CheckCircleIcon color="success" />
    ) : (
      <ErrorIcon color="error" />
    );
  };

  const importEnvToDb = async () => {
    try {
      setImportingEnv(true);
      setError(null);
      const res = await client.importEnv();
      setImportResult({ discovered: res.discovered, prefixes: res.prefixes });
      setSnack(`Imported ${res.discovered} environment keys.`);
    } catch (e: any) {
      setError(e?.message || 'Failed to import env');
    } finally {
      setImportingEnv(false);
    }
  };

  const handleApplySettings = async () => {
    try {
      setLoading(true);
      setError(null);
      setRestartHint(false);
      
      const p: any = {};
      
      // Core settings
      if (form.outbound_backend) p.outbound_backend = form.outbound_backend;
      else if (form.backend) p.backend = form.backend;
      if (form.inbound_backend) {
        p.inbound_backend = form.inbound_backend;
        p.inbound_enabled = true;
      }
      if (form.require_api_key !== undefined) p.require_api_key = !!form.require_api_key;
      if (form.enforce_public_https !== undefined) p.enforce_public_https = !!form.enforce_public_https;
      if (form.audit_log_enabled !== undefined) p.audit_log_enabled = !!form.audit_log_enabled;
      if (form.public_api_url) p.public_api_url = String(form.public_api_url);
      if (form.enable_persisted_settings !== undefined) p.enable_persisted_settings = !!form.enable_persisted_settings;
      if (form.feature_v3_plugins !== undefined) p.feature_v3_plugins = !!form.feature_v3_plugins;
      if (form.feature_plugin_install !== undefined) p.feature_plugin_install = !!form.feature_plugin_install;

      // Integration-specific settings (traits-aware)
      const methods = (traitValue('outbound', 'auth.methods') || []) as string[];
      // Integrations with basic-only auth (e.g., Phaxio-like)
      if (Array.isArray(methods) && methods.includes('basic') && !methods.includes('oauth2')) {
        if (form.phaxio_api_key) p.phaxio_api_key = form.phaxio_api_key;
        if (form.phaxio_api_secret) p.phaxio_api_secret = form.phaxio_api_secret;
      }
      // Integrations supporting OAuth2 (e.g., Sinch-like)
      if (Array.isArray(methods) && methods.includes('oauth2')) {
        if (form.sinch_project_id) p.sinch_project_id = form.sinch_project_id;
        if (form.sinch_api_key) p.sinch_api_key = form.sinch_api_key;
        if (form.sinch_api_secret) p.sinch_api_secret = form.sinch_api_secret;
        if (form.sinch_base_url) p.sinch_base_url = form.sinch_base_url;
        if (form.sinch_auth_method) p.sinch_auth_method = form.sinch_auth_method;
        if (form.sinch_auth_base_url) p.sinch_auth_base_url = form.sinch_auth_base_url;
      }
      if (hasTrait('outbound', 'requires_ami')) {
        if (form.ami_host) p.ami_host = form.ami_host;
        if (form.ami_port) p.ami_port = Number(form.ami_port);
        if (form.ami_username) p.ami_username = form.ami_username;
        if (form.ami_password) p.ami_password = form.ami_password;
        if (form.fax_station_id) p.fax_station_id = form.fax_station_id;
      }

      // Inbound settings
      if (form.inbound_retention_days !== undefined) p.inbound_retention_days = Number(form.inbound_retention_days);
      if (form.inbound_token_ttl_minutes !== undefined) p.inbound_token_ttl_minutes = Number(form.inbound_token_ttl_minutes);
      if (form.asterisk_inbound_secret) p.asterisk_inbound_secret = form.asterisk_inbound_secret;
      if (form.phaxio_inbound_verify_signature !== undefined) p.phaxio_inbound_verify_signature = !!form.phaxio_inbound_verify_signature;
      if (form.sinch_inbound_basic_user) p.sinch_inbound_basic_user = form.sinch_inbound_basic_user;
      if (form.sinch_inbound_basic_pass) p.sinch_inbound_basic_pass = form.sinch_inbound_basic_pass;

      // Storage settings
      if (form.storage_backend) p.storage_backend = form.storage_backend;
      if (form.s3_bucket) p.s3_bucket = form.s3_bucket;
      if (form.s3_region) p.s3_region = form.s3_region;
      if (form.s3_prefix) p.s3_prefix = form.s3_prefix;
      if (form.s3_endpoint_url) p.s3_endpoint_url = form.s3_endpoint_url;
      if (form.s3_kms_key_id) p.s3_kms_key_id = form.s3_kms_key_id;

      // Rate limiting
      if (form.max_file_size_mb !== undefined) p.max_file_size_mb = Number(form.max_file_size_mb);
      if (form.max_requests_per_minute !== undefined) p.max_requests_per_minute = Number(form.max_requests_per_minute);
      if (form.inbound_list_rpm !== undefined) p.inbound_list_rpm = Number(form.inbound_list_rpm);
      if (form.inbound_get_rpm !== undefined) p.inbound_get_rpm = Number(form.inbound_get_rpm);

      const res = await client.updateSettings(p);
      await client.reloadSettings();
      await fetchSettings();
      setSnack('Settings applied and reloaded');
      
      if (res && res._meta && res._meta.restart_recommended) setRestartHint(true);
      if (p.enable_persisted_settings !== undefined) setPersistedEnabled(!!p.enable_persisted_settings);
    } catch (e: any) {
      setError(e?.message || 'Failed to apply settings');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      {migrationBanner && (
        <Alert severity="warning" sx={{ mb: 2, borderRadius: 2 }}
          action={
            <Button color="inherit" size="small" onClick={importEnvToDb} disabled={importingEnv}>
              {importingEnv ? 'Importing…' : 'Import env → DB'}
            </Button>
          }
        >
          Using .env fallback; importing env keys to the database is recommended for live systems.
          {importResult && (
            <Box component="span" sx={{ ml: 1 }}>
              Imported {importResult.discovered} keys
            </Box>
          )}
        </Alert>
      )}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Settings
        </Typography>
        <HelpTip topic="settings" docsBase={docsBase} />
        <Box>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={fetchSettings}
            disabled={loading}
            sx={{ mr: 1 }}
          >
            Load Settings
          </Button>
          <Button variant="contained" onClick={exportEnv} disabled={loading} sx={{ mr: 1 }}>
            Export .env
          </Button>
          <Button
            variant="outlined"
            onClick={async () => {
              try {
                setLoading(true); setError(null);
                const res = await client.persistSettings();
                setSnack(`Saved to ${res.path}`);
              } catch (e: any) {
                setError(e?.message || 'Failed to save on server');
              } finally { setLoading(false); }
            }}
            disabled={loading || readOnly}
          >
            Save .env to server
          </Button>
          {allowRestart && (
            <Button
              variant="outlined"
              sx={{ ml: 1 }}
              onClick={async () => {
                try {
                  setLoading(true); setError(null);
                  // Persist current effective settings and restart
                  await client.persistSettings();
                  await client.restart();
                  setSnack('Saved .env and restarting API...');
                } catch (e:any) {
                  setError(e?.message || 'Failed to save and restart');
                } finally {
                  setLoading(false);
                }
              }}
              disabled={loading || readOnly}
            >
              Save & Restart
            </Button>
          )}
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2">Apply changes live, then export .env for persistence across restarts.</Typography>
      </Alert>

      {loading && !settings ? (
        <Box display="flex" justifyContent="center" py={4}>
          <CircularProgress />
        </Box>
      ) : settings ? (
        <Box>
        <Stack spacing={3}>
          {/* Integrations & Connections */}
          {/* Integrations & Connections — removed legacy fax provider selectors */}
          <ResponsiveFormSection
            title="Integrations & Connections"
            subtitle="Core connections and security. Fax provider selection moved to Setup Wizard."
            icon={<CloudIcon />}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
              <Chip
                label={settings.backend.disabled ? 'Disabled' : 'Active'}
                color={settings.backend.disabled ? 'error' : 'success'}
                size="small"
                variant="outlined"
                sx={{ borderRadius: 1 }}
              />
            </Box>
          </ResponsiveFormSection>

          {/* Security Settings */}
          <Box id="settings-security" />
          <ResponsiveFormSection
            title="Security Settings"
            subtitle="Configure authentication and HIPAA compliance"
            icon={<SecurityIcon />}
          >
            <ResponsiveSettingItem
              icon={settings.security.require_api_key ? <CheckCircleIcon color="success" /> : <WarningIcon color="warning" />}
              label="API Key Required"
              value={((form.require_api_key ?? settings.security.require_api_key) ? 'true' : 'false')}
              helperText="Enable in production; required for HIPAA. Mint DB-backed keys in the Keys tab and pass them as X-API-Key."
              onChange={(value) => handleForm('require_api_key', value === 'true')}
              type="select"
              options={[
                { value: 'true', label: 'Yes (Required for HIPAA)' },
                { value: 'false', label: 'No (Dev only)' }
              ]}
              showCurrentValue={false}
            />
            
            <ResponsiveSettingItem
              icon={settings.security.enforce_https ? <CheckCircleIcon color="success" /> : <WarningIcon color="warning" />}
              label="HTTPS Enforced"
              value={((form.enforce_public_https ?? settings.security.enforce_https) ? 'true' : 'false')}
              helperText="Required for PHI. PUBLIC_API_URL must be HTTPS for cloud providers to fetch PDFs securely."
              onChange={(value) => handleForm('enforce_public_https', value === 'true')}
              type="select"
              options={[
                { value: 'true', label: 'Yes (Required for PHI)' },
                { value: 'false', label: 'No (Dev only)' }
              ]}
              showCurrentValue={false}
            />
            
            <ResponsiveSettingItem
              icon={settings.security.audit_enabled ? <CheckCircleIcon color="success" /> : <WarningIcon color="warning" />}
              label="Audit Logging"
              value={((form.audit_log_enabled ?? settings.security.audit_enabled) ? 'true' : 'false')}
              helperText="Enable structured logs for admin actions and fax lifecycle. Set AUDIT_LOG_FILE to persist; view in Logs tab."
              onChange={(value) => handleForm('audit_log_enabled', value === 'true')}
              type="select"
              options={[
                { value: 'true', label: 'Enabled (HIPAA requirement)' },
                { value: 'false', label: 'Disabled' }
              ]}
              showCurrentValue={false}
            />
            
            <ResponsiveSettingItem
              icon={persistedEnabled ? <CheckCircleIcon color="success" /> : <WarningIcon color="warning" />}
              label="Load persisted .env at startup"
              value={((form.enable_persisted_settings ?? persistedEnabled) ? 'true' : 'false')}
              helperText='Loads a .env file at boot if configured. Use "Save .env to server" after applying changes to keep them across restarts.'
              onChange={(value) => handleForm('enable_persisted_settings', value === 'true')}
              type="select"
              options={[
                { value: 'true', label: 'Enabled' },
                { value: 'false', label: 'Disabled' }
              ]}
              showCurrentValue={false}
            />

            {/* Inline posture warning: HTTPS enforced but PUBLIC_API_URL not HTTPS (cloud backends) */}
            {(() => {
              try {
                const effectiveOb = (effectiveOutbound || '').toLowerCase();
                const httpsEnforced = Boolean(form.enforce_public_https ?? settings.security.enforce_https);
                const url = String(form.public_api_url || settings.security.public_api_url || '');
                const isCloud = ['phaxio', 'sinch', 'signalwire', 'documo'].includes(effectiveOb);
                if (!httpsEnforced || !isCloud || !url) return null;
                const isHttps = url.startsWith('https://');
                const isLocal = url.startsWith('http://localhost') || url.startsWith('http://127.0.0.1');
                if (!isHttps && !isLocal) {
                  return (
                    <Alert severity="warning" sx={{ mt: 1 }}>
                      ENFORCE_PUBLIC_HTTPS is enabled, but PUBLIC_API_URL is not HTTPS. Use an HTTPS URL or disable for non‑PHI dev.
                    </Alert>
                  );
                }
              } catch {}
              return null;
            })()}
          </ResponsiveFormSection>

          {/* VPN Tunnel (iOS connectivity) */}
          <ResponsiveSettingSection
            title="VPN Tunnel"
            subtitle="Configure a secure tunnel for Admin Console and iOS app connectivity."
          >
            <TunnelSettings
              client={client}
              docsBase={docsBase}
              hipaaMode={Boolean(settings.security?.enforce_https && settings.security?.require_api_key)}
            />
          </ResponsiveSettingSection>

          {/* Backend-Specific Configuration */}
          {(() => { const m = (traitValue('outbound','auth.methods') || []) as string[]; return Array.isArray(m) && m.includes('basic') && !m.includes('oauth2'); })() && (
                  <>
                  <Box id="settings-phaxio" />
                  <ResponsiveSettingSection
                    title="PHAXIO Configuration"
                    subtitle="Configure your Phaxio API credentials and settings"
                  >
                    <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                      <Chip
                        label="Phaxio Setup"
                        component="a"
                        href={`${docsBase}/backends/phaxio-setup.html`}
                        target="_blank"
                        rel="noreferrer"
                        clickable
                        size="small"
                        variant="outlined"
                      />
                    </Box>
                    
                    <ResponsiveSettingItem
                      icon={getStatusIcon(!!settings.phaxio.api_key)}
                      label="API Key"
                      value={settings.phaxio.api_key?.replace(/./g, '*').slice(0, 20) || ''}
                      helperText="Get from Phaxio console. Use a service account and keep this secret safe."
                      placeholder="Update PHAXIO_API_KEY"
                      onChange={(value) => handleForm('phaxio_api_key', value)}
                      type="password"
                      showCurrentValue={!!settings.phaxio.api_key}
                    />
                    
                    <ResponsiveSettingItem
                      icon={getStatusIcon(!!settings.phaxio.api_secret)}
                      label="API Secret"
                      value={settings.phaxio.api_secret?.replace(/./g, '*').slice(0, 20) || ''}
                      helperText="Get from Phaxio console. Required alongside API key for provider API calls."
                      placeholder="Update PHAXIO_API_SECRET"
                      onChange={(value) => handleForm('phaxio_api_secret', value)}
                      type="password"
                      showCurrentValue={!!settings.phaxio.api_secret}
                    />
                    
                    <ResponsiveSettingItem
                      icon={getStatusIcon(!!settings.phaxio.callback_url)}
                      label="Callback URL"
                      value={settings.phaxio.callback_url || form.public_api_url || ''}
                      helperText="Phaxio status webhooks hit /phaxio-callback; PUBLIC_API_URL must be HTTPS. Enable HMAC verification for security."
                      placeholder="https://localhost:8080/phaxio-callback"
                      onChange={(value) => handleForm('public_api_url', value)}
                      showCurrentValue={!!settings.phaxio.callback_url}
                    />
                  </ResponsiveSettingSection>
                  </>
                )}

                {(() => { const m = (traitValue('outbound','auth.methods') || []) as string[]; return Array.isArray(m) && m.includes('oauth2'); })() && (
                  <>
                  <Box id="settings-sinch" />
                  <ResponsiveSettingSection
                    title="Sinch Fax API v3 Configuration"
                    subtitle="Outbound API uses OAuth 2.0 (Bearer). Inbound webhooks are not provider‑signed; you may enforce Basic auth on your endpoint."
                  >
                    <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                      <Chip
                        label="Sinch Setup"
                        component="a"
                        href={`${docsBase}/backends/sinch-setup.html`}
                        target="_blank"
                        rel="noreferrer"
                        clickable
                        size="small"
                        variant="outlined"
                      />
                      <Chip
                        label="Sinch Fax API Docs"
                        component="a"
                        href={`https://developers.sinch.com/docs/fax/api-reference/`}
                        target="_blank"
                        rel="noreferrer"
                        clickable
                        size="small"
                        variant="outlined"
                      />
                      <Chip
                        label="OAuth 2.0 Auth"
                        component="a"
                        href={`https://developers.sinch.com/docs/fax/api-reference/authentication/oauth/`}
                        target="_blank"
                        rel="noreferrer"
                        clickable
                        size="small"
                        variant="outlined"
                      />
                      <Chip
                        label="Sinch Customer Dashboard (Access Keys)"
                        component="a"
                        href={`https://dashboard.sinch.com/settings/access-keys`}
                        target="_blank"
                        rel="noreferrer"
                        clickable
                        size="small"
                        variant="outlined"
                      />
                    </Box>
                    <ResponsiveSettingItem
                      icon={getStatusIcon(true)}
                      label="Outbound Auth Method"
                      value={(form.sinch_auth_method || (settings as any)?.sinch?.auth_method || 'basic')}
                      helperText="Choose OAuth 2.0 for HIPAA‑aligned deployments; Basic remains available for compatibility."
                      onChange={(value) => handleForm('sinch_auth_method', value)}
                      type="select"
                      options={[
                        { value: 'basic', label: 'Basic (Key/Secret)' },
                        { value: 'oauth', label: 'OAuth 2.0 (Bearer) — Recommended' },
                      ]}
                      showCurrentValue={false}
                    />
                    <ResponsiveSettingItem
                      icon={getStatusIcon(!!settings?.sinch?.project_id)}
                      label="Project ID"
                      value={settings?.sinch?.project_id || ''}
                      helperText="Your Sinch Fax project ID (used with key/secret to mint OAuth 2.0 access tokens for API calls)"
                      placeholder="SINCH_PROJECT_ID"
                      onChange={(value) => handleForm('sinch_project_id', value)}
                      showCurrentValue={!!settings?.sinch?.project_id}
                    />

                    <ResponsiveSettingItem
                      icon={getStatusIcon(!!settings?.sinch?.api_key)}
                      label="API Key"
                      value={settings?.sinch?.api_key ? '********' : ''}
                      helperText="Sinch API key (Key ID). Used to obtain OAuth 2.0 access tokens; stored server-side and masked here."
                      placeholder="SINCH_API_KEY"
                      onChange={(value) => handleForm('sinch_api_key', value)}
                      type="password"
                      showCurrentValue={!!settings?.sinch?.api_key}
                    />

                    <ResponsiveSettingItem
                      icon={getStatusIcon(!!settings?.sinch?.api_secret)}
                      label="API Secret"
                      value={settings?.sinch?.api_secret ? '********' : ''}
                      helperText="Sinch API secret. Used to obtain OAuth 2.0 access tokens; stored server-side and masked here."
                      placeholder="SINCH_API_SECRET"
                      onChange={(value) => handleForm('sinch_api_secret', value)}
                      type="password"
                      showCurrentValue={!!settings?.sinch?.api_secret}
                    />

                    <ResponsiveSettingItem
                      icon={getStatusIcon(true)}
                      label="Base URL (optional)"
                      value={(form.sinch_base_url as string) || ''}
                      helperText="Override region (e.g., https://us.fax.api.sinch.com/v3). Leave blank for default."
                      placeholder="SINCH_BASE_URL"
                      onChange={(value) => handleForm('sinch_base_url', value)}
                      showCurrentValue={false}
                    />
                    <ResponsiveSettingItem
                      icon={getStatusIcon(true)}
                      label="OAuth Token URL (optional)"
                      value={(form.sinch_auth_base_url as string) || ''}
                      helperText="Override auth region (e.g., https://eu.auth.sinch.com/oauth2/token). Leave blank for default."
                      placeholder="SINCH_AUTH_BASE_URL"
                      onChange={(value) => handleForm('sinch_auth_base_url', value)}
                      showCurrentValue={false}
                    />
                  </ResponsiveSettingSection>
                  </>
                )}

                {active?.outbound === 'documo' && (
                  <ResponsiveSettingSection
                    title="Documo Configuration"
                    subtitle="Configure your Documo API settings"
                  >
                    <ResponsiveSettingItem
                      icon={getStatusIcon(!!settings?.documo?.configured)}
                      label="Documo API Key"
                      value={settings?.documo?.configured ? 'Configured' : ''}
                      helperText="Enter your Documo API key for authentication."
                      placeholder="DOCUMO_API_KEY"
                      onChange={(value) => handleForm('documo_api_key', value)}
                      type="password"
                      showCurrentValue={settings?.documo?.configured}
                    />
                    
                    <ResponsiveSettingItem
                      icon={getStatusIcon(true)}
                      label="Sandbox Mode"
                      value={(form.documo_use_sandbox ?? false) ? 'true' : 'false'}
                      helperText="Enable sandbox mode for testing without sending real faxes."
                      onChange={(value) => handleForm('documo_use_sandbox', value === 'true')}
                      type="select"
                      options={[
                        { value: 'false', label: 'Production' },
                        { value: 'true', label: 'Sandbox' }
                      ]}
                      showCurrentValue={false}
                    />
                  </ResponsiveSettingSection>
                )}

                {hasTrait('outbound','requires_ami') && (
                  <>
                  <Box id="settings-sip" />
                  <ResponsiveSettingSection
                    title="SIP / Asterisk Configuration"
                    subtitle="Configure your Asterisk AMI connection settings"
                  >
                    <ResponsiveSettingItem
                      icon={getStatusIcon(!!settings.sip.ami_host)}
                      label="AMI Host"
                      value={settings.sip.ami_host || ''}
                      helperText='Asterisk service hostname on your private network (e.g., docker compose service name "asterisk").'
                      placeholder="ASTERISK_AMI_HOST"
                      onChange={(value) => handleForm('ami_host', value)}
                      showCurrentValue={!!settings.sip.ami_host}
                    />
                    
                    <ResponsiveSettingItem
                      icon={settings.sip.ami_password_is_default ? <WarningIcon color="warning" /> : <CheckCircleIcon color="success" />}
                      label="AMI Password"
                      value={settings.sip.ami_password_is_default ? 'Using default (insecure)' : 'Custom password set'}
                      helperText="Must not be the default. Update in both your app and Asterisk manager.conf; never expose 5038 publicly."
                      placeholder="Update ASTERISK_AMI_PASSWORD"
                      onChange={(value) => handleForm('ami_password', value)}
                      type="password"
                      showCurrentValue={!settings.sip.ami_password_is_default}
                    />
                    
                    <ResponsiveSettingItem
                      icon={getStatusIcon(!!settings.sip.station_id)}
                      label="Station ID"
                      value={settings.sip.station_id || ''}
                      helperText="Your fax header/DID in E.164 format (e.g., +15551234567)."
                      placeholder="FAX_LOCAL_STATION_ID"
                      onChange={(value) => handleForm('fax_station_id', value)}
                      showCurrentValue={!!settings.sip.station_id}
                    />
                  </ResponsiveSettingSection>
                </>
                )}

          {/* Feature Flags */}
          <ResponsiveFormSection
            title="Feature Flags"
            subtitle="Enable or disable v3 features. Changes require restart to take effect."
            icon={<SettingsIcon />}
          >
            <Stack spacing={2}>
              <FormControlLabel
                control={
                  <Switch
                    checked={form.feature_v3_plugins ?? settings?.features?.v3_plugins ?? false}
                    onChange={(e) => handleForm('feature_v3_plugins', e.target.checked)}
                    sx={{ '& .MuiSwitch-thumb': { width: 20, height: 20 } }}
                  />
                }
                label="Enable v3 Plugin System"
                sx={{ alignItems: 'flex-start', '& .MuiFormControlLabel-label': { mt: 0.5 } }}
              />
              <Typography variant="caption" color="text.secondary" sx={{ ml: 4, mb: 1 }}>
                Activates the modular plugin architecture for integrations
              </Typography>
              
              <FormControlLabel
                control={
                  <Switch
                    checked={form.fax_disabled ?? settings?.backend?.disabled ?? false}
                    onChange={(e) => handleForm('fax_disabled', e.target.checked)}
                    sx={{ '& .MuiSwitch-thumb': { width: 20, height: 20 } }}
                  />
                }
                label="Test Mode (No Real Faxes)"
                sx={{ alignItems: 'flex-start', '& .MuiFormControlLabel-label': { mt: 0.5 } }}
              />
              <Typography variant="caption" color="text.secondary" sx={{ ml: 4, mb: 1 }}>
                Simulates fax operations without actually sending - useful for development
              </Typography>
              
              <FormControlLabel
                control={
                  <Switch
                    checked={form.inbound_enabled ?? settings?.inbound?.enabled ?? false}
                    onChange={(e) => handleForm('inbound_enabled', e.target.checked)}
                    sx={{ '& .MuiSwitch-thumb': { width: 20, height: 20 } }}
                  />
                }
                label="Enable Inbound Fax Receiving"
                sx={{ alignItems: 'flex-start', '& .MuiFormControlLabel-label': { mt: 0.5 } }}
              />
              <Typography variant="caption" color="text.secondary" sx={{ ml: 4, mb: 1 }}>
                Allow receiving faxes (requires additional configuration based on backend)
              </Typography>

              <FormControlLabel
                control={
                  <Switch
                    checked={form.feature_plugin_install ?? settings?.features?.plugin_install ?? false}
                    onChange={(e) => handleForm('feature_plugin_install', e.target.checked)}
                    disabled
                    sx={{ '& .MuiSwitch-thumb': { width: 20, height: 20 } }}
                  />
                }
                label="Allow Remote Plugin Installation (Advanced)"
                sx={{ alignItems: 'flex-start', '& .MuiFormControlLabel-label': { mt: 0.5 } }}
              />
              <Typography variant="caption" color="text.secondary" sx={{ ml: 4 }}>
                Disabled by default for security. Enable only in trusted environments.
              </Typography>
            </Stack>
            {restartHint && (
              <Alert severity="info" sx={{ mt: 2, borderRadius: 2 }}>
                Feature flag changes require a restart to take effect
              </Alert>
            )}
          </ResponsiveFormSection>

          {/* Inbound Receiving */}
          <Box id="settings-inbound" />
          <ResponsiveFormSection
            title="Inbound Receiving"
            subtitle="Configure inbound fax receiving and storage settings"
            icon={<CheckCircleIcon />}
          >
            <ResponsiveSettingItem
              icon={settings.inbound?.enabled ? <CheckCircleIcon color="success" /> : <WarningIcon color="warning" />}
              label="Enable Inbound"
              value={(form.inbound_enabled ?? settings.inbound?.enabled) ? 'true' : 'false'}
              helperText="Allow receiving faxes (requires additional configuration based on backend)"
              onChange={(value) => handleForm('inbound_enabled', value === 'true')}
              type="select"
              options={[
                { value: 'true', label: 'Enabled' },
                { value: 'false', label: 'Disabled' }
              ]}
              showCurrentValue={true}
            />
            
            <ResponsiveSettingItem
              icon={<SettingsIcon />}
              label="Retention Days"
              value={String(settings.inbound?.retention_days ?? 30)}
              helperText="How long to keep inbound fax files before automatic cleanup"
              onChange={(value) => handleForm('inbound_retention_days', parseInt(value))}
              type="number"
              placeholder={String(settings.inbound?.retention_days ?? 30)}
              showCurrentValue={true}
            />
            
            <ResponsiveSettingItem
              icon={<SettingsIcon />}
              label="Token TTL (minutes)"
              value={"60"}
              helperText="Fixed: 60 minutes"
              onChange={() => { /* fixed TTL */ }}
              type="number"
              placeholder={"60"}
              showCurrentValue={true}
            />

            {hasTrait('inbound','requires_ami') && (
              <Box sx={{ mt: 2 }}>
                <ResponsiveSettingItem
                  icon={<SecurityIcon />}
                  label="Asterisk Inbound Secret"
                  value={lastGeneratedSecret ? 'Generated (copy below)' : 'Not configured'}
                  helperText="Shared secret used by your Asterisk dialplan to POST inbound metadata to the API. Keep this private and only use it on the private network."
                  onChange={(value) => handleForm('asterisk_inbound_secret', value)}
                  placeholder="ASTERISK_INBOUND_SECRET"
                  type="password"
                  showCurrentValue={false}
                />
                <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
                  <Button 
                    size="small" 
                    variant="outlined"
                    onClick={async () => {
                      try {
                        const bytes = new Uint8Array(32);
                        const cryptoObj: any = (typeof window !== 'undefined') ? (window as any).crypto : undefined;
                        if (cryptoObj && typeof cryptoObj.getRandomValues === 'function') {
                          cryptoObj.getRandomValues(bytes);
                        } else {
                          for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
                        }
                        const b64 = btoa(String.fromCharCode(...Array.from(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
                        setLastGeneratedSecret(b64);
                        await client.updateSettings({ asterisk_inbound_secret: b64 });
                        await client.reloadSettings();
                        await fetchSettings();
                        setSnack('Generated new inbound secret (displayed once below)');
                      } catch(e:any){ setError(e?.message||'Failed to generate secret'); }
                    }}
                    sx={{ borderRadius: 1 }}
                  >
                    Generate
                  </Button>
                  <Button 
                    size="small" 
                    variant="outlined"
                    onClick={async () => {
                      const toCopy = (form.asterisk_inbound_secret || lastGeneratedSecret || '').trim();
                      if (!toCopy) return;
                      try { await navigator.clipboard.writeText(toCopy); setSnack('Copied'); } catch {}
                    }} 
                    disabled={!form.asterisk_inbound_secret && !lastGeneratedSecret}
                    sx={{ borderRadius: 1 }}
                  >
                    Copy
                  </Button>
                </Box>
                {lastGeneratedSecret && (
                  <Alert severity="success" sx={{ mt: 2, borderRadius: 2 }}>
                    <Typography variant="body2">
                      New secret (copy now): <code>{lastGeneratedSecret}</code>
                    </Typography>
                  </Alert>
                )}
              </Box>
            )}

            {traitValue('inbound','webhook.verification') === 'hmac_sha256' && (
              <ResponsiveSettingItem
                icon={settings.inbound?.phaxio?.verify_signature ? <CheckCircleIcon color="success" /> : <WarningIcon color="warning" />}
                label="Verify Phaxio Inbound Signature"
                value={(form.phaxio_inbound_verify_signature ?? settings.inbound?.phaxio?.verify_signature) ? 'true' : 'false'}
                currentValue={settings.inbound?.phaxio?.verify_signature ? 'Enabled' : 'Disabled'}
                helperText="Enable HMAC signature verification for Phaxio inbound webhooks (recommended for security)"
                onChange={(value) => handleForm('phaxio_inbound_verify_signature', value === 'true')}
                type="select"
                options={[
                  { value: 'true', label: 'Enabled (Recommended)' },
                  { value: 'false', label: 'Disabled' }
                ]}
                showCurrentValue={true}
              />
            )}

            {traitValue('inbound','webhook.verification') === 'basic_auth' && (
              <Box sx={{ mt: 2 }}>
                <ResponsiveSettingItem
                  icon={settings.inbound?.sinch?.basic_auth_configured ? <CheckCircleIcon color="success" /> : <WarningIcon color="warning" />}
                  label="Inbound Basic Auth User"
                  value={settings.inbound?.sinch?.basic_auth_configured ? 'Configured' : 'Not configured'}
                  helperText="Some webhooks are not signed. Enforce Basic auth on your inbound endpoint and prefer application/json content type (multipart also supported)."
                  onChange={(value) => handleForm('sinch_inbound_basic_user', value)}
                  placeholder="SINCH_INBOUND_BASIC_USER"
                  showCurrentValue={false}
                />

                <ResponsiveSettingItem
                  icon={<SecurityIcon />}
                  label="Inbound Basic Auth Password"
                  value=""
                  helperText="Password for Basic authentication"
                  onChange={(value) => handleForm('sinch_inbound_basic_pass', value)}
                  placeholder="SINCH_INBOUND_BASIC_PASS"
                  type="password"
                  showCurrentValue={false}
                />
              </Box>
            )}
          </ResponsiveFormSection>

          {/* SignalWire (cloud) */}
          {active?.outbound === 'signalwire' && (
            <ResponsiveFormSection
              title="SignalWire Configuration"
              subtitle="Configure your SignalWire fax settings"
              icon={<CloudIcon />}
            >
              <ResponsiveSettingItem
                icon={<CloudIcon />}
                label="Space URL"
                value={settings.signalwire?.space_url || ''}
                helperText="Your SignalWire space URL (e.g., example.signalwire.com)"
                onChange={(value) => handleForm('signalwire_space_url', value)}
                placeholder="example.signalwire.com"
                showCurrentValue={!!settings.signalwire?.space_url}
              />
              
              <ResponsiveSettingItem
                icon={<SettingsIcon />}
                label="Project ID"
                value={settings.signalwire?.project_id || ''}
                helperText="Your SignalWire project identifier"
                onChange={(value) => handleForm('signalwire_project_id', value)}
                placeholder="SIGNALWIRE_PROJECT_ID"
                showCurrentValue={!!settings.signalwire?.project_id}
              />
              
              <ResponsiveSettingItem
                icon={<SecurityIcon />}
                label="API Token"
                value={settings.signalwire?.api_token ? '***' : ''}
                helperText="Your SignalWire API token for authentication"
                onChange={(value) => handleForm('signalwire_api_token', value)}
                placeholder="SIGNALWIRE_API_TOKEN"
                type="password"
                showCurrentValue={!!settings.signalwire?.api_token}
              />
              
              <ResponsiveSettingItem
                icon={<SettingsIcon />}
                label="From (fax)"
                value={settings.signalwire?.from_fax || ''}
                helperText="Your fax number in E.164 format (e.g., +13035551234)"
                onChange={(value) => handleForm('signalwire_fax_from_e164', value)}
                placeholder="+13035551234"
                showCurrentValue={!!settings.signalwire?.from_fax}
              />
            </ResponsiveFormSection>
          )}

          {/* Storage Configuration */}
          {/* FreeSWITCH (self-hosted) */}
          {active?.outbound === 'freeswitch' && (
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>FreeSWITCH</Typography>
                  <List dense>
                    <ListItem sx={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 1 }}>
                      <ListItemText primary="ESL Host" secondary={String(settings?.sip?.ami_host || settings?.fs?.esl_host || '')} />
                      <input placeholder="FREESWITCH_ESL_HOST" onChange={(e)=>handleForm('FREESWITCH_ESL_HOST'.toLowerCase(), e.target.value)} style={ctlStyle} />
                    </ListItem>
                    <ListItem sx={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 1 }}>
                      <ListItemText primary="ESL Port" secondary={String(settings?.fs?.esl_port || 8021)} />
                      <input placeholder="FREESWITCH_ESL_PORT" onChange={(e)=>handleForm('FREESWITCH_ESL_PORT'.toLowerCase(), e.target.value)} style={ctlStyle} />
                    </ListItem>
                    <ListItem sx={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 1 }}>
                      <ListItemText primary="ESL Password" secondary={'***'} />
                      <input placeholder="FREESWITCH_ESL_PASSWORD" onChange={(e)=>handleForm('FREESWITCH_ESL_PASSWORD'.toLowerCase(), e.target.value)} style={ctlStyle} />
                    </ListItem>
                    <ListItem sx={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 1 }}>
                      <ListItemText primary="Gateway Name" secondary={String((settings as any)?.fs?.gateway_name || settings?.sip?.ami_host || '')} />
                      <input placeholder="FREESWITCH_GATEWAY_NAME" onChange={(e)=>handleForm('FREESWITCH_GATEWAY_NAME'.toLowerCase(), e.target.value)} style={ctlStyle} />
                    </ListItem>
                    <ListItem sx={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 1 }}>
                      <ListItemText primary="Caller ID Number" secondary={String((settings as any)?.fs?.caller_id_number || '')} />
                      <input placeholder="FREESWITCH_CALLER_ID_NUMBER" onChange={(e)=>handleForm('FREESWITCH_CALLER_ID_NUMBER'.toLowerCase(), e.target.value)} style={ctlStyle} />
                    </ListItem>
                  </List>
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>Outbound Result Hook (copyable)</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      Add this to your outbound dialplan (before hangup) to post result details back to the API. Replace YOUR_SECRET with your <code>ASTERISK_INBOUND_SECRET</code> (shared internal secret).
                    </Typography>
                    <Box component="pre" sx={{ p: 1, bgcolor: 'background.default', border: '1px solid', borderColor: 'divider', borderRadius: 1, overflowX: 'auto', fontSize: '0.75rem' }}>
{`<action application="set" data="api_hangup_hook=system curl -s -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Secret: YOUR_SECRET' \
  -d '{\"job_id\":\"${'${faxbot_job_id}'}\",\"fax_status\":\"${'${fax_success}'}\",\"fax_result_text\":\"${'${fax_result_text}'}\",\"fax_document_transferred_pages\":${'${fax_document_transferred_pages}'},\"uuid\":\"${'${uuid}'}\"}' \
  http://api:8080/_internal/freeswitch/outbound_result"/>`}
                    </Box>
                    <Button size="small" sx={{ mt: 1 }} onClick={async ()=>{
                      try {
                        const text = `<action application=\"set\" data=\"api_hangup_hook=system curl -s -X POST \\\n+  -H 'Content-Type: application/json' \\\n+  -H 'X-Internal-Secret: YOUR_SECRET' \\\n+  -d '{\\\"job_id\\\":\\\"${'${faxbot_job_id}'}\\\",\\\"fax_status\\\":\\\"${'${fax_success}'}\\\",\\\"fax_result_text\\\":\\\"${'${fax_result_text}'}\\\",\\\"fax_document_transferred_pages\\\":${'${fax_document_transferred_pages}'},\\\"uuid\\\":\\\"${'${uuid}'}\\\"}' \\\n+  http://api:8080/_internal/freeswitch/outbound_result\"/>`;
                        await navigator.clipboard.writeText(text);
                        setSnack('Copied');
                      } catch {}
                    }}>Copy snippet</Button>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                      Use service name "api" for Docker Compose networking; otherwise set your API host. Ensure your dialplan sets <code>faxbot_job_id</code> (the originate flow sets it automatically).
                    </Typography>
                  </Box>
                  <Alert severity="info">For result updates, set an api_hangup_hook in your dialplan to POST to /_internal/freeswitch/outbound_result with X-Internal-Secret and include fax variables and the channel variable faxbot_job_id.</Alert>
                </CardContent>
              </Card>
            </Grid>
          )}
          <Box id="settings-storage" />
          <ResponsiveFormSection
            title="Storage Configuration"
            subtitle="Configure file storage backend and S3 settings"
            icon={<StorageIcon />}
          >
            <ResponsiveSettingItem
              icon={getStatusIcon(hasTrait('inbound', 'needs_storage') && (form.storage_backend === 's3' || settings.storage?.backend === 's3'))}
              label="Storage Backend"
              value={(form.storage_backend || settings.storage?.backend || 'local')}
              helperText="Local for development only. Use S3 with KMS for PHI in production."
              onChange={(value) => handleForm('storage_backend', value)}
              type="select"
              options={[
                { value: 'local', label: 'Local (Dev only)' },
                { value: 's3', label: 'S3 (Production)' }
              ]}
              showCurrentValue={true}
            />
            
            {hasTrait('inbound', 'needs_storage') && (form.storage_backend === 's3' || settings.storage?.backend === 's3') && (
              <Box sx={{ mt: 2 }}>
                <ResponsiveSettingItem
                  icon={<StorageIcon />}
                  label="S3 Bucket"
                  value={settings.storage?.s3_bucket || ''}
                  helperText="Your S3 bucket name for storing fax files"
                  onChange={(value) => handleForm('s3_bucket', value)}
                  placeholder="S3_BUCKET"
                  showCurrentValue={!!settings.storage?.s3_bucket}
                />
                
                <ResponsiveSettingItem
                  icon={<CloudIcon />}
                  label="S3 Region"
                  value={settings.storage?.s3_region || ''}
                  helperText="AWS region where your S3 bucket is located"
                  onChange={(value) => handleForm('s3_region', value)}
                  placeholder="S3_REGION"
                  showCurrentValue={!!settings.storage?.s3_region}
                />
                
                <ResponsiveSettingItem
                  icon={<SettingsIcon />}
                  label="S3 Prefix"
                  value={settings.storage?.s3_prefix || ''}
                  helperText="Optional prefix for organizing files within the bucket"
                  onChange={(value) => handleForm('s3_prefix', value)}
                  placeholder="S3_PREFIX"
                  showCurrentValue={!!settings.storage?.s3_prefix}
                />
                
                <ResponsiveSettingItem
                  icon={<CloudIcon />}
                  label="S3 Endpoint URL"
                  value={settings.storage?.s3_endpoint_url || ''}
                  helperText="Custom S3 endpoint for S3-compatible services (MinIO, etc.)"
                  onChange={(value) => handleForm('s3_endpoint_url', value)}
                  placeholder="S3_ENDPOINT_URL"
                  showCurrentValue={!!settings.storage?.s3_endpoint_url}
                />
                
                <ResponsiveSettingItem
                  icon={<SecurityIcon />}
                  label="S3 KMS Key ID"
                  value={settings.storage?.s3_kms_enabled ? 'Configured' : 'Not set'}
                  helperText="Enable server-side encryption with KMS by specifying a CMK (recommended for PHI)"
                  onChange={(value) => handleForm('s3_kms_key_id', value)}
                  placeholder="S3_KMS_KEY_ID"
                  showCurrentValue={false}
                />
                
                <Box sx={{ mt: 2 }}>
                  <Button 
                    variant="outlined" 
                    onClick={async () => { 
                      try { 
                        setLoading(true); 
                        const diag = await (client as any).runDiagnostics?.(); 
                        if (diag?.checks?.storage?.type === 's3') { 
                          const st = diag.checks.storage; 
                          const ok = st.accessible === true || st.bucket_set; 
                          setSnack(ok ? 'S3 validation passed' : ('S3 validation incomplete' + (st.error ? (': ' + st.error) : ''))); 
                        } else { 
                          setSnack('Diagnostics did not include S3 checks. Enable ENABLE_S3_DIAGNOSTICS=true on server for full validation.'); 
                        } 
                      } catch(e: any) { 
                        setError(e?.message || 'S3 validation failed'); 
                      } finally { 
                        setLoading(false); 
                      } 
                    }}
                    sx={{ borderRadius: 2 }}
                  >
                    Validate S3
                  </Button>
                  <Typography variant="caption" color="text.secondary" sx={{ ml: 2, display: 'block', mt: 1 }}>
                    Full validation requires ENABLE_S3_DIAGNOSTICS=true on server and proper AWS credentials via env/role.
                  </Typography>
                </Box>
              </Box>
            )}
          </ResponsiveFormSection>

          {/* Advanced Settings */}
          <ResponsiveFormSection
              title="Advanced Settings"
              subtitle="Database, rate limiting, and upload configuration"
              icon={<SettingsIcon />}
            >
              <Stack spacing={3}>
                {/* Database Configuration */}
                <Box>
                  <ResponsiveSettingItem
                    icon={getStatusIcon(!!settings.database?.url)}
                    label="Database URL"
                    value={settings.database?.url || 'sqlite:///./vivified.db'}
                    helperText="SQLite in /faxdata persists across rebuilds. For production scale, use Postgres."
                    showCurrentValue={true}
                  />
                  <Box sx={{ 
                    display: 'flex', 
                    gap: 2, 
                    mt: 2,
                    flexDirection: { xs: 'column', sm: 'row' }
                  }}>
                    <Button 
                      variant="outlined"
                      size={isSmall ? 'medium' : 'small'}
                      onClick={async ()=>{ 
                        try{ 
                          setLoading(true); 
                          setError(null); 
                          await client.updateSettings({ database_url: 'sqlite:////data/vivified.db' }); 
                          await client.reloadSettings(); 
                          await fetchSettings(); 
                          setSnack('Switched DB to /data/vivified.db'); 
                        } catch(e:any){ 
                          setError(e?.message||'Failed to switch DB'); 
                        } finally{ 
                          setLoading(false);
                        } 
                      }}
                      sx={{ borderRadius: 2 }}
                      fullWidth={isSmall}
                    >
                      Use persistent
                    </Button>
                    <Button 
                      variant="outlined"
                      size={isSmall ? 'medium' : 'small'}
                      onClick={async ()=>{ 
                        try{ 
                          setLoading(true); 
                          const res = await (client as any).fetch?.('/admin/db-status'); 
                          const data = await res.json(); 
                          setEnvContent(JSON.stringify(data, null, 2)); 
                          setSnack('DB status loaded'); 
                        } catch(e:any){ 
                          setError(e?.message||'Failed to load DB status'); 
                        } finally{ 
                          setLoading(false);
                        } 
                      }}
                      sx={{ borderRadius: 2 }}
                      fullWidth={isSmall}
                    >
                      Check DB Status
                    </Button>
                  </Box>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                    Shows current driver, connection, counts and SQLite file info.
                  </Typography>
                </Box>

                {/* Upload Limits */}
                <ResponsiveTextField
                  label="Max Upload Size (MB)"
                  value={String(form.max_file_size_mb ?? settings.limits?.max_file_size_mb ?? 10)}
                  onChange={(value) => handleForm('max_file_size_mb', parseInt(value) || 10)}
                  placeholder="10"
                  helperText="Default 10 MB aligns with provider limits. Increase only if your environment and provider allow it."
                  type="number"
                  icon={<CloudIcon />}
                />

                {/* Rate Limiting */}
                <ResponsiveTextField
                  label="Global Rate Limit (RPM)"
                  value={String(form.max_requests_per_minute ?? settings.limits?.rate_limit_rpm ?? 60)}
                  onChange={(value) => handleForm('max_requests_per_minute', parseInt(value) || 0)}
                  placeholder="60"
                  helperText="Per-key requests per minute. Set to mitigate abuse; 0 disables global rate limiting."
                  type="number"
                  icon={<SecurityIcon />}
                />

                <ResponsiveTextField
                  label="Inbound List RPM"
                  value={String(form.inbound_list_rpm ?? settings.limits?.inbound_list_rpm ?? 30)}
                  onChange={(value) => handleForm('inbound_list_rpm', parseInt(value) || 30)}
                  placeholder="30"
                  helperText="Rate limit for listing inbound faxes (per key). Keep conservative for HIPAA workloads."
                  type="number"
                  icon={<SecurityIcon />}
                />

                <ResponsiveTextField
                  label="Inbound Get RPM"
                  value={String(form.inbound_get_rpm ?? settings.limits?.inbound_get_rpm ?? 60)}
                  onChange={(value) => handleForm('inbound_get_rpm', parseInt(value) || 60)}
                  placeholder="60"
                  helperText="Rate limit for fetching inbound fax metadata/PDF (per key)."
                  type="number"
                  icon={<SecurityIcon />}
                />

                <Alert 
                  severity="info" 
                  sx={{ 
                    borderRadius: 2,
                    '& .MuiAlert-icon': { alignItems: 'center' }
                  }}
                >
                  <Typography variant="body2">
                    For HIPAA environments, set reasonable RPM limits and keep upload size within policy.
                  </Typography>
                </Alert>
              </Stack>
            </ResponsiveFormSection>
        </Stack>
        <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
          <Button variant="contained" onClick={handleApplySettings} disabled={loading || readOnly}>
            Apply & Reload
          </Button>
          <Button variant="outlined" startIcon={<RefreshIcon />} onClick={fetchSettings} disabled={loading}>
            Refresh
          </Button>
        </Box>
        {restartHint && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            Changes may require an API restart (backend or storage changed). {allowRestart ? 'You can restart below.' : 'Please restart the API process.'}
          </Alert>
        )}
        {allowRestart && (
          <Box sx={{ mt: 1 }}>
            <Button variant="outlined" disabled={readOnly} onClick={async () => { try { await client.restart(); } catch (e) { /* ignore */ } }}>
              Restart API
            </Button>
          </Box>
        )}
        </Box>
      ) : (
        <Typography variant="body2" color="text.secondary">
          Click "Load Settings" to view current configuration
        </Typography>
      )}

      {envContent && (
        <Card sx={{ mt: 3 }}>
          <CardContent>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6">
                Environment Configuration
              </Typography>
              <Box>
                <Button
                  variant="outlined"
                  startIcon={<ContentCopyIcon />}
                  onClick={() => copyToClipboard(envContent)}
                  sx={{ mr: 1 }}
                >
                  Copy
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={() => downloadText('vivified.env', envContent)}
                >
                  Download
                </Button>
              </Box>
            </Box>
            
            <Paper sx={{ p: 2, bgcolor: 'background.default' }}>
              <pre style={{ 
                margin: 0, 
                fontSize: '0.875rem', 
                overflow: 'auto',
                whiteSpace: 'pre-wrap'
              }}>
                {envContent}
              </pre>
            </Paper>
            
            <Alert severity="warning" sx={{ mt: 2 }}>
              After updating your .env file, restart the API with: <code>docker compose restart api</code>
            </Alert>
          </CardContent>
        </Card>
      )}
      {snack && (
        <Alert severity="success" sx={{ mt: 2 }} onClose={() => setSnack(null)}>
          {snack}
        </Alert>
      )}
    </Box>
  );
}

export default Settings;
