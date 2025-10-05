require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const { Api: HubSpotApi } = require('@friggframework/api-module-hubspot');
const { google } = require('googleapis');
const DiscordOAuth2 = require('discord-oauth2');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Correlation ID middleware (X-Request-Id); generate if missing
app.use((req, _res, next) => {
  const rid = req.header('X-Request-Id') || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  req.requestId = String(rid);
  next();
});

// Internal token middleware - required for all routes except health
// Accept both legacy 'X-Internal-Token' and 'X-Internal-Auth'
const requireInternalToken = (req, res, next) => {
  if (req.path === '/health') return next();
  const headerToken = req.header('X-Internal-Auth') || req.header('X-Internal-Token');
  const token = headerToken && String(headerToken);
  if (!token || token !== process.env.INTERNAL_TOKEN) {
    return res.status(401).json({
      error: {
        code: 'internal.unauthorized',
        message: 'Unauthorized internal call'
      }
    });
  }
  return next();
};

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// MongoDB connection event listeners
mongoose.connection.on('connected', () => {
  console.log('MongoDB connected');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.warn('MongoDB disconnected');
});

// MongoDB schemas
const credentialSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  provider: { type: String, required: true },
  accessToken: { type: String, required: true },
  refreshToken: { type: String },
  externalId: { type: String },
  accountName: { type: String },
  expiresAt: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

credentialSchema.index({ userId: 1, provider: 1 }, { unique: true });

const Credential = mongoose.model('Credential', credentialSchema);

// Provider configurations
const PROVIDERS = {
  hubspot: {
    name: 'HubSpot CRM',
    scopes: process.env.HUBSPOT_SCOPE || 'contacts'
  }
};

// Helper functions
// Simple egress allow-list for HubSpot
const ENFORCE_EGRESS = String(process.env.ENFORCE_EGRESS || 'false').toLowerCase() === 'true';
const HUBSPOT_ALLOWED_HOSTS = (process.env.HUBSPOT_ALLOWED_HOSTS || 'api.hubapi.com,app.hubspot.com')
  .split(',')
  .map((h) => h.trim())
  .filter(Boolean);

function enforceAllowedHost(url) {
  if (!ENFORCE_EGRESS) return;
  try {
    const u = new URL(url);
    if (!HUBSPOT_ALLOWED_HOSTS.includes(u.hostname)) {
      const err = new Error(`egress.blocked_host:${u.hostname}`);
      err.code = 'egress.blocked';
      throw err;
    }
  } catch (e) {
    const err = new Error('egress.invalid_url');
    err.code = 'egress.blocked';
    throw err;
  }
}

function wrapHttpGuards(api) {
  const wrap = (fn) => {
    const orig = api[fn].bind(api);
    api[fn] = async (options, ...rest) => {
      try {
        if (options && options.url) enforceAllowedHost(options.url);
      } catch (e) {
        const code = (e && e.code) || 'egress.blocked';
        const msg = (e && e.message) || 'egress blocked';
        const err = new Error(msg);
        err.code = code;
        throw err;
      }
      return orig(options, ...rest);
    };
  };
  ['_get', '_post', '_put', '_patch', '_delete'].forEach(wrap);
  return api;
}

const getHubSpotApi = (state) => {
  const api = new HubSpotApi({
    client_id: process.env.HUBSPOT_CLIENT_ID,
    client_secret: process.env.HUBSPOT_CLIENT_SECRET,
    redirect_uri: `${process.env.REDIRECT_URI}/hubspot/callback`,
    scope: PROVIDERS.hubspot.scopes,
    state: state || undefined,
  });
  return wrapHttpGuards(api);
};

// Helpers for Gmail/Discord
function buildRedirect(provider) {
  return `${String(process.env.REDIRECT_URI).replace(/\/+$/,'')}/${provider}/callback`;
}

async function upsertCredential(userId, provider, fields) {
  await Credential.findOneAndUpdate(
    { userId, provider },
    { userId, provider, ...fields, updatedAt: new Date() },
    { upsert: true, new: true }
  );
}

async function findCredential(userId, provider) {
  return Credential.findOne({ userId, provider });
}

async function deleteCredential(userId, provider) {
  return Credential.deleteOne({ userId, provider });
}

const handleError = (res, error, defaultCode = 'service.unavailable') => {
  // Production-safe logging: only log code/message, avoid full error objects
  const errorCode = error.code || defaultCode;
  const errorMessage = error.message || 'An error occurred';
  
  console.error(`Error [${errorCode}]: ${errorMessage}`);
  
  const statusCode = errorCode.includes('not_found') ? 404 : 
                    errorCode.includes('invalid') || errorCode.includes('bad_request') ? 400 :
                    errorCode.includes('unavailable') ? 503 : 500;
  
  res.status(statusCode).json({
    error: { code: errorCode, message: errorMessage }
  });
};

// Routes

// Health check - no auth required
app.get('/health', (req, res) => {
  // Check current Mongoose connection state
  const readyState = mongoose.connection.readyState;
  
  if (readyState !== 1) { // 1 = connected
    return res.status(503).json({
      error: {
        code: 'mongo.unavailable',
        message: 'Database connection not ready'
      }
    });
  }
  
  res.json({ ok: true });
});

// All other routes require internal token
app.use(requireInternalToken);

// Get OAuth URL
app.get('/oauth_url/:provider', async (req, res) => {
  try {
    const { provider } = req.params;
    const { userId, state } = req.query;
    
    if (!userId) {
      return handleError(res, { code: 'oauth.bad_request', message: 'userId is required' });
    }
    
    if (!PROVIDERS[provider]) {
      return handleError(res, { code: 'oauth.unsupported_provider', message: 'Unsupported provider' });
    }
    
    let authUrl;
    
    if (provider === 'hubspot') {
      const hubspotApi = getHubSpotApi(state);
      // Build authorization URL using provided state (Vivified validates)
      authUrl = hubspotApi.getAuthUri();
    }
    
    res.json({ url: authUrl });
    
  } catch (error) {
    handleError(res, error, 'oauth.url_generation_failed');
  }
});

// OAuth callback
app.post('/oauth_cb/:provider', async (req, res) => {
  try {
    const { provider } = req.params;
    const { userId, code, state } = req.body;
    
    if (!userId || !code) {
      return handleError(res, { code: 'oauth.bad_request', message: 'userId and code are required' });
    }
    
    if (!PROVIDERS[provider]) {
      return handleError(res, { code: 'oauth.unsupported_provider', message: 'Unsupported provider' });
    }
    
    // Test mode bypass
    if (process.env.NODE_ENV === 'test' && code === 'TEST_CODE') {
      const testEntity = {
        provider,
        account_name: 'Test Account',
        external_id: 'test_123'
      };
      
      // Save test credential
      await Credential.findOneAndUpdate(
        { userId, provider },
        {
          userId,
          provider,
          accessToken: 'test_token',
          refreshToken: 'test_refresh',
          externalId: testEntity.external_id,
          accountName: testEntity.account_name,
          updatedAt: new Date()
        },
        { upsert: true, new: true }
      );
      
      return res.json({ ok: true, entity: testEntity });
    }
    
    let entity = { provider };
    
    if (provider === 'hubspot') {
      const hubspotApi = getHubSpotApi(state);
      
      try {
        const tokenResponse = await hubspotApi.getTokenFromCode(code);
        
        if (!tokenResponse.access_token) {
          return handleError(res, { code: 'oauth.exchange_failed', message: 'Failed to exchange code for token' });
        }
        
        // Get account info
        // Fetch minimal user/account details (portalId, hub_domain)
        const userDetails = await hubspotApi.getUserDetails();
        entity.account_name = userDetails?.hub_domain || (userDetails?.portalId ? `Portal ${userDetails.portalId}` : 'HubSpot Account');
        entity.external_id = (userDetails?.portalId && String(userDetails.portalId)) || undefined;
        
        // Save credential
        await Credential.findOneAndUpdate(
          { userId, provider },
          {
            userId,
            provider,
            accessToken: tokenResponse.access_token,
            refreshToken: tokenResponse.refresh_token,
            externalId: entity.external_id,
            accountName: entity.account_name,
            expiresAt: tokenResponse.expires_in ? new Date(Date.now() + tokenResponse.expires_in * 1000) : null,
            updatedAt: new Date()
          },
          { upsert: true, new: true }
        );
        
      } catch (apiError) {
        return handleError(res, { code: 'oauth.exchange_failed', message: 'Failed to complete OAuth flow' });
      }
    }
    
    res.json({ ok: true, entity });
    
  } catch (error) {
    handleError(res, error, 'oauth.exchange_failed');
  }
});

// Get connection status
app.get('/status/:provider', async (req, res) => {
  try {
    const { provider } = req.params;
    const { userId } = req.query;
    
    if (!userId) {
      return handleError(res, { code: 'entity.bad_request', message: 'userId is required' });
    }
    
    if (!PROVIDERS[provider]) {
      return handleError(res, { code: 'entity.unsupported_provider', message: 'Unsupported provider' });
    }
    
    const credential = await Credential.findOne({ userId, provider });
    
    if (!credential) {
      return res.json({ connected: false });
    }
    
    const response = { connected: true };
    
    if (credential.accountName) {
      response.details = { account_name: credential.accountName };
    }
    
    res.json(response);
    
  } catch (error) {
    handleError(res, error, 'entity.status_check_failed');
  }
});

// Revoke connection
app.post('/revoke/:provider', async (req, res) => {
  try {
    const { provider } = req.params;
    const { userId } = req.body;
    
    if (!userId) {
      return handleError(res, { code: 'credential.bad_request', message: 'userId is required' });
    }
    
    if (!PROVIDERS[provider]) {
      return handleError(res, { code: 'credential.unsupported_provider', message: 'Unsupported provider' });
    }
    
    const credential = await Credential.findOne({ userId, provider });
    
    if (!credential) {
      return handleError(res, { code: 'entity.not_found', message: 'No connection found to revoke' });
    }
    
    // For HubSpot, we could call their revoke endpoint, but for now just delete locally
    await Credential.deleteOne({ userId, provider });
    
    res.json({ ok: true });
    
  } catch (error) {
    handleError(res, error, 'credential.delete_failed');
  }
});

// -----------------------------
// RPC endpoints for operator lane (POST-only)
// -----------------------------

// Connect (returns authorization URL)
app.post('/rpc/:provider/connect', async (req, res) => {
  try {
    const { provider } = req.params;
    const { userId, state } = req.body || {};
    if (!userId) return handleError(res, { code: 'oauth.bad_request', message: 'userId is required' });
    if (!PROVIDERS[provider]) return handleError(res, { code: 'oauth.unsupported_provider', message: 'Unsupported provider' });
    if (provider === 'hubspot') {
      const hubspotApi = getHubSpotApi(state);
      const url = hubspotApi.getAuthUri();
      return res.json({ url });
    }
    if (provider === 'gmail') {
      const oauth2 = new google.auth.OAuth2(
        process.env.GMAIL_CLIENT_ID,
        process.env.GMAIL_CLIENT_SECRET,
        buildRedirect('gmail'),
      );
      const scopes = (process.env.GMAIL_SCOPE || '').split(',').map(s => s.trim()).filter(Boolean);
      const url = oauth2.generateAuthUrl({ access_type: 'offline', include_granted_scopes: true, prompt: 'consent', scope: scopes, state });
      return res.json({ url });
    }
    if (provider === 'discord') {
      const oauth = new DiscordOAuth2({
        clientId: process.env.DISCORD_CLIENT_ID,
        clientSecret: process.env.DISCORD_CLIENT_SECRET,
        redirectUri: buildRedirect('discord'),
      });
      const scope = (process.env.DISCORD_SCOPE || 'identify,email').split(',').map(s => s.trim());
      const url = oauth.generateAuthUrl({ scope, state, prompt: 'consent', response_type: 'code' });
      return res.json({ url });
    }
    return handleError(res, { code: 'oauth.unsupported_provider', message: 'Unsupported provider' });
  } catch (e) {
    return handleError(res, { code: 'oauth.url_generation_failed', message: 'Failed to generate auth URL' });
  }
});

// Callback (code exchange)
app.post('/rpc/:provider/callback', async (req, res) => {
  const { provider } = req.params;
  req.url = `/oauth_cb/${provider}`; // reuse handler
  return app._router.handle(req, res, () => res.status(500).json({ error: { code: 'service.unavailable', message: 'Callback dispatch failed' } }));
});

// Status (O(1))
app.post('/rpc/:provider/status', async (req, res) => {
  const { provider } = req.params;
  const { userId } = req.body || {};
  if (!userId) return handleError(res, { code: 'entity.bad_request', message: 'userId is required' });
  const cred = await findCredential(userId, provider);
  if (!cred) return res.json({ connected: false });
  return res.json({ connected: true, details: { account_name: cred.accountName || provider } });
});

// Revoke (same as existing)
app.post('/rpc/:provider/revoke', async (req, res) => {
  const { provider } = req.params;
  req.url = `/revoke/${provider}`;
  return app._router.handle(req, res, () => res.status(500).json({ error: { code: 'service.unavailable', message: 'Revoke dispatch failed' } }));
});

// -----------------------------
// Gmail endpoints
// -----------------------------

app.get('/oauth_url/gmail', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return handleError(res, { code: 'oauth.bad_request', message: 'userId is required' });
    const oauth2 = new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET,
      buildRedirect('gmail'),
    );
    const scopes = (process.env.GMAIL_SCOPE || '').split(',').map(s => s.trim()).filter(Boolean);
    const state = req.query.state || req.header('X-Request-Id') || `${Date.now()}:${Math.random()}`;
    const url = oauth2.generateAuthUrl({
      access_type: 'offline', include_granted_scopes: true, prompt: 'consent', scope: scopes, state,
    });
    return res.json({ url, state, provider: 'gmail' });
  } catch (e) {
    return handleError(res, { code: 'oauth.url_generation_failed', message: 'Failed to generate Gmail URL' });
  }
});

app.post('/oauth_cb/gmail', async (req, res) => {
  try {
    const { code, userId } = req.body || {};
    if (!userId || !code) return handleError(res, { code: 'oauth.bad_request', message: 'userId and code are required' });

    if (process.env.NODE_ENV === 'test' && code === 'TEST_CODE') {
      await upsertCredential(userId, 'gmail', {
        accessToken: 'test', refreshToken: 'test', accountName: 'test@example.com', externalId: 'gmail_test'
      });
      return res.json({ ok: true, entity: { provider: 'gmail', account_name: 'test@example.com' } });
    }

    const oauth2 = new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET,
      buildRedirect('gmail'),
    );
    const { tokens } = await oauth2.getToken(code);
    oauth2.setCredentials(tokens);

    const oauth2Client = google.oauth2({ version: 'v2', auth: oauth2 });
    const userinfo = await oauth2Client.userinfo.get();
    const email = userinfo?.data?.email || null;
    const hd = userinfo?.data?.hd || (email ? String(email).split('@')[1] : null);

    const enforceWorkspace = String(process.env.GMAIL_ENFORCE_WORKSPACE_DOMAIN || 'false').toLowerCase() === 'true';
    const allowedDomain = (process.env.GMAIL_ALLOWED_DOMAIN || '').toLowerCase();
    if (enforceWorkspace && allowedDomain) {
      if (!hd || hd.toLowerCase() !== allowedDomain) {
        return res.status(403).json({ error: { code: 'oauth.domain_not_allowed', message: 'Workspace domain not allowed' } });
      }
    }

    await upsertCredential(userId, 'gmail', {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || null,
      externalId: email || 'gmail',
      accountName: email || 'Gmail',
      expiresAt: tokens.expiry_date ? new Date(tokens.expiry_date) : null,
    });
    return res.json({ ok: true, entity: { provider: 'gmail', account_name: email || 'Gmail' } });
  } catch (e) {
    return handleError(res, { code: 'oauth.exchange_failed', message: 'Gmail code exchange failed' });
  }
});

app.get('/status/gmail', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return handleError(res, { code: 'entity.bad_request', message: 'userId is required' });
    const cred = await findCredential(userId, 'gmail');
    if (!cred) return res.json({ connected: false });
    return res.json({ connected: true, details: { account_name: cred.accountName || 'Gmail' } });
  } catch (e) {
    return handleError(res, { code: 'entity.status_check_failed', message: 'Status check failed' });
  }
});

app.post('/revoke/gmail', async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return handleError(res, { code: 'credential.bad_request', message: 'userId is required' });
    await deleteCredential(userId, 'gmail');
    return res.json({ ok: true });
  } catch (e) {
    return handleError(res, { code: 'credential.delete_failed', message: 'Revoke failed' });
  }
});

// -----------------------------
// Discord endpoints
// -----------------------------

app.get('/oauth_url/discord', async (req, res) => {
  try {
    const state = req.query.state || req.header('X-Request-Id') || `${Date.now()}:${Math.random()}`;
    const scope = (process.env.DISCORD_SCOPE || 'identify,email').split(',').map(s => s.trim());
    const oauth = new DiscordOAuth2({
      clientId: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      redirectUri: buildRedirect('discord'),
    });
    const url = oauth.generateAuthUrl({ scope, state, prompt: 'consent', response_type: 'code' });
    return res.json({ url, state, provider: 'discord' });
  } catch (e) {
    return handleError(res, { code: 'oauth.url_generation_failed', message: 'Failed to generate Discord URL' });
  }
});

app.post('/oauth_cb/discord', async (req, res) => {
  try {
    const { code, userId } = req.body || {};
    if (!userId || !code) return handleError(res, { code: 'oauth.bad_request', message: 'userId and code are required' });

    if (process.env.NODE_ENV === 'test' && code === 'TEST_CODE') {
      await upsertCredential(userId, 'discord', { accessToken: 'test', refreshToken: 'test', accountName: 'TestUser#0001', externalId: 'discord_test' });
      return res.json({ ok: true, entity: { provider: 'discord', account_name: 'TestUser#0001' } });
    }

    const oauth = new DiscordOAuth2({
      clientId: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      redirectUri: buildRedirect('discord'),
    });
    const token = await oauth.tokenRequest({
      code,
      scope: (process.env.DISCORD_SCOPE || 'identify,email').split(',').map(s => s.trim()),
      grantType: 'authorization_code',
    });
    const me = await oauth.getUser(token.access_token);
    const tag = `${me.username}${me.discriminator ? '#' + me.discriminator : ''}`;
    await upsertCredential(req.body.userId, 'discord', {
      accessToken: token.access_token,
      refreshToken: token.refresh_token || null,
      externalId: me.id,
      accountName: tag,
    });
    return res.json({ ok: true, entity: { provider: 'discord', account_name: tag } });
  } catch (e) {
    return handleError(res, { code: 'oauth.exchange_failed', message: 'Discord code exchange failed' });
  }
});

app.get('/status/discord', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return handleError(res, { code: 'entity.bad_request', message: 'userId is required' });
    const cred = await findCredential(userId, 'discord');
    if (!cred) return res.json({ connected: false });
    return res.json({ connected: true, details: { account_name: cred.accountName || 'Discord' } });
  } catch (e) {
    return handleError(res, { code: 'entity.status_check_failed', message: 'Status check failed' });
  }
});

app.post('/revoke/discord', async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return handleError(res, { code: 'credential.bad_request', message: 'userId is required' });
    await deleteCredential(userId, 'discord');
    return res.json({ ok: true });
  } catch (e) {
    return handleError(res, { code: 'credential.delete_failed', message: 'Revoke failed' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: {
      code: 'service.unavailable',
      message: 'Internal server error'
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: {
      code: 'route.not_found',
      message: 'Endpoint not found'
    }
  });
});

// Start server
app.listen(PORT, () => {
  const env = process.env.NODE_ENV || 'development';
  console.log(`Integrations service running on port ${PORT}`);
  console.log(`Environment: ${env}`);
  
  if (env === 'production') {
    console.log('Production mode: logging at warn/error level');
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  mongoose.connection.close(() => {
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  mongoose.connection.close(() => {
    process.exit(0);
  });
});

module.exports = app;
