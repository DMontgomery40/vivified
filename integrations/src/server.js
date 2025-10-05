require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const { HubSpotApi } = require('@friggframework/api-module-hubspot');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Internal token middleware - required for all routes except health
const requireInternalToken = (req, res, next) => {
  const token = req.headers['x-internal-token'];
  
  if (!token || token !== process.env.INTERNAL_TOKEN) {
    return res.status(401).json({
      error: {
        code: 'auth.invalid_token',
        message: 'Invalid or missing internal token'
      }
    });
  }
  
  next();
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
const getHubSpotApi = () => {
  return new HubSpotApi({
    client_id: process.env.HUBSPOT_CLIENT_ID,
    client_secret: process.env.HUBSPOT_CLIENT_SECRET,
    redirect_uri: `${process.env.REDIRECT_URI}/hubspot/callback`,
    scope: PROVIDERS.hubspot.scopes
  });
};

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
      const hubspotApi = getHubSpotApi();
      // Use state provided by Vivified (if any) - Vivified generates and validates state
      authUrl = hubspotApi.getAuthorizationUrl(state);
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
      const hubspotApi = getHubSpotApi();
      
      try {
        const tokenResponse = await hubspotApi.getTokenFromCode(code);
        
        if (!tokenResponse.access_token) {
          return handleError(res, { code: 'oauth.exchange_failed', message: 'Failed to exchange code for token' });
        }
        
        // Get account info
        const accountInfo = await hubspotApi.getAccount(tokenResponse.access_token);
        
        entity.account_name = accountInfo?.portalId ? `Portal ${accountInfo.portalId}` : 'HubSpot Account';
        entity.external_id = accountInfo?.portalId?.toString();
        
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
