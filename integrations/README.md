# Vivified Integrations Service

A self-hosted integrator service that manages OAuth flows for third-party providers like HubSpot. This service exposes an internal API for the Vivified platform to handle integration authentication and management.

## Features

- **OAuth Flow Management**: Handles complete OAuth 2.0 flows for supported providers
- **Secure Token Storage**: Stores access tokens and refresh tokens in MongoDB
- **Internal API**: Provides a secure internal API for the Vivified core platform
- **Provider Support**: Currently supports HubSpot CRM with extensible architecture
- **HIPAA Compliance**: Designed with healthcare data security in mind
- **Docker Ready**: Fully containerized with health checks

## Architecture

The service acts as a bridge between Vivified Core and third-party providers:

```
Vivified Core ←→ Integrations Service ←→ Third-party APIs (HubSpot, etc.)
```

- **Internal Network Only**: Service runs on Docker internal network, not exposed to host
- **Token-based Security**: All requests require `X-Internal-Token` (or `X-Internal-Auth`) header
- **MongoDB Persistence**: Credentials and entities stored in dedicated MongoDB instance

### Access paths during migration

- Preferred (plugin-backed): Core exposes `/plugins/integration/{key}/...` routes that delegate to this service using internal auth headers and correlation IDs. Admin UI uses these routes by default.
- Legacy (compatibility): Core keeps `/integrations/*` endpoints temporarily and forwards to this service. These responses now include a `Deprecation: true` header. UI will migrate off these paths.

## Quick Start

### 1. Environment Setup

Copy the environment template:

```bash
cp env.example .env
```

Edit `.env` with your configuration:

```bash
# MongoDB Configuration
MONGO_URI=mongodb://mongo:27017/frigg

# Internal Security Token (must match Vivified Core)
INTERNAL_TOKEN=your-secure-internal-token-here

# OAuth Redirect Configuration
REDIRECT_URI=http://vivified-core:8000/integrations

# HubSpot OAuth Configuration
HUBSPOT_CLIENT_ID=your-hubspot-client-id
HUBSPOT_CLIENT_SECRET=your-hubspot-client-secret
HUBSPOT_SCOPE=contacts

# Environment
NODE_ENV=production
PORT=3001

# HIPAA mode (Core)
# When true, Core blocks non‑eligible providers unless explicitly allowed via INTEGRATIONS_HIPAA_ALLOWED
# For this step, hubspot/gmail/discord are not HIPAA‑eligible and will be blocked when HIPAA mode is enabled.
# INTEGRATIONS_HIPAA_MODE=true
# INTEGRATIONS_HIPAA_ALLOWED=hubspot
```

### 2. HubSpot App Registration

To use HubSpot integration, you need to create a HubSpot app:

1. Go to [HubSpot Developer Portal](https://developers.hubspot.com/)
2. Create a new app or use existing one
3. Configure OAuth settings:
   - **Redirect URL**: `http://your-vivified-domain:8000/integrations/hubspot/callback`
   - **Scopes**: At minimum `contacts` (or as configured in `HUBSPOT_SCOPE`)
4. Copy the Client ID and Client Secret to your `.env` file

### 3. Start Services

Using Docker Compose (recommended):

```bash
# From the vivified root directory
docker compose up -d mongo frigg
```

Or run locally for development:

```bash
# Install dependencies
npm install

# Start in development mode
npm run dev

# Or start in production mode
npm start
```

### 4. Verify Installation

Check service health:

```bash
# From within the Docker network (internal access only)
docker compose exec vivified-core curl -f http://frigg:3001/health

# Should return: {"ok": true}
```

## API Reference

All endpoints require the `X-Internal-Token` header for authentication.

### Health Check

```http
GET /health
```

Returns service and database health status. **No authentication required.**

**Response:**
```json
{
  "ok": true
}
```

### Get OAuth URL

```http
GET /oauth_url/{provider}?userId={userId}
```

Generates OAuth authorization URL for the specified provider.

**Parameters:**
- `provider`: Provider name (e.g., `hubspot`)
- `userId`: User identifier (query parameter)

**Response:**
```json
{
  "url": "https://app.hubspot.com/oauth/authorize?client_id=..."
}
```

### OAuth Callback

```http
POST /oauth_cb/{provider}
```

Exchanges OAuth authorization code for access token.

**Body:**
```json
{
  "userId": "user123",
  "code": "oauth_authorization_code",
  "state": "optional_state_parameter"
}
```

**Response:**
```json
{
  "ok": true,
  "entity": {
    "provider": "hubspot",
    "account_name": "Portal 12345",
    "external_id": "12345"
  }
}
```

### Check Connection Status

```http
GET /status/{provider}?userId={userId}
```

Returns connection status for a user and provider.

**Response:**
```json
{
  "connected": true,
  "details": {
    "account_name": "Portal 12345"
  }
}
```

### Revoke Connection

```http
POST /revoke/{provider}
```

Revokes and deletes stored credentials for a user and provider.

**Body:**
```json
{
  "userId": "user123"
}
```

**Response:**
```json
{
  "ok": true
}
```

## Error Handling

All errors follow a consistent format:

```json
{
  "error": {
    "code": "error_category.specific_error",
    "message": "Human readable error message"
  }
}
```

### Error Codes

- `auth.invalid_token`: Missing or invalid `X-Internal-Token`
- `mongo.unavailable`: Database connection issues
- `oauth.bad_request`: Missing required parameters
- `oauth.exchange_failed`: OAuth token exchange failed
- `oauth.unsupported_provider`: Provider not supported
- `entity.not_found`: No connection found for user/provider
- `credential.delete_failed`: Failed to revoke credentials
- `service.unavailable`: General service error

## Development

### Project Structure

```
integrations/
├── src/
│   └── server.js          # Main application server
├── Dockerfile             # Container configuration
├── package.json           # Node.js dependencies and scripts
├── env.example            # Environment template
└── README.md             # This file
```

### Scripts

- `npm run dev`: Start development server with auto-reload
- `npm start`: Start production server
- `npm run lint`: Run ESLint code linting
- `npm test`: Run test suite

### Testing

The service includes a test mode for CI/CD:

```bash
# Set test environment
NODE_ENV=test

# Use special test code
POST /oauth_cb/hubspot
{
  "userId": "test_user",
  "code": "TEST_CODE"
}
```

When `NODE_ENV=test` and `code=TEST_CODE`, the service bypasses external API calls and returns mock data.

### Adding New Providers

To add support for a new provider:

1. Add provider configuration to `PROVIDERS` object
2. Implement OAuth URL generation logic
3. Implement token exchange logic
4. Add provider-specific error handling
5. Update documentation

## Security Considerations

- **Internal Network Only**: Service should never be exposed to public internet
- **Token Security**: Internal tokens should be long, random, and rotated regularly
- **Credential Storage**: OAuth tokens are stored in MongoDB (internal-only network)
- **Audit Logging**: All operations are logged for compliance
- **No PII in Logs**: Personal information is never logged

## Monitoring

### Health Checks

The service provides health checks at multiple levels:

- **Application**: `/health` endpoint
- **Database**: MongoDB connection status
- **Docker**: Container health check every 30 seconds

### Logging

Logs are structured and include:

- Request/response logging (no sensitive data)
- Error tracking with stack traces
- OAuth flow completion events
- Database connection events

## Troubleshooting

### Common Issues

**Service won't start:**
- Check MongoDB connection string in `MONGO_URI`
- Verify all required environment variables are set
- Check Docker network connectivity

**OAuth flow fails:**
- Verify HubSpot app configuration matches redirect URI
- Check client ID and secret are correct
- Ensure scopes match between app and configuration

**Database connection issues:**
- Verify MongoDB is running and accessible
- Check network connectivity between containers
- Review MongoDB logs for authentication issues

### Debug Mode

Enable debug logging:

```bash
NODE_ENV=development npm run dev
```

This provides verbose logging for troubleshooting OAuth flows and database operations.

### Testing the Service

Test the service endpoints from within the Docker network:

```bash
# Test from within vivified-core container (internal access only)
docker compose exec vivified-core bash -c '
  TOKEN="change-this-internal-token"
  
  # Health check (no auth required)
  curl -f http://frigg:3001/health
  
  # Get OAuth URL
  curl -H "X-Internal-Token: $TOKEN" \
    "http://frigg:3001/oauth_url/hubspot?userId=test123"
  
  # Test OAuth callback (test mode)
  curl -X POST -H "X-Internal-Token: $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"userId\":\"test123\",\"code\":\"TEST_CODE\"}" \
    http://frigg:3001/oauth_cb/hubspot
  
  # Check connection status
  curl -H "X-Internal-Token: $TOKEN" \
    "http://frigg:3001/status/hubspot?userId=test123"
  
  # Revoke connection
  curl -X POST -H "X-Internal-Token: $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"userId\":\"test123\"}" \
    http://frigg:3001/revoke/hubspot
'
```

## Production Deployment

### Environment Variables

Ensure these are set in production:

```bash
NODE_ENV=production
MONGO_URI=mongodb://mongo:27017/frigg
INTERNAL_TOKEN=<secure-random-token>
HUBSPOT_CLIENT_ID=<your-client-id>
HUBSPOT_CLIENT_SECRET=<your-client-secret>
```

### Security Checklist

- [ ] Internal token is cryptographically secure
- [ ] MongoDB is not exposed to public internet
- [ ] Service runs as non-root user
- [ ] All dependencies are up to date
- [ ] Logs are monitored for errors
- [ ] Health checks are configured

## License

This software is proprietary to the Vivified platform. All rights reserved.
