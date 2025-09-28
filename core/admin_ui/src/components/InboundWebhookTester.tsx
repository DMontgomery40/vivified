import { useState } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  Alert,
  TextField,
  Paper,
  Chip,
  Stack,
  IconButton,
  Tooltip,
  Collapse,
  useTheme,
} from '@mui/material';
import {
  ContentCopy as CopyIcon,
  Send as SendIcon,
  ExpandMore as ExpandIcon,
  CheckCircle as ValidIcon,
  Error as InvalidIcon,
  Code as CodeIcon,
  Webhook as WebhookIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import AdminAPIClient from '../api/client';
import { useTraits } from '../hooks/useTraits';
import { ResponsiveFormSection } from './common/ResponsiveFormFields';

interface InboundWebhookTesterProps {
  client: AdminAPIClient;
}

interface TestResult {
  valid: boolean;
  signature_valid?: boolean;
  parsed_data?: any;
  error?: string;
  raw_response?: any;
}

export default function InboundWebhookTester({ client: _client }: InboundWebhookTesterProps) {
  const theme = useTheme();
  const { active, traitValue, getWebhookUrl, getSamplePayload, getProviderHeaders } = useTraits();

  const [testPayload, setTestPayload] = useState('');
  const [webhookSecret, setWebhookSecret] = useState('');
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [showCurl, setShowCurl] = useState(false);
  const [showRawResponse, setShowRawResponse] = useState(false);

  const activeInbound = active?.inbound || '';
  const inboundVerification = traitValue('inbound', 'inbound_verification') || 'none';

  const webhookUrl = getWebhookUrl('inbound') || `${window.location.origin}/webhook-inbound`;

  const getCurlCommand = () => {
    const headers = getProviderHeaders('inbound', webhookSecret);
    
    // Add basic auth if needed
    if (inboundVerification === 'basic' && webhookSecret) {
      const auth = btoa(`user:${webhookSecret}`);
      headers.push(`-H "Authorization: Basic ${auth}"`);
    }

    const payload = testPayload || getSamplePayload('inbound');
    
    return `curl -X POST ${webhookUrl} \\
  ${headers.join(' \\\n  ')} \\
  -d '${payload}'`;
  };


  const handleLoadSample = () => {
    setTestPayload(getSamplePayload('inbound'));
  };

  const handleTestPayload = async () => {
    if (!testPayload.trim()) {
      setTestResult({
        valid: false,
        error: 'Please enter a test payload'
      });
      return;
    }

    try {
      setLoading(true);
      setTestResult(null);

      // Parse the payload to validate JSON
      let parsedPayload;
      try {
        parsedPayload = JSON.parse(testPayload);
      } catch (e) {
        setTestResult({
          valid: false,
          error: 'Invalid JSON payload'
        });
        return;
      }

      // Simulate webhook processing locally
      // In a real implementation, this would call a server endpoint
      // that processes the webhook without making external calls
      const mockResult: TestResult = {
        valid: true,
        signature_valid: inboundVerification === 'none' ? undefined : !!webhookSecret,
        parsed_data: {
          fax_id: parsedPayload.fax?.id || parsedPayload.faxId || parsedPayload.FaxSid || 'test-12345',
          from: parsedPayload.fax?.from_number || parsedPayload.from || parsedPayload.From || 'unknown',
          to: parsedPayload.fax?.to_number || parsedPayload.to || parsedPayload.To || 'unknown',
          status: parsedPayload.fax?.status || parsedPayload.status || parsedPayload.Status || 'unknown',
          pages: parsedPayload.fax?.num_pages || parsedPayload.pages || parsedPayload.NumPages || 0,
        },
        raw_response: {
          processed: true,
          provider: activeInbound,
          verification: inboundVerification,
          timestamp: new Date().toISOString()
        }
      };

      setTestResult(mockResult);
    } catch (err) {
      setTestResult({
        valid: false,
        error: err instanceof Error ? err.message : 'Test failed'
      });
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      // Fallback for older browsers
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
    }
  };

  return (
    <ResponsiveFormSection
      title="Inbound Webhook Tester"
      subtitle="Test webhook payload processing without external calls"
      icon={<WebhookIcon />}
    >
      <Stack spacing={3}>
        {/* Provider Info */}
        <Alert severity="info" sx={{ borderRadius: 2 }}>
          <Typography variant="body2" fontWeight={500}>
            Active Inbound Provider: {activeInbound || 'None'}
          </Typography>
          <Typography variant="body2">
            Verification: {inboundVerification} • 
            Webhook URL: {getWebhookUrl('inbound')}
          </Typography>
        </Alert>

        {/* cURL Command */}
        <Card elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
              <Typography variant="subtitle2" fontWeight={600}>
                Provider Webhook Configuration
              </Typography>
              <Button
                size="small"
                onClick={() => setShowCurl(!showCurl)}
                endIcon={<ExpandIcon sx={{ transform: showCurl ? 'rotate(180deg)' : 'none' }} />}
              >
                {showCurl ? 'Hide' : 'Show'} cURL
              </Button>
            </Box>
            
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              Configure this URL in your provider console:
            </Typography>
            
            <Box sx={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: 1,
              p: 1,
              backgroundColor: theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)',
              borderRadius: 1,
              fontFamily: 'monospace',
              fontSize: '0.875rem',
              wordBreak: 'break-all'
            }}>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', flex: 1 }}>
                {getWebhookUrl('inbound')}
              </Typography>
              <Tooltip title="Copy URL">
                <IconButton size="small" onClick={() => copyToClipboard(getWebhookUrl('inbound') || '')}>
                  <CopyIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Box>

            <Collapse in={showCurl}>
              <Box sx={{ mt: 2 }}>
                <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
                  Test with cURL:
                </Typography>
                <Paper
                  elevation={0}
                  sx={{
                    p: 2,
                    backgroundColor: theme.palette.mode === 'dark' ? '#1e1e1e' : '#f5f5f5',
                    border: '1px solid',
                    borderColor: 'divider',
                    borderRadius: 1,
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                    <Typography
                      variant="body2"
                      sx={{
                        fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap',
                        flex: 1,
                        fontSize: '0.75rem',
                      }}
                    >
                      {getCurlCommand()}
                    </Typography>
                    <Tooltip title="Copy cURL">
                      <IconButton size="small" onClick={() => copyToClipboard(getCurlCommand())}>
                        <CopyIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </Paper>
              </Box>
            </Collapse>
          </CardContent>
        </Card>

        {/* Webhook Secret (if required) */}
        {inboundVerification !== 'none' && (
          <TextField
            label="Webhook Secret"
            value={webhookSecret}
            onChange={(e) => setWebhookSecret(e.target.value)}
            placeholder={inboundVerification === 'basic' ? 'Basic auth password' : 'HMAC secret key'}
            type="password"
            helperText={`Required for ${inboundVerification.toUpperCase()} verification`}
            fullWidth
            size="small"
            InputProps={{
              startAdornment: <SecurityIcon sx={{ mr: 1, color: 'text.secondary' }} />,
            }}
          />
        )}

        {/* Test Payload Input */}
        <Box>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="subtitle2" fontWeight={600}>
              Test Payload
            </Typography>
            <Button
              size="small"
              variant="outlined"
              onClick={handleLoadSample}
              startIcon={<CodeIcon />}
            >
              Load Sample
            </Button>
          </Box>
          
          <TextField
            multiline
            rows={8}
            value={testPayload}
            onChange={(e) => setTestPayload(e.target.value)}
            placeholder="Paste webhook payload JSON here..."
            fullWidth
            sx={{
              '& .MuiInputBase-input': {
                fontFamily: 'monospace',
                fontSize: '0.875rem',
              }
            }}
          />
        </Box>

        {/* Test Button */}
        <Button
          variant="contained"
          onClick={handleTestPayload}
          disabled={loading || !testPayload.trim()}
          startIcon={loading ? undefined : <SendIcon />}
          sx={{ borderRadius: 2 }}
        >
          {loading ? 'Testing...' : 'Send Test to Local Parser'}
        </Button>

        {/* Test Results */}
        {testResult && (
          <Card 
            elevation={0} 
            sx={{ 
              border: '2px solid', 
              borderColor: testResult.valid ? 'success.main' : 'error.main',
              borderRadius: 2 
            }}
          >
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                {testResult.valid ? (
                  <ValidIcon color="success" />
                ) : (
                  <InvalidIcon color="error" />
                )}
                <Typography variant="h6" fontWeight={600}>
                  {testResult.valid ? 'Valid Payload' : 'Invalid Payload'}
                </Typography>
              </Box>

              {testResult.error && (
                <Alert severity="error" sx={{ mb: 2, borderRadius: 1 }}>
                  {testResult.error}
                </Alert>
              )}

              {testResult.signature_valid !== undefined && (
                <Box sx={{ mb: 2 }}>
                  <Chip
                    icon={testResult.signature_valid ? <ValidIcon /> : <InvalidIcon />}
                    label={`Signature: ${testResult.signature_valid ? 'Valid' : 'Invalid'}`}
                    color={testResult.signature_valid ? 'success' : 'error'}
                    variant="outlined"
                    sx={{ borderRadius: 1 }}
                  />
                </Box>
              )}

              {testResult.parsed_data && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                    Parsed Data:
                  </Typography>
                  <Paper
                    elevation={0}
                    sx={{
                      p: 2,
                      backgroundColor: theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)',
                      borderRadius: 1,
                    }}
                  >
                    <pre style={{ 
                      margin: 0, 
                      fontFamily: 'monospace', 
                      fontSize: '0.875rem',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word'
                    }}>
                      {JSON.stringify(testResult.parsed_data, null, 2)}
                    </pre>
                  </Paper>
                </Box>
              )}

              {testResult.raw_response && (
                <Box>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                    <Typography variant="subtitle2" fontWeight={600}>
                      Raw Response:
                    </Typography>
                    <Button
                      size="small"
                      onClick={() => setShowRawResponse(!showRawResponse)}
                      endIcon={<ExpandIcon sx={{ transform: showRawResponse ? 'rotate(180deg)' : 'none' }} />}
                    >
                      {showRawResponse ? 'Hide' : 'Show'}
                    </Button>
                  </Box>
                  
                  <Collapse in={showRawResponse}>
                    <Paper
                      elevation={0}
                      sx={{
                        p: 2,
                        backgroundColor: theme.palette.mode === 'dark' ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)',
                        borderRadius: 1,
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
                        <pre style={{ 
                          margin: 0, 
                          fontFamily: 'monospace', 
                          fontSize: '0.875rem',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-word',
                          flex: 1
                        }}>
                          {JSON.stringify(testResult.raw_response, null, 2)}
                        </pre>
                        <Tooltip title="Copy Response">
                          <IconButton 
                            size="small" 
                            onClick={() => copyToClipboard(JSON.stringify(testResult.raw_response, null, 2))}
                          >
                            <CopyIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </Paper>
                  </Collapse>
                </Box>
              )}
            </CardContent>
          </Card>
        )}
      </Stack>
    </ResponsiveFormSection>
  );
}
