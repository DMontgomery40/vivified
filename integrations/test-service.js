// Simple test script to verify the integrations service
const axios = require('axios');

const BASE_URL = 'http://localhost:3001';
const INTERNAL_TOKEN = 'test-token';

const headers = {
  'X-Internal-Token': INTERNAL_TOKEN,
  'Content-Type': 'application/json'
};

async function testService() {
  console.log('Testing Integrations Service...\n');
  
  try {
    // Test health endpoint (no auth required)
    console.log('1. Testing health endpoint...');
    const healthResponse = await axios.get(`${BASE_URL}/health`);
    console.log('✓ Health check:', healthResponse.data);
    
    // Test OAuth URL generation
    console.log('\n2. Testing OAuth URL generation...');
    const oauthResponse = await axios.get(`${BASE_URL}/oauth_url/hubspot?userId=test123`, { headers });
    console.log('✓ OAuth URL:', oauthResponse.data);
    
    // Test OAuth callback with test code
    console.log('\n3. Testing OAuth callback (test mode)...');
    const callbackResponse = await axios.post(`${BASE_URL}/oauth_cb/hubspot`, {
      userId: 'test123',
      code: 'TEST_CODE'
    }, { headers });
    console.log('✓ OAuth callback:', callbackResponse.data);
    
    // Test status check
    console.log('\n4. Testing status check...');
    const statusResponse = await axios.get(`${BASE_URL}/status/hubspot?userId=test123`, { headers });
    console.log('✓ Status check:', statusResponse.data);
    
    // Test revoke
    console.log('\n5. Testing revoke...');
    const revokeResponse = await axios.post(`${BASE_URL}/revoke/hubspot`, {
      userId: 'test123'
    }, { headers });
    console.log('✓ Revoke:', revokeResponse.data);
    
    console.log('\n✅ All tests passed!');
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  testService();
}

module.exports = testService;
