#!/bin/bash
# Test the embedded assistant to make sure it's actually repo-aware

set -e

echo "=== Testing Embedded AI Assistant ==="
echo

# 1. Get a dev token
echo "1. Getting auth token..."
TOKEN=$(curl -s http://localhost:8000/auth/dev-login -H "Content-Type: application/json" -d '{"username":"admin"}' | jq -r '.token')
if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "❌ Failed to get auth token"
    exit 1
fi
echo "✓ Got auth token"
echo

# 2. Check AI config
echo "2. Checking AI config..."
AI_CONFIG=$(curl -s http://localhost:8000/admin/ai/config -H "Authorization: Bearer $TOKEN")
echo "$AI_CONFIG" | jq '.'
HAS_KEY=$(echo "$AI_CONFIG" | jq -r '.llm.api_key_present')
if [ "$HAS_KEY" != "true" ]; then
    echo "❌ No API key configured. Go to Admin Console → AI Studio → Connectors and set your ANTHROPIC_API_KEY"
    exit 1
fi
echo "✓ API key configured"
echo

# 3. Check if RAG is trained
echo "3. Checking RAG status..."
RAG_STATUS=$(curl -s http://localhost:8000/admin/ai/status -H "Authorization: Bearer $TOKEN")
echo "$RAG_STATUS" | jq '.'
INDEXED=$(echo "$RAG_STATUS" | jq -r '.indexed_documents // 0')
if [ "$INDEXED" = "0" ]; then
    echo "⚠️  No documents indexed yet. Training RAG..."
    curl -s -X POST http://localhost:8000/admin/ai/train \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"paths":["."],"force_reload":false}' | jq '.'
    echo "✓ Training complete (or in progress)"
else
    echo "✓ $INDEXED documents already indexed"
fi
echo

# 4. Test the agent with a repo-specific question
echo "4. Testing agent with repo-specific question..."
echo "Question: 'How do I create a Vivified plugin?'"
RESPONSE=$(curl -s -X POST http://localhost:8000/admin/ai/agent/run \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "messages": [
            {"role": "user", "content": "How do I create a Vivified plugin? Show me actual code from the repo."}
        ],
        "hipaa_mode": false
    }')

echo
echo "=== Response ==="
echo "$RESPONSE" | jq -r '.result' || echo "$RESPONSE"
echo
echo "=== Tools Used ==="
echo "$RESPONSE" | jq '.tools_used' || echo "None"
echo

# Check if rag_search was used
USED_RAG=$(echo "$RESPONSE" | jq -r '.tools_used[]?.name' | grep -q "rag_search" && echo "yes" || echo "no")
if [ "$USED_RAG" = "yes" ]; then
    echo "✅ SUCCESS: The assistant used rag_search tool to search the codebase!"
else
    echo "❌ PROBLEM: The assistant did NOT use the rag_search tool"
    echo "   This means it's not actually repo-aware and is just using its generic knowledge"
    echo
    echo "   To fix this, make sure:"
    echo "   1. AI_AGENT_TOOL_CALLING=true in docker-compose.yml (should already be set)"
    echo "   2. The RAG index is trained (check AI Studio)"
    echo "   3. The Anthropic API key is valid"
fi

echo
echo "=== Test Complete ==="
