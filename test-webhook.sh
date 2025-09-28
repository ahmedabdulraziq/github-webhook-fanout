#!/bin/bash

# Test script for the GitHub webhook fanout server
# This script simulates a GitHub webhook payload

SERVER_URL="http://localhost:8080"
WEBHOOK_SECRET="test-secret"

# Sample GitHub webhook payload
PAYLOAD='{
  "ref": "refs/heads/main",
  "repository": {
    "name": "test-repo",
    "full_name": "user/test-repo"
  },
  "commits": [
    {
      "id": "abc123",
      "message": "Test commit"
    }
  ]
}'

# Calculate signature (simplified for testing)
SIGNATURE="sha256=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" -binary | xxd -p -c 256)"

echo "Testing webhook endpoint..."
echo "Payload: $PAYLOAD"
echo "Signature: $SIGNATURE"
echo ""

# Send the webhook
curl -X POST "$SERVER_URL/webhook" \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: $SIGNATURE" \
  -d "$PAYLOAD" \
  -v

echo ""
echo "Test completed!"
