#!/bin/bash
# Secure push script with environment-based credentials

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Validate required environment variables
if [ -z "$KIRK_API_KEY" ]; then
    echo "Error: KIRK_API_KEY not set in environment"
    exit 1
fi

if [ -z "$DROPLET_ENDPOINT" ]; then
    DROPLET_ENDPOINT="https://api.paraxiom.org/api/quantum/entropy/push"
fi

if [ -z "$KIRQ_HUB_PORT" ]; then
    KIRQ_HUB_PORT="8001"
fi

# Get fresh entropy from local sources
echo "Fetching quantum entropy from Kirq Hub..."
ENTROPY_RESPONSE=$(curl -s -X POST http://localhost:${KIRQ_HUB_PORT}/api/entropy/mixed \
  -H "Content-Type: application/json" \
  -d '{
    "num_bytes": 32,
    "sources": ["qrng", "crypto4a", "quantum_vault"],
    "proof_required": false
  }')

# Extract entropy
ENTROPY=$(echo "$ENTROPY_RESPONSE" | jq -r .entropy)
if [ -z "$ENTROPY" ] || [ "$ENTROPY" = "null" ]; then
    echo "Failed to get entropy from Kirq Hub"
    echo "Response: $ENTROPY_RESPONSE"
    exit 1
fi

# Prepare push data
TIMESTAMP=$(date +%s)
SOURCES="qrng,crypto4a,quantum_vault"

# Create HMAC using KIRK_API_KEY
MESSAGE="${ENTROPY}:${TIMESTAMP}:${SOURCES}"
HMAC=$(echo -n "$MESSAGE" | openssl dgst -sha256 -hmac "$KIRK_API_KEY" | cut -d' ' -f2)

# Push to droplet
echo "Pushing quantum entropy to $DROPLET_ENDPOINT..."
RESPONSE=$(curl -s -X POST "$DROPLET_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${BEARER_TOKEN}" \
  -d "{
    \"entropy\": \"$ENTROPY\",
    \"sources\": [\"qrng\", \"crypto4a\", \"quantum_vault\"],
    \"timestamp\": $TIMESTAMP,
    \"hmac\": \"$HMAC\"
  }")

# Check response
if echo "$RESPONSE" | jq -e '.accepted == true' > /dev/null 2>&1; then
    echo "✓ Entropy pushed successfully"
    echo "  ID: $(echo "$RESPONSE" | jq -r .id)"
else
    echo "✗ Push failed:"
    echo "$RESPONSE" | jq .
fi