#!/bin/bash
# Quick test script for py3signer API

set -e

BASE_URL="${PY3SIGNER_URL:-http://localhost:8080}"

echo "Testing py3signer at $BASE_URL"
echo "================================"

# Health check
echo "1. Health check..."
curl -s "$BASE_URL/health" | python -m json.tool
echo ""

# List keystores (empty)
echo "2. List keystores..."
curl -s "$BASE_URL/eth/v1/keystores" | python -m json.tool
echo ""

# Import keystore (requires sample_keystore.json)
if [ -f "examples/sample_keystore.json" ]; then
    echo "3. Import keystore..."
    KEYSTORE=$(cat examples/sample_keystore.json)
    curl -s -X POST "$BASE_URL/eth/v1/keystores" \
        -H "Content-Type: application/json" \
        -d "{\"keystores\": [$KEYSTORE], \"passwords\": [\"testpassword123\"]}" | python -m json.tool
    echo ""

    # List again
    echo "4. List keystores after import..."
    curl -s "$BASE_URL/eth/v1/keystores" | python -m json.tool
    echo ""

    # Sign data
    PUBKEY="a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c"
    echo "5. Sign data..."
    curl -s -X POST "$BASE_URL/api/v1/eth2/sign/$PUBKEY" \
        -H "Content-Type: application/json" \
        -d '{
            "signingRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "domain_name": "beacon_attester"
        }' | python -m json.tool
    echo ""

    # Delete keystore
    echo "6. Delete keystore..."
    curl -s -X DELETE "$BASE_URL/eth/v1/keystores" \
        -H "Content-Type: application/json" \
        -d "{\"pubkeys\": [\"$PUBKEY\"]}" | python -m json.tool
    echo ""

    # List after delete
    echo "7. List keystores after delete..."
    curl -s "$BASE_URL/eth/v1/keystores" | python -m json.tool
    echo ""
fi

echo "Tests complete!"
