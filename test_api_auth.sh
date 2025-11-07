#!/bin/bash

# Test API authentication with the auth_pre_check plugin

echo "=== Testing API Authentication ==="
echo ""

# Get the JWT token from environment or use a default
if [ -z "$MCPGATEWAY_BEARER_TOKEN" ]; then
    echo "⚠️  MCPGATEWAY_BEARER_TOKEN not set, using token from .env"
    # Extract token from .env file
    TOKEN=$(grep "^MCPGATEWAY_BEARER_TOKEN=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
    if [ -z "$TOKEN" ]; then
        echo "❌ No token found in .env file"
        exit 1
    fi
else
    TOKEN="$MCPGATEWAY_BEARER_TOKEN"
fi

echo "Using token: ${TOKEN:0:20}..."
echo ""

# Test 1: GET /tools with Authorization header
echo "Test 1: GET /tools with Authorization header"
echo "-------------------------------------------"
curl -v -H "Authorization: Bearer $TOKEN" http://localhost:5555/tools 2>&1 | grep -E "(< HTTP|< Content-Type|jwt_claims|Plugin authenticated|RBAC|401|403|200)"
echo ""
echo ""

# Test 2: GET /tools without Authorization header (should fail)
echo "Test 2: GET /tools without Authorization header (should fail)"
echo "-------------------------------------------------------------"
curl -v http://localhost:5555/tools 2>&1 | grep -E "(< HTTP|< Content-Type|401|403)"
echo ""
echo ""

# Test 3: Check server logs for authentication flow
echo "Test 3: Check recent server logs"
echo "---------------------------------"
echo "Look for these log messages:"
echo "  ✅ Plugin authenticated request"
echo "  🔍 RBAC: Checking for plugin authentication"
echo "  ✅ RBAC: Using authentication from API auth middleware"
echo ""

# Made with Bob
