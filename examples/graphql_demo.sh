#!/bin/bash

# GraphQL API Gateway Demo Script
# This script demonstrates the GraphQL functionality

echo "🚀 GraphQL API Gateway Demo"
echo "================================"

# Check if server is running
SERVER_URL="http://localhost:8080"
GRAPHQL_ENDPOINT="$SERVER_URL/graphql"
PLAYGROUND_URL="$SERVER_URL/playground"

echo "📡 Checking if server is running at $SERVER_URL..."

# Health check
if curl -s "$SERVER_URL/health" > /dev/null; then
    echo "✅ Server is running!"
else
    echo "❌ Server is not running. Please start the server first:"
    echo "   go run examples/graphql_server_example.go"
    exit 1
fi

echo ""
echo "🔍 Testing GraphQL Health Query..."

# Test health query
HEALTH_QUERY='{
  "query": "{ health }"
}'

HEALTH_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$HEALTH_QUERY" \
  "$GRAPHQL_ENDPOINT")

echo "Response: $HEALTH_RESPONSE"

echo ""
echo "🔐 Testing GraphQL Login Mutation (will fail without auth service)..."

# Test login mutation
LOGIN_MUTATION='{
  "query": "mutation { login(input: { email: \"test@example.com\", password: \"password123\" }) { user { id firstName email } accessToken } }"
}'

LOGIN_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "$LOGIN_MUTATION" \
  "$GRAPHQL_ENDPOINT")

echo "Response: $LOGIN_RESPONSE"

echo ""
echo "🎮 GraphQL Playground is available at: $PLAYGROUND_URL"
echo ""
echo "📝 Example queries you can try in the playground:"
echo ""
echo "1. Health Check:"
echo "   { health }"
echo ""
echo "2. Current User (requires authentication):"
echo "   { me { id firstName lastName email } }"
echo ""
echo "3. Login:"
echo "   mutation {"
echo "     login(input: { email: \"user@example.com\", password: \"password\" }) {"
echo "       user { id firstName email }"
echo "       accessToken"
echo "     }"
echo "   }"
echo ""
echo "4. User Registration:"
echo "   mutation {"
echo "     register(input: {"
echo "       firstName: \"John\""
echo "       lastName: \"Doe\""
echo "       email: \"john@example.com\""
echo "       password: \"securepassword\""
echo "     }) {"
echo "       user { id email }"
echo "       accessToken"
echo "     }"
echo "   }"
echo ""
echo "✨ Demo completed! Visit $PLAYGROUND_URL to explore the GraphQL API interactively."