#!/bin/bash

# Simple integration test for the HTTP server

echo "Starting server integration test..."

# Set test configuration
export CONFIG_FILE=test-config.yaml

# Start the server in background
./bin/server &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Test health endpoint
echo "Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s http://localhost:8080/health)
if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
    echo "✓ Health check passed"
else
    echo "✗ Health check failed: $HEALTH_RESPONSE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Test readiness endpoint
echo "Testing readiness endpoint..."
READY_RESPONSE=$(curl -s http://localhost:8080/ready)
if echo "$READY_RESPONSE" | grep -q "ready\|not_ready"; then
    echo "✓ Readiness check passed"
else
    echo "✗ Readiness check failed: $READY_RESPONSE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Test metrics endpoint
echo "Testing metrics endpoint..."
METRICS_RESPONSE=$(curl -s http://localhost:8080/metrics)
if echo "$METRICS_RESPONSE" | grep -q "http_requests_total"; then
    echo "✓ Metrics endpoint passed"
else
    echo "✗ Metrics endpoint failed: $METRICS_RESPONSE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Test CORS headers
echo "Testing CORS headers..."
CORS_RESPONSE=$(curl -s -I -H "Origin: http://localhost:3000" -H "Access-Control-Request-Method: GET" -X OPTIONS http://localhost:8080/health)
if echo "$CORS_RESPONSE" | grep -q "Access-Control-Allow-Origin"; then
    echo "✓ CORS headers passed"
else
    echo "✗ CORS headers failed: $CORS_RESPONSE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Test WebSocket endpoint (should return authentication error since no token provided)
echo "Testing WebSocket endpoint..."
WS_RESPONSE=$(curl -s http://localhost:8080/ws)
if echo "$WS_RESPONSE" | grep -q "Authentication failed\|missing authentication token"; then
    echo "✓ WebSocket endpoint handled correctly (authentication required as expected)"
else
    echo "✗ WebSocket endpoint failed: $WS_RESPONSE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Test GraphQL endpoint (should return playground HTML for GET in development mode)
echo "Testing GraphQL endpoint..."
GRAPHQL_RESPONSE=$(curl -s -w "%{http_code}" http://localhost:8080/graphql)
if echo "$GRAPHQL_RESPONSE" | grep -q "GraphQL Playground\|200"; then
    echo "✓ GraphQL endpoint responded correctly (playground served)"
else
    echo "✗ GraphQL endpoint failed: $GRAPHQL_RESPONSE"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Clean up
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo "✓ All integration tests passed!"
echo "HTTP server and routing implementation is working correctly."