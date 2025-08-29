#!/bin/bash

# Test script for AI Copilot integration with API Gateway
# This script tests the integration between the API Gateway and AI Copilot service

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AI_COPILOT_URL="http://localhost:8003"
API_GATEWAY_URL="http://localhost:8000"
TEST_USER_ID="test-user-123"
TEST_CONVERSATION_ID="test-conv-456"

echo -e "${BLUE}🚀 Testing AI Copilot Integration with API Gateway${NC}"
echo "=================================================="

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "success" ]; then
        echo -e "${GREEN}✅ $message${NC}"
    elif [ "$status" = "error" ]; then
        echo -e "${RED}❌ $message${NC}"
    elif [ "$status" = "info" ]; then
        echo -e "${BLUE}ℹ️  $message${NC}"
    elif [ "$status" = "warning" ]; then
        echo -e "${YELLOW}⚠️  $message${NC}"
    fi
}

# Function to check if service is running
check_service() {
    local url=$1
    local service_name=$2
    
    print_status "info" "Checking if $service_name is running at $url..."
    
    if curl -s --max-time 5 "$url/health" > /dev/null 2>&1; then
        print_status "success" "$service_name is running"
        return 0
    else
        print_status "error" "$service_name is not running at $url"
        return 1
    fi
}

# Function to test AI Copilot service directly
test_ai_copilot_direct() {
    print_status "info" "Testing AI Copilot service directly..."
    
    # Test health endpoint
    if curl -s "$AI_COPILOT_URL/health" | grep -q "healthy"; then
        print_status "success" "AI Copilot health check passed"
    else
        print_status "error" "AI Copilot health check failed"
        return 1
    fi
    
    # Test models endpoint
    if curl -s "$AI_COPILOT_URL/models" | grep -q "ollama"; then
        print_status "success" "AI Copilot models endpoint working"
    else
        print_status "error" "AI Copilot models endpoint failed"
        return 1
    fi
    
    # Test chat endpoint
    local chat_response=$(curl -s -X POST "$AI_COPILOT_URL/chat" \
        -H "Content-Type: application/json" \
        -d '{"message": "What is the current inventory status?", "model": "unibase-erp"}')
    
    if echo "$chat_response" | grep -q "success.*true"; then
        print_status "success" "AI Copilot chat endpoint working"
        echo "Response: $(echo "$chat_response" | jq -r '.response' 2>/dev/null || echo 'Response received')"
    else
        print_status "error" "AI Copilot chat endpoint failed: $chat_response"
        return 1
    fi
    
    return 0
}

# Function to test API Gateway integration
test_api_gateway_integration() {
    print_status "info" "Testing API Gateway integration..."
    
    # Test API Gateway health
    if curl -s "$API_GATEWAY_URL/health" | grep -q "healthy"; then
        print_status "success" "API Gateway health check passed"
    else
        print_status "error" "API Gateway health check failed"
        return 1
    fi
    
    # Test AI endpoints through API Gateway
    local ai_response=$(curl -s "$API_GATEWAY_URL/api/ai/status" 2>/dev/null || echo "endpoint not available")
    
    if [ "$ai_response" != "endpoint not available" ]; then
        print_status "success" "API Gateway AI endpoints accessible"
    else
        print_status "warning" "API Gateway AI endpoints not yet implemented"
    fi
    
    return 0
}

# Function to test WebSocket connection
test_websocket_connection() {
    print_status "info" "Testing WebSocket connection..."
    
    # This would require a WebSocket client, so we'll just check if the endpoint exists
    local ws_response=$(curl -s -I "$AI_COPILOT_URL/ws" 2>/dev/null || echo "websocket not available")
    
    if echo "$ws_response" | grep -q "101 Switching Protocols\|Upgrade.*websocket"; then
        print_status "success" "WebSocket endpoint accessible"
    else
        print_status "warning" "WebSocket endpoint not yet implemented or not accessible"
    fi
    
    return 0
}

# Function to test gRPC integration
test_grpc_integration() {
    print_status "info" "Testing gRPC integration..."
    
    # Check if gRPC port is accessible
    if nc -z localhost 50051 2>/dev/null; then
        print_status "success" "gRPC port 50051 is accessible"
    else
        print_status "warning" "gRPC port 50051 is not accessible"
    fi
    
    return 0
}

# Function to run performance test
run_performance_test() {
    print_status "info" "Running performance test..."
    
    local start_time=$(date +%s.%N)
    local success_count=0
    local total_requests=5
    
    for i in $(seq 1 $total_requests); do
        if curl -s -X POST "$AI_COPILOT_URL/chat" \
            -H "Content-Type: application/json" \
            -d '{"message": "Test message", "model": "unibase-erp"}' \
            | grep -q "success.*true"; then
            success_count=$((success_count + 1))
        fi
        sleep 0.5
    done
    
    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
    local success_rate=$(echo "scale=2; $success_count * 100 / $total_requests" | bc -l 2>/dev/null || echo "0")
    
    print_status "info" "Performance test results:"
    echo "  - Total requests: $total_requests"
    echo "  - Successful requests: $success_count"
    echo "  - Success rate: ${success_rate}%"
    echo "  - Total duration: ${duration}s"
    echo "  - Average response time: $(echo "scale=3; $duration / $total_requests" | bc -l 2>/dev/null || echo "N/A")s"
}

# Main test execution
main() {
    echo -e "${BLUE}Starting integration tests...${NC}"
    echo ""
    
    # Check if services are running
    if ! check_service "$AI_COPILOT_URL" "AI Copilot Service"; then
        print_status "error" "Please start the AI Copilot service first"
        exit 1
    fi
    
    if ! check_service "$API_GATEWAY_URL" "API Gateway"; then
        print_status "warning" "API Gateway is not running, some tests will be skipped"
    fi
    
    echo ""
    
    # Run tests
    local test_results=()
    
    # Test AI Copilot directly
    if test_ai_copilot_direct; then
        test_results+=("ai_copilot:success")
    else
        test_results+=("ai_copilot:error")
    fi
    
    # Test API Gateway integration
    if test_api_gateway_integration; then
        test_results+=("api_gateway:success")
    else
        test_results+=("api_gateway:error")
    fi
    
    # Test WebSocket
    if test_websocket_connection; then
        test_results+=("websocket:success")
    else
        test_results+=("websocket:warning")
    fi
    
    # Test gRPC
    if test_grpc_integration; then
        test_results+=("grpc:success")
    else
        test_results+=("grpc:warning")
    fi
    
    echo ""
    
    # Run performance test
    run_performance_test
    
    echo ""
    echo -e "${BLUE}Test Summary:${NC}"
    echo "=============="
    
    local success_count=0
    local error_count=0
    local warning_count=0
    
    for result in "${test_results[@]}"; do
        local test_name=$(echo "$result" | cut -d: -f1)
        local test_status=$(echo "$result" | cut -d: -f2)
        
        case $test_status in
            "success")
                print_status "success" "$test_name: PASSED"
                success_count=$((success_count + 1))
                ;;
            "error")
                print_status "error" "$test_name: FAILED"
                error_count=$((error_count + 1))
                ;;
            "warning")
                print_status "warning" "$test_name: WARNING"
                warning_count=$((warning_count + 1))
                ;;
        esac
    done
    
    echo ""
    echo -e "${BLUE}Final Results:${NC}"
    echo "==============="
    echo -e "${GREEN}Passed: $success_count${NC}"
    echo -e "${RED}Failed: $error_count${NC}"
    echo -e "${YELLOW}Warnings: $warning_count${NC}"
    
    if [ $error_count -eq 0 ]; then
        echo ""
        print_status "success" "All critical tests passed! 🎉"
        exit 0
    else
        echo ""
        print_status "error" "Some tests failed. Please check the errors above."
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    for cmd in curl jq nc bc; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_status "warning" "Missing dependencies: ${missing_deps[*]}"
        print_status "info" "Some tests may not work correctly"
        echo ""
    fi
}

# Run dependency check and main test
check_dependencies
main
