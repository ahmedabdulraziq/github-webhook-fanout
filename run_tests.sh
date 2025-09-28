#!/bin/bash

# Test script for GitHub webhook fanout server
# This script runs different test suites

echo "🧪 Running GitHub Webhook Fanout Server Tests"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to run tests and show results
run_test_suite() {
    local suite_name="$1"
    local test_pattern="$2"
    
    echo -e "\n${YELLOW}Running $suite_name tests...${NC}"
    
    if go test -v -run "$test_pattern" -timeout 30s; then
        echo -e "${GREEN}✅ $suite_name tests passed${NC}"
        return 0
    else
        echo -e "${RED}❌ $suite_name tests failed${NC}"
        return 1
    fi
}

# Track overall results
overall_success=true

# 1. Signature verification tests
run_test_suite "Signature Verification" "TestSignature"
if [ $? -ne 0 ]; then overall_success=false; fi

# 2. ArgoCD integration tests (with mocks)
run_test_suite "ArgoCD Integration" "TestTriggerArgoCD"
if [ $? -ne 0 ]; then overall_success=false; fi

# 3. HTTP endpoint tests
run_test_suite "HTTP Endpoints" "TestHealth|TestWebhookEndpointWithoutSignature|TestWebhookEndpointWithInvalidSignature|TestWebhookEndpointWithInvalidJSON"
if [ $? -ne 0 ]; then overall_success=false; fi

# 4. Configuration tests
run_test_suite "Configuration" "TestLoadConfig|TestGetEnv"
if [ $? -ne 0 ]; then overall_success=false; fi

# 5. Test coverage
echo -e "\n${YELLOW}Generating test coverage report...${NC}"
go test -coverprofile=coverage.out -run "TestSignature|TestTriggerArgoCD|TestHealth|TestWebhookEndpointWithoutSignature|TestWebhookEndpointWithInvalidSignature|TestWebhookEndpointWithInvalidJSON|TestLoadConfig|TestGetEnv" -timeout 30s
coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
echo -e "Test Coverage: ${coverage}"

# 6. Show coverage details
echo -e "\n${YELLOW}Coverage details:${NC}"
go tool cover -func=coverage.out

# 7. Generate HTML coverage report
echo -e "\n${YELLOW}Generating HTML coverage report...${NC}"
go tool cover -html=coverage.out -o coverage.html
echo "HTML coverage report generated: coverage.html"

# Final results
echo -e "\n=============================================="
if [ "$overall_success" = true ]; then
    echo -e "${GREEN}🎉 All test suites passed!${NC}"
    exit 0
else
    echo -e "${RED}💥 Some test suites failed!${NC}"
    exit 1
fi
