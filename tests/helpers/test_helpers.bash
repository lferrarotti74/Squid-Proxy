#!/usr/bin/env bash

# BATS Test Helper Functions for Squid-Proxy
# Adapted from repository-security-checklist.md patterns

# Test configuration
TEST_IMAGE="${TEST_IMAGE:-squid-proxy:latest}"
SQUID_PORT="${SQUID_PORT:-3128}"
SQUID_CONFIG_PATH="${SQUID_CONFIG_PATH:-/etc/squid/squid.conf}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper function to print success messages
print_success() {
    echo -e "${GREEN}✅ $1${NC}" >&3
    return 0
}

# Helper function to print warning messages
print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}" >&3
    return 0
}

# Helper function to print error messages
print_error() {
    echo -e "${RED}❌ $1${NC}" >&3
    return 0
}

# Helper function to run squid container and capture output (for CLI tests)
run_squid_container_output() {
    local cmd="$1"
    local extra_args="${2:-}"
    
    # Special handling for -N flag which runs in foreground
    if [[ "$cmd" == *"-N"* ]]; then
        # Use a background process with kill after short delay for -N flag
        docker run --rm --entrypoint="" ${extra_args} "${TEST_IMAGE}" sh -c "
            squid $cmd &
            SQUID_PID=\$!
            sleep 1
            kill \$SQUID_PID 2>/dev/null || true
            wait \$SQUID_PID 2>/dev/null || true
        " 2>&1
    else
        # Override entrypoint to run squid commands directly
        docker run --rm --entrypoint="" ${extra_args} "${TEST_IMAGE}" squid ${cmd} 2>&1
    fi
    return $?
}

# Helper function to run shell commands in container and capture output (for container tests)
run_shell_container_output() {
    local cmd="$1"
    local extra_args="${2:-}"
    
    # Add timeout and resource limits to prevent hanging
    local timeout_cmd="timeout 30"
    
    # Override entrypoint to use shell for command execution with timeout
    ${timeout_cmd} docker run --rm --entrypoint="" ${extra_args} "${TEST_IMAGE}" sh -c "${cmd}" 2>&1
    return $?
}

# Helper function to run container without output capture (for exit code tests)
run_shell_container() {
    local cmd="$1"
    local extra_args="${2:-}"
    
    # Override entrypoint to use shell for command execution
    docker run --rm --entrypoint="" ${extra_args} "${TEST_IMAGE}" sh -c "${cmd}"
    return $?
}

# Helper function to run squid container in daemon mode for proxy testing
run_squid_daemon() {
    local container_name="${1:-squid-test-daemon}"
    local extra_args="${2:-}"
    
    docker run -d --name "${container_name}" -p "${SQUID_PORT}:3128" ${extra_args} "${TEST_IMAGE}"
    return $?
}

# Helper function to stop and remove squid daemon container
stop_squid_daemon() {
    local container_name="${1:-squid-test-daemon}"
    
    docker stop "${container_name}" >/dev/null 2>&1 || true
    docker rm "${container_name}" >/dev/null 2>&1 || true
    return 0
}

# Helper function to test proxy functionality
test_proxy_connection() {
    local proxy_host="${1:-localhost}"
    local proxy_port="${2:-$SQUID_PORT}"
    local test_url="${3:-http://httpbin.org/ip}"
    
    curl -s --proxy "${proxy_host}:${proxy_port}" --max-time 10 "${test_url}"
    return $?
}

# Helper function to wait for squid to be ready
wait_for_squid() {
    local container_name="${1:-squid-test-daemon}"
    local max_attempts="${2:-30}"
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker exec "${container_name}" nc -z localhost 3128 2>/dev/null; then
            print_success "Squid is ready after $attempt attempts"
            return 0
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    
    print_error "Squid failed to start after $max_attempts attempts"
    return 1
}

# Helper function to validate JSON output
validate_json() {
    local json_string="$1"
    
    if echo "$json_string" | jq . >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Helper function to check if container is running
is_container_running() {
    local container_name="$1"
    
    docker ps --format "table {{.Names}}" | grep -q "^${container_name}$"
    return $?
}

# Helper function to get container logs
get_container_logs() {
    local container_name="$1"
    local lines="${2:-50}"
    
    docker logs --tail "${lines}" "${container_name}" 2>&1
    return $?
}

# Helper function to check if Docker image exists
docker_image_exists() {
    local image_name="$1"
    
    docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "^${image_name}$"
    return $?
}

# Helper function to print test header
print_test_header() {
    local header="$1"
    echo -e "${YELLOW}=== $header ===${NC}" >&3
    return 0
}

# Helper function to cleanup test artifacts
cleanup_test_artifacts() {
    cleanup_test_containers
    return $?
}

# Helper function to build test image if it doesn't exist
ensure_test_image() {
    if ! docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "^${TEST_IMAGE}$"; then
        print_warning "Test image ${TEST_IMAGE} not found, building..."
        docker build -t "${TEST_IMAGE}" .
        if [ $? -eq 0 ]; then
            print_success "Test image ${TEST_IMAGE} built successfully"
        else
            print_error "Failed to build test image ${TEST_IMAGE}"
            return 1
        fi
    fi
    return 0
}

# Helper function to cleanup test containers
cleanup_test_containers() {
    local pattern="${1:-squid-test-*}"
    
    # Stop and remove containers matching pattern
    docker ps -a --format "{{.Names}}" | grep "${pattern}" | while read -r container_name; do
        if [ -n "$container_name" ] && [ "$container_name" != "NAMES" ]; then
            docker stop "$container_name" >/dev/null 2>&1 || true
            docker rm "$container_name" >/dev/null 2>&1 || true
        fi
    done
    
    # Also cleanup any containers using our test image that might have random names
    docker ps -a --filter "ancestor=${TEST_IMAGE}" --format "{{.Names}}" | while read -r container_name; do
        if [ -n "$container_name" ] && [ "$container_name" != "NAMES" ]; then
            docker stop "$container_name" >/dev/null 2>&1 || true
            docker rm "$container_name" >/dev/null 2>&1 || true
        fi
    done
    return 0
}

# Setup function to be called before tests
setup_test_environment() {
    ensure_test_image
    cleanup_test_containers
    return $?
}

# Teardown function to be called after tests
teardown_test_environment() {
    cleanup_test_containers
    return $?
}
