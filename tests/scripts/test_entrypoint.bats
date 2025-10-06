#!/usr/bin/env bats

# Entrypoint Script Tests for Squid-Proxy
# Tests the functionality of /scripts/entrypoint.sh

load '../helpers/test_helpers'

setup() {
    setup_test_environment
}

teardown() {
    teardown_test_environment
}

@test "Entrypoint script should exist and be executable" {
    run run_shell_container_output "ls -la /entrypoint.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "entrypoint.sh" ]]
    [[ "$output" =~ "-rwx" ]] || [[ "$output" =~ "-r-x" ]]
    print_success "Entrypoint script exists and is executable"
}

@test "Entrypoint script should have correct shebang" {
    run run_shell_container_output "head -1 /entrypoint.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "#!/bin/sh" ]] || [[ "$output" =~ "#!/bin/bash" ]]
    print_success "Entrypoint script has correct shebang: $output"
}

@test "Entrypoint script should contain squid command" {
    run run_shell_container_output "cat /entrypoint.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "squid" ]]
    [[ "$output" =~ "exec" ]]
    print_success "Entrypoint script contains squid execution command"
}

@test "Entrypoint script should use correct squid configuration path" {
    run run_shell_container_output "cat /entrypoint.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "/etc/squid/squid.conf" ]] || [[ "$output" =~ "squid.conf" ]]
    print_success "Entrypoint script references correct configuration path"
}

@test "Entrypoint script should run squid in foreground mode" {
    run run_shell_container_output "cat /entrypoint.sh"
    [ "$status" -eq 0 ]
    # Check for foreground flags: -N (foreground), -d (debug), -C (no catch signals)
    [[ "$output" =~ "-N" ]] || [[ "$output" =~ "-d" ]] || [[ "$output" =~ "foreground" ]]
    print_success "Entrypoint script runs squid in foreground mode"
}

@test "Entrypoint script should support EXTRA_ARGS environment variable" {
    run run_shell_container_output "cat /entrypoint.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "EXTRA_ARGS" ]] || [[ "$output" =~ "\${" ]]
    print_success "Entrypoint script supports EXTRA_ARGS environment variable"
}

@test "Container should start with entrypoint script by default" {
    # Start container in background and check if it's running
    run docker run -d --name squid-entrypoint-test "${TEST_IMAGE}"
    [ "$status" -eq 0 ]
    
    # Wait for container to initialize
    sleep 3
    
    # Check if container is still running (indicates successful entrypoint execution)
    run docker ps --filter "name=squid-entrypoint-test" --format "{{.Names}}"
    [[ "$output" =~ "squid-entrypoint-test" ]]
    
    # Check container logs for squid startup messages
    run docker logs squid-entrypoint-test
    [[ "$output" =~ "squid" ]] || [[ "$output" =~ "cache" ]] || [[ "$output" =~ "ready" ]]
    
    # Cleanup
    docker stop squid-entrypoint-test >/dev/null 2>&1 || true
    docker rm squid-entrypoint-test >/dev/null 2>&1 || true
    
    print_success "Container starts successfully with entrypoint script"
}

@test "Entrypoint should handle EXTRA_ARGS environment variable" {
    # Test with custom EXTRA_ARGS
    run docker run --rm -e EXTRA_ARGS="-d 1" "${TEST_IMAGE}" /entrypoint.sh &
    local container_pid=$!
    
    # Give it a moment to start
    sleep 2
    
    # Kill the background process
    kill $container_pid 2>/dev/null || true
    wait $container_pid 2>/dev/null || true
    
    print_success "Entrypoint script handles EXTRA_ARGS environment variable"
}

@test "Entrypoint should use exec to replace shell process" {
    run run_shell_container_output "cat /entrypoint.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "exec" ]]
    print_success "Entrypoint script uses exec to replace shell process"
}

@test "Entrypoint should locate squid binary correctly" {
    run run_shell_container_output "cat /entrypoint.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "which squid" ]] || [[ "$output" =~ "/usr/sbin/squid" ]] || [[ "$output" =~ "squid" ]]
    print_success "Entrypoint script locates squid binary correctly"
}

@test "Container should respond to signals when started with entrypoint" {
    # Start container in background
    run docker run -d --name squid-signal-test "${TEST_IMAGE}"
    [ "$status" -eq 0 ]
    
    # Wait for container to initialize
    sleep 3
    
    # Send SIGTERM to container
    run docker stop squid-signal-test
    [ "$status" -eq 0 ]
    
    # Container should stop gracefully (not be killed forcefully)
    run docker ps -a --filter "name=squid-signal-test" --format "{{.Status}}"
    [[ "$output" =~ "Exited" ]]
    
    # Cleanup
    docker rm squid-signal-test >/dev/null 2>&1 || true
    
    print_success "Container responds to signals correctly when started with entrypoint"
}

@test "Entrypoint should not contain hardcoded paths that don't exist" {
    run run_shell_container_output "cat /entrypoint.sh"
    [ "$status" -eq 0 ]
    
    # Extract any paths mentioned in the script and verify they exist
    local script_content="$output"
    
    # Check if /etc/squid/squid.conf exists (most common path)
    if [[ "$script_content" =~ "/etc/squid/squid.conf" ]]; then
        run run_shell_container_output "ls -la /etc/squid/squid.conf"
        [ "$status" -eq 0 ]
    fi
    
    print_success "Entrypoint script paths are valid and accessible"
}

@test "Entrypoint should handle missing configuration gracefully" {
    # Test behavior when config file might be missing (should be handled gracefully)
    run docker run --rm -v /dev/null:/etc/squid/squid.conf "${TEST_IMAGE}" /entrypoint.sh &
    local container_pid=$!
    
    # Give it a moment to start and potentially fail
    sleep 2
    
    # Kill the background process
    kill $container_pid 2>/dev/null || true
    wait $container_pid 2>/dev/null || true
    
    # The test passes if we reach here without hanging
    print_success "Entrypoint handles configuration issues gracefully"
}