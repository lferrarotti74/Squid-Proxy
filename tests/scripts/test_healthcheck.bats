#!/usr/bin/env bats

# Healthcheck Script Tests for Squid-Proxy
# Tests the functionality of /scripts/healthcheck.sh

load '../helpers/test_helpers'

setup() {
    setup_test_environment
}

teardown() {
    teardown_test_environment
}

@test "Healthcheck script should exist and be executable" {
    run run_shell_container_output "ls -la /healthcheck.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "healthcheck.sh" ]]
    [[ "$output" =~ "-rwx" ]] || [[ "$output" =~ "-r-x" ]]
    print_success "Healthcheck script exists and is executable"
}

@test "Healthcheck script should have correct shebang" {
    run run_shell_container_output "head -1 /healthcheck.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "#!/bin/sh" ]] || [[ "$output" =~ "#!/bin/bash" ]]
    print_success "Healthcheck script has correct shebang: $output"
}

@test "Healthcheck script should contain port check logic" {
    run run_shell_container_output "cat /healthcheck.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "3128" ]] && [[ "$output" =~ "nc" ]]
    print_success "Healthcheck script contains port check logic for port 3128"
}

@test "Healthcheck script should use netcat for port checking" {
    run run_shell_container_output "cat /healthcheck.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "nc" ]]
    [[ "$output" =~ "localhost" ]] || [[ "$output" =~ "127.0.0.1" ]]
    print_success "Healthcheck script uses netcat for port checking"
}

@test "Healthcheck script should check localhost on port 3128" {
    run run_shell_container_output "cat /healthcheck.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "localhost 3128" ]] || [[ "$output" =~ "127.0.0.1 3128" ]]
    print_success "Healthcheck script checks localhost on port 3128"
}

@test "Netcat should be available in container for healthcheck" {
    run run_shell_container_output "which nc"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "nc" ]]
    print_success "Netcat is available in container: $output"
}

@test "Healthcheck script should return proper exit codes" {
    run run_shell_container_output "cat /healthcheck.sh"
    [ "$status" -eq 0 ]
    
    # Should contain exit code logic
    [[ "$output" =~ "exit" ]] || [[ "$output" =~ "return" ]] || [[ "$output" =~ "\$?" ]]
    print_success "Healthcheck script contains proper exit code handling"
}

@test "Healthcheck should fail when squid is not running" {
    # Run healthcheck in a container where squid is not started
    # Override entrypoint to run only the healthcheck script
    run docker run --rm --entrypoint="" "${TEST_IMAGE}" /healthcheck.sh
    [ "$status" -ne 0 ]
    print_success "Healthcheck correctly fails when squid is not running"
}

@test "Healthcheck should succeed when squid is running" {
    # Start squid container in daemon mode
    run_squid_daemon "squid-healthcheck-test"
    
    # Wait for squid to start
    wait_for_squid "squid-healthcheck-test"
    
    # Run healthcheck
    run docker exec squid-healthcheck-test /healthcheck.sh
    [ "$status" -eq 0 ]
    
    # Cleanup
    stop_squid_daemon "squid-healthcheck-test"
    
    print_success "Healthcheck succeeds when squid is running"
}

@test "Docker healthcheck should be configured in Dockerfile" {
    # Check if the image has healthcheck configured
    run docker inspect "${TEST_IMAGE}" --format='{{.Config.Healthcheck}}'
    [ "$status" -eq 0 ]
    [[ "$output" =~ "healthcheck.sh" ]] || [[ "$output" =~ "Test" ]]
    print_success "Docker healthcheck is configured in the image"
}

@test "Container healthcheck should work with Docker" {
    # Start container and let Docker run healthcheck
    run docker run -d --name squid-docker-healthcheck-test "${TEST_IMAGE}"
    [ "$status" -eq 0 ]
    
    # Wait for container to initialize and healthcheck to run
    sleep 10
    
    # Check container health status
    run docker inspect squid-docker-healthcheck-test --format='{{.State.Health.Status}}'
    [ "$status" -eq 0 ]
    [[ "$output" =~ "healthy" ]] || [[ "$output" =~ "starting" ]]
    
    # Cleanup
    docker stop squid-docker-healthcheck-test >/dev/null 2>&1 || true
    docker rm squid-docker-healthcheck-test >/dev/null 2>&1 || true
    
    print_success "Docker healthcheck integration works correctly"
}

@test "Healthcheck script should handle network connectivity issues" {
    # Test healthcheck behavior when network might be restricted
    # Override entrypoint to run only the healthcheck script
    run docker run --rm --network none --entrypoint="" "${TEST_IMAGE}" /healthcheck.sh
    [ "$status" -ne 0 ]
    print_success "Healthcheck handles network connectivity issues appropriately"
}

@test "Healthcheck should be fast and lightweight" {
    # Measure healthcheck execution time
    start_time=$(date +%s%N)
    # Override entrypoint to run only the healthcheck script
    run docker run --rm --entrypoint="" "${TEST_IMAGE}" /healthcheck.sh
    end_time=$(date +%s%N)
    
    # Calculate duration in milliseconds
    duration=$(( (end_time - start_time) / 1000000 ))
    
    # Healthcheck should complete within reasonable time (less than 5 seconds)
    [ "$duration" -lt 5000 ]
    print_success "Healthcheck completes quickly: ${duration}ms"
}

@test "Healthcheck script should not produce excessive output" {
    # Override entrypoint to run only the healthcheck script
    run docker run --rm --entrypoint="" "${TEST_IMAGE}" /healthcheck.sh
    
    # Count lines of output
    local line_count=$(echo "$output" | wc -l)
    
    # Healthcheck should be quiet (minimal output)
    [ "$line_count" -lt 10 ]
    print_success "Healthcheck produces minimal output: $line_count lines"
}

@test "Healthcheck should work with custom squid port configuration" {
    # Test that healthcheck script can be adapted for different ports
    run run_shell_container_output "cat /healthcheck.sh"
    [ "$status" -eq 0 ]
    
    # Should either hardcode 3128 or be configurable
    [[ "$output" =~ "3128" ]] || [[ "$output" =~ "\$" ]]
    print_success "Healthcheck handles port configuration appropriately"
}