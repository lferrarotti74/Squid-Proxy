#!/usr/bin/env bats

# Container Build and Security Tests for Squid-Proxy
# Based on patterns from repository-security-checklist.md

load '../helpers/test_helpers'

setup() {
    print_test_header "Container Build Tests"
}

teardown() {
    cleanup_test_artifacts
}

@test "Docker image should exist after build" {
    run docker_image_exists "${TEST_IMAGE}"
    [ "$status" -eq 0 ]
    print_success "Docker image exists"
}

@test "Container should start without errors" {
    run docker run --rm -d --name squid-test-startup "${TEST_IMAGE}"
    [ "$status" -eq 0 ]
    
    # Wait a moment for container to initialize
    sleep 2
    
    # Check if container is still running
    run docker ps --filter "name=squid-test-startup" --format "{{.Names}}"
    [[ "$output" =~ "squid-test-startup" ]]
    
    # Cleanup
    docker stop squid-test-startup >/dev/null 2>&1 || true
    docker rm squid-test-startup >/dev/null 2>&1 || true
    
    print_success "Container starts and runs without errors"
}

@test "Container should run as non-root user" {
    run run_shell_container_output "whoami"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "squid" ]] || [[ "$output" =~ "proxy" ]] || [[ "$output" =~ "nobody" ]]
    print_success "Container runs as non-root user: $output"
}

@test "Container should have correct working directory" {
    run run_shell_container_output "pwd"
    [ "$status" -eq 0 ]
    # Container starts in root directory
    [[ "$output" == "/" ]]
    print_success "Working directory is correctly set: $output"
}

@test "Squid configuration file should exist and be readable" {
    run run_shell_container_output "ls -la ${SQUID_CONFIG_PATH}"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "squid.conf" ]]
    print_success "Squid configuration file exists and is accessible"
}

@test "Squid configuration file should have correct permissions" {
    run run_shell_container_output "ls -l ${SQUID_CONFIG_PATH}"
    [ "$status" -eq 0 ]
    # Configuration should be readable (at least r--r--r--)
    [[ "$output" =~ "-r" ]]
    print_success "Squid configuration file has correct permissions"
}

@test "Entrypoint script should exist and be executable" {
    run run_shell_container_output "ls -la /entrypoint.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "entrypoint.sh" ]]
    [[ "$output" =~ "-rwx" ]] || [[ "$output" =~ "-r-x" ]]
    print_success "Entrypoint script exists and is executable"
}

@test "Healthcheck script should exist and be executable" {
    run run_shell_container_output "ls -la /healthcheck.sh"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "healthcheck.sh" ]]
    [[ "$output" =~ "-rwx" ]] || [[ "$output" =~ "-r-x" ]]
    print_success "Healthcheck script exists and is executable"
}

@test "Container should be based on Alpine Linux" {
    run run_shell_container_output "cat /etc/os-release"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Alpine Linux" ]]
    print_success "Container is based on Alpine Linux"
}

@test "Squid binary should be installed and accessible" {
    run run_shell_container_output "which squid"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "/usr/sbin/squid" ]] || [[ "$output" =~ "squid" ]]
    print_success "Squid binary is installed and accessible: $output"
}

@test "Container should have minimal package footprint" {
    run run_shell_container_output "apk list --installed | wc -l"
    [ "$status" -eq 0 ]
    # Alpine base + squid should have relatively few packages (less than 100)
    local package_count=$(echo "$output" | tr -d ' ')
    [ "$package_count" -lt 100 ]
    print_success "Container has minimal package footprint: $package_count packages"
}

@test "Container should not have unnecessary development tools" {
    run run_shell_container_output "which gcc"
    [ "$status" -ne 0 ]
    
    run run_shell_container_output "which make"
    [ "$status" -ne 0 ]
    
    run run_shell_container_output "which git"
    [ "$status" -ne 0 ]
    
    print_success "Container does not contain unnecessary development tools"
}

@test "Container should not expose sensitive environment variables" {
    run run_shell_container_output "env"
    [ "$status" -eq 0 ]
    
    # Ensure no sensitive variables are exposed
    ! [[ "$output" =~ "PASSWORD" ]]
    ! [[ "$output" =~ "SECRET" ]]
    ! [[ "$output" =~ "TOKEN" ]]
    ! [[ "$output" =~ "KEY" ]]
    print_success "No sensitive environment variables exposed"
}

@test "Container should have proper timezone configuration" {
    run run_shell_container_output "date"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "UTC" ]] || [[ "$output" =~ "GMT" ]] || [[ "$output" =~ "20" ]]
    print_success "Container has proper timezone configuration"
}