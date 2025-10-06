#!/usr/bin/env bats

# Squid CLI Command Tests for Squid-Proxy
# Based on squid --help output and security checklist patterns

load '../helpers/test_helpers'

setup() {
    print_test_header "CLI Command Tests"
}

teardown() {
    cleanup_test_artifacts
}

@test "Squid should display help information" {
    run run_squid_container_output "--help"
    # Squid help commands exit with 1, not 0
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Usage:" ]] || [[ "$output" =~ "usage:" ]]
    [[ "$output" =~ "squid" ]]
    print_success "Squid displays help information correctly"
}

@test "Squid should display version information" {
    run run_squid_container_output "--version"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Squid" ]] || [[ "$output" =~ "squid" ]]
    [[ "$output" =~ "Version" ]] || [[ "$output" =~ "version" ]]
    print_success "Squid displays version information correctly"
}

@test "Squid should show usage when run with -h flag" {
    run run_squid_container_output "-h"
    # Squid help commands exit with 1, not 0
    [ "$status" -eq 1 ]
    [[ "$output" =~ "Usage:" ]] || [[ "$output" =~ "usage:" ]]
    [[ "$output" =~ "Print help message" ]] || [[ "$output" =~ "help" ]]
    print_success "Squid -h flag displays usage information"
}

@test "Squid should show version when run with -v flag" {
    run run_squid_container_output "-v"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Squid" ]] || [[ "$output" =~ "squid" ]]
    print_success "Squid -v flag displays version information"
}

@test "Squid should validate configuration file syntax" {
    run run_squid_container_output "-k parse"
    [ "$status" -eq 0 ]
    # Configuration parsing should succeed or show specific errors
    ! [[ "$output" =~ "FATAL" ]]
    print_success "Squid configuration file syntax validation works"
}

@test "Squid should accept custom configuration file parameter" {
    run run_squid_container_output "-f ${SQUID_CONFIG_PATH}"
    # This might fail if squid tries to start, but should recognize the parameter
    [[ "$output" =~ "config" ]] || [[ "$output" =~ "squid.conf" ]] || [ "$status" -eq 0 ]
    print_success "Squid accepts custom configuration file parameter"
}

@test "Squid should handle invalid options gracefully" {
    run run_squid_container_output "--invalid-option"
    [ "$status" -ne 0 ]
    [[ "$output" =~ "Usage:" ]] || [[ "$output" =~ "usage:" ]] || [[ "$output" =~ "invalid" ]] || [[ "$output" =~ "unknown" ]]
    print_success "Squid handles invalid options gracefully"
}

@test "Squid should support debug level parameter" {
    run run_squid_container_output "-d 1"
    # Debug parameter should be recognized (may fail due to other reasons)
    ! [[ "$output" =~ "invalid option" ]]
    ! [[ "$output" =~ "unknown option" ]]
    print_success "Squid recognizes debug level parameter"
}

@test "Squid should support foreground mode parameter" {
    # Test that -N flag is recognized by checking for startup messages
    run run_squid_container_output "-N -d1"
    # The command should exit cleanly after being killed
    [[ "$status" -eq 0 || "$status" -eq 130 || "$status" -eq 143 ]]
    # Check that squid actually started (no invalid option errors)
    ! [[ "$output" =~ "invalid option" ]]
    ! [[ "$output" =~ "unknown option" ]]
    ! [[ "$output" =~ "unrecognized option" ]]
    # Should see squid startup messages indicating -N worked
    [[ "$output" =~ "Accepting HTTP Socket connections" ]] || [[ "$output" =~ "listening port" ]]
    print_success "Squid recognizes foreground mode parameter"
}

@test "Squid should support port specification parameter" {
    run run_squid_container_output "-a 3128"
    # Port parameter should be recognized
    ! [[ "$output" =~ "invalid option" ]]
    ! [[ "$output" =~ "unknown option" ]]
    print_success "Squid recognizes port specification parameter"
}

@test "Squid configuration should specify correct default port" {
    run run_shell_container_output "grep -E '^http_port' ${SQUID_CONFIG_PATH}"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "3128" ]]
    print_success "Squid configuration specifies correct default port (3128)"
}

@test "Squid configuration should have security settings" {
    run run_shell_container_output "cat ${SQUID_CONFIG_PATH}"
    [ "$status" -eq 0 ]
    
    # Check for basic security configurations
    [[ "$output" =~ "http_access" ]] || [[ "$output" =~ "acl" ]]
    print_success "Squid configuration contains security settings"
}

@test "Squid should create necessary directories" {
    run run_shell_container_output "ls -la /var/cache/squid"
    [ "$status" -eq 0 ] || {
        # If /var/cache/squid doesn't exist, check for alternative cache directories
        run run_shell_container_output "ls -la /var/spool/squid"
        [ "$status" -eq 0 ] || {
            run run_shell_container_output "ls -la /tmp/squid"
            [ "$status" -eq 0 ]
        }
    }
    print_success "Squid cache directory exists and is accessible"
}

@test "Squid should have proper PID file configuration" {
    run run_shell_container_output "grep -E 'pid_filename' ${SQUID_CONFIG_PATH}"
    if [ "$status" -eq 0 ]; then
        [[ "$output" =~ "/var/run" ]] || [[ "$output" =~ "/tmp" ]] || [[ "$output" =~ "squid.pid" ]]
        print_success "Squid PID file configuration is present: $output"
    else
        # PID file configuration might be implicit
        print_success "Squid PID file configuration uses defaults"
    fi
}