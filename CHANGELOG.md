# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive documentation suite (README, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY)
- Status badges for build, release, Docker pulls, and image size
- SonarQube integration for code quality analysis

### Changed
- Improved project documentation structure
- Enhanced security guidelines and best practices

### Security
- Added comprehensive security policy and vulnerability reporting guidelines

## [6.12-r0] - 2025-09-14

### Added
- Initial release of Squid Proxy Docker container
- Alpine Linux based lightweight container
- Default Squid configuration with basic proxy functionality
- Health check script for container monitoring
- Entrypoint script for flexible container startup
- Docker Compose example configuration
- GitHub Actions CI/CD pipeline
- Automated Docker image building and publishing
- Dependabot configuration for dependency updates
- SonarQube integration for code quality

### Features
- **Lightweight**: Based on Alpine Linux for minimal footprint
- **Secure**: Runs as non-root user (squid)
- **Configurable**: Support for custom Squid configurations
- **Monitored**: Built-in health checks
- **Automated**: CI/CD pipeline for automated builds and releases

### Configuration
- Default proxy port: 3128
- Default configuration allows all access (suitable for development)
- No caching enabled by default
- Minimal logging for performance

### Docker
- Multi-architecture support (amd64, arm64)
- Automated builds on Alpine Linux updates
- Published to Docker Hub
- Semantic versioning for releases

### Security
- Container runs as `squid` user (non-root)
- Minimal attack surface with Alpine Linux
- Regular security updates through automated builds
- Security scanning with Docker Scout

## Release Notes Format

### Types of Changes
- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

### Version Numbering
This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version for incompatible API changes
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

### Release Process
1. Update version numbers in relevant files
2. Update this CHANGELOG.md with release notes
3. Create a git tag with the version number
4. GitHub Actions automatically builds and publishes the release
5. Docker images are published to Docker Hub
6. GitHub release is created with release notes

---

## Contributing to Changelog

When contributing to this project, please:

1. **Add entries to [Unreleased]** section for your changes
2. **Use the correct category** (Added, Changed, Fixed, etc.)
3. **Write clear, concise descriptions** of your changes
4. **Reference issue numbers** when applicable
5. **Follow the existing format** for consistency

Example entry:
```markdown
### Added
- New feature for custom authentication (#123)
- Support for IPv6 networks (#124)

### Fixed
- Fixed memory leak in health check script (#125)
- Resolved configuration parsing issue (#126)
```

## Links

- [Project Repository](https://github.com/lferrarotti74/SquidProxy)
- [Docker Hub](https://hub.docker.com/r/lferrarotti74/squidproxy)
- [Issues](https://github.com/lferrarotti74/SquidProxy/issues)
- [Releases](https://github.com/lferrarotti74/SquidProxy/releases)