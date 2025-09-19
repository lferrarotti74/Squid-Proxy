# Security Policy

## Supported Versions

We actively support the following versions of Squid Proxy with security updates:

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Considerations

### Proxy Security Best Practices

When deploying Squid Proxy, please consider the following security recommendations:

#### Access Control
- **Never use the default configuration in production** - The default configuration allows access from all clients (`http_access allow all`)
- **Implement proper ACLs** - Restrict access to authorized networks and users only
- **Use authentication** - Consider implementing authentication mechanisms for production deployments
- **Network segmentation** - Deploy the proxy in isolated network segments when possible

#### Configuration Security
- **Validate configurations** - Always test configuration changes in a safe environment first
- **Minimize permissions** - Run with least privilege principles
- **Secure file permissions** - Ensure configuration files have appropriate permissions (644 or more restrictive)
- **Regular updates** - Keep the container image updated with the latest security patches

#### Network Security
- **Firewall rules** - Implement proper firewall rules to restrict access
- **TLS/SSL** - Use HTTPS where possible and implement proper certificate validation
- **Monitoring** - Monitor access logs for suspicious activity
- **Rate limiting** - Implement rate limiting to prevent abuse

### Container Security

#### Image Security
- **Base image updates** - We regularly update the Alpine Linux base image for security patches
- **Minimal attack surface** - The container runs only necessary components
- **Non-root user** - The container runs as the `squid` user, not root
- **Read-only filesystem** - Consider running with read-only root filesystem where possible

#### Runtime Security
- **Resource limits** - Set appropriate CPU and memory limits
- **Security contexts** - Use appropriate security contexts and capabilities
- **Network policies** - Implement network policies to restrict container communication
- **Secrets management** - Use proper secrets management for sensitive configuration

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in Squid Proxy, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing us directly at:

**Email**: [lferrarotti74@gmail.com](mailto:lferrarotti74@gmail.com)

**Subject**: `[SECURITY] Squid Proxy Vulnerability Report`

### What to Include

Please include the following information in your report:

1. **Description**: A clear description of the vulnerability
2. **Impact**: The potential impact and severity of the vulnerability
3. **Reproduction**: Step-by-step instructions to reproduce the vulnerability
4. **Environment**: 
   - Container version
   - Host operating system
   - Docker version
   - Configuration details (sanitized)
5. **Proof of Concept**: If applicable, include a proof of concept (but please be responsible)
6. **Suggested Fix**: If you have suggestions for fixing the vulnerability

### Response Timeline

We will acknowledge receipt of your vulnerability report within **48 hours** and will strive to provide regular updates on our progress.

Our typical response timeline:
- **Initial Response**: Within 48 hours
- **Vulnerability Assessment**: Within 1 week
- **Fix Development**: Depends on complexity, typically 1-4 weeks
- **Release**: As soon as possible after fix is ready
- **Public Disclosure**: After fix is released and users have time to update

### Responsible Disclosure

We follow responsible disclosure practices:

1. **Private Reporting**: Report vulnerabilities privately first
2. **Coordinated Disclosure**: We'll work with you on disclosure timing
3. **Credit**: We'll credit you for the discovery (if desired)
4. **No Legal Action**: We won't pursue legal action against researchers who follow responsible disclosure

### Security Updates

When security vulnerabilities are fixed:

1. **New Release**: We'll create a new release with the fix
2. **Security Advisory**: We'll publish a GitHub Security Advisory
3. **Release Notes**: Security fixes will be clearly marked in release notes
4. **Docker Hub**: Updated images will be pushed to Docker Hub
5. **Notification**: We'll notify users through appropriate channels

### Bug Bounty

Currently, we do not offer a formal bug bounty program. However, we greatly appreciate security researchers who help improve the security of our project and will acknowledge their contributions.

## Security Resources

### Squid Security
- [Squid Security Advisories](http://www.squid-cache.org/Advisories/)
- [Squid Security Configuration](http://www.squid-cache.org/Doc/config/)

### Container Security
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)

### Alpine Linux Security
- [Alpine Linux Security](https://alpinelinux.org/security/)
- [Alpine Linux Security Advisories](https://secdb.alpinelinux.org/)

## Security Scanning

We use automated security scanning tools:

- **GitHub Security Advisories**: Automated vulnerability scanning
- **Dependabot**: Dependency vulnerability scanning
- **Docker Scout**: Container image vulnerability scanning
- **SonarQube**: Code quality and security analysis

## Security Contact

For security-related questions or concerns:

- **Email**: [lferrarotti74@gmail.com](mailto:lferrarotti74@gmail.com)
- **Subject**: `[SECURITY] Squid Proxy Security Question`

## Acknowledgments

We would like to thank the following security researchers and contributors who have helped improve the security of Squid Proxy:

- *No security reports received yet*

---

**Note**: This security policy applies to the Squid Proxy Docker container project. For vulnerabilities in the underlying Squid software itself, please report them to the [Squid project](http://www.squid-cache.org/) directly.