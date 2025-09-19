# Squid Proxy

[![Build Status](https://github.com/lferrarotti74/Squid-Proxy/workflows/Build%20release%20image/badge.svg)](https://github.com/lferrarotti74/Squid-Proxy/actions/workflows/build.yml)
[![GitHub release](https://img.shields.io/github/v/release/lferrarotti74/Squid-Proxy)](https://github.com/lferrarotti74/Squid-Proxy/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/lferrarotti74/squid-proxy)](https://hub.docker.com/r/lferrarotti74/squid-proxy)
[![Docker Image Size](https://img.shields.io/docker/image-size/lferrarotti74/squid-proxy/latest)](https://hub.docker.com/r/lferrarotti74/squid-proxy)
[![License](https://img.shields.io/github/license/lferrarotti74/Squid-Proxy)](LICENSE)

<!-- SonarQube Badges -->
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=lferrarotti74_Squid-Proxy&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=lferrarotti74_Squid-Proxy)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=lferrarotti74_Squid-Proxy&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=lferrarotti74_Squid-Proxy)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=lferrarotti74_Squid-Proxy&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=lferrarotti74_Squid-Proxy)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=lferrarotti74_Squid-Proxy&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=lferrarotti74_Squid-Proxy)

A lightweight, secure Docker container for Squid proxy server based on Alpine Linux. This container provides an easy way to deploy and manage a Squid caching proxy for web traffic filtering, caching, and network optimization without needing to install and configure Squid on your host system.

## What is Squid?

Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. It reduces bandwidth and improves response times by caching and reusing frequently-requested web pages. Squid has extensive access controls and makes a great server accelerator.

Key features:
- **Web Caching**: Reduces bandwidth usage and improves response times
- **Access Control**: Comprehensive access control lists (ACLs) for security
- **Protocol Support**: HTTP, HTTPS, FTP, and other protocols
- **Authentication**: Support for various authentication methods
- **Logging**: Detailed logging and monitoring capabilities
- **SSL/TLS**: SSL bumping and certificate management

## Quick Start

### Pull the Docker Image
```bash
docker pull lferrarotti74/squid-proxy:latest
```

### Run the Container
```bash
# Basic usage with default configuration
docker run -d --name squid-proxy -p 3128:3128 lferrarotti74/squid-proxy:latest

# With custom configuration
docker run -d --name squid-proxy \
  -p 3128:3128 \
  -v /path/to/your/squid.conf:/etc/squid/squid.conf:ro \
  lferrarotti74/squid-proxy:latest
```

## Usage Examples

### Basic Proxy Server
Run a simple proxy server accessible on port 3128:
```bash
docker run -d --name squid-proxy \
  -p 3128:3128 \
  lferrarotti74/squidproxy:latest
```

### Custom Configuration
Use your own Squid configuration file:
```bash
docker run -d --name squid-proxy \
  -p 3128:3128 \
  -v /path/to/custom/squid.conf:/etc/squid/squid.conf:ro \
  lferrarotti74/squidproxy:latest
```

### With Environment Variables
Pass additional arguments to Squid:
```bash
docker run -d --name squid-proxy \
  -p 3128:3128 \
  -e EXTRA_ARGS="-v" \
  lferrarotti74/squidproxy:latest
```

### Persistent Cache Storage
Mount a volume for cache persistence:
```bash
docker run -d --name squid-proxy \
  -p 3128:3128 \
  -v squid-cache:/var/cache/squid \
  -v /path/to/squid.conf:/etc/squid/squid.conf:ro \
  lferrarotti74/squidproxy:latest
```

## Using with Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  squid-proxy:
    image: lferrarotti74/squidproxy:latest
    container_name: squid-proxy
    ports:
      - "3128:3128"
    volumes:
      - ./config/squid.conf:/etc/squid/squid.conf:ro
      - squid-cache:/var/cache/squid
    environment:
      - EXTRA_ARGS=-v
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "/healthcheck.sh"]
      interval: 60s
      timeout: 5s
      retries: 3
      start_period: 30s

volumes:
  squid-cache:
```

Run with:
```bash
docker-compose up -d
```

## Configuration

### Default Configuration
The container comes with a basic configuration that:
- Listens on port 3128
- Allows access from all clients (`http_access allow all`)
- Disables caching (`cache deny all`)
- Minimal logging for performance

### Custom Configuration
To use your own configuration:

1. Create your custom `squid.conf` file
2. Mount it to `/etc/squid/squid.conf` in the container
3. Restart the container

Example custom configuration:
```bash
# /path/to/custom/squid.conf
http_port 3128

# Access control
acl localnet src 192.168.0.0/16
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12

http_access allow localnet
http_access deny all

# Caching settings
cache_dir ufs /var/cache/squid 1000 16 256
maximum_object_size 100 MB
cache_mem 256 MB

# Logging
access_log /var/log/squid/access.log squid
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `EXTRA_ARGS` | Additional arguments passed to squid | `""` |

## Network Requirements

- **Port 3128**: Default Squid proxy port (TCP)
- **Outbound Internet Access**: Required for proxy functionality
- **Client Access**: Clients must be able to reach the container on port 3128

### Firewall Configuration
Ensure your firewall allows:
- Inbound connections on port 3128 from client networks
- Outbound connections to the internet (ports 80, 443, etc.)

## Health Checks

The container includes a built-in health check that:
- Tests connectivity to port 3128 using netcat
- Runs every 60 seconds
- Has a 5-second timeout
- Allows 3 retries before marking as unhealthy

You can check the health status:
```bash
docker ps
# Look for "healthy" or "unhealthy" in the STATUS column

# Or get detailed health information
docker inspect squid-proxy | grep -A 10 '"Health"'
```

## Monitoring and Logs

### View Logs
```bash
# View container logs
docker logs squid-proxy

# Follow logs in real-time
docker logs -f squid-proxy

# View last 100 lines
docker logs --tail 100 squid-proxy
```

### Access Squid Logs
If you've configured Squid to log to files:
```bash
# Mount log directory
docker run -d --name squid-proxy \
  -p 3128:3128 \
  -v /path/to/logs:/var/log/squid \
  -v /path/to/squid.conf:/etc/squid/squid.conf:ro \
  lferrarotti74/squidproxy:latest
```

## Security Considerations

### Access Control
- **Default Configuration**: Allows access from all clients - modify for production use
- **Network Segmentation**: Run in isolated networks when possible
- **Authentication**: Consider implementing authentication for production deployments

### Best Practices
- Use custom configuration files instead of the default permissive settings
- Implement proper ACLs to restrict access to authorized clients only
- Regular security updates by pulling the latest image
- Monitor access logs for suspicious activity
- Use HTTPS where possible

## Troubleshooting

### Common Issues

**Container won't start:**
```bash
# Check logs for errors
docker logs squid-proxy

# Verify configuration syntax
docker run --rm -v /path/to/squid.conf:/etc/squid/squid.conf:ro \
  lferrarotti74/squidproxy:latest squid -k parse -f /etc/squid/squid.conf
```

**Permission denied errors:**
```bash
# Ensure proper file permissions
chmod 644 /path/to/squid.conf
```

**Connection refused:**
```bash
# Verify port mapping
docker port squid-proxy

# Check if service is listening
docker exec squid-proxy netstat -tlnp | grep 3128
```

**Health check failing:**
```bash
# Run health check manually
docker exec squid-proxy /healthcheck.sh
echo $?  # Should return 0 for success
```

## Building from Source

To build the Docker image yourself:

```bash
git clone https://github.com/lferrarotti74/SquidProxy.git
cd SquidProxy
docker build -t squidproxy .
```

### Build Arguments
- `VERSION`: Specify Squid version to install
- `CACHEBUST`: Force cache invalidation during build

```bash
docker build --build-arg VERSION=6.1-r0 -t squidproxy .
```

## Documentation

- [Contributing Guidelines](CONTRIBUTING.md) - How to contribute to the project
- [Code of Conduct](CODE_OF_CONDUCT.md) - Community standards and behavior expectations
- [Security Policy](SECURITY.md) - How to report security vulnerabilities
- [Changelog](CHANGELOG.md) - Version history and release notes

## Contributing

We welcome contributions from the community! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

- **Bug Reports**: Use GitHub issues with detailed information
- **Feature Requests**: Propose enhancements via GitHub issues
- **Code Contributions**: Fork, create feature branch, and submit PR
- **Documentation**: Help improve docs and examples

Please follow our [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Links

- [Squid Official Website](http://www.squid-cache.org/)
- [Squid Documentation](http://www.squid-cache.org/Doc/)
- [Alpine Linux](https://alpinelinux.org/)
- [Docker Hub Repository](https://hub.docker.com/r/lferrarotti74/squid-proxy)
- [GitHub Repository](https://github.com/lferrarotti74/Squid-Proxy)
- [SonarCloud Analysis](https://sonarcloud.io/summary/new_code?id=lferrarotti74_Squid-Proxy)