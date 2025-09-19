# Contributing to Squid Proxy

We love your input! We want to make contributing to Squid Proxy as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## We Develop with GitHub

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

## We Use [GitHub Flow](https://guides.github.com/introduction/flow/index.html)

Pull requests are the best way to propose changes to the codebase. We actively welcome your pull requests:

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](http://choosealicense.com/licenses/mit/) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issue tracker](https://github.com/lferrarotti74/SquidProxy/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/lferrarotti74/SquidProxy/issues/new); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

People *love* thorough bug reports. I'm not even kidding.

## Development Environment Setup

### Prerequisites

- Docker and Docker Compose
- Git
- A text editor or IDE
- Basic knowledge of Squid proxy configuration

### Setting up the development environment

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/yourusername/SquidProxy.git
   cd SquidProxy
   ```

2. **Build the Docker image locally**
   ```bash
   docker build -t squidproxy:dev .
   ```

3. **Test your changes**
   ```bash
   # Run the container
   docker run -d --name squid-test -p 3128:3128 squidproxy:dev
   
   # Test the proxy
   curl -x localhost:3128 http://httpbin.org/ip
   
   # Check health
   docker exec squid-test /healthcheck.sh
   
   # Clean up
   docker stop squid-test && docker rm squid-test
   ```

### Project Structure

```
SquidProxy/
├── .github/                 # GitHub workflows and templates
│   ├── workflows/          # CI/CD workflows
│   └── dependabot.yml     # Dependabot configuration
├── config/                 # Configuration files
│   └── squid.conf         # Default Squid configuration
├── scripts/               # Shell scripts
│   ├── entrypoint.sh     # Container entrypoint
│   └── healthcheck.sh    # Health check script
├── env/                   # Environment files
├── Dockerfile            # Docker image definition
├── docker-compose.yml    # Docker Compose example
└── README.md            # Project documentation
```

## Coding Standards

### Shell Scripts
- Use `#!/bin/sh` for maximum compatibility
- Follow POSIX shell standards
- Use `set -e` for error handling
- Add comments for complex logic
- Test scripts on Alpine Linux

### Docker
- Use multi-stage builds when beneficial
- Minimize image layers
- Follow Docker best practices
- Use specific version tags, not `latest`
- Include health checks

### Configuration
- Provide sensible defaults
- Document all configuration options
- Validate configuration when possible
- Support environment variable overrides

## Testing

### Manual Testing
1. **Build and run the container**
   ```bash
   docker build -t squidproxy:test .
   docker run -d --name squid-test -p 3128:3128 squidproxy:test
   ```

2. **Test proxy functionality**
   ```bash
   # Test HTTP proxy
   curl -x localhost:3128 http://httpbin.org/ip
   
   # Test HTTPS proxy (if configured)
   curl -x localhost:3128 https://httpbin.org/ip
   ```

3. **Test health check**
   ```bash
   docker exec squid-test /healthcheck.sh
   echo $?  # Should return 0
   ```

4. **Test with custom configuration**
   ```bash
   docker run -d --name squid-custom \
     -p 3129:3128 \
     -v ./test-config.conf:/etc/squid/squid.conf:ro \
     squidproxy:test
   ```

### Automated Testing
- GitHub Actions run automated tests on pull requests
- Tests include:
  - Docker image build
  - Container startup
  - Health check validation
  - Basic proxy functionality
  - Security scanning

## Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the coding standards
   - Add tests if applicable
   - Update documentation

3. **Test your changes**
   ```bash
   # Build and test locally
   docker build -t squidproxy:test .
   # Run your tests
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add feature: your feature description"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request**
   - Use a clear and descriptive title
   - Describe what changes you made and why
   - Reference any related issues
   - Include testing instructions

### Pull Request Guidelines

- **Keep PRs focused**: One feature or fix per PR
- **Write clear commit messages**: Use conventional commit format when possible
- **Update documentation**: Include relevant documentation updates
- **Add tests**: Include tests for new functionality
- **Follow the template**: Use the PR template when creating pull requests

## Issue Guidelines

### Bug Reports
Use the bug report template and include:
- **Environment details**: OS, Docker version, container version
- **Steps to reproduce**: Clear, numbered steps
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Logs**: Relevant log output
- **Configuration**: Relevant configuration files (sanitized)

### Feature Requests
Use the feature request template and include:
- **Problem description**: What problem does this solve?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Other approaches you've considered
- **Additional context**: Screenshots, examples, etc.

## Documentation

### README Updates
- Keep the README up to date with new features
- Include practical examples
- Update configuration options
- Add troubleshooting information

### Code Comments
- Comment complex logic
- Explain non-obvious decisions
- Include references to relevant documentation
- Use clear, concise language

### Configuration Documentation
- Document all configuration options
- Provide examples
- Explain security implications
- Include performance considerations

## Community Guidelines

### Be Respectful
- Use welcoming and inclusive language
- Be respectful of differing viewpoints and experiences
- Gracefully accept constructive criticism
- Focus on what is best for the community

### Be Collaborative
- Help others learn and grow
- Share knowledge and resources
- Provide constructive feedback
- Support new contributors

## Getting Help

- **Documentation**: Check the README and documentation first
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Community**: Join our community discussions

## Recognition

Contributors will be recognized in:
- The project's contributor list
- Release notes for significant contributions
- Special recognition for outstanding contributions

Thank you for contributing to Squid Proxy! 🎉