# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **BREAKING**: Removed sudo ipset fallback support - now requires CAP_NET_ADMIN capability
- Using mutex to make netlink handle thead-safe
- Skip matching if ipset family doesn't match IP family
- Performance improvement: Reuse netlink handle across requests to avoid socket creation overhead
- Simplified codebase by removing all sudo-related code and complexity
- Updated documentation to focus on `sudo setcap cap_net_admin+ep ./caddy` approach
- Docker testing now uses setcap to grant CAP_NET_ADMIN to test binary running as non-root user
- Replaced sudo package with libcap2-bin in Docker image
- Renamed test ipsets to use `test-ipset-v4` and `test-ipset-v6` naming convention
- Improved README

### Removed
- Sudo ipset fallback functionality
- `ipsetMethodSudo` constant and related code
- `testIPSudo()` and `verifySudoIpset()` functions
- All sudo-related tests and documentation
- Sudo configuration from Docker test environment

### Testing
- Now using producing coverage.out
- Coverage increased to 92.3%
- Manual testing in Docker using xcaddy
- Improved Makefile

## [0.2.0] - 2026-01-23

### Added
- Full IPv6 support for ipset matching
- Pre-commit hook for automatic code formatting and vetting before commit
- Consolidated `scripts/` directory for all project scripts

### Documentation
- Docker testing guide (DOCKER-TESTING.md)
- Automated test scripts for macOS users (test-docker.sh)
- macOS testing section in README.md
- Added IPv6 example to 'Testing the Module' section in README.md

### Fixed
- Improved check for netlink access
- CI workflow now properly installs ipset and configures test environment

### Testing
- Improved test coverage from 39.9% to 85.4%
- Fixed testing as non-root user
- Added comprehensive IPv6 test cases
- Shared ipset setup script for consistency between Docker and CI
- IPv6 test coverage with comprehensive test cases
- Docker-based testing environment for macOS (including Apple Silicon support)
- Multi-architecture Docker support (AMD64 and ARM64)
- CGO support for race detection in tests
- Makefile with convenient commands for Docker-based testing
- `.dockerignore` for optimized Docker builds

## [0.1.0] - 2026-01-22

### Added
- Initial release of Caddy IPSet Matcher module
- Native kernel communication using netlink for direct ipset access
- Automatic fallback to `sudo ipset` when running as non-privileged user
- Match HTTP requests against existing Linux ipset lists
- Integration with Caddy's built-in client IP detection (respects `trusted_proxies` configuration)
- Automatic ipset validation on startup
- Comprehensive logging for debugging and monitoring using zap logger
- Simple Caddyfile and JSON configuration support
- High performance with minimal overhead
- Comprehensive unit tests with race detection
- GitHub Actions CI/CD pipeline with test, lint, and build jobs
- Apache 2.0 license

### Documentation
- Comprehensive README.md with usage examples
- Example Caddyfile configurations for common use cases
- Detailed permission setup instructions for both netlink and sudo methods
- Troubleshooting guide for common issues

### Testing
- Unit tests for IP matching functionality
- Tests for both netlink and sudo fallback methods
- Coverage reporting integrated with Codecov

### Infrastructure
- GitHub Actions CI workflow
- golangci-lint configuration

### Fixed
- Improved warning messages for better user experience
- Sudo fallback method reliability improvements
- Go version compatibility (Go 1.25)
- Code formatting and linting issues

[0.2.0]: https://github.com/deovero/caddy-ipset/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/deovero/caddy-ipset/releases/tag/v0.1.0
