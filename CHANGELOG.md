# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Prometheus metrics

### Changed
- Prepend InstanceID with pid of Caddy process
- Improved debug logging of handler pool
- Enabled admin in Caddyfile used for testing
- Increased max handler pool size from 128 to 512

### Testing
- Increased test coverage to 94.1%
- Added tests for Prometheus metrics

## [v0.4.8]

### Changed
- Logging to Info on cleanup
- No longer checking for request context cancellation since because it caused errors in the logs while it's
  not that expensive to complete checking the ipsets for that request.

### Testing
- Increased test coverage to 91.6%
- Cleaned up tests
- Added tests for IPv4-mapped IPv6 addresses
- Added tests for an ipset name with spaces
- ipsets are no longer built in Docker image but initialized before testing
- Simplified Dockerfile

### Documentation
- Added comments about IPv4-mapped IPv6 addresses

## [v0.4.7]

### Fixed
- If an ipset is of an unknown family, try to match it.

### Changed
- Made `Cleanup()` safe when `MatchWithError()` is called concurrently.
- Performance optimization: Skip debug string allocations in hot paths when debug is not enabled.
- Switched to `github.com/syndtr/gocapability/capability` for capability checks to prevent CGo requirements.
- Made comparing ipset families against IP families a bit more efficient.
- Moved interface guards to top of file for better readability.

### Documentation
- Improved inline module documentation
- Improved and simplified README.md

## [v0.4.6]

### Changed
- Replaced `sync.Pool` with a leaky bucket pattern for netlink handles. The previous implementation was risky
  for memory/resource leaks and unbound growth.
- Removed check for empty ipset names in `Provision()` because it's already checked in `UnmarshalCaddyfile()`.

### Testing
- Added benchmarks for concurrent access and performance optimization

## [v0.4.5] - 2026-01-24

### Changed
- Using `instance_id` for debugging multiple instances of the module

## [v0.4.4] - 2026-01-24

### Changed
- Using a `sync.Pool` of netlink handles for concurrent access instead of a single mutex-protected handle
- Show path to actual caddy binary in error message when CAP_NET_ADMIN is missing instead of just `./caddy`
- Consolidated IP family mismatch checking into single conditional
- Simplified `Cleanup()` method by removing unnecessary outer conditional

### Fixed
- Error messages: Improved sanity check error message to show actual counts for easier debugging
- Context handling: Added support for request context cancellation in `MatchWithError` loop

### Removed
- Redundant sanity check for ipset count vs family count (impossible to fail)
- Removed stub implementation for non-Linux platforms

### Testing
- Added context cancellation test to verify graceful handling of canceled requests

## [v0.4.3] - 2026-01-24

### Fixed
- Changed `sync.Mutex` to `*sync.Mutex` to allow value receiver for `CaddyModule()` method
- Fixed module registration to use zero value `IpsetMatcher{}` instead of nil pointer
- Downgraded Go version from 1.25 to 1.23 for better compatibility with Caddy module scanner

### Changed
- Module now registers and builds on macOS, Windows, and other non-Linux platforms
- Non-Linux platforms return clear error messages when attempting to use the module

## [v0.4.2] - 2026-01-24

### Changed
- Added stub implementation for non-Linux platforms to enable module scanning on all platforms

## [v0.4.1] - 2026-01-24

### Documentation
- Improved inline module documentation

## [v0.4.0] - 2026-01-24

### Changed
- Support for passing multiple ipsets to one matcher
- Support for multiple ipset directives in one matcher block
- When IP family doesn't match ipset family, log as debug instead of warning

### Documentation
- Improved module description
- Examples with both IPv4 and IPv6 matching in one matcher

## [v0.3.1] - 2026-01-23

### Documentation
- Added 'Linux-specific' to module description

## [v0.3.0] - 2026-01-23

### Changed
- **BREAKING**: Removed sudo ipset fallback support - now requires CAP_NET_ADMIN capability
- Using mutex to make netlink handle thread-safe
- Skip matching if ipset family doesn't match IP family
- Performance improvement: Reuse netlink handle across requests to avoid socket creation overhead
- Simplified codebase by removing all sudo-related code and complexity
- Updated documentation to focus on `sudo setcap cap_net_admin+ep ./caddy` approach
- Docker testing now uses `setcap` to grant CAP_NET_ADMIN to test binary running as non-root user
- Replaced sudo package with `libcap2-bin` in Docker image
- Renamed test ipsets to use `test-ipset-v4` and `test-ipset-v6` naming convention
- No longer validating name of ipset since almost all characters are allowed
- Improved logging
- Switched from RequestMatcher to RequestMatcherWithError

### Removed
- Sudo ipset fallback functionality
- `ipsetMethodSudo` constant and related code
- `testIPSudo()` and `verifySudoIpset()` functions
- All sudo-related tests and documentation
- Sudo configuration from Docker test environment

### Testing
- Coverage increased to 94.5%
- Coverage is now written to `coverage.out`
- Manual testing in Docker using `xcaddy`
- Improved Makefile

### Documentation
- Updated README.md to focus on CAP_NET_ADMIN approach
- Added DOCKER-TESTING.md for Docker testing guide
- Point to scripts/Caddyfile from README.md
- Added X-Forwarded-For example to README.md
- Cleaned up README

## [v0.2.0] - 2026-01-23

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

## [v0.1.0] - 2026-01-22

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
- `golangci-lint` configuration

### Fixed
- Improved warning messages for better user experience
- Sudo fallback method reliability improvements
- Go version compatibility (Go 1.25)
- Code formatting and linting issues

[v0.3.0]: https://github.com/deovero/caddy-ipset/compare/v0.2.0...v0.3.0
[v0.2.0]: https://github.com/deovero/caddy-ipset/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/deovero/caddy-ipset/releases/tag/v0.1.0
