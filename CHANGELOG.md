# Changelog

All notable changes to mcp-ssh-orchestrator will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2025-01-28

### Added
- YAML Style Guide in `docs/POLICY_REFERENCE.md` with consistent formatting guidelines
- Standardized array formatting rules for improved readability

### Changed
- Enforced consistent YAML array formatting across all configuration files:
  - Empty arrays: inline format `[]`
  - Single items: inline format `["item"]`
  - Multiple items: multi-line format with dash syntax
- Updated all documentation examples to follow consistent style guide
- Standardized `aliases` and `tags` arrays in policy rules (multi-line for 2+ items)
- Updated all `servers.yml` tag arrays to multi-line format for consistency
- Refactored all YAML configuration files to follow unified style guidelines

### Files Modified
- `config/policy.yml`
- `config/servers.yml`
- `examples/example-policy.yml`
- `examples/example-servers.yml`
- `docs/POLICY_EXAMPLES.md`
- `docs/POLICY_REFERENCE.md`
- `README.md`

## [0.1.3] - 2025-01-27

### Added

- Comprehensive policy configuration documentation
  - `docs/POLICY_REFERENCE.md` - Complete technical reference with all configuration options, types, defaults, and examples
  - `docs/POLICY_EXAMPLES.md` - 10+ practical configuration examples for different environments and use cases
  - `docs/POLICY_SECURITY.md` - Security best practices, troubleshooting guide, and incident response procedures
- Policy documentation links in main README.md
- Cross-references between all policy documentation files
- Comprehensive tables for all policy configuration sections (limits, network, rules, overrides)
- Real-world examples for production, development, staging, Proxmox, and network-restricted environments
- Security checklists and troubleshooting guides
- Glob pattern matching syntax documentation
- Rule evaluation order and precedence explanations

### Changed

- Updated README.md to include dedicated "Policy Configuration" section with links to comprehensive documentation
- Enhanced documentation structure with consistent cross-references between policy docs

## [0.1.2] - 2025-10-24

### Fixed

- Fixed SSH host key handling when `require_known_host` is set to false
- Added `AcceptPolicy` class to handle unknown host keys without saving them
- Resolved "Server not found in known_hosts" error when using permissive host key policies
- Improved SSH connection reliability for environments with dynamic host keys

### Changed

- Enhanced SSH client logic to properly respect `require_known_host: false` setting
- Updated host key policy handling to support three modes: strict, permissive, and auto-add

## [0.1.1] - 2025-10-22

### Fixed

- Fixed Docker build issues in CI/CD pipeline
- Resolved linting and formatting errors for automated workflows
- Fixed Docker test step to properly load built images
- Corrected exception chaining in SSH client error handling
- Fixed loop variable binding issues in progress callbacks

### Changed

- Updated Python base image to 3.14-slim for latest security patches
- Improved Docker build process with better .dockerignore configuration
- Enhanced CI/CD workflows with proper dependency management
- Updated development dependencies (black, ruff, mypy, pytest)

### Added

- Automated dependency management with Dependabot
- Comprehensive CI/CD pipeline with linting, testing, and Docker builds
- Automated code formatting and type checking
- Docker Compose setup with automated configuration
- Example configuration files and setup scripts

## [0.1.0] - 2025-10-21

### Added

- Initial release of MCP SSH Orchestrator
- Core MCP server implementation with STDIO transport
- SSH command execution with Paramiko
- Policy-based access control engine
  - Allow/deny rules with glob pattern matching
  - Per-alias and per-tag limit overrides
  - Deny substrings for dangerous commands
- Network security controls
  - IP allowlist/blocklist with CIDR support
  - Pre-connect DNS resolution verification
  - Post-connect peer IP validation
- Credential management
  - SSH key-based authentication
  - Password-based authentication
  - Docker secrets integration
  - Environment variable support for secrets
- Configuration system
  - YAML-based configuration (servers, credentials, policy)
  - Hot-reload capability
  - Example configuration files
- MCP Tools
  - `ssh_ping` - Health check
  - `ssh_list_hosts` - List configured hosts
  - `ssh_describe_host` - Get host details
  - `ssh_plan` - Dry-run command with policy check
  - `ssh_run` - Execute command on single host
  - `ssh_run_on_tag` - Execute command on tagged hosts
  - `ssh_cancel` - Cancel running commands
  - `ssh_reload_config` - Hot-reload configuration
- Execution features
  - Real-time streaming output
  - Cancellation support
  - Timeout enforcement
  - Output size limits
  - Progress callbacks
- Docker support
  - Multi-stage Dockerfile
  - Non-root user (UID 10001)
  - Health checks
  - Docker Compose configuration
- Audit logging
  - JSON-formatted logs to stderr
  - Policy decisions
  - Execution metrics
  - Network events
- Documentation
  - Comprehensive README
  - Example configurations
  - Docker Desktop integration guide
- Docker MCP Registry compliance
  - Registry-compliant server.json metadata
  - Proper versioning and tagging

### Security

- Host key verification with known_hosts
- Network egress controls
- Deny-by-default policy model
- Audit trail for all commands
- Read-only container mounts
- Non-root container execution

