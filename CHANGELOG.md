# Changelog

All notable changes to mcp-ssh-orchestrator will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

