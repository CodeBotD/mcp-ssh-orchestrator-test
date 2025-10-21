# Changelog

All notable changes to mcp-ssh-orchestrator will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

