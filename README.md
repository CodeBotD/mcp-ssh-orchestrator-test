# MCP SSH Orchestrator

<div align="center">
  <img src="assets/logo/logo-v1.png" alt="MCP SSH Orchestrator Logo" width="200" height="200">
  <h3>A secure SSH fleet orchestrator built as a Model Context Protocol (MCP) server</h3>
  <p>Execute commands across your server fleet with policy-based access control, network filtering, and comprehensive audit logging.</p>
</div>

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-1.2+-green.svg)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/samerfarida/mcp-ssh-orchestrator/badge)](https://scorecard.dev/viewer/?uri=github.com/samerfarida/mcp-ssh-orchestrator)

## 🚀 Quick Start

### Using Docker (Recommended)

```bash
# Pull the image
docker pull ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0

# Run interactively
docker run -i --rm \
  -v ~/mcp-ssh/config:/app/config:ro \
  -v ~/mcp-ssh/keys:/app/keys:ro \
  ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0
```

## 📚 Documentation

**📖 [Complete Documentation Wiki](https://github.com/samerfarida/mcp-ssh-orchestrator/wiki)**

- **[Architecture](https://github.com/samerfarida/mcp-ssh-orchestrator/wiki/04-Architecture)** - Component design and data flow
- **[Security Model](https://github.com/samerfarida/mcp-ssh-orchestrator/wiki/05-Security-Model)** - Defense-in-depth security
- **[Configuration](https://github.com/samerfarida/mcp-ssh-orchestrator/wiki/06-Configuration)** - servers.yml, credentials.yml, policy.yml
- **[Usage Cookbook](https://github.com/samerfarida/mcp-ssh-orchestrator/wiki/08-Usage-Cookbook)** - Practical examples
- **[Deployment](https://github.com/samerfarida/mcp-ssh-orchestrator/wiki/09-Deployment)** - Production setup

## 🔒 Security Features

- **Policy-Based Access Control**: Fine-grained command allow/deny rules
- **Network Security**: IP allowlists with CIDR support
- **Containerized Execution**: Runs in containers with resource limits
- **Audit Logging**: JSON audit trail for all operations
- **MCP Security Best Practices**: Implements Docker MCP Gateway principles

## 🛠️ MCP Tools

| Tool | Purpose | Execution Type |
|------|---------|----------------|
| `ssh_ping` | Health check | N/A |
| `ssh_list_hosts` | List all hosts | N/A |
| `ssh_describe_host` | Get host details | N/A |
| `ssh_plan` | Policy dry-run | N/A |
| `ssh_run` | Execute command | Synchronous |
| `ssh_run_on_tag` | Execute on tagged hosts | Synchronous |
| `ssh_run_async` | Start async task | Asynchronous |
| `ssh_get_task_status` | Check task progress | Async monitoring |
| `ssh_get_task_result` | Get task result | Async result |
| `ssh_get_task_output` | Stream task output | Async monitoring |
| `ssh_cancel` | Cancel sync task | Task control |
| `ssh_cancel_async_task` | Cancel async task | Async control |
| `ssh_reload_config` | Reload configuration | Management |

[See complete Tools Reference](https://github.com/samerfarida/mcp-ssh-orchestrator/wiki/07-Tools-Reference)

## 🤝 Contributing

See [Contributing Guide](https://github.com/samerfarida/mcp-ssh-orchestrator/wiki/13-Contributing) for development setup.

## 📄 License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## 🔗 Links

- **[GitHub Repository](https://github.com/samerfarida/mcp-ssh-orchestrator)**
- **[Issue Tracker](https://github.com/samerfarida/mcp-ssh-orchestrator/issues)**
- **[MCP Specification](https://modelcontextprotocol.io)**
- **[Docker MCP Security Guide](https://www.docker.com/blog/mcp-security-explained/)**