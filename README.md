# MCP SSH Orchestrator

<div align="center">
  <img src="assets/logo/logo-v1.png" alt="MCP SSH Orchestrator Logo" width="200" height="200">
  <h3>A secure SSH fleet orchestrator built as a Model Context Protocol (MCP) server</h3>
  <p>Execute commands across your server fleet with policy-based access control, network filtering, and comprehensive audit logging.</p>
</div>

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-1.2+-green.svg)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)

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

| Tool | Purpose | Example |
|------|---------|---------|
| `ssh_ping` | Health check | `{"name": "ssh_ping"}` |
| `ssh_run` | Execute command | `{"name": "ssh_run", "arguments": {"alias": "web1", "command": "uptime"}}` |
| `ssh_run_on_tag` | Bulk operations | `{"name": "ssh_run_on_tag", "arguments": {"tag": "prod", "command": "uptime"}}` |

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