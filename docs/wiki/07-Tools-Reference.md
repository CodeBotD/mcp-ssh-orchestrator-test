# 7. Tools Reference

**Purpose:** Complete documentation of all MCP tools provided by mcp-ssh-orchestrator, including parameters, return values, and usage examples.

## Overview

mcp-ssh-orchestrator provides **8 MCP tools** that enable secure SSH command execution, host management, and policy testing. All tools follow the MCP specification and return structured JSON responses.

## Tool Categories

### Health & Discovery Tools
- `ssh_ping` - Health check
- `ssh_list_hosts` - List configured hosts
- `ssh_describe_host` - Get host details

### Execution Tools
- `ssh_run` - Execute command on single host
- `ssh_run_on_tag` - Execute command on multiple hosts
- `ssh_cancel` - Cancel running command

### Management Tools
- `ssh_plan` - Dry-run command (policy testing)
- `ssh_reload_config` - Reload configuration

## Tool Reference

### ssh_ping

**Purpose:** Health check to verify mcp-ssh-orchestrator is running and responsive.

**Parameters:** None

**Request:**
```json
{
  "name": "ssh_ping",
  "arguments": {}
}
```

**Response:**
```json
{
  "status": "ok",
  "message": "mcp-ssh-orchestrator is running",
  "timestamp": 1729512345.67,
  "version": "0.1.0"
}
```

**Use Cases:**
- Verify MCP server is running
- Test connectivity to mcp-ssh-orchestrator
- Health monitoring and alerting

**Example:**
```bash
# Test via Claude Desktop
ssh_ping
```

---

### ssh_list_hosts

**Purpose:** List all configured hosts from servers.yml.

**Parameters:** None

**Request:**
```json
{
  "name": "ssh_list_hosts",
  "arguments": {}
}
```

**Response:**
```json
[
  "web1",
  "web2", 
  "db1",
  "monitor1"
]
```

**Use Cases:**
- Discover available hosts
- Verify host configuration
- Build dynamic host lists

**Example:**
```bash
# List all configured hosts
ssh_list_hosts
```

---

### ssh_describe_host

**Purpose:** Get detailed information about a specific host.

**Parameters:**
| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `alias` | string | Yes | Host alias to describe | `"web1"` |

**Request:**
```json
{
  "name": "ssh_describe_host",
  "arguments": {
    "alias": "web1"
  }
}
```

**Response:**
```json
{
  "alias": "web1",
  "host": "10.0.0.11",
  "port": 22,
  "credentials": "prod_admin",
  "tags": ["production", "web", "linux"],
  "description": "Primary web server",
  "policy_limits": {
    "max_seconds": 30,
    "max_output_bytes": 524288,
    "require_known_host": true
  }
}
```

**Use Cases:**
- Get host connection details
- Verify host configuration
- Check policy limits for specific host

**Example:**
```bash
# Get details for web1
ssh_describe_host --alias "web1"
```

---

### ssh_plan

**Purpose:** Dry-run a command to test policy rules without executing.

**Parameters:**
| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `alias` | string | Yes | Target host alias | `"web1"` |
| `command` | string | Yes | Command to test | `"uptime"` |

**Request:**
```json
{
  "name": "ssh_plan",
  "arguments": {
    "alias": "web1",
    "command": "uptime"
  }
}
```

**Response:**
```json
{
  "alias": "web1",
  "command": "uptime",
  "policy_decision": "allow",
  "rule_matched": "prod-readonly",
  "network_check": "passed",
  "execution_limits": {
    "max_seconds": 30,
    "max_output_bytes": 524288
  },
  "would_execute": true
}
```

**Use Cases:**
- Test policy rules before execution
- Debug policy configuration
- Validate command authorization
- Learn about policy behavior

**Example:**
```bash
# Test if command would be allowed
ssh_plan --alias "web1" --command "uptime"
ssh_plan --alias "prod-web-1" --command "systemctl restart nginx"
```

---

### ssh_run

**Purpose:** Execute a command on a single host.

**Parameters:**
| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `alias` | string | Yes | Target host alias | `"web1"` |
| `command` | string | Yes | Command to execute | `"uptime"` |

**Request:**
```json
{
  "name": "ssh_run",
  "arguments": {
    "alias": "web1",
    "command": "uptime"
  }
}
```

**Response:**
```json
{
  "task_id": "web1:a1b2c3d4:1234567890",
  "alias": "web1",
  "command": "uptime",
  "exit_code": 0,
  "duration_ms": 123,
  "cancelled": false,
  "timeout": false,
  "target_ip": "10.0.0.11",
  "output": " 14:30:45 up 42 days,  3:14,  1 user,  load average: 0.15, 0.08, 0.05",
  "error": "",
  "policy_decision": "allow",
  "rule_matched": "prod-readonly"
}
```

**Response Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `task_id` | string | Unique task identifier |
| `alias` | string | Target host alias |
| `command` | string | Executed command |
| `exit_code` | integer | Command exit status (0 = success) |
| `duration_ms` | integer | Execution time in milliseconds |
| `cancelled` | boolean | Whether command was cancelled |
| `timeout` | boolean | Whether command timed out |
| `target_ip` | string | Actual IP address connected to |
| `output` | string | Command stdout output |
| `error` | string | Command stderr output |
| `policy_decision` | string | Policy decision (allow/deny) |
| `rule_matched` | string | Policy rule that matched |

**Use Cases:**
- Execute single commands on hosts
- Run system diagnostics
- Perform maintenance tasks
- Test host connectivity

**Example:**
```bash
# Execute uptime command
ssh_run --alias "web1" --command "uptime"

# Check disk usage
ssh_run --alias "web1" --command "df -h"

# Check service status
ssh_run --alias "web1" --command "systemctl status nginx"
```

---

### ssh_run_on_tag

**Purpose:** Execute a command on all hosts with a specific tag.

**Parameters:**
| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `tag` | string | Yes | Tag to match hosts | `"production"` |
| `command` | string | Yes | Command to execute | `"uptime"` |

**Request:**
```json
{
  "name": "ssh_run_on_tag",
  "arguments": {
    "tag": "production",
    "command": "uptime"
  }
}
```

**Response:**
```json
{
  "tag": "production",
  "command": "uptime",
  "hosts_matched": ["prod-web-1", "prod-web-2", "prod-db-1"],
  "results": [
    {
      "task_id": "prod-web-1:a1b2c3d4:1234567890",
      "alias": "prod-web-1",
      "exit_code": 0,
      "duration_ms": 123,
      "output": " 14:30:45 up 42 days,  3:14,  1 user,  load average: 0.15, 0.08, 0.05"
    },
    {
      "task_id": "prod-web-2:a1b2c3d4:1234567891",
      "alias": "prod-web-2", 
      "exit_code": 0,
      "duration_ms": 145,
      "output": " 14:30:45 up 41 days,  2:45,  2 users,  load average: 0.25, 0.12, 0.08"
    },
    {
      "task_id": "prod-db-1:a1b2c3d4:1234567892",
      "alias": "prod-db-1",
      "exit_code": 0,
      "duration_ms": 98,
      "output": " 14:30:45 up 43 days,  1:23,  0 users,  load average: 0.05, 0.03, 0.02"
    }
  ],
  "summary": {
    "total_hosts": 3,
    "successful": 3,
    "failed": 0,
    "cancelled": 0,
    "timeout": 0
  }
}
```

**Use Cases:**
- Bulk operations across host groups
- Environment-wide maintenance
- Tag-based host management
- Parallel command execution

**Example:**
```bash
# Check uptime on all production hosts
ssh_run_on_tag --tag "production" --command "uptime"

# Check disk usage on all web servers
ssh_run_on_tag --tag "web" --command "df -h"

# Check service status on all database servers
ssh_run_on_tag --tag "database" --command "systemctl status postgresql"
```

---

### ssh_cancel

**Purpose:** Cancel a running command using its task ID.

**Parameters:**
| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `task_id` | string | Yes | Task ID to cancel | `"web1:a1b2c3d4:1234567890"` |

**Request:**
```json
{
  "name": "ssh_cancel",
  "arguments": {
    "task_id": "web1:a1b2c3d4:1234567890"
  }
}
```

**Response:**
```json
{
  "task_id": "web1:a1b2c3d4:1234567890",
  "cancelled": true,
  "message": "Command cancelled successfully"
}
```

**Use Cases:**
- Stop long-running commands
- Cancel stuck processes
- Emergency command termination
- Resource management

**Example:**
```bash
# Cancel a running command
ssh_cancel --task_id "web1:a1b2c3d4:1234567890"
```

---

### ssh_reload_config

**Purpose:** Reload configuration files without restarting the MCP server.

**Parameters:** None

**Request:**
```json
{
  "name": "ssh_reload_config",
  "arguments": {}
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Configuration reloaded successfully",
  "files_reloaded": [
    "servers.yml",
    "credentials.yml", 
    "policy.yml"
  ],
  "timestamp": 1729512345.67
}
```

**Use Cases:**
- Update configuration without restart
- Apply policy changes
- Add new hosts dynamically
- Update credentials

**Example:**
```bash
# Reload configuration
ssh_reload_config
```

## Tool Usage Patterns

### Health Monitoring

```bash
# Check system health
ssh_ping

# List all hosts
ssh_list_hosts

# Check specific host details
ssh_describe_host --alias "web1"
```

### Policy Testing

```bash
# Test policy before execution
ssh_plan --alias "web1" --command "uptime"
ssh_plan --alias "prod-web-1" --command "systemctl restart nginx"

# Test network policies
ssh_plan --alias "web1" --command "ping 8.8.8.8"
```

### Single Host Operations

```bash
# System information
ssh_run --alias "web1" --command "uptime"
ssh_run --alias "web1" --command "df -h"
ssh_run --alias "web1" --command "free -h"

# Service management
ssh_run --alias "web1" --command "systemctl status nginx"
ssh_run --alias "web1" --command "systemctl is-active nginx"

# Process information
ssh_run --alias "web1" --command "ps aux | grep nginx"
ssh_run --alias "web1" --command "top -n 1"
```

### Bulk Operations

```bash
# Environment-wide checks
ssh_run_on_tag --tag "production" --command "uptime"
ssh_run_on_tag --tag "production" --command "df -h"

# Service-specific operations
ssh_run_on_tag --tag "web" --command "systemctl status nginx"
ssh_run_on_tag --tag "database" --command "systemctl status postgresql"

# Infrastructure checks
ssh_run_on_tag --tag "monitoring" --command "systemctl status prometheus"
```

### Command Management

```bash
# Start long-running command
ssh_run --alias "web1" --command "tail -f /var/log/nginx/access.log"

# Cancel if needed
ssh_cancel --task_id "web1:a1b2c3d4:1234567890"

# Reload configuration
ssh_reload_config
```

## Error Handling

### Common Error Responses

**Policy Denied:**
```json
{
  "error": "Policy denied",
  "alias": "web1",
  "command": "rm -rf /",
  "policy_decision": "deny",
  "reason": "Command contains blocked substring: rm -rf /"
}
```

**Host Not Found:**
```json
{
  "error": "Host not found",
  "alias": "nonexistent",
  "available_hosts": ["web1", "web2", "db1"]
}
```

**Network Blocked:**
```json
{
  "error": "Network access denied",
  "alias": "web1",
  "target_ip": "8.8.8.8",
  "reason": "IP not in allowlist"
}
```

**SSH Connection Failed:**
```json
{
  "error": "SSH connection failed",
  "alias": "web1",
  "target_ip": "10.0.0.11",
  "reason": "Connection refused",
  "exit_code": 255
}
```

**Command Timeout:**
```json
{
  "task_id": "web1:a1b2c3d4:1234567890",
  "alias": "web1",
  "command": "sleep 120",
  "exit_code": 124,
  "timeout": true,
  "duration_ms": 60000
}
```

## Security Considerations

### Policy Enforcement

All tools respect policy configuration:
- **ssh_run** and **ssh_run_on_tag** check policy before execution
- **ssh_plan** shows policy decision without executing
- **ssh_cancel** respects cancellation policies
- **ssh_reload_config** validates new configuration

### Audit Logging

All tool usage is logged:
- **JSON audit logs** to stderr
- **Complete operation trail** for compliance
- **Security-relevant metadata** in every log entry
- **Immutable log format** for integrity

### Network Security

All tools enforce network policies:
- **IP allowlists** prevent unauthorized connections
- **Host key verification** prevents MITM attacks
- **DNS resolution** verification before connection
- **Network segmentation** via CIDR controls

## Next Steps

- **[Usage Cookbook](08-Usage-Cookbook)** - Practical tool usage examples
- **[Configuration](06-Configuration)** - Tool configuration and policies
- **[Troubleshooting](12-Troubleshooting)** - Common tool issues and solutions
- **[Deployment](09-Deployment)** - Production tool deployment
