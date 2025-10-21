# Docker Desktop MCP Integration Guide

This guide shows how to integrate mcp-ssh-orchestrator with Docker Desktop's Model Context Protocol (MCP) support.

## Prerequisites

- Docker Desktop 4.34+ with MCP support enabled
- Claude Desktop app (or other MCP-compatible client)
- SSH keys and configuration files prepared

## Step 1: Prepare Configuration

### Create Configuration Directory

```bash
mkdir -p ~/mcp-ssh/{config,keys,secrets}
```

### Copy Example Files

```bash
# If you've cloned the repository
cp examples/example-servers.yml ~/mcp-ssh/config/servers.yml
cp examples/example-credentials.yml ~/mcp-ssh/config/credentials.yml
cp examples/example-policy.yml ~/mcp-ssh/config/policy.yml

# Edit files with your actual hosts and credentials
```

### Add SSH Keys

```bash
# Copy your SSH private keys
cp ~/.ssh/id_ed25519 ~/mcp-ssh/keys/
chmod 0400 ~/mcp-ssh/keys/id_ed25519

# If you have a known_hosts file
cp ~/.ssh/known_hosts ~/mcp-ssh/keys/
```

### Add Secrets (Optional)

```bash
# For password-based authentication
echo "my-secure-password" > ~/mcp-ssh/secrets/admin_password

# For key passphrases
echo "my-key-passphrase" > ~/mcp-ssh/secrets/ssh_key_passphrase
```

## Step 2: Configure Claude Desktop

### Locate Config File

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```
~/.config/Claude/claude_desktop_config.json
```

### Add MCP Server Configuration

Edit the config file and add:

```json
{
  "mcpServers": {
    "ssh-orchestrator": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh/config:/app/config:ro",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh/keys:/app/keys:ro",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh/secrets:/app/secrets:ro",
        "ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0"
      ]
    }
  }
}
```

**Important:** Replace `/Users/YOUR_USERNAME` with your actual home directory path.

### Alternative: Using Environment Variables

For passwords/passphrases, you can use environment variables instead of files:

```json
{
  "mcpServers": {
    "ssh-orchestrator": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e", "MCP_SSH_SECRET_ADMIN_PASSWORD=my-password",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh/config:/app/config:ro",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh/keys:/app/keys:ro",
        "ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0"
      ]
    }
  }
}
```

## Step 3: Test the Configuration

### Restart Claude Desktop

Completely quit and restart Claude Desktop to load the new MCP server.

### Verify Connection

In Claude, try these commands:

```
Can you list my SSH hosts?
```

This should trigger the `ssh_list_hosts` tool and return your configured hosts.

```
Can you check the uptime on web1?
```

This should plan and execute `uptime` command on the host aliased as "web1".

### Check Logs

View Docker container logs:

```bash
docker ps -a | grep mcp-ssh
docker logs <container-id>
```

Logs are JSON-formatted and sent to stderr.

## Step 4: Configure Policies

### Example: Allow Read-Only Commands on Production

Edit `~/mcp-ssh/config/policy.yml`:

```yaml
rules:
  - action: "allow"
    aliases: ["prod-*"]
    tags: ["production"]
    commands:
      - "uptime*"
      - "df -h*"
      - "ps aux*"
      - "cat /var/log/*"
  
  - action: "deny"
    aliases: ["prod-*"]
    tags: []
    commands:
      - "rm*"
      - "systemctl restart*"
```

### Reload Configuration

In Claude:

```
Can you reload the SSH orchestrator configuration?
```

Or use the tool directly:

```json
{
  "name": "ssh_reload_config",
  "arguments": {}
}
```

## Step 5: Advanced Configuration

### Network Restrictions

Limit SSH targets to specific IP ranges:

```yaml
network:
  allow_cidrs:
    - "10.0.0.0/8"
    - "192.168.1.0/24"
  block_ips:
    - "10.10.10.10"
```

### Per-Host Limits

Override global limits for specific hosts:

```yaml
overrides:
  aliases:
    prod-web-1:
      max_seconds: 30
      max_output_bytes: 262144
```

### Tag-Based Operations

Execute commands across multiple hosts:

In Claude:
```
Can you check disk space on all production servers?
```

This triggers `ssh_run_on_tag` with tag="production" and command="df -h".

## Troubleshooting

### "Connection refused" errors

- Check that Docker Desktop is running
- Verify the image is pulled: `docker pull ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0`
- Check Claude Desktop config file syntax (must be valid JSON)

### "Host alias not found"

- Verify `servers.yml` has correct syntax
- Check the alias name matches exactly
- Try `ssh_list_hosts` to see available aliases

### "Denied by policy"

- Review `policy.yml` rules
- Use `ssh_plan` to see why a command was denied
- Check deny_substrings in limits section

### SSH connection failures

- Verify SSH keys have correct permissions (0400)
- Check known_hosts file if `require_known_host: true`
- Ensure target hosts are reachable from Docker container
- Check credentials reference in servers.yml

### Volume mount errors

- Use absolute paths in Docker args
- Ensure directories exist before starting
- Check file permissions (should be readable by UID 10001 or world-readable)

## Security Considerations

1. **Read-Only Mounts**: Always mount config and keys as `:ro`
2. **Key Permissions**: Set private keys to `chmod 0400`
3. **Secrets Management**: Prefer Docker secrets or env vars over files
4. **Network Isolation**: Use `allow_cidrs` to restrict targets
5. **Audit Logs**: Monitor stderr output for security events
6. **Policy Testing**: Use `ssh_plan` before `ssh_run` in production

## Next Steps

- Review [SECURITY.md](SECURITY.md) for hardening recommendations
- See [README.md](../README.md) for complete tool reference
- Check [CONTRIBUTING.md](CONTRIBUTING.md) to report issues or contribute

