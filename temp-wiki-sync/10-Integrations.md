# 10. Integrations

**Purpose:** Guide for integrating mcp-ssh-orchestrator with MCP clients like Claude Desktop, OpenAI Codex, and custom applications.

## Overview

mcp-ssh-orchestrator integrates with MCP clients through the **stdio transport** protocol. This section covers setup for popular MCP clients and custom integrations.

## Claude Desktop Integration

### Basic Setup

**1. Create configuration directory:**
```bash
mkdir -p ~/mcp-ssh/{config,keys,secrets}
```

**2. Copy example configurations:**
```bash
cp examples/example-servers.yml ~/mcp-ssh/config/servers.yml
cp examples/example-credentials.yml ~/mcp-ssh/config/credentials.yml
cp examples/example-policy.yml ~/mcp-ssh/config/policy.yml
```

**3. Add SSH keys:**
```bash
cp ~/.ssh/id_ed25519 ~/mcp-ssh/keys/
chmod 0400 ~/mcp-ssh/keys/id_ed25519
```

**4. Configure Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

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

### Advanced Configuration

**With environment variables for secrets:**
```json
{
  "mcpServers": {
    "ssh-orchestrator": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e", "MCP_SSH_SECRET_PROD_PASSWORD=your-password",
        "-e", "MCP_SSH_SECRET_KEY_PASSPHRASE=your-passphrase",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh/config:/app/config:ro",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh/keys:/app/keys:ro",
        "ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0"
      ]
    }
  }
}
```

**With resource limits:**
```json
{
  "mcpServers": {
    "ssh-orchestrator": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--memory=512m",
        "--cpus=1",
        "--user=10001:10001",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh/config:/app/config:ro",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh/keys:/app/keys:ro",
        "ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0"
      ]
    }
  }
}
```

## Docker Desktop Integration

### Using Docker MCP Toolkit

**1. Install Docker Desktop** with MCP Toolkit extension

**2. Configure MCP Toolkit:**
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
        "ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0"
      ]
    }
  }
}
```

**3. Test integration:**
```bash
# Test MCP server
docker run -i --rm \
  -v ~/mcp-ssh/config:/app/config:ro \
  -v ~/mcp-ssh/keys:/app/keys:ro \
  ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0
```

## OpenAI Codex Integration

### Via Docker MCP Toolkit

**1. Install Docker MCP Toolkit**

**2. Configure Codex integration:**
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
        "ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0"
      ]
    }
  }
}
```

**3. Test with Codex:**
```bash
# Test MCP tools
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ssh_ping","arguments":{}},"id":1}' | \
  docker run -i --rm \
  -v ~/mcp-ssh/config:/app/config:ro \
  -v ~/mcp-ssh/keys:/app/keys:ro \
  ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0
```

## Custom Application Integration

### Python Integration

**Using MCP SDK:**
```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    # Configure server parameters
    server_params = StdioServerParameters(
        command="docker",
        args=[
            "run", "-i", "--rm",
            "-v", "/path/to/config:/app/config:ro",
            "-v", "/path/to/keys:/app/keys:ro",
            "ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0"
        ]
    )
    
    # Create client session
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize session
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print("Available tools:", tools)
            
            # Execute SSH command
            result = await session.call_tool(
                "ssh_run",
                {"alias": "web1", "command": "uptime"}
            )
            print("Command result:", result)

if __name__ == "__main__":
    asyncio.run(main())
```

### Node.js Integration

**Using MCP client library:**
```javascript
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');
const { spawn } = require('child_process');

async function main() {
  // Create transport
  const transport = new StdioClientTransport({
    command: 'docker',
    args: [
      'run', '-i', '--rm',
      '-v', '/path/to/config:/app/config:ro',
      '-v', '/path/to/keys:/app/keys:ro',
      'ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0'
    ]
  });
  
  // Create client
  const client = new Client({
    name: 'ssh-orchestrator-client',
    version: '1.0.0'
  }, {
    capabilities: {}
  });
  
  // Connect
  await client.connect(transport);
  
  // List tools
  const tools = await client.listTools();
  console.log('Available tools:', tools);
  
  // Execute SSH command
  const result = await client.callTool({
    name: 'ssh_run',
    arguments: {
      alias: 'web1',
      command: 'uptime'
    }
  });
  
  console.log('Command result:', result);
  
  // Disconnect
  await client.close();
}

main().catch(console.error);
```

## Multi-Environment Setup

### Development Environment

**Claude Desktop config for development:**
```json
{
  "mcpServers": {
    "ssh-orchestrator-dev": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e", "MCP_SSH_DEBUG=1",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh-dev/config:/app/config:ro",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh-dev/keys:/app/keys:ro",
        "ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0"
      ]
    }
  }
}
```

### Staging Environment

**Claude Desktop config for staging:**
```json
{
  "mcpServers": {
    "ssh-orchestrator-staging": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh-staging/config:/app/config:ro",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh-staging/keys:/app/keys:ro",
        "ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0"
      ]
    }
  }
}
```

### Production Environment

**Claude Desktop config for production:**
```json
{
  "mcpServers": {
    "ssh-orchestrator-prod": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--memory=512m",
        "--cpus=1",
        "--user=10001:10001",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh-prod/config:/app/config:ro",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh-prod/keys:/app/keys:ro",
        "-v", "/Users/YOUR_USERNAME/mcp-ssh-prod/secrets:/app/secrets:ro",
        "ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0"
      ]
    }
  }
}
```

## Testing Integrations

### Health Check

**Test MCP server connectivity:**
```bash
# Test ping
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ssh_ping","arguments":{}},"id":1}' | \
  docker run -i --rm \
  -v ~/mcp-ssh/config:/app/config:ro \
  -v ~/mcp-ssh/keys:/app/keys:ro \
  ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0
```

**Test host listing:**
```bash
# List hosts
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ssh_list_hosts","arguments":{}},"id":1}' | \
  docker run -i --rm \
  -v ~/mcp-ssh/config:/app/config:ro \
  -v ~/mcp-ssh/keys:/app/keys:ro \
  ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0
```

### Command Testing

**Test policy with dry-run:**
```bash
# Test policy
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ssh_plan","arguments":{"alias":"web1","command":"uptime"}},"id":1}' | \
  docker run -i --rm \
  -v ~/mcp-ssh/config:/app/config:ro \
  -v ~/mcp-ssh/keys:/app/keys:ro \
  ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0
```

**Execute test command:**
```bash
# Execute command
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"ssh_run","arguments":{"alias":"web1","command":"uptime"}},"id":1}' | \
  docker run -i --rm \
  -v ~/mcp-ssh/config:/app/config:ro \
  -v ~/mcp-ssh/keys:/app/keys:ro \
  ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0
```

## Troubleshooting

### Common Issues

**MCP server not responding:**
```bash
# Check container logs
docker logs $(docker ps -q --filter "ancestor=ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0")

# Test container health
docker run --rm ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0 python -c "import mcp_ssh; print('OK')"
```

**Configuration errors:**
```bash
# Validate configuration
docker run --rm \
  -v ~/mcp-ssh/config:/app/config:ro \
  ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0 \
  python -c "
from mcp_ssh.config import Config
config = Config('/app/config')
print('Config valid:', config.validate())
"
```

**SSH connection issues:**
```bash
# Test SSH connectivity
ssh -i ~/mcp-ssh/keys/id_ed25519 ubuntu@10.0.0.11

# Check host key verification
ssh-keyscan 10.0.0.11 >> ~/mcp-ssh/keys/known_hosts
```

## Next Steps

- **[Deployment](09-Deployment)** - Production deployment guide
- **[Observability & Audit](11-Observability-Audit)** - Monitoring and compliance
- **[Troubleshooting](12-Troubleshooting)** - Common integration issues
- **[Usage Cookbook](08-Usage-Cookbook)** - Practical usage examples
