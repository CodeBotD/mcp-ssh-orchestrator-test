# Local Development Guide

This guide covers setting up mcp-ssh-orchestrator for local development and testing.

## Prerequisites

- Python 3.11+ (3.13 recommended)
- Docker Desktop (for container testing)
- Git

## Development Setup

### 1. Clone and Install

```bash
# Clone the repository
git clone https://github.com/samerfarida/mcp-ssh-orchestrator
cd mcp-ssh-orchestrator

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in editable mode
pip install -e .

# Install development dependencies
pip install -e ".[dev]"
```

### 2. Configure for Local Testing

```bash
# Create local config directory
mkdir -p ~/mcp-ssh-local/{config,keys,secrets}

# Copy example configurations
cp examples/example-servers.yml ~/mcp-ssh-local/config/servers.yml
cp examples/example-credentials.yml ~/mcp-ssh-local/config/credentials.yml
cp examples/example-policy.yml ~/mcp-ssh-local/config/policy.yml

# Add test SSH keys (optional)
cp ~/.ssh/id_ed25519 ~/mcp-ssh-local/keys/ 2>/dev/null || echo "No SSH key found, using password auth"
chmod 0400 ~/mcp-ssh-local/keys/id_ed25519 2>/dev/null || true
```

### 3. Test MCP Server Locally

```bash
# Test basic functionality
echo '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}}' | python -m mcp_ssh.mcp_server stdio

# Test with configuration
MCP_SSH_CONFIG_DIR=~/mcp-ssh-local/config python -m mcp_ssh.mcp_server stdio
```

### 4. Test with Docker

```bash
# Build local image
docker build -t mcp-ssh-orchestrator:local .

# Test container
echo -e '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}}\n{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ssh_ping", "arguments": {}}}' | docker run -i --rm -v ~/mcp-ssh-local/config:/app/config:ro mcp-ssh-orchestrator:local
```

## Development Workflow

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mcp_ssh --cov-report=html

# Run specific test file
pytest tests/test_ssh.py -v
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint code
ruff check src/ tests/

# Type checking
mypy src/
```

### Testing MCP Tools

Create a test script `test_mcp.py`:

```python
#!/usr/bin/env python3
"""Test MCP server tools locally."""

import json
import subprocess
import sys

def test_mcp_tool(tool_name, arguments=None):
    """Test a single MCP tool."""
    if arguments is None:
        arguments = {}
    
    # Initialize
    init_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "clientInfo": {"name": "test-client", "version": "1.0.0"}
        }
    }
    
    # Tool call
    tool_request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }
    
    # Send requests
    input_data = json.dumps(init_request) + "\n" + json.dumps(tool_request) + "\n"
    
    try:
        result = subprocess.run(
            ["python", "-m", "mcp_ssh.mcp_server", "stdio"],
            input=input_data,
            text=True,
            capture_output=True,
            timeout=10
        )
        
        print(f"Tool: {tool_name}")
        print(f"Exit code: {result.returncode}")
        print(f"Output: {result.stdout}")
        if result.stderr:
            print(f"Errors: {result.stderr}")
        print("-" * 50)
        
    except subprocess.TimeoutExpired:
        print(f"Tool {tool_name} timed out")
    except Exception as e:
        print(f"Error testing {tool_name}: {e}")

if __name__ == "__main__":
    # Test basic tools
    test_mcp_tool("ssh_ping")
    test_mcp_tool("ssh_list_hosts")
    test_mcp_tool("ssh_describe_host", {"alias": "web1"})
    test_mcp_tool("ssh_plan", {"alias": "web1", "command": "uptime"})
```

Run the test:

```bash
python test_mcp.py
```

## Configuration Testing

### Test Different Configurations

1. **Test with missing config files:**
   ```bash
   mkdir -p /tmp/empty-config
   MCP_SSH_CONFIG_DIR=/tmp/empty-config python -m mcp_ssh.mcp_server stdio
   ```

2. **Test with invalid YAML:**
   ```bash
   echo "invalid: yaml: content: [" > /tmp/bad-config/servers.yml
   MCP_SSH_CONFIG_DIR=/tmp/bad-config python -m mcp_ssh.mcp_server stdio
   ```

3. **Test with network restrictions:**
   ```bash
   # Edit policy.yml to add network restrictions
   # Test that connections are blocked appropriately
   ```

## Debugging

### Enable Debug Logging

Set environment variables for verbose output:

```bash
export PYTHONUNBUFFERED=1
export MCP_SSH_DEBUG=1
python -m mcp_ssh.mcp_server stdio
```

### Common Issues

1. **Import errors:**
   ```bash
   # Ensure package is installed in editable mode
   pip install -e .
   ```

2. **Configuration errors:**
   ```bash
   # Check YAML syntax
   python -c "import yaml; yaml.safe_load(open('config/servers.yml'))"
   ```

3. **SSH connection issues:**
   ```bash
   # Test SSH connection manually
   ssh -i ~/mcp-ssh-local/keys/id_ed25519 user@host
   ```

## Integration Testing

### Test with Claude Desktop

1. **Configure Claude Desktop** to use local development version:
   ```json
   {
     "mcpServers": {
       "ssh-orchestrator-dev": {
         "command": "python",
         "args": [
           "-m", "mcp_ssh.mcp_server", "stdio"
         ],
         "env": {
           "MCP_SSH_CONFIG_DIR": "/Users/YOUR_USERNAME/mcp-ssh-local/config"
         }
       }
     }
   }
   ```

2. **Test in Claude:**
   - "List my SSH hosts"
   - "Check uptime on web1"
   - "Run 'df -h' on all production servers"

### Test with Docker Compose

```bash
# Use the provided docker-compose.yml
cd compose
docker-compose up

# Test MCP connection
echo '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}}' | docker exec -i mcp-ssh-orchestrator python -m mcp_ssh.mcp_server stdio
```

## Performance Testing

### Load Testing

Create a load test script:

```python
#!/usr/bin/env python3
"""Load test MCP server."""

import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor

def test_concurrent_requests():
    """Test concurrent MCP requests."""
    def make_request():
        # Implementation for concurrent testing
        pass
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_request) for _ in range(100)]
        results = [f.result() for f in futures]
    
    print(f"Completed {len(results)} concurrent requests")

if __name__ == "__main__":
    test_concurrent_requests()
```

## Contributing

### Before Submitting

1. **Run all tests:**
   ```bash
   pytest
   ```

2. **Check code quality:**
   ```bash
   black src/ tests/
   ruff check src/ tests/
   mypy src/
   ```

3. **Test Docker build:**
   ```bash
   docker build -t mcp-ssh-orchestrator:test .
   ```

4. **Test with real SSH hosts:**
   - Configure real hosts in `servers.yml`
   - Test actual SSH connections
   - Verify policy enforcement

### Adding New Features

1. **Add new MCP tools** in `src/mcp_ssh/mcp_server.py`
2. **Update tests** in `tests/`
3. **Update documentation** in `README.md` and `docs/`
4. **Update examples** in `examples/`

## Troubleshooting

### Common Development Issues

1. **Module not found:**
   ```bash
   # Ensure you're in the virtual environment
   source .venv/bin/activate
   pip install -e .
   ```

2. **Permission denied on SSH keys:**
   ```bash
   chmod 0400 ~/mcp-ssh-local/keys/*
   ```

3. **Docker build fails:**
   ```bash
   # Check Docker is running
   docker info
   
   # Clean build
   docker build --no-cache -t mcp-ssh-orchestrator:test .
   ```

4. **MCP handshake fails:**
   - Ensure proper JSON-RPC format
   - Check that initialize is called before tools
   - Verify transport is stdio

For more help, see [CONTRIBUTING.md](CONTRIBUTING.md) or open an issue on GitHub.
