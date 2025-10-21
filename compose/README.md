# 🐳 MCP-SSH-ORCHESTRATOR — Compose Environment

This directory provides a **local development and test setup** for the  
[`mcp-ssh-orchestrator`](https://github.com/samerfarida/mcp-ssh-orchestrator)  
MCP (Model Context Protocol) server.  

It allows you to:
- Run the container **locally** using Docker Compose
- Mount configs, secrets, and SSH keys
- Test STDIO connectivity with **Claude Desktop** or **Docker MCP Toolkit**

---

## ⚙️ What's Included

| File | Purpose |
|------|----------|
| `docker-compose.yml` | Defines the MCP SSH service container |
| `.env.example` | Example environment variable configuration |
| `setup.sh` | Automated setup script for directories and configs |
| `README.md` | You're reading it! Usage guide and examples |

---

## 📦 Prerequisites

Before running the container:
1. Ensure **Docker** and **Docker Compose v2+** are installed.
2. Run the automated setup script:
   ```bash
   cd compose
   ./setup.sh
   ```
   This will:
   - Create required directories (`../config`, `../keys`, `../secrets`)
   - Copy example configuration files
   - Create `.env` from `.env.example`
3. Add your SSH private keys and password files under:
   - `../keys` — SSH key files (e.g., id_ed25519)
   - `../secrets` — password or passphrase files

## 🚀 Running the Server

1. Configure Environment (if not done by setup script)

The setup script already creates `.env` from `.env.example`, but you can modify it:
```bash
# Edit the .env file to tune settings
nano .env
```

You can tune concurrency or timeout:
```env
MCP_SSH_MAX_CONCURRENCY=10
MCP_SSH_TIMEOUT_SEC=60
```

2. Start MCP-SSH Locally

```bash
docker compose up --build
```
This:
	•	Builds (if needed) and starts the container
	•	Mounts ../config, ../keys, and ../secrets as read-only volumes
	•	Launches the MCP server in STDIO mode (ready for Claude / MCP clients)

You’ll see logs like:
```json
{"evt": "server_start", "tool": "mcp-ssh-orchestrator", "mode": "stdio"}
```

3. Test from Claude Desktop

Add this entry to your Claude Desktop config.json or claude_desktop_config.json:
```json
{
  "mcpServers": {
    "mcp-ssh-orchestrator": {
      "command": "docker",
      "args": [
        "compose",
        "-f",
        "/ABS/PATH/mcp-ssh-orchestrator/compose/docker-compose.yml",
        "run",
        "--rm",
        "mcp-ssh"
      ],
      "env": {
        "MCP_SSH_CONFIG_DIR": "/app/config",
        "PYTHONUNBUFFERED": "1",
        "MCP_SSH_MAX_CONCURRENCY": "5",
        "MCP_SSH_TIMEOUT_SEC": "45"
      }
    }
  }
}
```
>Replace /ABS/PATH/mcp-ssh-orchestrator/ with your actual directory path.

🧠 Useful Commands
Action
Command
Check container logs
docker compose logs -f
Rebuild image
docker compose build --no-cache
Stop everything
docker compose down -v
Clean old images
docker system prune -f

🏗️ Developer Notes
•	The server uses STDIO transport only.
•	Default config path: /app/config
•	Default entrypoint: python -m mcp_ssh.mcp_server stdio
•	Parallel SSH execution supports configurable concurrency limits.
•	Policy enforcement supports glob and regex patterns.
