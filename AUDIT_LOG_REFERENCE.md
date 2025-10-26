# Audit Log Reference

This document shows exactly what logs are written to **stderr** in the Docker container.

## Summary

All audit logs use **structured JSON** and are written to `stderr`. The MCP protocol (JSON-RPC 2.0) uses `stdout` for tool responses.

## Log Types

### 1. Policy Decision Log

**When:** Before every command execution (to determine if command is allowed)

```json
{
  "type": "policy_decision",
  "ts": 1761489054.1433952,
  "alias": "web1",
  "hash": "7063dece7ccc",
  "allowed": true
}
```

**Fields:**
- `type`: Always `"policy_decision"`
- `ts`: Unix timestamp (float)
- `alias`: Host alias from servers.yml
- `hash`: SHA256 hash of the command
- `allowed`: Boolean - true if allowed, false if denied

---

### 2. Audit Log

**When:** After command execution completes (success or failure)

```json
{
  "type": "audit",
  "ts": 1761489054.143448,
  "alias": "web1",
  "hash": "7063dece7ccc",
  "exit_code": 0,
  "duration_ms": 150,
  "bytes_out": 25,
  "bytes_err": 0,
  "cancelled": false,
  "timeout": false,
  "target_ip": "10.0.0.11"
}
```

**Fields:**
- `type`: Always `"audit"`
- `ts`: Unix timestamp (float)
- `alias`: Host alias from servers.yml
- `hash`: SHA256 hash of the command
- `exit_code`: Process exit code (0-255)
- `duration_ms`: Execution time in milliseconds
- `bytes_out`: Bytes of stdout output captured
- `bytes_err`: Bytes of stderr output captured
- `cancelled`: Boolean - was the task cancelled?
- `timeout`: Boolean - did the task hit the timeout?
- `target_ip`: Actual IP address of the SSH server connected to

---

### 3. Progress Log

**When:** During command execution (every 0.5 seconds while output is being read)

```json
{
  "type": "progress",
  "ts": 1761489054.143455,
  "task_id": "task_abc123",
  "phase": "connecting",
  "bytes_read": 0,
  "elapsed_ms": 50
}
```

**Fields:**
- `type`: Always `"progress"`
- `ts`: Unix timestamp (float)
- `task_id`: Unique task identifier
- `phase`: Execution phase:
  - `"connecting"`: Establishing SSH connection
  - `"connected"`: SSH connection established
  - `"running"`: Command executing (logged every 0.5s)
- `bytes_read`: Total bytes read so far (stdout + stderr)
- `elapsed_ms`: Elapsed time since start (milliseconds)

---

### 4. Error/Trace Logs

**When:** Exceptions or trace events occur

```json
{
  "level": "error",
  "msg": "run_exception",
  "error": "Connection failed"
}
```

```json
{
  "type": "trace",
  "op": "run_done",
  "elapsed_ms": 123
}
```

**Fields:**
- `level`: "error" | "warn"
- `msg`: Error message identifier
- `error`: Error details
- `type`: "trace"
- `op`: Operation name
- `elapsed_ms`: Elapsed time (milliseconds)

---

## Real Example Sequence

Here's what gets logged for a simple `hostname` command on a Proxmox host:

```json
{"type": "policy_decision", "ts": 1761489054.1433952, "alias": "Proxmox Prod 01", "hash": "abc123", "allowed": true}
{"type": "progress", "ts": 1761489054.2000000, "task_id": "task_xyz", "phase": "connecting", "bytes_read": 0, "elapsed_ms": 50}
{"type": "progress", "ts": 1761489054.4500000, "task_id": "task_xyz", "phase": "connected", "bytes_read": 0, "elapsed_ms": 250}
{"type": "progress", "ts": 1761489054.7000000, "task_id": "task_xyz", "phase": "running", "bytes_read": 0, "elapsed_ms": 500}
{"type": "audit", "ts": 1761489054.6500000, "alias": "Proxmox Prod 01", "hash": "abc123", "exit_code": 0, "duration_ms": 650, "bytes_out": 25, "bytes_err": 0, "cancelled": false, "timeout": false, "target_ip": "10.0.0.50"}
{"type": "trace", "op": "run_done", "elapsed_ms": 700}
```

---

## Capturing Logs

### Docker

```bash
# View all logs (stdout + stderr mixed)
docker logs mcp-ssh-container

# Follow logs
docker logs -f mcp-ssh-container

# View only last 100 lines
docker logs --tail 100 mcp-ssh-container

# Extract only JSON logs
docker logs mcp-ssh-container 2>&1 | grep '^{' | jq '.'
```

### Docker Compose

```bash
docker-compose logs -f mcp-ssh
```

### Parse and Analyze

```bash
# Count policy violations
docker logs mcp-ssh-container 2>&1 | jq 'select(.type == "policy_decision" and .allowed == false) | .alias' | sort | uniq -c

# Show all audit entries for a specific host
docker logs mcp-ssh-container 2>&1 | jq 'select(.type == "audit" and .alias == "Proxmox Prod 01")'

# Calculate average execution time
docker logs mcp-ssh-container 2>&1 | jq 'select(.type == "audit") | .duration_ms' | awk '{sum+=$1; count++} END {print sum/count}'
```

---

## Important Notes

1. **All logs go to stderr** - This is intentional to separate audit logs from MCP protocol responses
2. **JSON Lines format** - Each log is a single JSON object on one line
3. **Timestamps are Unix floats** - `ts` field is seconds since epoch with microsecond precision
4. **Command hashes** - Commands are hashed (SHA256) for privacy and consistency
5. **Progress logs are emitted every 0.5 seconds** during long-running commands

---

## Security Implications

- Audit logs contain **host aliases** and **command hashes** (not full commands)
- IP addresses are logged for network compliance
- No sensitive command output is in audit logs (output goes to stdout for the LLM)
- Logs are append-only (written to stderr stream)
