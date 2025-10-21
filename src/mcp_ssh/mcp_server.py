import sys
import json
import time
from mcp.server.fastmcp import FastMCP
from mcp_ssh.config import Config
from mcp_ssh.policy import Policy
from mcp_ssh.ssh_client import SSHClient
from mcp_ssh.tools.utilities import hash_command, TASKS, log_json


mcp = FastMCP()
config = Config()


def _client_for(alias: str, limits: dict, require_known_host: bool) -> SSHClient:
    """Build SSH client from config and limits."""
    host = config.get_host(alias)
    creds_ref = host.get("credentials", "")
    creds = config.get_credentials(creds_ref) if creds_ref else {}
    known_hosts_path = (config.get_policy() or {}).get("known_hosts_path", "")
    auto_add = bool(limits.get("host_key_auto_add", False))
    
    # Input validation
    hostname = host.get("host", "").strip()
    if not hostname:
        raise ValueError(f"Host '{alias}' has no hostname configured")
    
    username = creds.get("username", "").strip()
    if not username:
        if creds_ref:
            raise ValueError(f"Host '{alias}' references credentials '{creds_ref}' but no username found")
        else:
            raise ValueError(f"Host '{alias}' has no credentials reference and no username configured")
    
    port = host.get("port", 22)
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port {port} for host '{alias}'")
    except (ValueError, TypeError):
        raise ValueError(f"Invalid port '{port}' for host '{alias}'")
    
    # Validate authentication method
    key_path = creds.get("key_path", "").strip()
    password = creds.get("password", "").strip()
    
    if not key_path and not password:
        raise ValueError(f"Host '{alias}' has no authentication method configured (neither key_path nor password)")
    
    return SSHClient(
        host=hostname,
        username=username,
        port=port,
        key_path=creds.get("key_path", ""),
        password=creds.get("password", ""),
        passphrase=creds.get("passphrase", ""),
        known_hosts_path=known_hosts_path,
        auto_add_host_keys=auto_add,
        require_known_host=require_known_host,
    )


def _precheck_network(pol: Policy, hostname: str) -> tuple[bool, str]:
    """Resolve hostname and verify at least one resolved IP is allowed."""
    ips = SSHClient.resolve_ips(hostname)
    if not ips:
        # No resolution: fail closed to be safe.
        return False, "DNS resolution failed"
    for ip in ips:
        if pol.is_ip_allowed(ip):
            return True, ""
    return False, "No resolved IPs allowed by policy.network"


@mcp.tool()
def ssh_ping() -> str:
    """Health check."""
    return "pong"


@mcp.tool()
def ssh_list_hosts() -> str:
    """List configured hosts."""
    try:
        hosts = config.list_hosts()
        return json.dumps(hosts)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def ssh_describe_host(alias: str = "") -> str:
    """Return host definition in JSON."""
    try:
        host = config.get_host(alias)
        return json.dumps(host, indent=2)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def ssh_plan(alias: str = "", command: str = "") -> str:
    """Show what would be executed and if policy allows."""
    try:
        cmd_hash = hash_command(command)
        tags = config.get_host_tags(alias)
        pol = Policy(config.get_policy())
        allowed = pol.is_allowed(alias, tags, command)
        limits = pol.limits_for(alias, tags)
        preview = {
            "alias": alias,
            "command": command,
            "hash": cmd_hash,
            "allowed": allowed,
            "limits": {
                "max_seconds": limits.get("max_seconds", 60),
                "max_output_bytes": limits.get("max_output_bytes", 1024 * 1024),
                "host_key_auto_add": bool(limits.get("host_key_auto_add", False)),
                "require_known_host": bool(limits.get("require_known_host", True)),
            },
        }
        return json.dumps(preview, indent=2)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def ssh_run(alias: str = "", command: str = "") -> str:
    """Execute SSH command with policy, network checks, progress, timeout, and cancellation."""
    start = time.time()
    try:
        # Input validation
        if not alias.strip():
            return "Error: alias is required"
        if not command.strip():
            return "Error: command is required"
        
        # Basic command validation
        command = command.strip()
        if len(command) > 10000:  # Reasonable limit
            return "Error: command too long (max 10000 characters)"
        host = config.get_host(alias)
        hostname = host.get("host", "")
        cmd_hash = hash_command(command)
        tags = config.get_host_tags(alias)
        pol = Policy(config.get_policy())

        # Command policy
        allowed = pol.is_allowed(alias, tags, command)
        pol.log_decision(alias, cmd_hash, allowed)
        if not allowed:
            return f"Denied by policy: {command}"

        # Network precheck (DNS -> allowlist)
        ok, reason = _precheck_network(pol, hostname)
        if not ok:
            return f"Denied by network policy: {reason}"

        limits = pol.limits_for(alias, tags)
        max_seconds = int(limits.get("max_seconds", 60))
        max_output_bytes = int(limits.get("max_output_bytes", 1024 * 1024))
        require_known_host = bool(limits.get("require_known_host", pol.require_known_host()))

        task_id = TASKS.create(alias, cmd_hash)

        def progress_cb(phase, bytes_read, elapsed_ms):
            pol.log_progress(task_id, phase, int(bytes_read), int(elapsed_ms))

        client = _client_for(alias, limits, require_known_host)
        cancel_event = TASKS.get_event(task_id)
        exit_code, duration_ms, cancelled, timeout, bytes_out, bytes_err, combined, peer_ip = client.run_streaming(
            command=command,
            cancel_event=cancel_event,
            max_seconds=max_seconds,
            max_output_bytes=max_output_bytes,
            progress_cb=progress_cb,
        )
        TASKS.cleanup(task_id)

        # Post-connect enforcement: ensure actual peer IP is allowed
        if peer_ip and not pol.is_ip_allowed(peer_ip):
            pol.log_audit(
                alias, cmd_hash, int(exit_code), int(duration_ms),
                int(bytes_out), int(bytes_err), bool(cancelled), bool(timeout), peer_ip
            )
            return f"Denied by network policy: peer IP {peer_ip} not allowed"

        pol.log_audit(
            alias, cmd_hash, int(exit_code), int(duration_ms),
            int(bytes_out), int(bytes_err), bool(cancelled), bool(timeout), peer_ip
        )
        result = {
            "task_id": task_id,
            "alias": alias,
            "hash": cmd_hash,
            "exit_code": int(exit_code),
            "duration_ms": int(duration_ms),
            "cancelled": bool(cancelled),
            "timeout": bool(timeout),
            "target_ip": peer_ip,
            "output": combined,
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        log_json({"level": "error", "msg": "run_exception", "error": str(e)})
        return f"Run error: {e}"
    finally:
        elapsed = int((time.time() - start) * 1000)
        log_json({"type": "trace", "op": "run_done", "elapsed_ms": elapsed})


@mcp.tool()
def ssh_run_on_tag(tag: str = "", command: str = "") -> str:
    """Execute SSH command on all hosts with a tag (with network checks)."""
    try:
        # Input validation
        if not tag.strip():
            return "Error: tag is required"
        if not command.strip():
            return "Error: command is required"
        
        # Basic command validation
        command = command.strip()
        if len(command) > 10000:  # Reasonable limit
            return "Error: command too long (max 10000 characters)"
        aliases = config.find_hosts_by_tag(tag)
        if not aliases:
            return json.dumps({"tag": tag, "results": [], "note": "No hosts matched."}, indent=2)

        results = []
        for alias in aliases:
            host = config.get_host(alias)
            hostname = host.get("host", "")
            cmd_hash = hash_command(command)
            tags = config.get_host_tags(alias)
            pol = Policy(config.get_policy())

            # Command policy
            allowed = pol.is_allowed(alias, tags, command)
            pol.log_decision(alias, cmd_hash, allowed)
            if not allowed:
                results.append({"alias": alias, "hash": cmd_hash, "denied": True, "reason": "policy"})
                continue

            # Network precheck
            ok, reason = _precheck_network(pol, hostname)
            if not ok:
                results.append({"alias": alias, "hash": cmd_hash, "denied": True, "reason": f"network: {reason}"})
                continue

            limits = pol.limits_for(alias, tags)
            max_seconds = int(limits.get("max_seconds", 60))
            max_output_bytes = int(limits.get("max_output_bytes", 1024 * 1024))
            require_known_host = bool(limits.get("require_known_host", pol.require_known_host()))

            task_id = TASKS.create(alias, cmd_hash)

            def progress_cb(phase, bytes_read, elapsed_ms):
                pol.log_progress(task_id, phase, int(bytes_read), int(elapsed_ms))

            client = _client_for(alias, limits, require_known_host)
            cancel_event = TASKS.get_event(task_id)
            exit_code, duration_ms, cancelled, timeout, bytes_out, bytes_err, combined, peer_ip = client.run_streaming(
                command=command,
                cancel_event=cancel_event,
                max_seconds=max_seconds,
                max_output_bytes=max_output_bytes,
                progress_cb=progress_cb,
            )
            TASKS.cleanup(task_id)

            # Post-connect enforcement
            if peer_ip and not pol.is_ip_allowed(peer_ip):
                pol.log_audit(
                    alias, cmd_hash, int(exit_code), int(duration_ms),
                    int(bytes_out), int(bytes_err), bool(cancelled), bool(timeout), peer_ip
                )
                results.append({
                    "alias": alias, "task_id": task_id, "hash": cmd_hash,
                    "denied": True, "reason": f"network: peer {peer_ip} not allowed"
                })
                continue

            pol.log_audit(
                alias, cmd_hash, int(exit_code), int(duration_ms),
                int(bytes_out), int(bytes_err), bool(cancelled), bool(timeout), peer_ip
            )
            results.append({
                "alias": alias,
                "task_id": task_id,
                "hash": cmd_hash,
                "exit_code": int(exit_code),
                "duration_ms": int(duration_ms),
                "cancelled": bool(cancelled),
                "timeout": bool(timeout),
                "target_ip": peer_ip,
                "output": combined,
            })

        return json.dumps({"tag": tag, "results": results}, indent=2)
    except Exception as e:
        return f"Run on tag error: {e}"


@mcp.tool()
def ssh_cancel(task_id: str = "") -> str:
    """Request cancellation for a running task."""
    try:
        if not task_id:
            return "Error: task_id is required."
        ok = TASKS.cancel(task_id)
        if ok:
            return f"Cancellation signaled for task_id: {task_id}"
        return f"Task not found: {task_id}"
    except Exception as e:
        return f"Cancel error: {e}"


@mcp.tool()
def ssh_reload_config() -> str:
    """Reload configuration files."""
    try:
        config.reload()
        return "Configuration reloaded."
    except Exception as e:
        return f"Reload error: {e}"


def main():
    """Main entry point for MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()