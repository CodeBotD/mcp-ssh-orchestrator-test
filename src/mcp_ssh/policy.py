import fnmatch
import ipaddress
import json
import sys
import time


def _match_any(value: str, patterns) -> bool:
    """Return True if value matches any glob pattern."""
    if not isinstance(patterns, list):
        return False
    for p in patterns:
        try:
            if fnmatch.fnmatch(value, str(p)):
                return True
        except Exception:
            continue
    return False


class Policy:
    """Policy engine for allow/deny with limits and network controls."""

    def __init__(self, config: dict):
        self.config = config or {}
        # Command/exec defaults (safe but overridable via policy.yml)
        self.default_limits = {
            "max_seconds": 60,
            "max_output_bytes": 1024 * 1024,
            "host_key_auto_add": False,
            "require_known_host": True,  # new: fail if no known_hosts entry when strict
            "task_result_ttl": 300,  # 5 minutes default (SEP-1686 keepAlive)
            "task_progress_interval": 5,  # 5 seconds default
            # Expanded egress hardening defaults (can be overridden in policy.yml)
            "deny_substrings": [
                "rm -rf /",
                ":(){ :|:& };:",
                "mkfs ",
                "dd if=/dev/zero",
                "shutdown -h",
                "reboot",
                "userdel ",
                "passwd ",
                # Egress / lateral movement helpers
                "ssh ",
                "scp ",
                "rsync -e ssh",
                "curl ",
                "wget ",
                "nc ",
                "nmap ",
                "telnet ",
                "kubectl ",
                "aws ",
                "gcloud ",
                "az ",
            ],
        }

    # ----------------------------
    # Limits / Allow-Deny (commands)
    # ----------------------------
    def _collect_limits(self, alias: str, tags):
        """Resolve limits for alias and tags."""
        limits = dict(self.default_limits)
        pol = self.config or {}
        gl = pol.get("limits", {})
        for k, v in gl.items():
            limits[k] = v
        overrides = pol.get("overrides", {})
        alias_over = overrides.get("aliases", {}).get(alias, {})
        for k, v in alias_over.items():
            limits[k] = v
        if isinstance(tags, list):
            tag_over = overrides.get("tags", {})
            for t in tags:
                tv = tag_over.get(t, {})
                for k, v in tv.items():
                    # Tag overrides should only apply if not already set by alias
                    if k not in alias_over:
                        limits[k] = v
        return limits

    def limits_for(self, alias: str, tags):
        """Return effective limits for alias."""
        return self._collect_limits(alias, tags)

    def is_allowed(self, alias: str, tags, command: str) -> bool:
        """Return True if command is allowed by rules + deny substrings."""
        pol = self.config or {}
        deny_substrings = self._collect_limits(alias, tags).get("deny_substrings", [])
        if isinstance(deny_substrings, list):
            for s in deny_substrings:
                if s and s in command:
                    return False

        rules = pol.get("rules", [])
        matched = None
        for rule in rules:
            action = rule.get("action", "deny")
            aliases = rule.get("aliases", [])
            tag_patterns = rule.get("tags", [])
            cmd_patterns = rule.get("commands", [])
            alias_ok = _match_any(alias, aliases) if aliases else True
            tags_ok = True
            if isinstance(tag_patterns, list) and len(tag_patterns) > 0:
                tags_ok = False
                if isinstance(tags, list):
                    for t in tags:
                        if _match_any(t, tag_patterns):
                            tags_ok = True
                            break
            cmd_ok = _match_any(command, cmd_patterns) if cmd_patterns else False
            if alias_ok and tags_ok and cmd_ok:
                matched = action

        if matched is None:
            return False
        return matched == "allow"

    # ----------------------------
    # Network policy (IP/CIDR)
    # ----------------------------
    def _cidrs(self, items):
        nets = []
        if not isinstance(items, list):
            return nets
        for x in items:
            try:
                nets.append(ipaddress.ip_network(str(x), strict=False))
            except Exception:
                continue
        return nets

    def _ips(self, items):
        ips = set()
        if not isinstance(items, list):
            return ips
        for x in items:
            try:
                ips.add(str(ipaddress.ip_address(str(x))))
            except Exception:
                continue
        return ips

    def _network_cfg(self):
        return self.config.get("network", {}) or {}

    def is_ip_allowed(self, ip_str: str) -> bool:
        """Return True if peer IP passes allow/block lists."""
        cfg = self._network_cfg()
        # Hard blocks first
        block_ips = self._ips(cfg.get("block_ips", []))
        if ip_str in block_ips:
            return False
        block_cidrs = self._cidrs(cfg.get("block_cidrs", []))
        try:
            ipobj = ipaddress.ip_address(ip_str)
            for net in block_cidrs:
                if ipobj in net:
                    return False
        except Exception:
            # If it isn't a valid IP, fail closed
            return False

        # If allow lists are present, require membership
        allow_ips = self._ips(cfg.get("allow_ips", []))
        allow_cidrs = self._cidrs(cfg.get("allow_cidrs", []))
        if allow_ips or allow_cidrs:
            if ip_str in allow_ips:
                return True
            for net in allow_cidrs:
                if ipobj in net:
                    return True
            return False

        # No allow lists configured => allow (but blocks already applied)
        return True

    def require_known_host(self) -> bool:
        """Whether a known_hosts entry is required for connection."""
        cfg = self._network_cfg()
        # network.require_known_host overrides limits.require_known_host if set
        if "require_known_host" in cfg:
            return bool(cfg.get("require_known_host"))
        # fallback to limits default
        return True

    # ----------------------------
    # Logging helpers
    # ----------------------------
    def log_decision(self, alias: str, command_hash: str, allowed: bool):
        """Log policy decision."""
        entry = {
            "type": "policy_decision",
            "ts": time.time(),
            "alias": alias,
            "hash": command_hash,
            "allowed": allowed,
        }
        print(json.dumps(entry), file=sys.stderr)

    def log_audit(
        self,
        alias: str,
        command_hash: str,
        exit_code: int,
        duration_ms: int,
        bytes_out: int,
        bytes_err: int,
        cancelled: bool,
        timeout: bool,
        target_ip: str,
    ):
        """Log execution audit JSON."""
        entry = {
            "type": "audit",
            "ts": time.time(),
            "alias": alias,
            "hash": command_hash,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "bytes_out": bytes_out,
            "bytes_err": bytes_err,
            "cancelled": cancelled,
            "timeout": timeout,
            "target_ip": target_ip,
        }
        print(json.dumps(entry), file=sys.stderr)

    def log_progress(self, task_id: str, phase: str, bytes_read: int, elapsed_ms: int):
        """Log progress JSON."""
        entry = {
            "type": "progress",
            "ts": time.time(),
            "task_id": task_id,
            "phase": phase,
            "bytes_read": bytes_read,
            "elapsed_ms": elapsed_ms,
        }
        print(json.dumps(entry), file=sys.stderr)
