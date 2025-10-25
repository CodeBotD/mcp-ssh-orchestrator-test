# Policy Security Guide

This document provides security best practices, troubleshooting guidance, and incident response procedures for mcp-ssh-orchestrator policy configuration.

## Table of Contents

- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Security Checklists](#security-checklists)
- [Incident Response](#incident-response)
- [Common Issues](#common-issues)

## Security Best Practices

### Deny-by-Default Strategy

**Principle**: Start with no access and explicitly allow only what's needed.

```yaml
# Good: Explicit allow rules
rules:
  - action: "allow"
    aliases: ["prod-*"]
    tags: ["production"]
    commands:
      - "uptime*"
      - "df -h*"
      - "systemctl status *"

# Bad: Overly permissive
rules:
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "*"  # Allows everything
```

### Host Key Verification

**Critical**: Always enable host key verification in production.

```yaml
# Production configuration
limits:
  require_known_host: true
  host_key_auto_add: false

network:
  require_known_host: true

# Populate known_hosts file
known_hosts_path: "/app/keys/known_hosts"
```

**Setup known_hosts**:
```bash
# Scan host keys
ssh-keyscan -H 10.0.0.11 >> /app/keys/known_hosts
ssh-keyscan -H 10.0.0.21 >> /app/keys/known_hosts

# Or copy from existing
cp ~/.ssh/known_hosts /app/keys/
```

### Network Segmentation

**Principle**: Restrict SSH targets to known networks only.

```yaml
# Restrictive network policy
network:
  # Only allow private networks
  allow_cidrs:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
    - "172.16.0.0/12"
  
  # Block public internet and dangerous ranges
  block_cidrs:
    - "0.0.0.0/0"
    - "169.254.0.0/16"
    - "224.0.0.0/4"
    - "240.0.0.0/4"
  
  # Block specific problematic IPs
  block_ips:
    - "0.0.0.0"
    - "255.255.255.255"
```

### Dangerous Command Patterns

**Block these patterns by default**:

```yaml
deny_substrings:
  # Destructive filesystem operations
  - "rm -rf /"
  - "rm -rf /*"
  - "mkfs "
  - "dd if=/dev/zero"
  
  # System control
  - "shutdown*"
  - "reboot*"
  - "halt*"
  - "poweroff*"
  - "init 0"
  - "init 6"
  
  # User management
  - "userdel "
  - "passwd "
  - "usermod "
  - "groupdel "
  
  # Lateral movement
  - "ssh "
  - "scp "
  - "rsync -e ssh"
  - "curl "
  - "wget "
  - "nc "
  - "nmap "
  - "telnet "
  
  # Cloud/container tools
  - "kubectl "
  - "k3s "
  - "helm "
  - "aws "
  - "gcloud "
  - "az "
  - "docker run"
  - "docker exec"
  
  # Fork bombs and DoS
  - ":(){ :|:& };:"
  - "while true; do :; done"
```

### Production vs Non-Production Separation

**Use tags and aliases to separate environments**:

```yaml
rules:
  # Production - minimal access
  - action: "allow"
    aliases: ["prod-*"]
    tags: ["production"]
    commands:
      - "uptime*"
      - "df -h*"
      - "systemctl status *"
      - "journalctl --no-pager -n 20 *"

  # Staging - moderate access
  - action: "allow"
    aliases: ["stg-*"]
    tags: ["staging"]
    commands:
      - "systemctl restart *"
      - "docker ps*"
      - "kubectl get *"

  # Development - permissive access
  - action: "allow"
    aliases: ["dev-*"]
    tags: ["development"]
    commands:
      - "systemctl *"
      - "docker *"
      - "kubectl *"
      - "ping*"
      - "traceroute*"
```

### Least Privilege Access

**Grant minimum necessary permissions**:

```yaml
# Good: Specific commands
rules:
  - action: "allow"
    aliases: ["web-*"]
    tags: ["web"]
    commands:
      - "systemctl status nginx"
      - "systemctl status apache2"
      - "nginx -t"
      - "apache2ctl status"

# Bad: Overly broad
rules:
  - action: "allow"
    aliases: ["web-*"]
    tags: ["web"]
    commands:
      - "systemctl *"  # Allows all systemctl commands
```

### Audit Logging

**Monitor all policy decisions and executions**:

```yaml
# Enable comprehensive logging
limits:
  require_known_host: true  # Logs host key verification

# All operations are logged to stderr as JSON:
# - policy_decision: Command allow/deny decisions
# - audit: Command execution results
# - progress: Long-running command progress
```

**Log Analysis**:
```bash
# Monitor policy denials
docker logs mcp-ssh-orchestrator 2>&1 | jq -r 'select(.type == "policy_decision" and .allowed == false)'

# Monitor command executions
docker logs mcp-ssh-orchestrator 2>&1 | jq -r 'select(.type == "audit")'

# Monitor specific host
docker logs mcp-ssh-orchestrator 2>&1 | jq -r 'select(.alias == "prod-web-1")'
```

## Troubleshooting

### Common Policy Denial Reasons

1. **No matching rule**: Command doesn't match any allow rule
2. **Deny substring match**: Command contains blocked substring
3. **Network policy violation**: Target IP not in allowlist
4. **Host key verification failed**: Host not in known_hosts
5. **Rule evaluation order**: Deny rule matched before allow rule

### Debugging Policy Decisions

**Use the `ssh_plan` tool**:
```bash
# Test command without execution
ssh_plan --alias prod-web-1 --command "systemctl status nginx"
```

**Check logs for policy decisions**:
```bash
# View policy decision logs
docker logs mcp-ssh-orchestrator 2>&1 | jq -r 'select(.type == "policy_decision")'
```

### Network Policy Issues

**Common problems**:
- DNS resolution fails
- IP not in allowlist
- CIDR notation errors
- Block rules too restrictive

**Debugging**:
```bash
# Test DNS resolution
nslookup target-host.example.com

# Check IP ranges
ipcalc 10.0.0.0/8

# Test network policy
ssh_plan --alias target-host --command "uptime"
```

### Rule Matching Problems

**Check pattern matching**:
```yaml
# Test patterns
aliases: ["prod-*"]     # Matches: prod-web-1, prod-db-1
aliases: ["*prod*"]     # Matches: prod-web-1, staging-prod-1
aliases: ["prod-?"]     # Matches: prod-1, prod-a (single char)
```

**Common issues**:
- Case sensitivity
- Special characters in patterns
- Empty arrays vs missing fields
- Rule order matters

### Override Conflicts

**Precedence order**:
1. Alias overrides (highest)
2. Tag overrides
3. Global limits
4. Default values (lowest)

**Debugging**:
```yaml
# Check effective limits
overrides:
  aliases:
    prod-web-1:
      max_seconds: 30  # This overrides tag settings
  tags:
    production:
      max_seconds: 60  # This is overridden by alias
```

### Performance Considerations

**Optimize for performance**:
- Use specific patterns instead of `*`
- Order rules by frequency (most common first)
- Limit output size caps
- Use appropriate timeouts

```yaml
# Good: Specific patterns
commands:
  - "systemctl status nginx"
  - "systemctl status apache2"

# Bad: Overly broad
commands:
  - "systemctl *"
```

## Security Checklists

### Pre-Production Deployment

- [ ] `require_known_host: true` enabled
- [ ] Known_hosts file populated
- [ ] Network allowlists configured
- [ ] Deny substrings enabled
- [ ] Production-specific deny rules
- [ ] Audit logging enabled
- [ ] Read-only mounts configured
- [ ] Non-root container user
- [ ] Timeout limits appropriate
- [ ] Output size caps set

### Regular Security Audit

**Monthly**:
- [ ] Review policy denials
- [ ] Check for new dangerous patterns
- [ ] Verify network restrictions
- [ ] Update deny_substrings if needed
- [ ] Review host key changes

**Quarterly**:
- [ ] Rotate SSH keys
- [ ] Review and update policies
- [ ] Test policy effectiveness
- [ ] Update documentation
- [ ] Security training for operators

### Incident Response Checklist

**Policy Bypass Detected**:
1. [ ] Stop orchestrator immediately
2. [ ] Review audit logs for pattern
3. [ ] Identify bypass technique
4. [ ] Update deny_substrings
5. [ ] Test updated policy
6. [ ] Restart orchestrator
7. [ ] Monitor for recurrence

**Unauthorized Access**:
1. [ ] Check audit logs for access pattern
2. [ ] Identify compromised credentials
3. [ ] Revoke affected SSH keys
4. [ ] Rotate all credentials
5. [ ] Review policy gaps
6. [ ] Update security controls

## Common Issues

### "Denied by policy" Errors

**Causes**:
- No matching allow rule
- Command contains deny substring
- Network policy violation

**Solutions**:
- Add specific allow rule
- Remove substring from deny list
- Update network allowlist
- Use `ssh_plan` to debug

### "Denied by network policy" Errors

**Causes**:
- IP not in allowlist
- DNS resolution failed
- Block rule matched

**Solutions**:
- Add IP to allow_cidrs
- Fix DNS resolution
- Remove from block list
- Check CIDR notation

### "Host not found in known_hosts" Errors

**Causes**:
- Host key not in known_hosts
- Wrong known_hosts path
- Host key changed

**Solutions**:
- Add host key to known_hosts
- Update known_hosts_path
- Verify host key fingerprint
- Use `ssh-keyscan` to add

### Performance Issues

**Causes**:
- Too many rules
- Broad patterns
- Large output caps
- Long timeouts

**Solutions**:
- Optimize rule order
- Use specific patterns
- Reduce output limits
- Set appropriate timeouts

## Related Documentation

- [Policy Reference](POLICY_REFERENCE.md) - Complete configuration reference
- [Policy Examples](POLICY_EXAMPLES.md) - Practical configuration examples
- [Main README](../README.md) - General project documentation
- [Security Guide](SECURITY.md) - General security guidelines
- [Contributing Guide](CONTRIBUTING.md) - Development and contribution guidelines
