# Policy Configuration Examples

This document provides practical examples of policy configurations for different use cases and environments.

## Table of Contents

- [Basic Read-Only Policy](#basic-read-only-policy)
- [Production Environment Policy](#production-environment-policy)
- [Development/Staging Policy](#developmentstaging-policy)
- [Multi-Tier Policy](#multi-tier-policy)
- [Proxmox-Specific Policy](#proxmox-specific-policy)
- [Network-Restricted Policy](#network-restricted-policy)
- [Per-Host Custom Limits](#per-host-custom-limits)
- [Tag-Based Operations](#tag-based-operations)
- [Complex Deny Rules](#complex-deny-rules)
- [Maintenance Window Configuration](#maintenance-window-configuration)

## Basic Read-Only Policy

**Use Case**: Safe read-only access for monitoring and basic diagnostics.

```yaml
# Basic read-only policy
known_hosts_path: "/app/keys/known_hosts"

limits:
  max_seconds: 30
  max_output_bytes: 262144
  host_key_auto_add: false
  require_known_host: true

network:
  allow_cidrs:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
  require_known_host: true

rules:
  # Basic system information
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "uname*"
      - "uptime*"
      - "whoami"
      - "hostname*"
      - "date*"
      - "id*"

  # Disk and memory usage
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "df -h*"
      - "free -h*"
      - "lsblk*"

  # Process information
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "ps aux*"
      - "top -n 1*"

  # Service status (read-only)
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "systemctl status *"
      - "systemctl is-active *"
      - "systemctl is-enabled *"
```

## Production Environment Policy

**Use Case**: Strict security for production systems with minimal allowed commands.

```yaml
# Production environment policy
known_hosts_path: "/app/keys/known_hosts"

limits:
  max_seconds: 20
  max_output_bytes: 131072
  host_key_auto_add: false
  require_known_host: true
  deny_substrings:
    - "rm -rf /"
    - "shutdown*"
    - "reboot*"
    - "systemctl restart*"
    - "systemctl stop*"
    - "systemctl start*"
    - "apt *"
    - "yum *"
    - "docker run*"
    - "kubectl *"

network:
  allow_cidrs:
    - "10.0.0.0/8"
  block_cidrs:
    - "0.0.0.0/0"  # Block all public internet
  require_known_host: true

rules:
  # Minimal read-only commands for production
  - action: "allow"
    aliases: ["prod-*"]
    tags: ["production"]
    commands:
      - "uptime*"
      - "df -h*"
      - "systemctl status *"
      - "journalctl --no-pager -n 20 *"

  # Explicit deny for production
  - action: "deny"
    aliases: ["prod-*"]
    tags: ["production"]
    commands:
      - "systemctl restart*"
      - "systemctl stop*"
      - "systemctl start*"
      - "apt *"
      - "yum *"
      - "docker *"
      - "kubectl *"

overrides:
  aliases:
    prod-db-1:
      max_seconds: 10
      max_output_bytes: 65536
    prod-web-1:
      max_seconds: 15
      max_output_bytes: 131072
```

## Development/Staging Policy

**Use Case**: More permissive access for development and testing environments.

```yaml
# Development/staging policy
known_hosts_path: "/app/keys/known_hosts"

limits:
  max_seconds: 60
  max_output_bytes: 1048576
  host_key_auto_add: true
  require_known_host: false

network:
  allow_cidrs:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
    - "172.16.0.0/12"
  require_known_host: false

rules:
  # Read-only commands
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "uname*"
      - "uptime*"
      - "df -h*"
      - "ps aux*"
      - "systemctl status *"

  # Development-specific commands
  - action: "allow"
    aliases:
      - "dev-*"
      - "stg-*"
    tags:
      - "development"
      - "staging"
    commands:
      - "systemctl restart *"
      - "systemctl stop *"
      - "systemctl start *"
      - "docker ps*"
      - "docker logs *"
      - "kubectl get *"
      - "kubectl describe *"

  # Network diagnostics for dev/staging
  - action: "allow"
    aliases:
      - "dev-*"
      - "stg-*"
    tags:
      - "development"
      - "staging"
    commands:
      - "ping*"
      - "traceroute*"
      - "ss -tulpn*"
      - "netstat*"

overrides:
  tags:
    development:
      max_seconds: 120
      host_key_auto_add: true
      require_known_host: false
    staging:
      max_seconds: 90
      host_key_auto_add: true
      require_known_host: false
```

## Multi-Tier Policy

**Use Case**: Different security levels for different environment tiers.

```yaml
# Multi-tier policy
known_hosts_path: "/app/keys/known_hosts"

limits:
  max_seconds: 60
  max_output_bytes: 1048576
  host_key_auto_add: false
  require_known_host: true

network:
  allow_cidrs:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
  require_known_host: true

rules:
  # Common read-only commands for all tiers
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "uname*"
      - "uptime*"
      - "df -h*"
      - "systemctl status *"

  # Development tier - most permissive
  - action: "allow"
    aliases: ["dev-*"]
    tags: ["development"]
    commands:
      - "systemctl restart *"
      - "systemctl stop *"
      - "systemctl start *"
      - "docker *"
      - "kubectl *"
      - "ping*"
      - "traceroute*"

  # Staging tier - moderate permissions
  - action: "allow"
    aliases: ["stg-*"]
    tags: ["staging"]
    commands:
      - "systemctl restart *"
      - "docker ps*"
      - "docker logs *"
      - "kubectl get *"
      - "kubectl describe *"

  # Production tier - minimal permissions
  - action: "allow"
    aliases: ["prod-*"]
    tags: ["production"]
    commands:
      - "journalctl --no-pager -n 20 *"
      - "tail -n 10 /var/log/*"

  # Explicit denies for production
  - action: "deny"
    aliases: ["prod-*"]
    tags: ["production"]
    commands:
      - "systemctl restart*"
      - "systemctl stop*"
      - "systemctl start*"
      - "docker *"
      - "kubectl *"

overrides:
  tags:
    development:
      max_seconds: 120
      host_key_auto_add: true
      require_known_host: false
    staging:
      max_seconds: 90
      host_key_auto_add: true
      require_known_host: false
    production:
      max_seconds: 20
      max_output_bytes: 131072
      require_known_host: true
```

## Proxmox-Specific Policy

**Use Case**: Secure access to Proxmox VE hosts with read-only operations.

```yaml
# Proxmox-specific policy
known_hosts_path: "/app/keys/known_hosts"

limits:
  max_seconds: 30
  max_output_bytes: 524288
  host_key_auto_add: false
  require_known_host: true

network:
  allow_cidrs:
    - "10.0.0.0/8"
  require_known_host: true

rules:
  # Basic system commands
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "uname*"
      - "uptime*"
      - "df -h*"
      - "systemctl status *"

  # Proxmox read-only commands
  - action: "allow"
    aliases: ["Proxmox*"]
    tags: ["proxmox"]
    commands:
      - "pvesh get *"
      - "qm list"
      - "pct list"
      - "pveversion -v"
      - "systemctl status pve*"
      - "journalctl -u pve* --no-pager -n 20"
      - "cat /etc/pve/*"

  # Explicit deny for dangerous Proxmox operations
  - action: "deny"
    aliases: ["Proxmox*"]
    tags: ["proxmox"]
    commands:
      - "qm start *"
      - "qm stop *"
      - "qm shutdown *"
      - "qm destroy *"
      - "qm clone *"
      - "qm migrate *"
      - "pct start *"
      - "pct stop *"
      - "pct destroy *"
      - "pct clone *"
      - "pct migrate *"
      - "pveceph *"
      - "pvecm *"
      - "pve-ha-*"

overrides:
  aliases:
    "Proxmox Prod 01":
      max_seconds: 15
      max_output_bytes: 131072
    "Proxmox Prod 02":
      max_seconds: 15
      max_output_bytes: 131072
  tags:
    proxmox:
      max_seconds: 20
      max_output_bytes: 262144
      require_known_host: true
```

## Network-Restricted Policy

**Use Case**: Strict network segmentation with specific IP allowlists.

```yaml
# Network-restricted policy
known_hosts_path: "/app/keys/known_hosts"

limits:
  max_seconds: 30
  max_output_bytes: 262144
  host_key_auto_add: false
  require_known_host: true

network:
  # Only allow specific private networks
  allow_cidrs:
    - "10.0.0.0/8"
    - "192.168.1.0/24"
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
  require_known_host: true

rules:
  # Basic read-only commands
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "uname*"
      - "uptime*"
      - "df -h*"
      - "systemctl status *"
      - "ps aux*"

  # Network diagnostics (restricted to specific hosts)
  - action: "allow"
    aliases:
      - "monitor-*"
      - "net-*"
    tags:
      - "monitoring"
      - "network"
    commands:
      - "ss -tulpn*"
      - "netstat*"
      - "ip addr*"
      - "ip route*"
```

## Per-Host Custom Limits

**Use Case**: Different limits for different types of hosts based on their role.

```yaml
# Per-host custom limits
known_hosts_path: "/app/keys/known_hosts"

limits:
  max_seconds: 60
  max_output_bytes: 1048576
  host_key_auto_add: false
  require_known_host: true

network:
  allow_cidrs:
    - "10.0.0.0/8"
  require_known_host: true

rules:
  # Basic commands for all hosts
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "uname*"
      - "uptime*"
      - "df -h*"
      - "systemctl status *"

overrides:
  aliases:
    # Web servers - moderate limits
    web-1:
      max_seconds: 30
      max_output_bytes: 524288
    web-2:
      max_seconds: 30
      max_output_bytes: 524288
    
    # Database servers - strict limits
    db-1:
      max_seconds: 15
      max_output_bytes: 131072
    db-2:
      max_seconds: 15
      max_output_bytes: 131072
    
    # Monitoring servers - relaxed limits
    monitor-1:
      max_seconds: 120
      max_output_bytes: 2097152
    monitor-2:
      max_seconds: 120
      max_output_bytes: 2097152
    
    # Log servers - very relaxed limits
    log-1:
      max_seconds: 300
      max_output_bytes: 10485760
    log-2:
      max_seconds: 300
      max_output_bytes: 10485760
```

## Tag-Based Operations

**Use Case**: Using host tags for group-based policy management.

```yaml
# Tag-based operations policy
known_hosts_path: "/app/keys/known_hosts"

limits:
  max_seconds: 60
  max_output_bytes: 1048576
  host_key_auto_add: false
  require_known_host: true

network:
  allow_cidrs:
    - "10.0.0.0/8"
  require_known_host: true

rules:
  # Basic commands for all hosts
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "uname*"
      - "uptime*"
      - "df -h*"

  # Web tier specific commands
  - action: "allow"
    aliases: ["*"]
    tags: ["web"]
    commands:
      - "systemctl status nginx*"
      - "systemctl status apache2*"
      - "nginx -t*"
      - "apache2ctl status*"

  # Database tier specific commands
  - action: "allow"
    aliases: ["*"]
    tags: ["database"]
    commands:
      - "systemctl status mysql*"
      - "systemctl status postgresql*"
      - "mysqladmin status*"
      - "psql -c 'SELECT version()'"

  # Monitoring tier specific commands
  - action: "allow"
    aliases: ["*"]
    tags: ["monitoring"]
    commands:
      - "systemctl status prometheus*"
      - "systemctl status grafana*"
      - "systemctl status node_exporter*"
      - "curl -s localhost:9090/api/v1/status*"

  # Development tier - more permissive
  - action: "allow"
    aliases: ["*"]
    tags: ["development"]
    commands:
      - "systemctl restart *"
      - "systemctl stop *"
      - "systemctl start *"
      - "docker ps*"
      - "docker logs *"

overrides:
  tags:
    web:
      max_seconds: 30
      max_output_bytes: 524288
    database:
      max_seconds: 20
      max_output_bytes: 131072
    monitoring:
      max_seconds: 90
      max_output_bytes: 2097152
    development:
      max_seconds: 120
      host_key_auto_add: true
      require_known_host: false
```

## Complex Deny Rules

**Use Case**: Sophisticated command blocking with multiple patterns and conditions.

```yaml
# Complex deny rules policy
known_hosts_path: "/app/keys/known_hosts"

limits:
  max_seconds: 60
  max_output_bytes: 1048576
  host_key_auto_add: false
  require_known_host: true
  deny_substrings:
    - "rm -rf /"
    - ":(){ :|:& };:"
    - "mkfs "
    - "dd if=/dev/zero"
    - "shutdown*"
    - "reboot*"
    - "userdel "
    - "passwd "
    - "ssh "
    - "scp "
    - "curl "
    - "wget "

network:
  allow_cidrs:
    - "10.0.0.0/8"
  require_known_host: true

rules:
  # Basic read-only commands
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "uname*"
      - "uptime*"
      - "df -h*"
      - "systemctl status *"

  # Explicit denies for dangerous operations
  - action: "deny"
    aliases: ["*"]
    tags: []
    commands:
      - "rm *"
      - "chmod 777*"
      - "chown -R *"
      - "shutdown*"
      - "reboot*"
      - "halt*"
      - "poweroff*"
      - "init 0"
      - "init 6"
      - "wall *"
      - "write *"
      - "mesg *"

  # Production-specific denies
  - action: "deny"
    aliases: ["prod-*"]
    tags: ["production"]
    commands:
      - "systemctl restart*"
      - "systemctl stop*"
      - "systemctl start*"
      - "systemctl enable*"
      - "systemctl disable*"
      - "apt *"
      - "yum *"
      - "dnf *"
      - "zypper *"
      - "pkg *"
      - "docker run*"
      - "docker start*"
      - "docker stop*"
      - "docker restart*"
      - "kubectl *"
      - "k3s *"
      - "helm *"

  # Development allows some operations
  - action: "allow"
    aliases: ["dev-*"]
    tags: ["development"]
    commands:
      - "systemctl restart*"
      - "systemctl stop*"
      - "systemctl start*"
      - "docker ps*"
      - "docker logs*"
      - "kubectl get*"
      - "kubectl describe*"
```

## Maintenance Window Configuration

**Use Case**: Temporary relaxed permissions during maintenance windows.

```yaml
# Maintenance window configuration
known_hosts_path: "/app/keys/known_hosts"

limits:
  max_seconds: 60
  max_output_bytes: 1048576
  host_key_auto_add: false
  require_known_host: true

network:
  allow_cidrs:
    - "10.0.0.0/8"
  require_known_host: true

rules:
  # Basic read-only commands
  - action: "allow"
    aliases: ["*"]
    tags: []
    commands:
      - "uname*"
      - "uptime*"
      - "df -h*"
      - "systemctl status *"

  # Maintenance-specific commands (use with caution)
  - action: "allow"
    aliases: ["maintenance-*"]
    tags: ["maintenance"]
    commands:
      - "systemctl restart *"
      - "systemctl stop *"
      - "systemctl start *"
      - "systemctl enable *"
      - "systemctl disable *"
      - "apt update"
      - "apt upgrade"
      - "yum update"
      - "docker restart *"
      - "kubectl rollout restart *"

overrides:
  tags:
    maintenance:
      max_seconds: 300  # 5 minutes for maintenance operations
      max_output_bytes: 10485760  # 10 MB for verbose output
      host_key_auto_add: true  # Allow new hosts during maintenance
      require_known_host: false  # Relaxed host key requirements
```

## Related Documentation

- [Policy Reference](POLICY_REFERENCE.md) - Complete configuration reference
- [Policy Security](POLICY_SECURITY.md) - Security best practices and troubleshooting
- [Main README](../README.md) - General project documentation
- [Security Guide](SECURITY.md) - General security guidelines
- [Contributing Guide](CONTRIBUTING.md) - Development and contribution guidelines
