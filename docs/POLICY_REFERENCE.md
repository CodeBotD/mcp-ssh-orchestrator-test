# Policy Configuration Reference

This document provides a comprehensive reference for the `policy.yml` configuration file used by mcp-ssh-orchestrator. The policy engine implements a **deny-by-default** security model where commands must explicitly match an "allow" rule to execute.

## Table of Contents

- [Overview](#overview)
- [Configuration Sections](#configuration-sections)
- [Root Level Settings](#root-level-settings)
- [Limits Section](#limits-section)
- [Network Section](#network-section)
- [Rules Section](#rules-section)
- [Overrides Section](#overrides-section)
- [Glob Pattern Matching](#glob-pattern-matching)
- [Rule Evaluation Order](#rule-evaluation-order)
- [Override Hierarchy](#override-hierarchy)
- [Default Values](#default-values)

## Overview

The policy engine provides multiple layers of security controls:

1. **Command Substring Blocking** - Hard blocks commands containing dangerous substrings
2. **Rule-based Allow/Deny** - Pattern-based command matching with glob support
3. **Network Controls** - IP/CIDR allowlists and blocklists
4. **Execution Limits** - Timeouts, output size caps, and host key requirements
5. **Per-host/Tag Overrides** - Granular control for specific hosts or host groups

## Configuration Sections

| Section | Purpose | Required |
|---------|---------|----------|
| `known_hosts_path` | Path to SSH known_hosts file | No |
| `limits` | Global execution limits and security settings | No |
| `network` | Network access controls and IP filtering | No |
| `rules` | Command allow/deny rules with pattern matching | No |
| `overrides` | Per-host and per-tag limit overrides | No |

## Root Level Settings

| Field | Type | Required | Default | Description | Example |
|-------|------|----------|---------|-------------|---------|
| `known_hosts_path` | string | No | None | Path to SSH known_hosts file for host key verification | `"/app/keys/known_hosts"` |

## Limits Section

The `limits` section defines global execution limits and security settings that apply to all hosts unless overridden.

| Field | Type | Required | Default | Description | Example |
|-------|------|----------|---------|-------------|---------|
| `max_seconds` | integer | No | 60 | Maximum command execution time in seconds | `30` |
| `max_output_bytes` | integer | No | 1048576 | Maximum combined stdout/stderr output size in bytes | `524288` |
| `host_key_auto_add` | boolean | No | false | Automatically add unknown host keys to known_hosts | `true` |
| `require_known_host` | boolean | No | true | Require host to exist in known_hosts before connection | `false` |
| `deny_substrings` | array | No | See below | List of substrings that will block any command containing them | `["rm -rf", "shutdown"]` |

### Default deny_substrings

The following dangerous command substrings are blocked by default:

```yaml
deny_substrings:
  # Destructive commands
  - "rm -rf /"
  - ":(){ :|:& };:"  # Fork bomb
  - "mkfs "
  - "dd if=/dev/zero"
  - "shutdown -h"
  - "reboot"
  - "userdel "
  - "passwd "
  # Lateral movement / egress tools
  - "ssh "
  - "scp "
  - "rsync -e ssh"
  - "curl "
  - "wget "
  - "nc "
  - "nmap "
  - "telnet "
  - "kubectl "
  - "aws "
  - "gcloud "
  - "az "
```

## Network Section

The `network` section controls which IP addresses and networks are allowed for SSH connections.

| Field | Type | Required | Default | Description | Example |
|-------|------|----------|---------|-------------|---------|
| `allow_ips` | array | No | `[]` | List of specific IP addresses to allow | `["10.0.0.1", "192.168.1.100"]` |
| `allow_cidrs` | array | No | `[]` | List of CIDR networks to allow | `["10.0.0.0/8", "192.168.0.0/16"]` |
| `block_ips` | array | No | `[]` | List of specific IP addresses to block | `["0.0.0.0", "255.255.255.255"]` |
| `block_cidrs` | array | No | `[]` | List of CIDR networks to block | `["169.254.0.0/16", "224.0.0.0/4"]` |
| `require_known_host` | boolean | No | true | Override for host key verification (overrides limits setting) | `false` |

### Network Policy Evaluation

1. **Block Check**: If IP is in `block_ips` or `block_cidrs`, deny connection
2. **Allow Check**: If `allow_ips` or `allow_cidrs` are configured, IP must be in one of them
3. **Default**: If no allow lists are configured, allow all (after block checks)

## Rules Section

The `rules` section defines command allow/deny rules using glob pattern matching.

| Field | Type | Required | Default | Description | Example |
|-------|------|----------|---------|-------------|---------|
| `action` | string | Yes | "deny" | Rule action: "allow" or "deny" | `"allow"` |
| `aliases` | array | No | `[]` | List of host aliases to match (glob patterns) | `["prod-*", "web1"]` |
| `tags` | array | No | `[]` | List of host tags to match (glob patterns) | `["production", "web"]` |
| `commands` | array | No | `[]` | List of command patterns to match (glob patterns) | `["uptime*", "df -h*"]` |

### Rule Matching Logic

A rule matches when **ALL** specified conditions are met:

- **aliases**: If specified, host alias must match at least one pattern
- **tags**: If specified, at least one host tag must match at least one pattern  
- **commands**: If specified, command must match at least one pattern

If any condition is empty (`[]`), it matches all values.

## Overrides Section

The `overrides` section allows per-host and per-tag customization of limits.

### Aliases Subsection

Override limits for specific host aliases.

| Field | Type | Required | Default | Description | Example |
|-------|------|----------|---------|-------------|---------|
| `{alias_name}` | object | No | N/A | Host alias name (exact match) | `"prod-web-1"` |
| `max_seconds` | integer | No | From limits | Override max execution time | `30` |
| `max_output_bytes` | integer | No | From limits | Override max output size | `524288` |
| `host_key_auto_add` | boolean | No | From limits | Override host key auto-add | `false` |
| `require_known_host` | boolean | No | From limits | Override host key requirement | `true` |
| `deny_substrings` | array | No | From limits | Override deny substrings list | `["rm -rf", "shutdown"]` |

### Tags Subsection

Override limits for hosts with specific tags.

| Field | Type | Required | Default | Description | Example |
|-------|------|----------|---------|-------------|---------|
| `{tag_name}` | object | No | N/A | Tag name (exact match) | `"production"` |
| `max_seconds` | integer | No | From limits | Override max execution time | `30` |
| `max_output_bytes` | integer | No | From limits | Override max output size | `524288` |
| `host_key_auto_add` | boolean | No | From limits | Override host key auto-add | `false` |
| `require_known_host` | boolean | No | From limits | Override host key requirement | `true` |
| `deny_substrings` | array | No | From limits | Override deny substrings list | `["rm -rf", "shutdown"]` |

## Glob Pattern Matching

The policy engine uses Python's `fnmatch` module for pattern matching, supporting:

| Pattern | Description | Matches | Doesn't Match |
|---------|-------------|---------|---------------|
| `*` | Matches any characters | `uptime`, `systemctl status` | None |
| `?` | Matches single character | `cat`, `cut` | `cat`, `cats` |
| `[seq]` | Matches any char in seq | `[abc]` matches `a`, `b`, `c` | `d`, `ab` |
| `[!seq]` | Matches any char not in seq | `[!abc]` matches `d`, `e` | `a`, `b`, `c` |

### Common Patterns

| Pattern | Purpose | Example Matches |
|---------|---------|-----------------|
| `*` | Match all commands | Any command |
| `uptime*` | Commands starting with "uptime" | `uptime`, `uptime -s` |
| `systemctl status *` | systemctl status with any service | `systemctl status nginx`, `systemctl status apache2` |
| `prod-*` | Hosts starting with "prod-" | `prod-web-1`, `prod-db-1` |
| `*prod*` | Hosts containing "prod" | `prod-web-1`, `staging-prod-1` |

## Rule Evaluation Order

1. **Deny Substrings Check**: Commands containing any substring in `deny_substrings` are blocked
2. **Rule Matching**: Rules are evaluated in order until a match is found
3. **Default Deny**: If no rule matches, command is denied

## Override Hierarchy

When multiple overrides apply, precedence is (highest to lowest):

1. **Alias Overrides** - Specific host alias settings
2. **Tag Overrides** - Host tag settings (only if not set by alias)
3. **Global Limits** - Settings in the `limits` section
4. **Default Values** - Hardcoded defaults in the policy engine

## Default Values

| Setting | Default Value | Description |
|---------|---------------|-------------|
| `max_seconds` | 60 | Maximum command execution time |
| `max_output_bytes` | 1048576 | Maximum output size (1 MiB) |
| `host_key_auto_add` | false | Don't auto-add host keys |
| `require_known_host` | true | Require known_hosts entry |
| `deny_substrings` | 14+ patterns | Dangerous command substrings |
| `allow_ips` | `[]` | No IP allowlist (allow all) |
| `allow_cidrs` | `[]` | No CIDR allowlist (allow all) |
| `block_ips` | `[]` | No IP blocklist |
| `block_cidrs` | `[]` | No CIDR blocklist |
| `known_hosts_path` | None | Use system default |

## Related Documentation

- [Policy Examples](POLICY_EXAMPLES.md) - Practical configuration examples
- [Policy Security](POLICY_SECURITY.md) - Security best practices and troubleshooting
- [Main README](../README.md) - General project documentation
- [Security Guide](SECURITY.md) - General security guidelines
- [Contributing Guide](CONTRIBUTING.md) - Development and contribution guidelines
