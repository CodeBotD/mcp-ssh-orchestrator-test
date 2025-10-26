# 11. Observability & Audit

**Purpose:** Comprehensive guide for monitoring, logging, and auditing mcp-ssh-orchestrator operations for security and compliance.

## Overview

mcp-ssh-orchestrator provides comprehensive observability through structured logging, metrics, and audit trails. This enables security monitoring, compliance reporting, and operational insights.

## Logging Architecture

### Log Levels and Categories

**Structured Logging:**
```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "component": "policy",
  "event": "command_allowed",
  "details": {
    "alias": "web1",
    "command": "uptime",
    "tags": ["production"],
    "rule": "allow_production_readonly",
    "execution_time_ms": 150
  }
}
```

**Log Categories:**
- **AUDIT**: All command executions and policy decisions
- **SECURITY**: Authentication failures, policy violations, suspicious activity
- **OPERATIONAL**: System health, configuration changes, performance metrics
- **ERROR**: Exceptions, failures, and error conditions

### Audit Logging

**Command Execution Audit:**
```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "event_type": "command_execution",
  "user": "claude-desktop",
  "session_id": "sess_123456789",
  "command": {
    "alias": "web1",
    "command": "uptime",
    "tags": ["production"],
    "policy_result": "allowed",
    "rule_applied": "allow_production_readonly"
  },
  "execution": {
    "start_time": "2024-01-15T10:30:45.123Z",
    "end_time": "2024-01-15T10:30:45.273Z",
    "duration_ms": 150,
    "exit_code": 0,
    "output_bytes": 1024,
    "error_bytes": 0
  },
  "network": {
    "source_ip": "192.168.1.100",
    "target_ip": "10.0.0.11",
    "host_key_verified": true
  }
}
```

**Policy Decision Audit:**
```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "event_type": "policy_decision",
  "decision": "denied",
  "reason": "command_not_allowed",
  "details": {
    "alias": "web1",
    "command": "rm -rf /",
    "tags": ["production"],
    "violated_rules": ["deny_destructive_commands"],
    "policy_version": "1.2.3"
  }
}
```

## Monitoring Setup

### Prometheus Metrics

**Key Metrics:**
```python
# Command execution metrics
ssh_commands_total = Counter('ssh_commands_total', 'Total SSH commands executed', ['alias', 'status'])
ssh_command_duration = Histogram('ssh_command_duration_seconds', 'SSH command execution time', ['alias'])
ssh_policy_decisions_total = Counter('ssh_policy_decisions_total', 'Policy decisions', ['decision', 'rule'])

# Security metrics
ssh_auth_failures_total = Counter('ssh_auth_failures_total', 'SSH authentication failures', ['alias'])
ssh_policy_violations_total = Counter('ssh_policy_violations_total', 'Policy violations', ['violation_type'])

# System metrics
ssh_active_sessions = Gauge('ssh_active_sessions', 'Active SSH sessions')
ssh_config_reloads_total = Counter('ssh_config_reloads_total', 'Configuration reloads')
```

**Prometheus Configuration:**
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'mcp-ssh-orchestrator'
    static_configs:
      - targets: ['mcp-ssh:8000']
    metrics_path: '/metrics'
    scrape_interval: 5s
```

### Grafana Dashboards

**Security Dashboard:**
```json
{
  "dashboard": {
    "title": "MCP SSH Orchestrator - Security",
    "panels": [
      {
        "title": "Policy Violations",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(ssh_policy_violations_total[5m])",
            "legendFormat": "Violations/sec"
          }
        ]
      },
      {
        "title": "Authentication Failures",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(ssh_auth_failures_total[5m])",
            "legendFormat": "{{alias}}"
          }
        ]
      }
    ]
  }
}
```

**Operational Dashboard:**
```json
{
  "dashboard": {
    "title": "MCP SSH Orchestrator - Operations",
    "panels": [
      {
        "title": "Command Execution Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(ssh_commands_total[5m])",
            "legendFormat": "{{alias}} - {{status}}"
          }
        ]
      },
      {
        "title": "Command Duration",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(ssh_command_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      }
    ]
  }
}
```

## Security Monitoring

### Anomaly Detection

**Suspicious Activity Patterns:**
```python
# Rate limiting alerts
if ssh_commands_total.labels(alias=alias).rate(1m) > 100:
    alert("HIGH_COMMAND_RATE", f"High command rate for {alias}")

# Unusual command patterns
if "rm" in command and alias not in ["backup-server"]:
    alert("DESTRUCTIVE_COMMAND", f"Destructive command on {alias}")

# Authentication failures
if ssh_auth_failures_total.labels(alias=alias).rate(5m) > 5:
    alert("AUTH_FAILURE_SPIKE", f"Auth failure spike for {alias}")
```

**Security Alerts:**
```yaml
# alertmanager.yml
groups:
  - name: mcp-ssh-security
    rules:
      - alert: HighCommandRate
        expr: rate(ssh_commands_total[1m]) > 100
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "High command execution rate detected"
          
      - alert: PolicyViolation
        expr: increase(ssh_policy_violations_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Policy violation detected"
          
      - alert: AuthFailureSpike
        expr: rate(ssh_auth_failures_total[5m]) > 5
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Authentication failure spike detected"
```

### Compliance Reporting

**SOC 2 Compliance:**
```python
# Generate compliance report
def generate_soc2_report(start_date, end_date):
    return {
        "access_controls": {
            "total_commands": ssh_commands_total.sum(),
            "allowed_commands": ssh_commands_total.labels(status="allowed").sum(),
            "denied_commands": ssh_commands_total.labels(status="denied").sum(),
            "policy_violations": ssh_policy_violations_total.sum()
        },
        "audit_trail": {
            "audit_logs": get_audit_logs(start_date, end_date),
            "log_integrity": verify_log_integrity(),
            "retention_compliance": check_log_retention()
        },
        "security_monitoring": {
            "auth_failures": ssh_auth_failures_total.sum(),
            "suspicious_activity": get_suspicious_activity(start_date, end_date),
            "incident_response": get_incident_response_logs(start_date, end_date)
        }
    }
```

**PCI DSS Compliance:**
```python
# PCI DSS requirements
def generate_pci_report():
    return {
        "requirement_1": {
            "network_security": verify_network_policies(),
            "firewall_rules": get_firewall_rules(),
            "network_segmentation": verify_network_segmentation()
        },
        "requirement_2": {
            "default_passwords": check_default_passwords(),
            "system_configuration": verify_system_configuration(),
            "security_patches": check_security_patches()
        },
        "requirement_3": {
            "data_encryption": verify_data_encryption(),
            "key_management": verify_key_management(),
            "data_protection": verify_data_protection()
        }
    }
```

## Log Management

### Centralized Logging

**ELK Stack Setup:**
```yaml
# docker-compose.yml
version: '3.8'

services:
  mcp-ssh:
    image: ghcr.io/samerfarida/mcp-ssh-orchestrator:0.1.0
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    environment:
      - LOG_LEVEL=INFO
      - LOG_FORMAT=json
      - LOG_OUTPUT=stdout

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    ports:
      - "9200:9200"

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    depends_on:
      - elasticsearch

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
```

**Logstash Configuration:**
```ruby
# logstash.conf
input {
  docker {
    type => "mcp-ssh"
  }
}

filter {
  if [type] == "mcp-ssh" {
    json {
      source => "message"
    }
    
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    mutate {
      add_field => { "log_level" => "%{level}" }
      add_field => { "component" => "%{component}" }
      add_field => { "event_type" => "%{event}" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "mcp-ssh-%{+YYYY.MM.dd}"
  }
}
```

### Log Retention and Archival

**Retention Policy:**
```yaml
# retention-policy.yml
retention:
  audit_logs:
    hot_storage: 30_days
    warm_storage: 90_days
    cold_storage: 1_year
    delete_after: 7_years
  
  security_logs:
    hot_storage: 90_days
    warm_storage: 1_year
    cold_storage: 7_years
    delete_after: never
  
  operational_logs:
    hot_storage: 7_days
    warm_storage: 30_days
    cold_storage: 90_days
    delete_after: 1_year
```

**Archival Script:**
```bash
#!/bin/bash
# archive-logs.sh

ARCHIVE_DIR="/opt/archives/mcp-ssh"
DATE=$(date +%Y%m%d)

# Archive audit logs older than 30 days
find /var/log/mcp-ssh/audit -name "*.log" -mtime +30 -exec \
  tar -czf "$ARCHIVE_DIR/audit_$DATE.tar.gz" {} +

# Archive security logs older than 90 days
find /var/log/mcp-ssh/security -name "*.log" -mtime +90 -exec \
  tar -czf "$ARCHIVE_DIR/security_$DATE.tar.gz" {} +

# Clean up archived files
find "$ARCHIVE_DIR" -name "*.tar.gz" -mtime +365 -delete
```

## Incident Response

### Automated Response

**Incident Detection:**
```python
# incident_detection.py
def detect_incidents():
    incidents = []
    
    # Policy violation incident
    if ssh_policy_violations_total.sum() > 0:
        incidents.append({
            "type": "policy_violation",
            "severity": "high",
            "description": "Policy violation detected",
            "timestamp": datetime.now().isoformat()
        })
    
    # Authentication failure incident
    if ssh_auth_failures_total.sum() > 10:
        incidents.append({
            "type": "auth_failure_spike",
            "severity": "medium",
            "description": "Authentication failure spike",
            "timestamp": datetime.now().isoformat()
        })
    
    return incidents
```

**Automated Response Actions:**
```python
# automated_response.py
def handle_incident(incident):
    if incident["type"] == "policy_violation":
        # Block suspicious IP
        block_ip(incident["source_ip"])
        
        # Send alert
        send_alert(incident)
        
        # Create incident ticket
        create_incident_ticket(incident)
    
    elif incident["type"] == "auth_failure_spike":
        # Rate limit the source
        rate_limit_ip(incident["source_ip"])
        
        # Send warning
        send_warning(incident)
```

### Forensic Analysis

**Command Execution Forensics:**
```python
# forensic_analysis.py
def analyze_command_execution(alias, command, timestamp):
    return {
        "command_analysis": {
            "command": command,
            "risk_score": calculate_risk_score(command),
            "similar_commands": find_similar_commands(command),
            "execution_pattern": analyze_execution_pattern(alias, command)
        },
        "context_analysis": {
            "user_behavior": analyze_user_behavior(alias),
            "session_context": get_session_context(timestamp),
            "network_context": get_network_context(timestamp)
        },
        "threat_indicators": {
            "iocs": extract_iocs(command),
            "ttps": map_to_ttps(command),
            "attribution": attempt_attribution(alias, command)
        }
    }
```

## Performance Monitoring

### System Metrics

**Resource Monitoring:**
```python
# system_metrics.py
def collect_system_metrics():
    return {
        "cpu_usage": psutil.cpu_percent(),
        "memory_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "network_io": psutil.net_io_counters(),
        "active_connections": len(psutil.net_connections()),
        "ssh_sessions": count_ssh_sessions()
    }
```

**Performance Alerts:**
```yaml
# performance-alerts.yml
groups:
  - name: mcp-ssh-performance
    rules:
      - alert: HighCPUUsage
        expr: cpu_usage_percent > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          
      - alert: HighMemoryUsage
        expr: memory_usage_percent > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
          
      - alert: SlowCommandExecution
        expr: histogram_quantile(0.95, rate(ssh_command_duration_seconds_bucket[5m])) > 30
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Slow command execution detected"
```

## Next Steps

- **[Troubleshooting](12-Troubleshooting)** - Common monitoring and logging issues
- **[Security Model](05-Security-Model)** - Security architecture details
- **[Deployment](09-Deployment)** - Production deployment with monitoring
- **[FAQ](15-FAQ)** - Common observability questions
