# Security Policy

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

Email: security@example.com

## Quick Security Checklist

- [ ] Use Ed25519 or RSA 4096-bit keys
- [ ] Enable `require_known_host: true`
- [ ] Configure IP allowlists (`allow_cidrs`)
- [ ] Use deny-by-default policy model
- [ ] Mount config and keys as read-only (`:ro`)

## Comprehensive Security Guide

For detailed security documentation, see our [Security Model](https://github.com/samerfarida/mcp-ssh-orchestrator/wiki/05-Security-Model) wiki page.

## Security Features

This project implements MCP security best practices:
- **Containerized execution** with resource limits
- **Policy-based access control** with deny-by-default
- **Network segmentation** with IP allowlists
- **Comprehensive audit logging** for all operations
- **Secret management** via Docker secrets or environment variables

## Security Framework Alignment

- **OWASP LLM07** (Insecure Plugin Design) - Policy-based command validation
- **OWASP LLM08** (Excessive Agency) - Role-based access restrictions
- **MITRE ATT&CK** - SSH protocol monitoring and logging
- Security features support compliance efforts (SOC 2, ISO 27001, PCI-DSS, HIPAA)

*Note: Compliance is the responsibility of the deploying organization. This tool provides security controls that can support compliance frameworks.*
