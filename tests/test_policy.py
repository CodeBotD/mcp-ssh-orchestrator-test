"""Tests for policy engine."""

import pytest

from mcp_ssh.policy import Policy


@pytest.fixture
def basic_policy():
    """Basic policy configuration for testing."""
    return {
        "limits": {
            "max_seconds": 60,
            "max_output_bytes": 1048576,
            "deny_substrings": ["rm -rf", "shutdown"],
        },
        "network": {
            "allow_ips": [],
            "allow_cidrs": ["10.0.0.0/8"],
            "block_ips": ["10.10.10.10"],
            "block_cidrs": [],
        },
        "rules": [
            {
                "action": "allow",
                "aliases": ["*"],
                "tags": [],
                "commands": ["uptime*", "df -h*"],
            },
            {
                "action": "allow",
                "aliases": [],
                "tags": ["staging"],
                "commands": ["systemctl restart *"],
            },
            {
                "action": "deny",
                "aliases": ["prod-*"],
                "tags": [],
                "commands": ["rm *"],
            },
        ],
        "overrides": {
            "aliases": {
                "prod-db-1": {
                    "max_seconds": 30,
                }
            },
            "tags": {
                "production": {
                    "max_output_bytes": 524288,
                }
            },
        },
    }


def test_is_allowed_safe_command(basic_policy):
    """Test allowing safe command."""
    pol = Policy(basic_policy)

    assert pol.is_allowed("test1", [], "uptime") is True
    assert pol.is_allowed("test1", [], "df -h") is True


def test_is_denied_no_match(basic_policy):
    """Test denying command that doesn't match any rule."""
    pol = Policy(basic_policy)

    # No rule matches, deny by default
    assert pol.is_allowed("test1", [], "unknown-command") is False


def test_is_allowed_tag_based(basic_policy):
    """Test allowing command based on tag."""
    pol = Policy(basic_policy)

    assert pol.is_allowed("stg-web-1", ["staging"], "systemctl restart nginx") is True
    assert (
        pol.is_allowed("prod-web-1", ["production"], "systemctl restart nginx") is False
    )


def test_is_denied_by_substring(basic_policy):
    """Test denying command by substring."""
    pol = Policy(basic_policy)

    assert pol.is_allowed("test1", [], "rm -rf /tmp") is False
    assert pol.is_allowed("test1", [], "shutdown -h now") is False


def test_is_denied_by_explicit_rule(basic_policy):
    """Test denying command by explicit rule."""
    pol = Policy(basic_policy)

    assert pol.is_allowed("prod-web-1", [], "rm file.txt") is False


def test_limits_global(basic_policy):
    """Test global limits."""
    pol = Policy(basic_policy)

    limits = pol.limits_for("test1", [])
    assert limits["max_seconds"] == 60
    assert limits["max_output_bytes"] == 1048576


def test_limits_alias_override(basic_policy):
    """Test alias-specific limit override."""
    pol = Policy(basic_policy)

    limits = pol.limits_for("prod-db-1", [])
    assert limits["max_seconds"] == 30  # Overridden


def test_limits_tag_override(basic_policy):
    """Test tag-specific limit override."""
    pol = Policy(basic_policy)

    limits = pol.limits_for("test1", ["production"])
    assert limits["max_output_bytes"] == 524288  # Overridden


def test_is_ip_allowed_in_cidr(basic_policy):
    """Test IP allowed by CIDR."""
    pol = Policy(basic_policy)

    assert pol.is_ip_allowed("10.0.0.1") is True
    assert pol.is_ip_allowed("10.255.255.255") is True


def test_is_ip_denied_outside_cidr(basic_policy):
    """Test IP denied outside allowed CIDR."""
    pol = Policy(basic_policy)

    assert pol.is_ip_allowed("192.168.1.1") is False
    assert pol.is_ip_allowed("11.0.0.1") is False


def test_is_ip_blocked_explicit(basic_policy):
    """Test IP explicitly blocked."""
    pol = Policy(basic_policy)

    assert pol.is_ip_allowed("10.10.10.10") is False


def test_is_ip_allowed_no_allowlist():
    """Test IP allowed when no allowlist configured."""
    pol = Policy({"network": {"allow_ips": [], "allow_cidrs": []}})

    # No allowlist = allow all (unless blocked)
    assert pol.is_ip_allowed("1.2.3.4") is True
    assert pol.is_ip_allowed("10.0.0.1") is True


def test_is_ip_allowed_exact_ip():
    """Test exact IP match in allowlist."""
    pol = Policy(
        {
            "network": {
                "allow_ips": ["10.0.0.1", "10.0.0.2"],
                "allow_cidrs": [],
            }
        }
    )

    assert pol.is_ip_allowed("10.0.0.1") is True
    assert pol.is_ip_allowed("10.0.0.2") is True
    assert pol.is_ip_allowed("10.0.0.3") is False


def test_require_known_host_default(basic_policy):
    """Test default known_host requirement."""
    pol = Policy(basic_policy)

    # Should default to True
    assert pol.require_known_host() is True


def test_require_known_host_network_override():
    """Test known_host requirement from network config."""
    pol = Policy(
        {
            "network": {"require_known_host": False},
            "limits": {"require_known_host": True},
        }
    )

    # Network setting overrides limits
    assert pol.require_known_host() is False


def test_glob_pattern_matching():
    """Test glob pattern matching in rules."""
    pol = Policy(
        {
            "rules": [
                {
                    "action": "allow",
                    "aliases": ["web-*"],
                    "tags": [],
                    "commands": ["systemctl status *"],
                }
            ]
        }
    )

    assert pol.is_allowed("web-1", [], "systemctl status nginx") is True
    assert pol.is_allowed("web-prod", [], "systemctl status apache") is True
    assert pol.is_allowed("db-1", [], "systemctl status nginx") is False


def test_multiple_tags_any_match():
    """Test that any tag matching enables the rule."""
    pol = Policy(
        {
            "rules": [
                {
                    "action": "allow",
                    "aliases": [],
                    "tags": ["staging", "dev"],
                    "commands": ["deploy*"],
                }
            ]
        }
    )

    assert pol.is_allowed("test1", ["staging"], "deploy.sh") is True
    assert pol.is_allowed("test2", ["dev"], "deploy.sh") is True
    assert pol.is_allowed("test3", ["staging", "other"], "deploy.sh") is True
    assert pol.is_allowed("test4", ["production"], "deploy.sh") is False


def test_empty_config():
    """Test policy with empty config."""
    pol = Policy({})

    # Should have sensible defaults
    limits = pol.limits_for("test1", [])
    assert "max_seconds" in limits
    assert "max_output_bytes" in limits

    # Deny by default
    assert pol.is_allowed("test1", [], "any command") is False
