"""Tests for MCP server tools."""

import json
import pytest
import tempfile
import os
import yaml
from unittest.mock import patch, MagicMock
from mcp_ssh import mcp_server
from mcp_ssh.config import Config


@pytest.fixture
def mock_config():
    """Create a mock config for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test servers.yml
        servers = {
            "hosts": [
                {"alias": "test1", "host": "10.0.0.1", "port": 22, "credentials": "cred1", "tags": ["web"]},
                {"alias": "test2", "host": "10.0.0.2", "port": 22, "credentials": "cred1", "tags": ["db", "prod"]},
            ]
        }
        with open(os.path.join(tmpdir, "servers.yml"), "w") as f:
            yaml.dump(servers, f)
        
        credentials = {
            "entries": [
                {"name": "cred1", "username": "user1", "key_path": "id_ed25519"},
            ]
        }
        with open(os.path.join(tmpdir, "credentials.yml"), "w") as f:
            yaml.dump(credentials, f)
        
        policy = {
            "limits": {"max_seconds": 60},
            "rules": [
                {"action": "allow", "aliases": ["*"], "tags": [], "commands": ["uptime*"]},
            ]
        }
        with open(os.path.join(tmpdir, "policy.yml"), "w") as f:
            yaml.dump(policy, f)
        
        # Replace global config
        config = Config(config_dir=tmpdir)
        mcp_server.config = config
        
        yield config


def test_ssh_ping():
    """Test ping tool."""
    result = mcp_server.ssh_ping()
    assert result == "pong"


def test_ssh_list_hosts(mock_config):
    """Test list_hosts tool."""
    result = mcp_server.ssh_list_hosts()
    hosts = json.loads(result)
    
    assert isinstance(hosts, list)
    assert len(hosts) == 2
    assert "test1" in hosts
    assert "test2" in hosts


def test_ssh_describe_host(mock_config):
    """Test describe_host tool."""
    result = mcp_server.ssh_describe_host(alias="test1")
    host = json.loads(result)
    
    assert host["alias"] == "test1"
    assert host["host"] == "10.0.0.1"
    assert host["port"] == 22


def test_ssh_describe_host_not_found(mock_config):
    """Test describe_host with non-existent host."""
    result = mcp_server.ssh_describe_host(alias="nonexistent")
    
    assert "Error" in result


def test_ssh_plan(mock_config):
    """Test plan tool."""
    result = mcp_server.ssh_plan(alias="test1", command="uptime")
    plan = json.loads(result)
    
    assert plan["alias"] == "test1"
    assert plan["command"] == "uptime"
    assert "allowed" in plan
    assert "limits" in plan


def test_ssh_reload_config(mock_config):
    """Test reload_config tool."""
    result = mcp_server.ssh_reload_config()
    
    assert "reloaded" in result.lower()


def test_ssh_cancel_not_found():
    """Test cancel tool with non-existent task."""
    result = mcp_server.ssh_cancel(task_id="nonexistent")
    
    assert "not found" in result.lower()


def test_ssh_cancel_no_task_id():
    """Test cancel tool without task_id."""
    result = mcp_server.ssh_cancel(task_id="")
    
    assert "required" in result.lower()


# Note: Testing ssh_run and ssh_run_on_tag requires mocking SSH connections,
# which is complex and better suited for integration tests with a real SSH server.
# The core logic is tested through the individual component tests (policy, ssh_client, config).


def test_default_parameters():
    """Test that all MCP tools have default empty string parameters."""
    # Per instructions: all params should default to empty strings
    assert mcp_server.ssh_describe_host() == "Error: Host alias not found: "
    assert mcp_server.ssh_plan() != ""  # Should return an error but not crash

