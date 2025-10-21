"""Tests for configuration loading and credential resolution."""

import os
import tempfile
import pytest
import yaml
from mcp_ssh.config import Config, _resolve_secret, _resolve_key_path


@pytest.fixture
def temp_config_dir():
    """Create temporary config directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test servers.yml
        servers = {
            "hosts": [
                {"alias": "test1", "host": "10.0.0.1", "port": 22, "credentials": "cred1", "tags": ["web", "prod"]},
                {"alias": "test2", "host": "10.0.0.2", "port": 2222, "credentials": "cred2", "tags": ["db"]},
            ]
        }
        with open(os.path.join(tmpdir, "servers.yml"), "w") as f:
            yaml.dump(servers, f)
        
        # Create test credentials.yml
        credentials = {
            "entries": [
                {"name": "cred1", "username": "user1", "key_path": "id_ed25519", "password_secret": "", "key_passphrase_secret": ""},
                {"name": "cred2", "username": "user2", "key_path": "", "password_secret": "db_password", "key_passphrase_secret": ""},
            ]
        }
        with open(os.path.join(tmpdir, "credentials.yml"), "w") as f:
            yaml.dump(credentials, f)
        
        # Create test policy.yml
        policy = {
            "limits": {"max_seconds": 60, "max_output_bytes": 1048576},
            "rules": [
                {"action": "allow", "aliases": ["*"], "tags": [], "commands": ["uptime*"]},
            ]
        }
        with open(os.path.join(tmpdir, "policy.yml"), "w") as f:
            yaml.dump(policy, f)
        
        yield tmpdir


def test_config_load(temp_config_dir):
    """Test loading configuration files."""
    config = Config(config_dir=temp_config_dir)
    
    hosts = config.list_hosts()
    assert len(hosts) == 2
    assert "test1" in hosts
    assert "test2" in hosts


def test_get_host(temp_config_dir):
    """Test getting host by alias."""
    config = Config(config_dir=temp_config_dir)
    
    host = config.get_host("test1")
    assert host["host"] == "10.0.0.1"
    assert host["port"] == 22
    assert host["credentials"] == "cred1"


def test_get_host_not_found(temp_config_dir):
    """Test getting non-existent host."""
    config = Config(config_dir=temp_config_dir)
    
    with pytest.raises(ValueError, match="Host alias not found"):
        config.get_host("nonexistent")


def test_get_host_tags(temp_config_dir):
    """Test getting host tags."""
    config = Config(config_dir=temp_config_dir)
    
    tags = config.get_host_tags("test1")
    assert tags == ["web", "prod"]
    
    tags2 = config.get_host_tags("test2")
    assert tags2 == ["db"]


def test_find_hosts_by_tag(temp_config_dir):
    """Test finding hosts by tag."""
    config = Config(config_dir=temp_config_dir)
    
    web_hosts = config.find_hosts_by_tag("web")
    assert web_hosts == ["test1"]
    
    prod_hosts = config.find_hosts_by_tag("prod")
    assert prod_hosts == ["test1"]
    
    db_hosts = config.find_hosts_by_tag("db")
    assert db_hosts == ["test2"]
    
    no_hosts = config.find_hosts_by_tag("nonexistent")
    assert no_hosts == []


def test_get_credentials(temp_config_dir):
    """Test getting credentials."""
    config = Config(config_dir=temp_config_dir, keys_dir="/app/keys", secrets_dir="/app/secrets")
    
    creds = config.get_credentials("cred1")
    assert creds["username"] == "user1"
    assert creds["key_path"] == "/app/keys/id_ed25519"
    assert creds["password"] == ""


def test_get_credentials_not_found(temp_config_dir):
    """Test getting non-existent credentials."""
    config = Config(config_dir=temp_config_dir)
    
    creds = config.get_credentials("nonexistent")
    assert creds == {}


def test_get_policy(temp_config_dir):
    """Test getting policy."""
    config = Config(config_dir=temp_config_dir)
    
    policy = config.get_policy()
    assert policy["limits"]["max_seconds"] == 60
    assert len(policy["rules"]) == 1


def test_reload_config(temp_config_dir):
    """Test reloading configuration."""
    config = Config(config_dir=temp_config_dir)
    
    # Initial state
    hosts = config.list_hosts()
    assert len(hosts) == 2
    
    # Modify servers.yml
    servers = {
        "hosts": [
            {"alias": "test3", "host": "10.0.0.3", "port": 22, "credentials": "cred1", "tags": []},
        ]
    }
    with open(os.path.join(temp_config_dir, "servers.yml"), "w") as f:
        yaml.dump(servers, f)
    
    # Reload
    config.reload()
    
    # Verify change
    hosts = config.list_hosts()
    assert len(hosts) == 1
    assert "test3" in hosts


def test_resolve_secret_from_env(monkeypatch):
    """Test resolving secret from environment variable."""
    monkeypatch.setenv("MCP_SSH_SECRET_TEST_PASSWORD", "env-password")
    
    secret = _resolve_secret("test_password")
    assert secret == "env-password"


def test_resolve_secret_from_file():
    """Test resolving secret from file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        secret_path = os.path.join(tmpdir, "test_secret")
        with open(secret_path, "w") as f:
            f.write("file-secret")
        
        secret = _resolve_secret("test_secret", secrets_dir=tmpdir)
        assert secret == "file-secret"


def test_resolve_secret_not_found():
    """Test resolving non-existent secret."""
    with tempfile.TemporaryDirectory() as tmpdir:
        secret = _resolve_secret("nonexistent", secrets_dir=tmpdir)
        assert secret == ""


def test_resolve_key_path_relative():
    """Test resolving relative key path."""
    path = _resolve_key_path("id_ed25519", keys_dir="/app/keys")
    assert path == "/app/keys/id_ed25519"


def test_resolve_key_path_absolute():
    """Test resolving absolute key path."""
    path = _resolve_key_path("/absolute/path/key", keys_dir="/app/keys")
    assert path == "/absolute/path/key"


def test_resolve_key_path_empty():
    """Test resolving empty key path."""
    path = _resolve_key_path("", keys_dir="/app/keys")
    assert path == ""

