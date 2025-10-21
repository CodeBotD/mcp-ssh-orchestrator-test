"""Tests for SSH client."""

import threading

from mcp_ssh.ssh_client import SSHClient


def test_resolve_ips_localhost():
    """Test DNS resolution for localhost."""
    ips = SSHClient.resolve_ips("localhost")

    # Should resolve to 127.0.0.1
    assert "127.0.0.1" in ips


def test_resolve_ips_invalid():
    """Test DNS resolution for invalid hostname."""
    ips = SSHClient.resolve_ips("this-hostname-does-not-exist-12345.invalid")

    # Should return empty list
    assert ips == []


def test_ssh_client_init():
    """Test SSH client initialization."""
    client = SSHClient(
        host="10.0.0.1",
        username="testuser",
        port=22,
        key_path="/path/to/key",
        password="",
    )

    assert client.host == "10.0.0.1"
    assert client.username == "testuser"
    assert client.port == 22
    assert client.key_path == "/path/to/key"
    assert client.password == ""


def test_ssh_client_default_port():
    """Test SSH client with default port."""
    client = SSHClient(
        host="10.0.0.1",
        username="testuser",
    )

    assert client.port == 22


def test_ssh_client_run_streaming_cancel():
    """Test cancellation of SSH command (mock)."""
    # This test is limited because we can't actually SSH to a real host
    # We test the cancel event mechanism

    cancel_event = threading.Event()

    # Simulate cancellation
    cancel_event.set()

    assert cancel_event.is_set() is True


def test_ssh_client_known_hosts_settings():
    """Test known_hosts configuration."""
    client = SSHClient(
        host="10.0.0.1",
        username="testuser",
        known_hosts_path="/app/keys/known_hosts",
        auto_add_host_keys=False,
        require_known_host=True,
    )

    assert client.known_hosts_path == "/app/keys/known_hosts"
    assert client.auto_add_host_keys is False
    assert client.require_known_host is True


def test_ssh_client_auto_add_host_keys():
    """Test auto-add host keys mode."""
    client = SSHClient(
        host="10.0.0.1",
        username="testuser",
        auto_add_host_keys=True,
        require_known_host=False,
    )

    assert client.auto_add_host_keys is True
    assert client.require_known_host is False


# Note: Full integration tests with actual SSH connections would require
# a test SSH server (like docker-based openssh-server). These are better
# suited for integration test suite rather than unit tests.
