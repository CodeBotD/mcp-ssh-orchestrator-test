"""Tests for AsyncTaskManager."""

import json
import threading
import time
from unittest.mock import Mock, patch

import pytest

from mcp_ssh.tools.utilities import AsyncTaskManager


class TestAsyncTaskManager:
    """Test cases for AsyncTaskManager."""

    def setup_method(self):
        """Set up test fixtures."""
        self.task_manager = AsyncTaskManager()
        self.mock_ssh_client = Mock()
        self.mock_limits = {
            "max_seconds": 60,
            "max_output_bytes": 1024,
            "task_result_ttl": 300,
            "task_progress_interval": 5,
        }

    def teardown_method(self):
        """Clean up after tests."""
        # Clean up any remaining tasks
        self.task_manager.cleanup_expired_tasks()

    def test_task_manager_initialization(self):
        """Test AsyncTaskManager initialization."""
        assert self.task_manager._tasks == {}
        assert self.task_manager._results == {}
        assert self.task_manager._output_buffers == {}
        assert self.task_manager._notification_callback is None

    def test_set_notification_callback(self):
        """Test setting notification callback."""
        callback = Mock()
        self.task_manager.set_notification_callback(callback)
        assert self.task_manager._notification_callback == callback

    def test_start_async_task(self):
        """Test starting an async task."""
        with patch.object(self.task_manager, '_execute_task_in_thread') as mock_execute:
            task_id = self.task_manager.start_async_task(
                alias="test1",
                command="uptime",
                ssh_client=self.mock_ssh_client,
                limits=self.mock_limits,
                progress_cb=None
            )

            assert task_id.startswith("test1:")
            assert task_id in self.task_manager._tasks
            assert task_id in self.task_manager._output_buffers

            task_info = self.task_manager._tasks[task_id]
            assert task_info["status"] == "pending"
            assert task_info["alias"] == "test1"
            assert task_info["command"] == "uptime"
            assert task_info["ssh_client"] == self.mock_ssh_client
            assert task_info["limits"] == self.mock_limits

    def test_get_task_status_pending(self):
        """Test getting status of pending task."""
        task_id = self.task_manager.start_async_task(
            alias="test1",
            command="uptime",
            ssh_client=self.mock_ssh_client,
            limits=self.mock_limits,
            progress_cb=None
        )

        status = self.task_manager.get_task_status(task_id)
        status_data = json.loads(status)

        assert status_data["task_id"] == task_id
        assert status_data["status"] == "pending"
        assert status_data["keepAlive"] == 300
        assert status_data["pollFrequency"] == 5
        assert "elapsed_ms" in status_data
        assert "bytes_read" in status_data
        assert "output_lines_available" in status_data

    def test_get_task_status_running(self):
        """Test getting status of running task."""
        task_id = self.task_manager.start_async_task(
            alias="test1",
            command="uptime",
            ssh_client=self.mock_ssh_client,
            limits=self.mock_limits,
            progress_cb=None
        )

        # Simulate task running
        with self.task_manager._lock:
            self.task_manager._tasks[task_id]["status"] = "running"
            self.task_manager._tasks[task_id]["started"] = time.time()
            self.task_manager._tasks[task_id]["bytes_out"] = 100

        status = self.task_manager.get_task_status(task_id)
        status_data = json.loads(status)

        assert status_data["status"] == "running"
        assert status_data["bytes_read"] == 100

    def test_get_task_status_completed(self):
        """Test getting status of completed task."""
        task_id = self.task_manager.start_async_task(
            alias="test1",
            command="uptime",
            ssh_client=self.mock_ssh_client,
            limits=self.mock_limits,
            progress_cb=None
        )

        # Simulate task completion
        with self.task_manager._lock:
            self.task_manager._tasks[task_id]["status"] = "completed"
            self.task_manager._tasks[task_id]["started"] = time.time() - 5
            self.task_manager._tasks[task_id]["completed"] = time.time()
            self.task_manager._tasks[task_id]["exit_code"] = 0
            self.task_manager._tasks[task_id]["bytes_out"] = 50

        status = self.task_manager.get_task_status(task_id)
        status_data = json.loads(status)

        assert status_data["status"] == "completed"
        assert status_data["bytes_read"] == 50

    def test_get_task_result_completed(self):
        """Test getting result of completed task."""
        task_id = self.task_manager.start_async_task(
            alias="test1",
            command="uptime",
            ssh_client=self.mock_ssh_client,
            limits=self.mock_limits,
            progress_cb=None
        )

        # Simulate task completion and store result
        with self.task_manager._lock:
            self.task_manager._tasks[task_id]["status"] = "completed"
            self.task_manager._tasks[task_id]["started"] = time.time() - 5
            self.task_manager._tasks[task_id]["completed"] = time.time()
            self.task_manager._tasks[task_id]["exit_code"] = 0
            self.task_manager._tasks[task_id]["output"] = "up 1 day, 2:30"
            self.task_manager._tasks[task_id]["target_ip"] = "10.0.0.1"

        # Store result
        self.task_manager._results[task_id] = {
            "task_id": task_id,
            "status": "completed",
            "exit_code": 0,
            "duration_ms": 5000,
            "output": "up 1 day, 2:30",
            "cancelled": False,
            "timeout": False,
            "target_ip": "10.0.0.1",
            "created": time.time()
        }

        result = self.task_manager.get_task_result(task_id)
        result_data = json.loads(result)

        assert result_data["task_id"] == task_id
        assert result_data["status"] == "completed"
        assert result_data["exit_code"] == 0
        assert result_data["output"] == "up 1 day, 2:30"
        assert result_data["target_ip"] == "10.0.0.1"

    def test_get_task_result_not_found(self):
        """Test getting result of non-existent task."""
        result = self.task_manager.get_task_result("nonexistent:task:id")
        assert "Error" in result
        assert "not found" in result.lower()

    def test_get_task_output_not_found(self):
        """Test getting output of non-existent task."""
        result = self.task_manager.get_task_output("nonexistent:task:id")
        assert "Error" in result
        assert "not found" in result.lower()

    def test_cancel_task(self):
        """Test cancelling a task."""
        task_id = self.task_manager.start_async_task(
            alias="test1",
            command="uptime",
            ssh_client=self.mock_ssh_client,
            limits=self.mock_limits,
            progress_cb=None
        )

        # Simulate task running
        with self.task_manager._lock:
            self.task_manager._tasks[task_id]["status"] = "running"

        result = self.task_manager.cancel_task(task_id)
        assert "cancelled" in result.lower()

        # Check that cancel event is set
        with self.task_manager._lock:
            assert self.task_manager._tasks[task_id]["cancel"].is_set()

    def test_cancel_task_not_found(self):
        """Test cancelling non-existent task."""
        result = self.task_manager.cancel_task("nonexistent:task:id")
        assert "Error" in result
        assert "not found" in result.lower()

    def test_cleanup_expired_tasks(self):
        """Test cleanup of expired tasks."""
        task_id = self.task_manager.start_async_task(
            alias="test1",
            command="uptime",
            ssh_client=self.mock_ssh_client,
            limits=self.mock_limits,
            progress_cb=None
        )

        # Store an expired result
        self.task_manager._results[task_id] = {
            "task_id": task_id,
            "status": "completed",
            "created": time.time() - 400  # 400 seconds ago (expired)
        }

        # Cleanup should remove expired results
        self.task_manager.cleanup_expired_tasks()

        assert task_id not in self.task_manager._results

    def test_task_id_format(self):
        """Test task ID format."""
        task_id = self.task_manager.start_async_task(
            alias="test-host",
            command="uptime",
            ssh_client=self.mock_ssh_client,
            limits=self.mock_limits,
            progress_cb=None
        )

        # Task ID should be in format: alias:hash:timestamp
        parts = task_id.split(":")
        assert len(parts) == 3
        assert parts[0] == "test-host"
        assert len(parts[1]) == 12  # hash length
        assert parts[2].isdigit()  # timestamp

    def test_concurrent_task_management(self):
        """Test thread safety of task management."""
        task_ids = []
        
        # Start multiple tasks concurrently
        for i in range(5):
            task_id = self.task_manager.start_async_task(
                alias=f"test{i}",
                command="uptime",
                ssh_client=self.mock_ssh_client,
                limits=self.mock_limits,
                progress_cb=None
            )
            task_ids.append(task_id)

        # All tasks should be created
        assert len(self.task_manager._tasks) == 5
        assert len(self.task_manager._output_buffers) == 5

        # All task IDs should be unique
        assert len(set(task_ids)) == 5

        # All tasks should be accessible
        for task_id in task_ids:
            status = self.task_manager.get_task_status(task_id)
            status_data = json.loads(status)
            assert status_data["task_id"] == task_id
            assert status_data["status"] == "pending"
