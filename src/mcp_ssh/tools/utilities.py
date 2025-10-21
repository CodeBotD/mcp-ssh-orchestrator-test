import hashlib
import json
import sys
import threading
import time


def hash_command(command: str) -> str:
    """Return short SHA256 hash for a command."""
    return hashlib.sha256((command or "").encode()).hexdigest()[:12]


class TaskManager:
    """In-memory task registry for cancellation."""

    def __init__(self):
        self._lock = threading.Lock()
        self._tasks = {}

    def create(self, alias: str, command_hash: str) -> str:
        """Create task and return id."""
        with self._lock:
            # Use microsecond precision to avoid collisions
            timestamp = int(time.time() * 1000000)
            task_id = f"{alias}:{command_hash}:{timestamp}"
            self._tasks[task_id] = {
                "cancel": threading.Event(),
                "created": time.time(),
                "alias": alias,
                "hash": command_hash,
            }
            return task_id

    def cancel(self, task_id: str) -> bool:
        """Signal cancellation for task id."""
        with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id]["cancel"].set()
                return True
            return False

    def get_event(self, task_id: str):
        """Return cancel event for task id."""
        with self._lock:
            t = self._tasks.get(task_id)
            if t:
                return t["cancel"]
            return None

    def cleanup(self, task_id: str):
        """Remove task."""
        with self._lock:
            if task_id in self._tasks:
                del self._tasks[task_id]


TASKS = TaskManager()


def log_json(obj: dict):
    """Log JSON to stderr."""
    try:
        print(json.dumps(obj), file=sys.stderr)
    except Exception:
        pass
