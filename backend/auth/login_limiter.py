"""
Login attempt limiter (Team 4)

Stops password guessing by counting FAILED logins over the last 15 minutes:

- per username:  after 5 failures, that username is blocked until the oldest
                 failure is 15 minutes old
- per computer:  after 20 failures from the same IP address (for any usernames),
                 that computer is blocked the same way

A successful login clears that username's failures.

Limitation: the counts live in memory. They reset when the server restarts and
are not shared between several server processes. That is fine for one server;
running several would need a shared store (for example the database or Redis).
"""

import math
import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Tuple


class LoginLimiter:
    def __init__(
        self,
        max_failures_per_user: int = 5,
        max_failures_per_ip: int = 20,
        window_seconds: int = 15 * 60,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.max_failures_per_user = max_failures_per_user
        self.max_failures_per_ip = max_failures_per_ip
        self.window_seconds = window_seconds
        self._clock = clock
        self._failures: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    @staticmethod
    def _user_key(username: str) -> Tuple[str, str]:
        return ("user", (username or "").strip().lower())

    @staticmethod
    def _ip_key(ip: str) -> Tuple[str, str]:
        return ("ip", ip or "unknown")

    def _recent(self, key: Tuple[str, str], now: float) -> Deque[float]:
        """Failures for `key` inside the time window (older ones are dropped)."""
        failures = self._failures[key]
        while failures and now - failures[0] >= self.window_seconds:
            failures.popleft()
        return failures

    def seconds_until_allowed(self, username: str, ip: str) -> int:
        """0 if a login attempt is allowed now, otherwise how many seconds to wait."""
        now = self._clock()
        with self._lock:
            waits = []
            for key, limit in ((self._user_key(username), self.max_failures_per_user),
                               (self._ip_key(ip), self.max_failures_per_ip)):
                failures = self._recent(key, now)
                if len(failures) >= limit:
                    # Allowed again once enough old failures have left the window.
                    oldest_that_matters = failures[len(failures) - limit]
                    waits.append(oldest_that_matters + self.window_seconds - now)
            return max(1, math.ceil(max(waits))) if waits else 0

    def record_failure(self, username: str, ip: str) -> None:
        now = self._clock()
        with self._lock:
            if len(self._failures) > 10_000:  # keep memory bounded
                for key in [k for k, v in self._failures.items() if not v or now - v[-1] >= self.window_seconds]:
                    del self._failures[key]
            self._failures[self._user_key(username)].append(now)
            self._failures[self._ip_key(ip)].append(now)

    def record_success(self, username: str) -> None:
        with self._lock:
            self._failures.pop(self._user_key(username), None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
