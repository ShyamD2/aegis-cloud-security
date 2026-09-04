"""
Project AEGIS - Concurrency & Race Condition Verification
Simulates distributed racing remediation executions against IdempotencyStore and ensures
strict single-winner mutual exclusion semantics.
"""

from __future__ import annotations

import concurrent.futures
import logging
from typing import Any

from services.remediation.idempotency import IdempotencyStore

logger = logging.getLogger("aegis.resilience.concurrency")


class ConcurrencyStressTester:
    """
    Stress-tests idempotency locking and atomic conditional operations under high concurrency.
    """

    def __init__(self, store: IdempotencyStore | None = None) -> None:
        self.store = store or IdempotencyStore()

    def run_lock_race(
        self,
        idempotency_key: str,
        num_threads: int = 20,
    ) -> dict[str, Any]:
        """
        Launch concurrent threads racing to acquire the same lock simultaneously.

        Returns:
            Dict containing count of acquired locks, rejected locks, and consistency verification.
        """
        acquired_locks: list[str] = []
        denied_locks: list[str] = []

        def worker(worker_id: int) -> tuple[int, bool]:
            rem_id = f"rem-worker-{worker_id}"
            acquired = self.store.acquire_lock(idempotency_key, rem_id)
            return worker_id, acquired

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, i) for i in range(num_threads)]
            for future in concurrent.futures.as_completed(futures):
                worker_id, acquired = future.result()
                if acquired:
                    acquired_locks.append(f"worker-{worker_id}")
                else:
                    denied_locks.append(f"worker-{worker_id}")

        is_consistent = len(acquired_locks) == 1 and len(denied_locks) == (num_threads - 1)

        return {
            "num_threads": num_threads,
            "acquired_count": len(acquired_locks),
            "denied_count": len(denied_locks),
            "winner": acquired_locks[0] if acquired_locks else None,
            "is_consistent": is_consistent,
        }
