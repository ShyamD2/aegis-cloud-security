"""
Project AEGIS - Remediation Idempotency Store
Enforces distributed locking and deduplication via DynamoDB conditional writes
to prevent double-containment or race conditions.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from services.remediation.models import RemediationResult

logger = logging.getLogger("aegis.remediation.idempotency")


class IdempotencyStore:
    """
    DynamoDB-backed distributed idempotency store with in-memory fallback for testing.
    Uses conditional expressions (attribute_not_exists) to prevent concurrent execution.
    """

    def __init__(
        self, table_name: str = "aegis-remediation-idempotency", dynamodb_client: Any = None
    ) -> None:
        self.table_name = table_name
        self.client = dynamodb_client
        self._local_cache: dict[str, dict[str, Any]] = {}

    def acquire_lock(
        self, idempotency_key: str, remediation_id: str, ttl_seconds: int = 3600
    ) -> bool:
        """
        Acquires an atomic execution lock for the given idempotency key.
        Returns True if lock acquired; False if an active or completed execution exists.
        """
        expiry = int(time.time()) + ttl_seconds

        if not self.client:
            # Local in-memory lock simulation
            if idempotency_key in self._local_cache:
                existing = self._local_cache[idempotency_key]
                if existing.get("status") in ("IN_PROGRESS", "VERIFIED"):
                    logger.warning(
                        f"Idempotency conflict for key '{idempotency_key}' (already {existing.get('status')})"
                    )
                    return False
            self._local_cache[idempotency_key] = {
                "idempotency_key": idempotency_key,
                "remediation_id": remediation_id,
                "status": "IN_PROGRESS",
                "ttl": expiry,
            }
            return True

        # Real DynamoDB conditional write
        try:
            self.client.put_item(
                TableName=self.table_name,
                Item={
                    "idempotency_key": {"S": idempotency_key},
                    "remediation_id": {"S": remediation_id},
                    "status": {"S": "IN_PROGRESS"},
                    "ttl": {"N": str(expiry)},
                },
                ConditionExpression="attribute_not_exists(idempotency_key)",
            )
            return True
        except Exception as e:
            logger.warning(f"DynamoDB conditional write rejected lock acquisition: {e}")
            return False

    def record_completion(self, idempotency_key: str, result: RemediationResult) -> None:
        """Record final execution result and post-state in the idempotency table."""
        if not self.client:
            if idempotency_key in self._local_cache:
                self._local_cache[idempotency_key].update(
                    {
                        "status": result.status.value,
                        "verified": result.verified,
                        "pre_state": result.pre_state,
                        "post_state": result.post_state,
                        "verification_details": result.verification_details,
                    }
                )
            return

        try:
            self.client.update_item(
                TableName=self.table_name,
                Key={"idempotency_key": {"S": idempotency_key}},
                UpdateExpression="SET #s = :status, #v = :verified, #det = :details",
                ExpressionAttributeNames={
                    "#s": "status",
                    "#v": "verified",
                    "#det": "verification_details",
                },
                ExpressionAttributeValues={
                    ":status": {"S": result.status.value},
                    ":verified": {"BOOL": result.verified},
                    ":details": {"S": result.verification_details},
                },
            )
        except Exception as e:
            logger.error(f"Failed to record completion in DynamoDB idempotency table: {e}")

    def get_record(self, idempotency_key: str) -> dict[str, Any] | None:
        """Retrieve existing record by key."""
        if not self.client:
            return self._local_cache.get(idempotency_key)

        try:
            resp = self.client.get_item(
                TableName=self.table_name,
                Key={"idempotency_key": {"S": idempotency_key}},
            )
            item = resp.get("Item")
            if not item:
                return None
            return {
                "idempotency_key": item.get("idempotency_key", {}).get("S"),
                "remediation_id": item.get("remediation_id", {}).get("S"),
                "status": item.get("status", {}).get("S"),
            }
        except Exception as e:
            logger.error(f"Failed to fetch idempotency record from DynamoDB: {e}")
            return None
