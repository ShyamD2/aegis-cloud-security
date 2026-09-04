"""Telemetry validation and mandatory field integrity verification."""

from services.common.models import NormalizedSecurityEvent


class TelemetryValidationError(ValueError):
    """Raised when a normalized security event violates mandatory telemetry retention rules."""

    pass


def validate_telemetry_event(event: NormalizedSecurityEvent) -> bool:
    """Verify that every security event retains mandatory telemetry attributes per AEGIS standards.

    Mandatory fields:
    - account ID
    - region
    - timestamp
    - event source
    - event name / action
    - principal identity
    - source IP (where available)
    - resource identifiers (where available)
    """
    if not event.event_id or not event.event_id.strip():
        raise TelemetryValidationError("Missing mandatory field: event_id")

    if not event.account_id or len(event.account_id) != 12 or not event.account_id.isdigit():
        raise TelemetryValidationError(
            f"Invalid AWS account ID: '{event.account_id}'. Must be a 12-digit string."
        )

    if not event.region or not event.region.strip():
        raise TelemetryValidationError("Missing mandatory field: region")

    if not event.source or not event.source.strip():
        raise TelemetryValidationError("Missing mandatory field: source")

    if not event.action or not event.action.strip():
        raise TelemetryValidationError("Missing mandatory field: action")

    if not event.principal_arn or not event.principal_arn.strip():
        raise TelemetryValidationError("Missing mandatory field: principal_arn")

    if not event.resource_arns or len(event.resource_arns) == 0:
        raise TelemetryValidationError(
            "Missing mandatory field: resource_arns. Must contain at least one resource ARN."
        )

    return True
