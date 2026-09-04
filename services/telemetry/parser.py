"""Telemetry parsers converting heterogeneous AWS security logs into NormalizedSecurityEvent."""

from datetime import UTC, datetime
from typing import Any

from services.common.models import CloudTrailRecord, NormalizedSecurityEvent


def parse_cloudtrail_event(raw_event: dict[str, Any]) -> NormalizedSecurityEvent:
    """Parse a raw AWS CloudTrail record into a canonical NormalizedSecurityEvent."""
    record = CloudTrailRecord.model_validate(raw_event)

    # Extract resource ARNs from CloudTrail 'resources' block or request parameters
    resource_arns: list[str] = []
    if "resources" in raw_event and isinstance(raw_event["resources"], list):
        for res in raw_event["resources"]:
            if isinstance(res, dict) and "ARN" in res:
                resource_arns.append(res["ARN"])
            elif isinstance(res, dict) and "arn" in res:
                resource_arns.append(res["arn"])

    # Fallback to userName or roleArn if no resources explicitly listed
    if not resource_arns and record.user_identity.arn:
        resource_arns.append(record.user_identity.arn)

    action_name = f"{record.event_source.split('.')[0]}:{record.event_name}"
    status = "FAILURE" if (record.error_code or record.error_message) else "SUCCESS"

    return NormalizedSecurityEvent(
        event_id=record.event_id,
        source="cloudtrail",
        timestamp=record.event_time,
        account_id=record.recipient_account_id,
        region=record.aws_region,
        principal_arn=record.user_identity.arn
        or f"arn:aws:iam::{record.recipient_account_id}:root",
        principal_type=record.user_identity.type,
        action=action_name,
        resource_arns=resource_arns,
        source_ip=record.source_ip_address,
        user_agent=record.user_agent,
        status=status,
        raw_payload=raw_event,
    )


def parse_vpc_flow_log_line(flow_line: str, region: str = "us-east-1") -> NormalizedSecurityEvent:
    """Parse a space-delimited Amazon VPC Flow Log entry into a NormalizedSecurityEvent.

    Default AWS format:
    version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
    """
    parts = flow_line.strip().split()
    if len(parts) < 14:
        raise ValueError(
            f"Invalid VPC Flow Log format. Expected at least 14 fields, got {len(parts)}"
        )

    account_id = parts[1]
    interface_id = parts[2]
    srcaddr = parts[3]
    dstaddr = parts[4]
    srcport = parts[5]
    dstport = parts[6]
    protocol = parts[7]
    start_time = int(parts[10])
    action = parts[12]  # ACCEPT or REJECT

    timestamp = datetime.fromtimestamp(start_time, tz=UTC)
    event_id = f"flow-{interface_id}-{start_time}-{srcaddr}-{dstport}"
    resource_arn = f"arn:aws:ec2:{region}:{account_id}:network-interface/{interface_id}"

    return NormalizedSecurityEvent(
        event_id=event_id,
        source="vpcflow",
        timestamp=timestamp,
        account_id=account_id,
        region=region,
        principal_arn=f"network-interface/{interface_id}",
        principal_type="ENI",
        action=f"network:{action.lower()}",
        resource_arns=[resource_arn],
        source_ip=srcaddr,
        user_agent=f"protocol/{protocol}",
        status="SUCCESS" if action == "ACCEPT" else "REJECTED",
        raw_payload={
            "srcaddr": srcaddr,
            "dstaddr": dstaddr,
            "srcport": srcport,
            "dstport": dstport,
            "protocol": protocol,
            "action": action,
        },
    )


def parse_dns_query_log(
    dns_event: dict[str, Any], region: str = "us-east-1"
) -> NormalizedSecurityEvent:
    """Parse a Route 53 Resolver query log entry into a NormalizedSecurityEvent."""
    account_id = dns_event.get("account_id", "000000000000")
    query_name = dns_event.get("query_name", "")
    src_ip = dns_event.get("srcids", {}).get("instance", "") or dns_event.get("srcaddr", "")
    query_timestamp = dns_event.get("query_timestamp")

    if query_timestamp:
        try:
            timestamp = datetime.fromisoformat(query_timestamp.replace("Z", "+00:00"))
        except ValueError:
            timestamp = datetime.now(UTC)
    else:
        timestamp = datetime.now(UTC)

    event_id = dns_event.get("id") or f"dns-{account_id}-{int(timestamp.timestamp())}"

    return NormalizedSecurityEvent(
        event_id=event_id,
        source="route53",
        timestamp=timestamp,
        account_id=account_id,
        region=region,
        principal_arn=f"instance/{src_ip}"
        if src_ip
        else f"arn:aws:route53:{region}:{account_id}:resolver",
        principal_type="ComputeInstance" if src_ip else "Resolver",
        action="dns:query",
        resource_arns=[f"domain/{query_name}"],
        source_ip=src_ip,
        user_agent=dns_event.get("query_type", "A"),
        status=dns_event.get("rcode", "NOERROR"),
        raw_payload=dns_event,
    )
