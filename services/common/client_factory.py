"""Centralized AWS Boto3 client factory with adaptive retries and secure configuration."""

import os
from typing import Any

import boto3
from botocore.config import Config

DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

SECURE_BOTO_CONFIG = Config(
    region_name=DEFAULT_REGION,
    retries={
        "max_attempts": 5,
        "mode": "adaptive",
    },
    connect_timeout=5,
    read_timeout=15,
)


def get_aws_client(
    service_name: str,
    region_name: str | None = None,
    session: boto3.Session | None = None,
    custom_config: Config | None = None,
) -> Any:
    """Instantiate a configured Boto3 client enforcing adaptive retry and timeout standards."""
    active_session = session or boto3.Session()
    config = custom_config or SECURE_BOTO_CONFIG
    if region_name:
        config = config.merge(Config(region_name=region_name))
    return active_session.client(service_name, config=config)
