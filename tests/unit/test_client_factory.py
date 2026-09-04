"""Unit tests for AWS Boto3 client factory."""

import pytest

from services.common.client_factory import SECURE_BOTO_CONFIG, get_aws_client


@pytest.mark.unit
def test_client_factory_configuration() -> None:
    """Verify that clients are configured with adaptive retries and secure timeouts."""
    assert SECURE_BOTO_CONFIG.retries["max_attempts"] == 5
    assert SECURE_BOTO_CONFIG.retries["mode"] == "adaptive"
    assert SECURE_BOTO_CONFIG.connect_timeout == 5
    assert SECURE_BOTO_CONFIG.read_timeout == 15


@pytest.mark.unit
def test_client_instantiation_without_credentials() -> None:
    """Verify client initialization does not fail during factory instantiation."""
    # Instantiating client without active API calls
    client = get_aws_client("sts", region_name="us-east-1")
    assert client is not None
    assert client.meta.region_name == "us-east-1"
