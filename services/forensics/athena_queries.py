"""
Project AEGIS - Amazon Athena Forensic Queries
DDL and analytical SQL queries for investigating immutable incident evidence stored in S3.
"""

from __future__ import annotations


def get_athena_evidence_ddl(
    database: str = "aegis_forensics",
    table: str = "evidence_records",
    bucket: str = "aegis-forensics-vault-lab",
) -> str:
    """Generate Athena table DDL for querying JSON-lines evidence records in S3 Object Lock."""
    return f"""CREATE EXTERNAL TABLE IF NOT EXISTS {database}.{table} (
  evidence_id STRING,
  incident_id STRING,
  timestamp STRING,
  evidence_type STRING,
  source_service STRING,
  account_id STRING,
  region STRING,
  raw_data STRING,
  sha256_checksum STRING,
  retention_days INT
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
WITH SERDEPROPERTIES (
  'ignore.malformed.json' = 'FALSE',
  'dots.in.keys' = 'FALSE',
  'case.insensitive' = 'TRUE'
)
LOCATION 's3://{bucket}/incidents/'
TBLPROPERTIES ('has_encrypted_data'='true');"""


def query_incident_chronology(database: str, table: str, incident_id: str) -> str:
    """SQL query retrieving the complete chronological evidence trail for an incident."""
    safe_incident_id = incident_id.replace("'", "''")
    return f"""SELECT
  evidence_id,
  timestamp,
  evidence_type,
  source_service,
  account_id,
  sha256_checksum
FROM {database}.{table}
WHERE incident_id = '{safe_incident_id}'
ORDER BY timestamp ASC;"""  # noqa: S608


def query_principal_forensic_history(
    database: str, table: str, principal_pattern: str
) -> str:
    """SQL query discovering all incidents and forensic records involving a compromised principal."""
    safe_pattern = principal_pattern.replace("'", "''")
    return f"""SELECT
  incident_id,
  timestamp,
  evidence_type,
  account_id,
  raw_data
FROM {database}.{table}
WHERE raw_data LIKE '%{safe_pattern}%'
ORDER BY timestamp DESC
LIMIT 100;"""  # noqa: S608
