"""Validation package: the KQL, ARM-operation, and shell-script validators
that check generated detection artifacts before they are deployed or run."""

from .operation import operation_status, validate_operation
from .playbook_check import PlaybookCheck, check_playbook, fence_bare_kql
from .sanitize import is_allowed_doc_url, sanitize_service
from .schemas import FLAT_TABLES, PLAIN_STRING_FIELDS, TABLE_SCHEMAS
from .script_check import ParseResult, parse_check
from .validate_kql import ValidationResult, extract_query_table, validate_kql

__all__ = [
    "FLAT_TABLES",
    "PLAIN_STRING_FIELDS",
    "TABLE_SCHEMAS",
    "ParseResult",
    "PlaybookCheck",
    "ValidationResult",
    "check_playbook",
    "fence_bare_kql",
    "extract_query_table",
    "is_allowed_doc_url",
    "operation_status",
    "parse_check",
    "sanitize_service",
    "validate_kql",
    "validate_operation",
]
