"""The Key Vault operation catalogue against Microsoft's own table.

Source: https://learn.microsoft.com/en-us/azure/key-vault/general/logging
        the "operationName values and corresponding REST API commands" table,
        four tabs: Vault, Keys, Secrets, Certificates. Checked 2026-09-09.

Two catalogues carry these names and they had drifted apart AND from the docs.
`service_files/microsoft-keyvault-vaults.json` is reference; the YAML is what
actually reaches the model. The YAML held 29 of the 78 documented operations
and NONE of the six vault ones, so the data-plane track could not produce an
access-policy detection at all -- there was no operation to hang it on.
"""

from __future__ import annotations

import json
import pathlib

import pytest
import yaml

# Transcribed from the four tabs of the operationName table.
DOCUMENTED = {
    "vault": ["Authentication", "VaultGet", "VaultPut", "VaultDelete",
              "VaultPatch", "VaultRecover",
              "VaultAccessPolicyChangedEventGridNotification"],
    "keys": ["KeyCreate", "KeyGet", "KeyImport", "KeyDelete", "KeySign",
             "KeyVerify", "KeyWrap", "KeyUnwrap", "KeyEncrypt", "KeyDecrypt",
             "KeyUpdate", "KeyList", "KeyListVersions", "KeyPurge", "KeyBackup",
             "KeyRestore", "KeyRecover", "KeyGetDeleted", "KeyListDeleted",
             "KeyNearExpiryEventGridNotification",
             "KeyExpiredEventGridNotification", "KeyRotate", "KeyRotateIfDue",
             "KeyRotationPolicyGet", "KeyRotationPolicySet"],
    "secrets": ["SecretSet", "SecretGet", "SecretUpdate", "SecretDelete",
                "SecretList", "SecretListVersions", "SecretPurge",
                "SecretBackup", "SecretRestore", "SecretRecover",
                "SecretGetDeleted", "SecretListDeleted",
                "SecretNearExpiryEventGridNotification",
                "SecretExpiredEventGridNotification"],
    "certificates": ["CertificateGet", "CertificateCreate", "CertificateImport",
                     "CertificateUpdate", "CertificateList",
                     "CertificateListVersions", "CertificateDelete",
                     "CertificatePurge", "CertificateBackup",
                     "CertificateRestore", "CertificateRecover",
                     "CertificateGetDeleted", "CertificateListDeleted",
                     "CertificatePolicyGet", "CertificatePolicyUpdate",
                     "CertificatePolicySet", "CertificateContactsGet",
                     "CertificateContactsSet", "CertificateContactsDelete",
                     "CertificateIssuerGet", "CertificateIssuerSet",
                     "CertificateIssuerUpdate", "CertificateIssuerDelete",
                     "CertificateIssuersList", "CertificateEnroll",
                     "CertificateRenew", "CertificatePendingGet",
                     "CertificatePendingMerge", "CertificatePendingUpdate",
                     "CertificatePendingDelete",
                     "CertificateNearExpiryEventGridNotification",
                     "CertificateExpiredEventGridNotification"],
}
ALL = {name for group in DOCUMENTED.values() for name in group}


def _yaml_ops() -> dict:
    doc = yaml.safe_load(
        pathlib.Path("src/pylon/catalog/data-plane-operations.yaml")
        .read_text(encoding="utf-8"))
    return doc["tables"]["AZKVAuditLogs"]["operations"]


def _service_file_ops() -> dict:
    doc = json.loads(
        pathlib.Path("src/pylon/catalog/service_files/"
                     "microsoft-keyvault-vaults.json").read_text(encoding="utf-8"))
    return doc["tables"]["AZKVAuditLogs"]["operations"]


def test_the_generation_catalogue_has_every_documented_operation():
    missing = sorted(ALL - set(_yaml_ops()))
    assert not missing, f"{len(missing)} documented operations absent: {missing}"


def test_the_service_file_has_every_documented_operation():
    have = {n for group in _service_file_ops().values() for n in group}
    assert not sorted(ALL - have)


def test_the_two_catalogues_agree():
    """They are transcribed from one table and had drifted apart. One rots
    quietly; two rot quietly and disagree."""
    have = {n for group in _service_file_ops().values() for n in group}
    assert have == set(_yaml_ops())


def test_neither_catalogue_invents_an_operation():
    """A name the docs table does not carry is a name the log will never hold,
    and a detection filtering on it is silently dead."""
    assert not sorted(set(_yaml_ops()) - ALL)
    have = {n for group in _service_file_ops().values() for n in group}
    assert not sorted(have - ALL)


@pytest.mark.parametrize("name", DOCUMENTED["vault"])
def test_every_vault_operation_is_present(name):
    """The group that was missing entirely, and the one the question was about.
    An access policy change is logged three ways -- VaultPut, VaultPatch, and a
    dedicated notification Microsoft publishes whether or not anyone subscribed
    to Event Grid."""
    assert name in _yaml_ops()


def test_the_access_policy_notification_is_marked_sensitive():
    op = _yaml_ops()["VaultAccessPolicyChangedEventGridNotification"]
    assert op["sensitive"] is True
    assert "Event Grid" in op["desc"], "the 'logged regardless' clause is the point"


def test_every_operation_carries_a_verb_and_a_description():
    for name, meta in _yaml_ops().items():
        assert meta.get("verb") in {"read", "list", "write", "delete", "crypto"}, name
        assert isinstance(meta.get("sensitive"), bool), name
        assert meta.get("desc", "").strip(), name
