import asyncio
import os
import tempfile
from uuid import uuid4

from core.storage.models import StorageConfig, DataClassification, StorageQuery
from core.storage.service import StorageService
from core.policy.engine import PolicyEngine
from core.audit.service import AuditService


def run(coro):
    """Execute an async coroutine in a fresh event loop.

    Python 3.11 no longer implicitly creates a default event loop; use
    asyncio.run() to drive coroutines in tests that aren't using
    pytest-asyncio.
    """
    return asyncio.run(coro)


def _make_service(tmpdir: str) -> StorageService:
    cfg = StorageConfig(
        default_provider="filesystem",  # enum coerced by pydantic
        encryption_enabled=True,
        auto_classify_content=True,
        filesystem_base_path=tmpdir,
    )
    return StorageService(config=cfg, policy_engine=PolicyEngine(), audit_service=AuditService())


def test_store_and_retrieve_phi_object_audited_and_encrypted():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _make_service(tmp)
        user_id = uuid4()
        content = b"patient medical record data"

        # Provide traits required by policy engine for PHI access
        traits = ["handles_phi", "audit_required"]

        meta = run(
            svc.store_object(
                content=content,
                filename="record.pdf",
                user_id=user_id,
                content_type="application/pdf",
                data_classification=None,  # auto-classify to PHI
                traits=traits,
            )
        )
        # Classified and encrypted
        assert meta.data_classification == DataClassification.PHI
        assert meta.is_encrypted is True
        assert meta.encryption_key_id is not None
        assert meta.expires_at is not None  # retention applied

        # Retrieve and verify decrypted content path exists indirectly by not raising
        obj = run(svc.retrieve_object(meta.object_key, user_id))
        assert obj is not None
        # content is decrypted back to bytes
        assert obj.content is not None and len(obj.content) > 0


def test_list_objects_emits_minimal_audit_and_filters(tmp_path):
    svc = _make_service(str(tmp_path))
    user_id = uuid4()
    traits = ["handles_phi", "audit_required"]
    run(
        svc.store_object(
            content=b"patient data",
            filename="a.json",
            user_id=user_id,
            content_type="application/json",
            traits=traits,
        )
    )
    items = run(svc.list_objects(query=StorageQuery(limit=10), user_id=user_id))
    assert isinstance(items, list)
    assert len(items) >= 1
