import hashlib
import tempfile
from pathlib import Path

from src.services.storage import LocalEvidenceStorage


def test_local_evidence_storage_save_and_retrieve():
    """Verify LocalEvidenceStorage writes file, calculates correct SHA-256, and retrieves bytes."""
    with tempfile.TemporaryDirectory() as temp_dir:
        storage = LocalEvidenceStorage(base_dir=temp_dir)

        test_data = b"From: attacker@evil.com\r\nTo: victim@target.com\r\nSubject: Invoice\r\n\r\nMalicious content"
        expected_sha = hashlib.sha256(test_data).hexdigest()

        storage_key, sha256_hash = storage.save(test_data, "invoice.eml")

        assert sha256_hash == expected_sha
        assert storage_key.endswith(".eml")
        assert Path(temp_dir, storage_key).exists()

        # Retrieve bytes
        retrieved = storage.get(storage_key)
        assert retrieved == test_data

        # Verify deletion
        assert storage.delete(storage_key) is True
        assert storage.get(storage_key) is None


def test_storage_path_traversal_protection():
    """Verify LocalEvidenceStorage rejects path traversal keys."""
    with tempfile.TemporaryDirectory() as temp_dir:
        storage = LocalEvidenceStorage(base_dir=temp_dir)

        # Attempt to access non-existent or traversed keys
        assert storage.get("../../etc/passwd") is None
        assert storage.get("..\\..\\windows\\win.ini") is None
        assert storage.delete("../../../some_file.eml") is False
