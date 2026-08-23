import hashlib
import os
import uuid
from abc import ABC, abstractmethod
from pathlib import Path

from src.core.config import settings


class EvidenceStorage(ABC):
    """Abstract evidence storage provider interface."""

    @abstractmethod
    def save(self, data: bytes, original_filename: str) -> tuple[str, str]:
        """Saves evidence bytes safely and returns (storage_key, sha256_hash)."""
        pass

    @abstractmethod
    def get(self, storage_key: str) -> bytes | None:
        """Retrieves raw evidence bytes using opaque storage key."""
        pass

    @abstractmethod
    def delete(self, storage_key: str) -> bool:
        """Removes stored evidence file."""
        pass


class LocalEvidenceStorage(EvidenceStorage):
    """Local filesystem evidence storage provider."""

    def __init__(
        self,
        base_dir: str | Path | None = None,
        storage_dir: str | Path | None = None,
    ) -> None:
        self.base_dir = Path(storage_dir or base_dir or settings.STORAGE_DIR).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def calculate_sha256(self, data: bytes) -> str:
        """Computes cryptographic SHA-256 hash of raw evidence bytes."""
        return hashlib.sha256(data).hexdigest()

    def save(self, data: bytes, original_filename: str) -> tuple[str, str]:
        """Stores evidence file with opaque UUID key and read/write-only permissions."""
        sha256_hash = self.calculate_sha256(data)
        file_uuid = uuid.uuid4().hex
        storage_key = f"{file_uuid}.eml"
        target_path = self.base_dir / storage_key

        # Write evidence bytes
        with open(target_path, "wb") as f:
            f.write(data)

        # Set read/write only permissions (no execution) on POSIX systems
        try:
            os.chmod(target_path, 0o600)
        except (AttributeError, OSError):
            pass

        return storage_key, sha256_hash

    def get(self, storage_key: str) -> bytes | None:
        """Retrieves evidence bytes, preventing path traversal attacks."""
        # Sanitize storage_key to strictly the filename
        safe_key = Path(storage_key).name
        target_path = (self.base_dir / safe_key).resolve()

        # Ensure path is within base_dir
        if not str(target_path).startswith(str(self.base_dir)):
            return None

        if not target_path.exists() or not target_path.is_file():
            return None

        with open(target_path, "rb") as f:
            return f.read()

    def delete(self, storage_key: str) -> bool:
        """Deletes evidence file."""
        safe_key = Path(storage_key).name
        target_path = (self.base_dir / safe_key).resolve()

        if not str(target_path).startswith(str(self.base_dir)):
            return False

        if target_path.exists() and target_path.is_file():
            target_path.unlink()
            return True
        return False


# Global default evidence storage instance
default_storage = LocalEvidenceStorage()


def get_evidence_storage() -> EvidenceStorage:
    """Dependency injector for evidence storage."""
    return default_storage
