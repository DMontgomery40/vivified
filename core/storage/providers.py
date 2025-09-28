"""
Storage providers for different backends (filesystem, S3, etc.).
"""

import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import AsyncIterator, List, Optional

import aiofiles
import aiofiles.os

from .models import StorageObject, StorageMetadata, StorageProvider, StorageQuery


class StorageProviderBase(ABC):
    """Abstract base class for storage providers."""

    @abstractmethod
    async def store_object(self, storage_object: StorageObject) -> StorageMetadata:
        """Store an object and return updated metadata."""
        pass

    @abstractmethod
    async def retrieve_object(self, object_key: str) -> Optional[StorageObject]:
        """Retrieve an object by key."""
        pass

    @abstractmethod
    async def delete_object(self, object_key: str) -> bool:
        """Delete an object by key."""
        pass

    @abstractmethod
    async def list_objects(self, query: StorageQuery) -> List[StorageMetadata]:
        """List objects matching query criteria."""
        pass

    @abstractmethod
    async def object_exists(self, object_key: str) -> bool:
        """Check if object exists."""
        pass

    @abstractmethod
    async def get_object_metadata(self, object_key: str) -> Optional[StorageMetadata]:
        """Get object metadata without content."""
        pass


class FilesystemProvider(StorageProviderBase):
    """
    Filesystem storage provider with directory-based organization.

    Organizes files by data classification and date for efficient management.
    """

    def __init__(self, base_path: str = "/var/lib/vivified/storage"):
        """Initialize filesystem provider."""
        self.base_path = Path(base_path)
        self.metadata_suffix = ".meta"

    async def _ensure_directory(self, path: Path) -> None:
        """Ensure directory exists."""
        await aiofiles.os.makedirs(path, exist_ok=True)

    def _get_object_path(self, metadata: StorageMetadata) -> Path:
        """Get filesystem path for object based on classification and date."""
        # Organize by classification and year/month for efficient management
        date_path = metadata.created_at.strftime("%Y/%m")
        classification_path = (
            self.base_path / metadata.data_classification.value / date_path
        )

        # Use secure filename from metadata
        from .encryption import StorageEncryption

        encryption = StorageEncryption()
        secure_filename = encryption.create_secure_filename(
            metadata.original_filename or "unknown", str(metadata.id)
        )

        return classification_path / secure_filename

    def _get_metadata_path(self, object_path: Path) -> Path:
        """Get metadata file path for object."""
        return object_path.with_suffix(object_path.suffix + self.metadata_suffix)

    async def store_object(self, storage_object: StorageObject) -> StorageMetadata:
        """Store object and metadata to filesystem."""
        if storage_object.content is None:
            raise ValueError("Content is required for filesystem storage")

        # Update provider info
        storage_object.metadata.provider = StorageProvider.FILESYSTEM

        # Get storage paths
        object_path = self._get_object_path(storage_object.metadata)
        metadata_path = self._get_metadata_path(object_path)

        # Ensure directory exists
        await self._ensure_directory(object_path.parent)

        # Store object content
        storage_object.metadata.provider_path = str(object_path)

        async with aiofiles.open(object_path, "wb") as f:
            await f.write(storage_object.content)

        # Store metadata
        metadata_json = storage_object.metadata.json()
        async with aiofiles.open(metadata_path, "w") as f:
            await f.write(metadata_json)

        return storage_object.metadata

    async def retrieve_object(self, object_key: str) -> Optional[StorageObject]:
        """Retrieve object from filesystem."""
        # Find object by scanning metadata files
        metadata = await self.get_object_metadata(object_key)
        if not metadata:
            return None

        object_path = Path(metadata.provider_path)
        if not await aiofiles.os.path.exists(object_path):
            return None

        # Read content
        async with aiofiles.open(object_path, "rb") as f:
            content = await f.read()

        return StorageObject(metadata=metadata, content=content)

    async def delete_object(self, object_key: str) -> bool:
        """Delete object and metadata from filesystem."""
        metadata = await self.get_object_metadata(object_key)
        if not metadata:
            return False

        object_path = Path(metadata.provider_path)
        metadata_path = self._get_metadata_path(object_path)

        try:
            # Delete object file
            if await aiofiles.os.path.exists(object_path):
                await aiofiles.os.remove(object_path)

            # Delete metadata file
            if await aiofiles.os.path.exists(metadata_path):
                await aiofiles.os.remove(metadata_path)

            return True
        except Exception:
            return False

    async def list_objects(self, query: StorageQuery) -> List[StorageMetadata]:
        """List objects by scanning metadata files."""
        results = []

        # Scan base directory for metadata files
        for classification_dir in self.base_path.iterdir():
            if not classification_dir.is_dir():
                continue

            async for metadata in self._scan_metadata_files(classification_dir, query):
                results.append(metadata)

        # Apply additional filtering
        results = self._filter_results(results, query)

        # Apply pagination
        start = query.offset
        end = start + query.limit
        return results[start:end]

    async def _scan_metadata_files(
        self, directory: Path, query: StorageQuery
    ) -> AsyncIterator[StorageMetadata]:
        """Scan directory for metadata files matching query."""
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(self.metadata_suffix):
                    metadata_path = Path(root) / file
                    try:
                        async with aiofiles.open(metadata_path, "r") as f:
                            metadata_json = await f.read()
                        metadata = StorageMetadata.parse_raw(metadata_json)

                        # Basic filtering
                        if self._matches_query(metadata, query):
                            yield metadata
                    except Exception:
                        # Skip corrupted metadata files
                        continue

    def _matches_query(self, metadata: StorageMetadata, query: StorageQuery) -> bool:
        """Check if metadata matches query criteria."""
        if query.object_keys and metadata.object_key not in query.object_keys:
            return False

        if (
            query.data_classification
            and metadata.data_classification != query.data_classification
        ):
            return False

        if query.traits and not any(trait in metadata.traits for trait in query.traits):
            return False

        if query.created_by and metadata.created_by != query.created_by:
            return False

        if query.created_after and metadata.created_at < query.created_after:
            return False

        if query.created_before and metadata.created_at > query.created_before:
            return False

        if query.content_type and metadata.content_type != query.content_type:
            return False

        if query.expired_only and not metadata.expires_at:
            return False

        return True

    def _filter_results(
        self, results: List[StorageMetadata], query: StorageQuery
    ) -> List[StorageMetadata]:
        """Apply additional filtering and sorting."""
        # Sort by creation date (newest first)
        results.sort(key=lambda x: x.created_at, reverse=True)
        return results

    async def object_exists(self, object_key: str) -> bool:
        """Check if object exists on filesystem."""
        metadata = await self.get_object_metadata(object_key)
        if not metadata:
            return False

        object_path = Path(metadata.provider_path)
        return await aiofiles.os.path.exists(object_path)

    async def get_object_metadata(self, object_key: str) -> Optional[StorageMetadata]:
        """Get object metadata by scanning filesystem."""
        # This is inefficient for large datasets - in production, use a database index
        for classification_dir in self.base_path.iterdir():
            if not classification_dir.is_dir():
                continue

            for root, dirs, files in os.walk(classification_dir):
                for file in files:
                    if file.endswith(self.metadata_suffix):
                        metadata_path = Path(root) / file
                        try:
                            async with aiofiles.open(metadata_path, "r") as f:
                                metadata_json = await f.read()
                            metadata = StorageMetadata.parse_raw(metadata_json)

                            if metadata.object_key == object_key:
                                return metadata
                        except Exception:
                            continue

        return None


class S3Provider(StorageProviderBase):
    """
    S3-compatible storage provider.

    Note: This is a placeholder implementation. In production, use aiobotocore
    or similar async S3 client.
    """

    def __init__(
        self, bucket: str, region: str = "us-east-1", endpoint_url: Optional[str] = None
    ):
        """Initialize S3 provider."""
        self.bucket = bucket
        self.region = region
        self.endpoint_url = endpoint_url
        # In production: initialize aiobotocore session here

    async def store_object(self, storage_object: StorageObject) -> StorageMetadata:
        """Store object to S3."""
        # Placeholder - implement with aiobotocore
        raise NotImplementedError("S3 provider not yet implemented")

    async def retrieve_object(self, object_key: str) -> Optional[StorageObject]:
        """Retrieve object from S3."""
        # Placeholder - implement with aiobotocore
        raise NotImplementedError("S3 provider not yet implemented")

    async def delete_object(self, object_key: str) -> bool:
        """Delete object from S3."""
        # Placeholder - implement with aiobotocore
        raise NotImplementedError("S3 provider not yet implemented")

    async def list_objects(self, query: StorageQuery) -> List[StorageMetadata]:
        """List objects from S3."""
        # Placeholder - implement with aiobotocore
        raise NotImplementedError("S3 provider not yet implemented")

    async def object_exists(self, object_key: str) -> bool:
        """Check if object exists in S3."""
        # Placeholder - implement with aiobotocore
        raise NotImplementedError("S3 provider not yet implemented")

    async def get_object_metadata(self, object_key: str) -> Optional[StorageMetadata]:
        """Get object metadata from S3."""
        # Placeholder - implement with aiobotocore
        raise NotImplementedError("S3 provider not yet implemented")
