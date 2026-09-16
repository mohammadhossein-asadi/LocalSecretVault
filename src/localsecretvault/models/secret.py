"""Data models for vault secrets."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

class SecretType(str, Enum):
    """Supported secret types."""

    LOGIN = "Login"
    API_KEY = "API Key"
    DATABASE = "Database"
    ENVIRONMENT = "Environment"
    SSH_KEY = "SSH Key"
    SECURE_NOTE = "Secure Note"
    GENERIC = "Generic Secret"

def _new_id() -> str:
    """Generate a new unique identifier."""
    return str(uuid.uuid4())

def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()

@dataclass
class Secret:
    """A single secret entry in the vault."""

    id: str = field(default_factory=_new_id)
    type: str = SecretType.GENERIC.value
    name: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    custom_fields: dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Secret:
        """Deserialize from a dictionary."""
        return cls(
            id=str(data.get("id", _new_id())),
            type=str(data.get("type", SecretType.GENERIC.value)),
            name=str(data.get("name", "")),
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            url=str(data.get("url", "")),
            notes=str(data.get("notes", "")),
            tags=list(data.get("tags", [])),
            custom_fields=dict(data.get("custom_fields", {})),
            created_at=str(data.get("created_at", _now_iso())),
            updated_at=str(data.get("updated_at", _now_iso())),
        )

    def update_timestamp(self) -> None:
        """Update the last-modified timestamp."""
        self.updated_at = _now_iso()

    def matches_search(self, query: str) -> bool:
        """Check if the secret matches a search query (case-insensitive).

        Searches: name, username, url, tags, type, custom field names.
        Does NOT search password or note content for safety.
        """
        query_lower = query.lower()
        searchable = [
            self.name,
            self.username,
            self.url,
            self.type,
            " ".join(self.tags),
            " ".join(self.custom_fields.keys()),
        ]
        return any(query_lower in field.lower() for field in searchable)

def create_secret(secret_type: str, name: str, **kwargs: Any) -> Secret:
    """Factory function to create a secret of the given type."""
    return Secret(type=secret_type, name=name, **kwargs)
