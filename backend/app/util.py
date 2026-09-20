"""Utilidades comunes."""
from datetime import datetime, timezone


def utcnow() -> datetime:
    """Fecha y hora actual en UTC, sin zona horaria (compatible con las columnas de la base)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
