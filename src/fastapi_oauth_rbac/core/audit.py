from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..database.models import AuditLog


class AuditManager:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def log(
        self,
        actor_email: str,
        action: str,
        target: Optional[str] = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = None,
    ):
        """Create an audit log entry."""
        log_entry = AuditLog(
            actor_email=actor_email,
            action=action,
            target=target,
            details=details,
            ip_address=ip_address,
        )
        self.db.add(log_entry)
        await self.db.commit()
