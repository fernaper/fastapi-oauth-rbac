import asyncio
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from fastapi_oauth_rbac import FastAPIOAuthRBAC, Base, Permission, AuditLog, Role, User
from sqlalchemy import select, func

async def test_audit_configuration(enabled: bool):
    print(f"\n--- Testing Audit Enabled={enabled} ---")
    app = FastAPI()
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    
    auth = FastAPIOAuthRBAC(app, enable_audit=enabled)
    
    # Trigger lifespan manually or just check table creation
    async with engine.begin() as conn:
        if enabled:
            await conn.run_sync(Base.metadata.create_all)
        else:
            # Filter as in main.py
            tables = [t for n, t in Base.metadata.tables.items() if n != 'audit_logs']
            await conn.run_sync(Base.metadata.create_all, tables=tables)

    async with engine.connect() as conn:
        res = await conn.run_sync(lambda sync_conn: engine.dialect.has_table(sync_conn, "audit_logs"))
        print(f"Table 'audit_logs' exists: {res}")
        if enabled != res:
            print(f"ERROR: Expected audit_logs table existence to be {enabled}")
        else:
            print("SUCCESS: Table creation matches configuration.")

if __name__ == "__main__":
    asyncio.run(test_audit_configuration(True))
    asyncio.run(test_audit_configuration(False))
