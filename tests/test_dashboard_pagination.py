import pytest

from fastapi_oauth_rbac.database.models import Base, User, Role
from fastapi_oauth_rbac.dashboard.router import dashboard_index
from fastapi import Request
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
    AsyncSession,
)
from sqlalchemy.orm import selectinload
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_dashboard_pagination_and_filtering():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    AsyncSessionLocal = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )

    async with AsyncSessionLocal() as db:
        # Create roles
        admin_role = Role(name='admin')
        user_role = Role(name='user')
        db.add_all([admin_role, user_role])
        await db.commit()

        # Create multiple users
        users = []
        for i in range(25):
            email = f'user{i}@example.com'
            is_active = i % 2 == 0
            is_verified = i % 3 == 0
            roles = [admin_role] if i < 5 else [user_role]
            user = User(
                email=email,
                is_active=is_active,
                is_verified=is_verified,
                roles=roles,
            )
            users.append(user)
        db.add_all(users)
        await db.commit()

        # Mock Request
        class MockApp:
            def __init__(self):
                self.state = type('state', (), {'oauth_rbac': None})()

        mock_request = type(
            'Request',
            (),
            {
                'app': MockApp(),
                'url_for': lambda name, **path_params: f'/{name}',
            },
        )()

        current_user = users[0]

        with patch(
            'fastapi_oauth_rbac.dashboard.router.RBACManager'
        ) as MockRBAC:
            rbac_mock = AsyncMock()
            rbac_mock.has_permission.return_value = True
            rbac_mock.get_user_permissions.return_value = ['dashboard:view']
            MockRBAC.return_value = rbac_mock

            with patch(
                'fastapi_oauth_rbac.dashboard.router.templates.TemplateResponse'
            ) as MockTemplate:
                # 1. Test Default Pagination (Page 0, PageSize 10)
                await dashboard_index(
                    mock_request, db, current_user, pageSize=10, page=0
                )
                args, kwargs = MockTemplate.call_args
                context = args[1]
                assert len(context['users']) == 10
                assert context['total_users'] == 25
                assert context['filtered_users'] == 25
                assert context['page'] == 0

                # 2. Test Page 2
                await dashboard_index(
                    mock_request, db, current_user, pageSize=10, page=2
                )
                args, kwargs = MockTemplate.call_args
                context = args[1]
                assert len(context['users']) == 5
                assert context['page'] == 2

                # 3. Test Filter by Email (user1 -> matching user1, user10-19)
                await dashboard_index(
                    mock_request, db, current_user, filter='user1'
                )
                args, kwargs = MockTemplate.call_args
                context = args[1]
                assert context['filtered_users'] == 11

                # 4. Test Filter by Status (active -> i % 2 == 0)
                await dashboard_index(
                    mock_request, db, current_user, filter='active'
                )
                args, kwargs = MockTemplate.call_args
                context = args[1]
                # 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24 -> 13 users
                assert context['filtered_users'] == 13

                # 5. Test Filter by Verified (verified -> i % 3 == 0)
                await dashboard_index(
                    mock_request, db, current_user, filter='verified'
                )
                args, kwargs = MockTemplate.call_args
                context = args[1]
                # 0, 3, 6, 9, 12, 15, 18, 21, 24 -> 9 users
                assert context['filtered_users'] == 9

                # 6. Test Filter by Role (admin -> first 5 users)
                await dashboard_index(
                    mock_request, db, current_user, filter='admin'
                )
                args, kwargs = MockTemplate.call_args
                context = args[1]
                assert context['filtered_users'] == 5

    await engine.dispose()
