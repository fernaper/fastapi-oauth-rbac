import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi_oauth_rbac.database.models import Base, User, Role, Permission
from fastapi_oauth_rbac.rbac.manager import RBACManager


def test_rbac_hierarchy():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    # Create permissions: Admin > Manage > View
    view_p = Permission(name='view')
    manage_p = Permission(name='manage', children=[view_p])
    admin_p = Permission(name='admin', children=[manage_p])
    db.add_all([view_p, manage_p, admin_p])

    role = Role(name='manager_role', permissions=[manage_p])
    user = User(email='mgr@example.com', roles=[role])
    db.add_all([role, user])
    db.commit()

    rbac = RBACManager(db)

    # Manager should have 'manage' and 'view'
    perms = rbac.get_user_permissions(user)
    assert 'manage' in perms
    assert 'view' in perms
    assert 'admin' not in perms

    assert rbac.has_permission(user, 'view') is True
    assert rbac.has_permission(user, 'admin') is False

    db.close()
