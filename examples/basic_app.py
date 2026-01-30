from fastapi import FastAPI, Depends, APIRouter
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from fastapi_oauth_rbac import FastAPIOAuthRBAC
from fastapi_oauth_rbac.database.models import User, Role, Permission
from fastapi_oauth_rbac.rbac.dependencies import (
    get_current_user,
    requires_permission,
)
from fastapi_oauth_rbac.core.security import hash_password

app = FastAPI(title='Example App')

# Database Setup
SQLALCHEMY_DATABASE_URL = 'sqlite:///./example.db'
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={'check_same_thread': False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db_override():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Initialize Library
auth_lib = FastAPIOAuthRBAC(app, db_session_dependency=get_db_override)
auth_lib.include_auth_router()


@app.on_event('startup')
def startup():
    auth_lib.init_db(engine)

    # Create default roles/permissions for demo
    db = SessionLocal()
    if not db.query(Role).all():
        view_perm = Permission(name='items:read', description='Can view items')
        edit_perm = Permission(
            name='items:update', description='Can edit items'
        )
        db.add_all([view_perm, edit_perm])

        user_role = Role(
            name='user', description='Default user', permissions=[view_perm]
        )
        admin_role = Role(
            name='admin',
            description='Admin user',
            permissions=['*'],
        )
        db.add_all([user_role, admin_role])

        # Default user: admin@example.com / password123
        admin_user = User(
            email='admin@example.com',
            hashed_password=hash_password('password123'),
            is_superuser=True,
            roles=[admin_role],
        )
        db.add(admin_user)
        db.commit()
    db.close()


@app.get('/')
def read_root():
    return {'message': 'Welcome to the fastapi-oauth-rbac example!'}


@app.get('/me')
def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        'email': current_user.email,
        'roles': [r.name for r in current_user.roles],
    }


@app.get('/protected', dependencies=[requires_permission('items:edit')])
def protected_route():
    return {'message': "You have 'items:edit' permission!"}


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8000)
