from typing import Optional

from fastapi import FastAPI, Depends
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from fastapi_oauth_rbac import (
    FastAPIOAuthRBAC,
    UserBaseMixin,
    Base,
    BaseEmailExporter,
    get_current_user,
)


# 1. Custom User Model
# You can extend our UserBaseMixin to add your own fields
class MyCustomUser(Base, UserBaseMixin):
    __tablename__ = 'users'  # Use the same table name or a different one

    phone: Mapped[Optional[str]] = mapped_column(String(20))
    bio: Mapped[Optional[str]] = mapped_column(String(500))

    # You must define roles relationship if you override the class
    from fastapi_oauth_rbac.database.models import user_roles, Role

    roles: Mapped[list[Role]] = relationship(secondary=user_roles)


# 2. Custom Email Service
class SendGridSimulator(BaseEmailExporter):
    async def send_verification_email(self, user: MyCustomUser, token: str):
        print(f'DEBUG: Calling SendGrid API for {user.email}')
        print(f'DEBUG: Link: https://myapp.com/verify?token={token}')

    async def send_password_reset_email(self, user: MyCustomUser, token: str):
        print(f'DEBUG: Sending Password Reset via SendGrid to {user.email}')


app = FastAPI(title='Advanced Extension Example')

# 3. Initialize with Custom User and Email Service
auth = FastAPIOAuthRBAC(
    app, user_model=MyCustomUser, email_exporter=SendGridSimulator()
)
auth.include_auth_router()


# 4. Using Event Hooks
@auth.hooks.register('post_signup')
async def on_signup(user: MyCustomUser, **kwargs):
    print(f'HOOK: User {user.email} signed up!')
    # Maybe add them to a mailing list or create a 'Profile' record
    print(f"HOOK: Custom field 'phone' is: {user.phone}")


@auth.hooks.register('post_login')
async def on_login(user: MyCustomUser, **kwargs):
    print(f'HOOK: User {user.email} logged in. Tracking analytics...')


@app.get('/profile')
async def get_profile(user: MyCustomUser = Depends(get_current_user)):
    return {
        'email': user.email,
        'phone': user.phone,
        'bio': user.bio,
        'is_verified': user.is_verified,
    }


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8002)
