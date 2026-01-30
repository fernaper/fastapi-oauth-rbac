from abc import ABC, abstractmethod
from typing import Optional
from ..database.models import User


class BaseEmailExporter(ABC):
    """
    Base class for sending emails.
    Users should subclass this to implement their preferred provider (SendGrid, Mailgun, SMTP, etc.)
    """

    @abstractmethod
    async def send_verification_email(self, user: User, token: str):
        """Send an email to verify the user's account."""
        pass

    @abstractmethod
    async def send_password_reset_email(self, user: User, token: str):
        """Send an email to reset the user's password."""
        pass


class ConsoleEmailExporter(BaseEmailExporter):
    """Default exporter that just prints to the console (for development)."""

    async def send_verification_email(self, user: User, token: str):
        print('\n--- [EMAIL SIMULATION: VERIFICATION] ---')
        print(f'To: {user.email}')
        print(f'Token: {token}')
        print('---------------------------------------\n')

    async def send_password_reset_email(self, user: User, token: str):
        print('\n--- [EMAIL SIMULATION: PASSWORD RESET] ---')
        print(f'To: {user.email}')
        print(f'Token: {token}')
        print('-----------------------------------------\n')
