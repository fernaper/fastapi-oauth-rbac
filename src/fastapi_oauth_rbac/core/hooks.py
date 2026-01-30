from typing import Callable, Any, List, Dict, Optional, Awaitable
from ..database.models import User

# Hook types
HookFunc = Callable[[User, Any], Awaitable[None]]


class EventHooks:
    def __init__(self):
        self._hooks: Dict[str, List[HookFunc]] = {
            'post_signup': [],
            'post_login': [],
            'post_password_reset': [],
            'post_email_verify': [],
        }

    def register(self, event: str, func: HookFunc):
        if event in self._hooks:
            self._hooks[event].append(func)
        else:
            raise ValueError(f'Unknown event: {event}')

    async def trigger(self, event: str, user: User, **kwargs):
        if event in self._hooks:
            for hook in self._hooks[event]:
                await hook(user, **kwargs)


hooks = EventHooks()
