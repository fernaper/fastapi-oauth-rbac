from abc import ABC, abstractmethod
from typing import Set, Union


class Requirement(ABC):
    @abstractmethod
    def evaluate(self, user_permissions: Set[str]) -> bool:
        """Evaluate the requirement against a set of user permissions."""
        pass

    @abstractmethod
    def get_permission_names(self) -> Set[str]:
        """Return all permission names involved in this requirement."""
        pass


class Permission(Requirement):
    def __init__(self, name: str):
        self.name = name

    def evaluate(self, user_permissions: Set[str]) -> bool:
        # Check for exact match or wildcard match
        if self.name in user_permissions:
            return True

        if '*' in user_permissions:
            return True

        # Check for prefix:* matches
        for up in user_permissions:
            if up.endswith(':*'):
                prefix = up[:-2]
                if self.name.startswith(prefix + ':'):
                    return True
        return False

    def get_permission_names(self) -> Set[str]:
        return {self.name}


class And(Requirement):
    def __init__(self, *requirements: Union[str, Requirement]):
        self.requirements = [
            r if isinstance(r, Requirement) else Permission(r)
            for r in requirements
        ]

    def evaluate(self, user_permissions: Set[str]) -> bool:
        return all(r.evaluate(user_permissions) for r in self.requirements)

    def get_permission_names(self) -> Set[str]:
        names = set()
        for r in self.requirements:
            names.update(r.get_permission_names())
        return names


class Or(Requirement):
    def __init__(self, *requirements: Union[str, Requirement]):
        self.requirements = [
            r if isinstance(r, Requirement) else Permission(r)
            for r in requirements
        ]

    def evaluate(self, user_permissions: Set[str]) -> bool:
        return any(r.evaluate(user_permissions) for r in self.requirements)

    def get_permission_names(self) -> Set[str]:
        names = set()
        for r in self.requirements:
            names.update(r.get_permission_names())
        return names


class Not(Requirement):
    def __init__(self, requirement: Union[str, Requirement]):
        self.requirement = (
            requirement
            if isinstance(requirement, Requirement)
            else Permission(requirement)
        )

    def evaluate(self, user_permissions: Set[str]) -> bool:
        return not self.requirement.evaluate(user_permissions)

    def get_permission_names(self) -> Set[str]:
        return self.requirement.get_permission_names()
