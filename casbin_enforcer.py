import casbin
import os
from pathlib import Path

class CasbinEnforcer:
    _instance = None
    _enforcer = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._enforcer is None:
            model_path = Path(__file__).parent / "model.conf"
            policy_path = Path(__file__).parent / "policy.csv"
            self._enforcer = casbin.Enforcer(str(model_path), str(policy_path))

    def enforce(self, role: str, resource: str, action: str) -> bool:
        return self._enforcer.enforce(role, resource, action)

    def add_role_for_user(self, user: str, role: str) -> bool:
        return self._enforcer.add_role_for_user(user, role)

    def get_roles_for_user(self, user: str):
        return self._enforcer.get_roles_for_user(user)


casbin_enforcer = CasbinEnforcer()