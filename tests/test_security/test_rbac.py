import pytest
class TestRBAC:
    def test_permissions(self):
        from argus.security.rbac import Permission
        perms = list(Permission)
        assert len(perms) >= 8
        assert Permission.READ in perms
    def test_role_perms(self):
        from argus.security.rbac import ROLE_PERMISSIONS
        assert "admin" in ROLE_PERMISSIONS
        assert "viewer" in ROLE_PERMISSIONS
        assert len(ROLE_PERMISSIONS["admin"]) > len(ROLE_PERMISSIONS["viewer"])
    def test_admin_all(self):
        from argus.security.rbac import ROLE_PERMISSIONS, Permission
        for p in Permission:
            assert p in ROLE_PERMISSIONS["admin"]
