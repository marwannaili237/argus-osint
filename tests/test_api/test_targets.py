import pytest
class TestTargetSchemas:
    def test_target_create_requires_value(self):
        from argus.schemas.target import TargetCreate
        with pytest.raises(Exception):
            TargetCreate()
    def test_target_create_with_value(self):
        from argus.schemas.target import TargetCreate
        t = TargetCreate(value="example.com")
        assert t.value == "example.com"
    def test_target_response_fields(self):
        from argus.schemas.target import TargetResponse
        resp = TargetResponse(id=1, type="domain", value="example.com", status="pending", priority=0, created_at="", updated_at="", metadata_={})
        assert resp.id == 1
    def test_target_list_pagination(self):
        from argus.schemas.target import TargetListResponse
        resp = TargetListResponse(items=[], total=0, page=1, per_page=20)
        assert resp.total == 0
    def test_router_exists(self):
        from argus.api.targets import router
        assert router is not None
