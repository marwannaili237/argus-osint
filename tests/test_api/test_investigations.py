import pytest
class TestInvestigationSchemas:
    def test_create(self):
        from argus.schemas.investigation import InvestigationCreate
        inv = InvestigationCreate(name="Test", description="Desc")
        assert inv.name == "Test"
    def test_with_tags(self):
        from argus.schemas.investigation import InvestigationCreate
        inv = InvestigationCreate(name="Test", tags=["osint", "phishing"])
        assert len(inv.tags) == 2
    def test_response_tlp(self):
        from argus.schemas.investigation import InvestigationResponse
        resp = InvestigationResponse(id=1, name="T", description="", status="active", priority=0, created_at="", updated_at="", tags=[], classification="TLP:CLEAR", access_groups=[])
        assert resp.classification == "TLP:CLEAR"
    def test_list_response(self):
        from argus.schemas.investigation import InvestigationListResponse
        resp = InvestigationListResponse(items=[], total=0, page=1)
        assert resp.total == 0
    def test_router_exists(self):
        from argus.api.investigations import router
        assert router is not None
