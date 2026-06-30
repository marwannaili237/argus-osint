import pytest
class TestInvestigation:
    def test_fields(self):
        from argus.models.investigation import Investigation
        for f in ["id", "name", "classification", "access_groups"]:
            assert hasattr(Investigation, f)
    def test_tlp(self):
        for level in ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"]:
            assert level.startswith("TLP:")
