import pytest
class TestConfig:
    def test_import(self):
        from argus.config import settings
        assert settings is not None
    def test_db_url(self):
        from argus.config import settings
        assert hasattr(settings, "DATABASE_URL")
    def test_secret_key(self):
        from argus.config import settings
        assert hasattr(settings, "SECRET_KEY")
    def test_log_level(self):
        from argus.config import settings
        assert hasattr(settings, "LOG_LEVEL")
    def test_cors(self):
        from argus.config import settings
        assert hasattr(settings, "CORS_ORIGINS")
    def test_shodan(self):
        from argus.config import settings
        assert hasattr(settings, "SHODAN_API_KEY")
    def test_vt(self):
        from argus.config import settings
        assert hasattr(settings, "VIRUSTOTAL_API_KEY")
