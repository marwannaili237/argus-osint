import pytest
class TestI18n:
    def test_en(self):
        from argus.bot.i18n import t
        assert "Argus" in t("welcome", "en")
    def test_fr(self):
        from argus.bot.i18n import t
        assert "Argus" in t("welcome", "fr") or "Bienvenue" in t("welcome", "fr")
    def test_ar(self):
        from argus.bot.i18n import t
        assert "Argus" in t("welcome", "ar") or chr(1605) in t("welcome", "ar")
    def test_es(self):
        from argus.bot.i18n import t
        assert "Argus" in t("welcome", "es") or "Bienvenido" in t("welcome", "es")
    def test_fallback(self):
        from argus.bot.i18n import t
        assert t("no_such_key", "zz") == "no_such_key"
    def test_kwargs(self):
        from argus.bot.i18n import t
        r = t("scanning", "en", target="example.com", current=1, total=10)
        assert "example.com" in r
    def test_languages(self):
        from argus.bot.i18n import SUPPORTED_LANGUAGES
        assert len(SUPPORTED_LANGUAGES) == 4
    def test_names(self):
        from argus.bot.i18n import LANGUAGE_NAMES
        assert len(LANGUAGE_NAMES) == 4
