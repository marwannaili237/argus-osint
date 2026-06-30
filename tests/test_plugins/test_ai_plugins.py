import pytest
class TestAIPlugins:
    def test_classifier(self):
        from argus.plugins.ai_classifier import AIClassifierPlugin
        assert AIClassifierPlugin().name == "ai_classifier"
    def test_correlation(self):
        from argus.plugins.ai_correlation import AICorrelationPlugin
        assert AICorrelationPlugin().name == "ai_correlation"
    def test_ioc(self):
        from argus.plugins.ai_ioc import AIIOCExtractionPlugin, IOC_PATTERNS
        assert len(IOC_PATTERNS) >= 8
    def test_threat_scoring(self):
        from argus.plugins.ai_threat_scoring import AIThreatScoringPlugin, FACTOR_WEIGHTS
        assert sum(FACTOR_WEIGHTS.values()) == 100
    def test_nl_query(self):
        from argus.plugins.ai_nl_query import AINLQueryPlugin, ENTITY_PATTERNS
        assert len(ENTITY_PATTERNS) >= 5
    def test_sentiment(self):
        from argus.plugins.ai_sentiment import AISentimentPlugin, POSITIVE_WORDS, NEGATIVE_WORDS
        assert len(POSITIVE_WORDS) >= 10
        assert len(NEGATIVE_WORDS) >= 10
    def test_report(self):
        from argus.plugins.ai_report_generator import AIReportGeneratorPlugin
        assert AIReportGeneratorPlugin().name == "ai_report_generator"
