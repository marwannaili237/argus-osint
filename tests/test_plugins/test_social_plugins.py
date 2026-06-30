import pytest
class TestSocialPlugins:
    def test_sherlock(self):
        from argus.plugins.social_sherlock import SocialSherlockPlugin
        p = SocialSherlockPlugin()
        assert p.name == "social_sherlock"
        assert "username" in p.target_types
    def test_sherlock_sites(self):
        from argus.plugins.social_sherlock import SITES
        assert len(SITES) >= 25
    def test_telegram(self):
        from argus.plugins.social_telegram import SocialTelegramPlugin
        assert SocialTelegramPlugin().name == "social_telegram"
    def test_reddit(self):
        from argus.plugins.social_reddit import SocialRedditPlugin
        assert SocialRedditPlugin().name == "social_reddit"
    def test_twitter(self):
        from argus.plugins.social_twitter import SocialTwitterPlugin
        assert SocialTwitterPlugin().name == "social_twitter"
    def test_instagram(self):
        from argus.plugins.social_instagram import SocialInstagramPlugin
        assert SocialInstagramPlugin().name == "social_instagram"
    def test_discord(self):
        from argus.plugins.social_discord import SocialDiscordPlugin
        assert SocialDiscordPlugin().name == "social_discord"
