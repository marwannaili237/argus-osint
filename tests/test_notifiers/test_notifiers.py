import pytest
class TestNotifiers:
    def test_slack(self):
        from argus.notifiers.slack import SlackNotifier
        assert SlackNotifier().name == "slack"
    def test_discord(self):
        from argus.notifiers.discord import DiscordNotifier
        assert DiscordNotifier().name == "discord"
    def test_email(self):
        from argus.notifiers.email_notifier import EmailNotifier
        assert EmailNotifier().name == "email"
    def test_thehive(self):
        from argus.notifiers.thehive import TheHiveNotifier
        assert TheHiveNotifier().name == "thehive"
    def test_mattermost(self):
        from argus.notifiers.mattermost import MattermostNotifier
        assert MattermostNotifier().name == "mattermost"
    def test_teams(self):
        from argus.notifiers.teams import TeamsNotifier
        assert TeamsNotifier().name == "teams"
    def test_pagerduty(self):
        from argus.notifiers.pagerduty import PagerDutyNotifier
        assert PagerDutyNotifier().name == "pagerduty"
    def test_jira(self):
        from argus.notifiers.jira import JiraNotifier
        assert JiraNotifier().name == "jira"
    def test_opencti(self):
        from argus.notifiers.opencti import OpenCTINotifier
        assert OpenCTINotifier().name == "opencti"
    def test_elk(self):
        from argus.notifiers.elk import ELKNotifier
        assert ELKNotifier().name == "elk"
    def test_base(self):
        from argus.notifiers.base import BaseNotifier
        assert hasattr(BaseNotifier, "send")
        assert hasattr(BaseNotifier, "test_connection")
