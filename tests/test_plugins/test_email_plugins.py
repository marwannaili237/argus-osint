import pytest
class TestEmailPlugins:
    def test_fullcontact(self):
        from argus.plugins.email_fullcontact import EmailFullContactPlugin
        assert EmailFullContactPlugin().name == "email_fullcontact"
    def test_hunter(self):
        from argus.plugins.email_hunter import EmailHunterPlugin
        assert EmailHunterPlugin().name == "email_hunter"
    def test_clearbit(self):
        from argus.plugins.email_clearbit import EmailClearbitPlugin
        assert EmailClearbitPlugin().name == "email_clearbit"
    def test_header(self):
        from argus.plugins.email_header import EmailHeaderPlugin
        assert EmailHeaderPlugin().name == "email_header"
    def test_gravatar(self):
        from argus.plugins.email_gravatar import EmailGravatarPlugin
        assert EmailGravatarPlugin().name == "email_gravatar"
    def test_smtp(self):
        from argus.plugins.email_smtp import EmailSmtpPlugin
        assert EmailSmtpPlugin().name == "email_smtp"
    def test_forwarding(self):
        from argus.plugins.email_forwarding import EmailForwardingPlugin
        assert EmailForwardingPlugin().name == "email_forwarding"
    def test_domain_whois(self):
        from argus.plugins.email_domain_whois import EmailDomainWhoisPlugin
        assert EmailDomainWhoisPlugin().name == "email_domain_whois"
    def test_reputation(self):
        from argus.plugins.email_reputation_enhanced import EmailReputationEnhancedPlugin
        assert EmailReputationEnhancedPlugin().name == "email_reputation_enhanced"
    def test_thread(self):
        from argus.plugins.email_thread import EmailThreadPlugin
        assert EmailThreadPlugin().name == "email_thread"
    def test_to_phone(self):
        from argus.plugins.email_to_phone import EmailToPhonePlugin
        assert EmailToPhonePlugin().name == "email_to_phone"
