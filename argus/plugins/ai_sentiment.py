"""AI sentiment analysis plugin for web content."""
import re
import logging
import aiohttp
from argus.plugins.runner import BasePlugin, PluginResult

logger = logging.getLogger(__name__)

POSITIVE_WORDS = {
    'good', 'great', 'excellent', 'amazing', 'wonderful', 'best', 'love',
    'happy', 'secure', 'safe', 'reliable', 'trusted', 'official', 'verified',
    'legitimate', 'authentic', 'positive', 'success', 'award', 'certified',
}

NEGATIVE_WORDS = {
    'bad', 'danger', 'threat', 'attack', 'malware', 'phishing', 'scam',
    'fraud', 'fake', 'suspicious', 'hack', 'breach', 'vulnerability', 'exploit',
    'malicious', 'compromised', 'infected', 'risky', 'illegal', 'criminal',
    'warning', 'alert', 'critical', 'emergency', 'blocked', 'blacklist',
}

NEUTRAL_WORDS = {
    'information', 'data', 'record', 'entry', 'result', 'report', 'page',
    'service', 'system', 'platform', 'website', 'network', 'server', 'account',
}


class AISentimentPlugin(BasePlugin):
    name = "ai_sentiment"
    target_types = ["domain", "url"]
    timeout_seconds = 20

    async def run(self, target: str) -> PluginResult:
        """Analyze sentiment of web content using keyword-based approach."""
        url = target if target.startswith('http') else f'https://{target}'
        text = ""

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        return PluginResult(
                            plugin_name=self.name, status="error", data={},
                            error_message=f"HTTP {resp.status}",
                        )
                    body = await resp.text()
                    # Strip HTML tags for text analysis
                    text = re.sub(r'<[^>]+>', ' ', body)
                    text = re.sub(r'\s+', ' ', text).strip()[:5000]
        except Exception as e:
            return PluginResult(plugin_name=self.name, status="error", data={}, error_message=str(e))

        words = text.lower().split()
        pos_count = sum(1 for w in words if w in POSITIVE_WORDS)
        neg_count = sum(1 for w in words if w in NEGATIVE_WORDS)
        neu_count = sum(1 for w in words if w in NEUTRAL_WORDS)
        total = max(pos_count + neg_count + neu_count, 1)

        pos_score = pos_count / total
        neg_score = neg_count / total
        neu_score = neu_count / total

        # Compute overall sentiment score (-1 to 1)
        sentiment_score = round(pos_score - neg_score, 3)

        if sentiment_score > 0.2:
            sentiment = "positive"
        elif sentiment_score < -0.2:
            sentiment = "negative"
        else:
            sentiment = "neutral"

        # Extract top keywords
        from collections import Counter
        # Filter out common stop words
        stop_words = {'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
                      'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
                      'should', 'may', 'might', 'shall', 'can', 'to', 'of', 'in', 'for',
                      'on', 'with', 'at', 'by', 'from', 'as', 'into', 'about', 'and', 'but',
                      'or', 'not', 'no', 'if', 'then', 'that', 'this', 'it', 'its'}
        meaningful_words = [w for w in words if w not in stop_words and len(w) > 3]
        word_counts = Counter(meaningful_words)
        top_keywords = [word for word, count in word_counts.most_common(15)]

        # Detect topics
        topics = set()
        topic_keywords = {
            'security': ['security', 'firewall', 'encryption', 'ssl', 'tls', 'certificate'],
            'e-commerce': ['shop', 'cart', 'buy', 'price', 'product', 'order', 'payment'],
            'social': ['share', 'follow', 'like', 'comment', 'post', 'profile', 'friend'],
            'technology': ['cloud', 'api', 'docker', 'kubernetes', 'devops', 'microservice'],
            'news': ['news', 'article', 'blog', 'story', 'breaking', 'update'],
        }
        for topic, keywords in topic_keywords.items():
            if any(kw in meaningful_words for kw in keywords):
                topics.add(topic)

        return PluginResult(
            plugin_name=self.name, status="success",
            data={
                "sentiment": sentiment,
                "score": sentiment_score,
                "positive_count": pos_count,
                "negative_count": neg_count,
                "neutral_count": neu_count,
                "keywords": top_keywords,
                "topics": sorted(topics),
                "total_words_analyzed": len(words),
            },
        )
