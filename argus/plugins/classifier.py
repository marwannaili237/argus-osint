"""Argus OSINT – Target Classifier Utility"""

from __future__ import annotations

import re

# Pre-compiled patterns for performance
_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}$')
_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$')
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
_PHONE_RE = re.compile(r'^\+\d{10,15}$')
_IMAGE_EXT_RE = re.compile(r'\.(jpg|jpeg|png|gif|webp|bmp|svg)(\?.*)?$', re.IGNORECASE)
_IMAGE_HOSTS = {'imgur.com', 'i.imgur.com', 'ibb.co', 'postimg.cc',
               'imgbb.com', 'flickr.com', 'staticflickr.com'}
_BTC_RE = re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-zA-HJ-NP-Z0-9]{25,39}$')
_ETH_RE = re.compile(r'^0x[a-fA-F0-9]{40}$')
_COMPANY_KW = {'inc', 'ltd', 'corp', 'corporation', 'llc', 'gmbh', 'sa', 'ag', 'pty', 'plc'}


def classify_target(value: str) -> str:
    """Classify a target string into its type.

    Returns one of: domain, url, ip, email, username, phone,
    image, crypto, person, company, unknown.
    """
    v = value.strip()
    if not v:
        return 'unknown'

    # URL (starts with http)
    if v.lower().startswith(('http://', 'https://')):
        if _IMAGE_EXT_RE.search(v) or any(h in v.lower() for h in _IMAGE_HOSTS):
            return 'image'
        return 'url'

    # Image URL without http prefix (rare)
    if _IMAGE_EXT_RE.search(v) or any(v.lower().startswith(h) for h in _IMAGE_HOSTS):
        return 'image'

    # Email
    if '@' in v and _EMAIL_RE.match(v):
        return 'email'
    if '@' in v and '.' in v.split('@')[-1]:
        return 'email'

    # IP address
    if _IP_RE.match(v):
        parts = v.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            return 'ip'

    # Phone
    if v.startswith('+') and _PHONE_RE.match(v):
        return 'phone'

    # Crypto
    if _BTC_RE.match(v) or _ETH_RE.match(v):
        return 'crypto'

    # Domain
    if _DOMAIN_RE.match(v):
        return 'domain'

    # Company (comma-separated with company keywords)
    if ',' in v:
        words = v.lower().replace(',', ' ').split()
        if any(w.rstrip('.,') in _COMPANY_KW for w in words):
            return 'company'
        # Person (comma-separated name-like, 2+ words)
        name_words = [w for w in words if w.isalpha() and len(w) > 1]
        if len(name_words) >= 2:
            return 'person'

    # Check for company keywords in single tokens
    words = v.lower().split()
    if any(w.rstrip('.,') in _COMPANY_KW for w in words):
        return 'company'

    # Person (2+ capitalized words)
    cap_words = [w for w in v.split() if w[0].isupper() and w[1:].islower() and w.isalpha()]
    if len(cap_words) >= 2:
        return 'person'

    # Username (alphanumeric + underscore, 3-20 chars)
    if _USERNAME_RE.match(v):
        return 'username'

    return 'unknown'
