import re
import math
from urllib.parse import urlparse, parse_qs


def _shannon_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _is_ip_address(hostname):
    """Check if hostname is an IP address (IPv4 or IPv6)."""
    ipv4 = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)
    ipv6 = re.match(r"^\[?[0-9a-fA-F:]+\]?$", hostname)
    return bool(ipv4 or ipv6)


# Ref: Vanhoenshoven et al. (2020) — "ML for Malicious URL Detection"
# Ref: Sahoo et al. (2017) — "Malicious URL Detection using ML: A Survey"
# Ref: Mohammad et al. (2014) — Phishing Websites Features (UCI Dataset)

PHISHING_KEYWORDS = [
    "login", "verify", "password", "reset", "secure", "account",
    "update", "confirm", "banking", "signin", "suspend", "alert",
    "expire", "unlock", "authenticate", "wallet", "credential",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".xyz",
    ".top", ".club", ".work", ".info", ".link", ".click",
]

SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "adf.ly", "cutt.ly", "rb.gy", "short.io",
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".js", ".bat", ".cmd", ".scr", ".php", ".cgi", ".zip", ".rar",
]

BRAND_NAMES = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "whatsapp", "chase",
    "wellsfargo", "bankofamerica", "dropbox", "outlook",
]


def extract_features(url):
    features = {}
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        return {key: 0 for key in [
            "has_https", "has_keyword", "url_length", "num_dots",
            "at_symbol", "num_digits", "suspicious_tld", "hyphen_count",
            "has_ip_address", "domain_length", "path_length", "num_subdomains",
            "num_subdirectories", "num_query_params", "query_length",
            "has_fragment", "has_port", "double_slash_redirect", "is_shortened",
            "suspicious_extension", "num_encoded_chars", "url_entropy",
            "domain_entropy", "digit_letter_ratio", "has_punycode", "has_tilde",
            "num_special_chars", "num_slashes", "num_ampersands", "brand_in_path",
            "domain_has_digits", "max_host_token_len", "avg_token_length",
            "num_tokens", "max_consecutive_chars"
        ]}
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    url_lower = url.lower()

    # ── Original 8 features ──────────────────────────────────────────────

    # 1. HTTPS protocol
    features["has_https"] = url.startswith("https://")

    # 2. Phishing keywords in URL
    features["has_keyword"] = any(kw in url_lower for kw in PHISHING_KEYWORDS)

    # 3. Total URL length
    features["url_length"] = len(url)

    # 4. Number of dots
    features["num_dots"] = url.count(".")

    # 5. @ symbol presence (can redirect browser to different host)
    features["at_symbol"] = "@" in url

    # 6. Count of digits in URL
    features["num_digits"] = sum(ch.isdigit() for ch in url)

    # 7. Suspicious TLD
    features["suspicious_tld"] = any(url_lower.endswith(tld) for tld in SUSPICIOUS_TLDS)

    # 8. Hyphen count
    features["hyphen_count"] = url.count("-")

    # ── New features (9–35) ──────────────────────────────────────────────

    # 9. IP address instead of domain name
    features["has_ip_address"] = _is_ip_address(hostname)

    # 10. Domain length
    features["domain_length"] = len(hostname)

    # 11. Path length
    features["path_length"] = len(path)

    # 12. Number of subdomains  (e.g. a.b.c.example.com → 3 subdomains)
    features["num_subdomains"] = max(hostname.count(".") - 1, 0)

    # 13. Number of subdirectories in path
    features["num_subdirectories"] = path.count("/") - 1 if path.startswith("/") else path.count("/")

    # 14. Number of query parameters
    features["num_query_params"] = len(parse_qs(query))

    # 15. Query string length
    features["query_length"] = len(query)

    # 16. Fragment present (# in URL)
    features["has_fragment"] = len(fragment) > 0

    # 17. Uses non-standard port
    features["has_port"] = parsed.port is not None and parsed.port not in (80, 443)

    # 18. Double-slash redirect (//) after the protocol
    after_protocol = url.split("://", 1)[1] if "://" in url else url
    features["double_slash_redirect"] = "//" in after_protocol

    # 19. URL shortening service
    features["is_shortened"] = any(svc in url_lower for svc in SHORTENING_SERVICES)

    # 20. Suspicious file extension in path
    features["suspicious_extension"] = any(path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)

    # 21. Percent-encoded characters count (%xx)
    features["num_encoded_chars"] = len(re.findall(r"%[0-9a-fA-F]{2}", url))

    # 22. Shannon entropy of the full URL (high entropy → randomised/obfuscated)
    features["url_entropy"] = round(_shannon_entropy(url), 4)

    # 23. Shannon entropy of the domain only
    features["domain_entropy"] = round(_shannon_entropy(hostname), 4)

    # 24. Digit-to-letter ratio
    num_letters = sum(ch.isalpha() for ch in url)
    features["digit_letter_ratio"] = round(features["num_digits"] / max(num_letters, 1), 4)

    # 25. Contains punycode (internationalised domain, xn--)
    features["has_punycode"] = "xn--" in hostname.lower()

    # 26. Tilde (~) in URL — often used in personal pages / phishing kits
    features["has_tilde"] = "~" in url

    # 27. Number of special characters (!$*+,;=)
    features["num_special_chars"] = len(re.findall(r"[!$*+,;=]", url))

    # 28. Number of forward slashes
    features["num_slashes"] = url.count("/")

    # 29. Number of ampersands (&) — excessive params can signal injection
    features["num_ampersands"] = url.count("&")

    # 30. Contains brand name but not on official domain (brand impersonation)
    features["brand_in_path"] = any(
        brand in path.lower() or brand in query.lower()
        for brand in BRAND_NAMES
    )

    # 31. Hostname contains digits (e.g. secure1-login.com)
    features["domain_has_digits"] = any(ch.isdigit() for ch in hostname)

    # 32. Longest word length in hostname (very long tokens → DGA-style)
    host_tokens = re.split(r"[.\-]", hostname)
    features["max_host_token_len"] = max((len(t) for t in host_tokens), default=0)

    # 33. Average token length in the full URL
    url_tokens = re.split(r"[/.\-?&=_]", url)
    url_tokens = [t for t in url_tokens if t]
    features["avg_token_length"] = round(
        sum(len(t) for t in url_tokens) / max(len(url_tokens), 1), 2
    )

    # 34. Number of tokens in the URL (high count → complex/obfuscated)
    features["num_tokens"] = len(url_tokens)

    # 35. Consecutive character repetition (e.g. "aaa", "111")
    features["max_consecutive_chars"] = max(
        (len(m.group()) for m in re.finditer(r"(.)\1+", url)), default=1
    )

    return features
