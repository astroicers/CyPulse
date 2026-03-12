import pytest
from cypulse.utils.sanitize import sanitize_domain


class TestSanitizeDomain:
    def test_valid_domain(self):
        assert sanitize_domain("example.com") == "example.com"

    def test_uppercase(self):
        assert sanitize_domain("EXAMPLE.COM") == "example.com"

    def test_strip_whitespace(self):
        assert sanitize_domain("  example.com  ") == "example.com"

    def test_strip_trailing_dot(self):
        assert sanitize_domain("example.com.") == "example.com"

    def test_strip_http(self):
        assert sanitize_domain("https://example.com/path") == "example.com"

    def test_strip_http_plain(self):
        assert sanitize_domain("http://sub.example.com") == "sub.example.com"

    def test_subdomain(self):
        assert sanitize_domain("www.example.com") == "www.example.com"

    def test_invalid_domain(self):
        with pytest.raises(ValueError):
            sanitize_domain("not a domain!!!")

    def test_empty_domain(self):
        with pytest.raises(ValueError):
            sanitize_domain("")
