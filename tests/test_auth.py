"""
Tests for the auth module - HTTP Signature verification.
"""

import base64
import hashlib
import hmac
from unittest.mock import Mock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from cio_lambda_proxy.auth import (
    Request,
    build_signing_string,
    get_signing_key,
    parse_signature_header,
    verify_request,
    verify_signature,
    verify_signature_value,
)

# Mock RSA key pair for testing
TEST_PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqZspAmjSdVvku
TMKvI11itcrHWp87c5MG8SKc8V4oQiio4upg5z3YimuSk5OL1DGDcNbrhiEYSBqj
SE1G7bapUuvhL86BMsB6Lpt9tnlCsrUtgi//BgkVioKVZq1S0OxRy5jtIRwJaS7V
THUe6ayA/j2UVrxbFgQEpdyK5Afsr8REa052UFuxxZKJVaU79By0HJJHIGFvBE/3
r42DNJCG3lR9Pwb5L71d+wt58vHW5Z24SIjU15s1ZR1G6bqlI7kcDNOuHSdBCBCI
aLzJdDxgZYbaJRlkxGNGrgmX82dfQ4nQTE54bjwXW/KFwc/Q0foGzDGI4p8ikk5t
+3Syw+rRAgMBAAECggEABaCDq512q6lxwhMmgf+8zOPW8JKwBm0Qcl69Ign1w4Y9
GdKgeGxlG5pP52pjKW9rkSfFQ8ginfl86QkcBYHCZ0CwlGJD7fqd5jWqzHxy8FO+
wuQf2fU6OzwJ3Y14n278bCO5MZTHJxJnnwM5gjinidJGI04NRe6/WY3xRKQ3ahvt
M1D9If+6aK9F0IwvZ9ef3Cak/BROZ/1g7bEqVr3IQDvSfD1kwzv8bkQ1SB9v9Vyv
R9TgDobWR3BLIUo5qLqj0JfLCYDCEvLQO+XYmmRt3wwDYB4MaprWnOH6irB+vV4A
whhLsBJkrZIAknVnkEFUw27IQp8sKgJDU1/H+NK2aQKBgQDuf1cMHaMoRwZsx2Ak
swNL6LjeSatX/l/6tkJXVgy5FPreAmwH6lJ4qa+eucF9OQ60kzT3bVQT529i+tBu
LBsa9DQ7TzsVz6usIdt8+bxEmGPRsDbuhfGIdaxGzYzEMS5rGSLezSSij4pHFtHs
3hYEpAyX8Zh4jRa0GNPmQVSt1QKBgQC26CE82OtzwezEqZxlRAhzIpawnK5UnjB/
PYMNYJPwraLevtDn/vvn4Cn2cOSdyR3oUJvK4qWZcv7yPRzfiGVQE4HQWJk2PwCT
ylH3Snr/WsyGj8mNd4u3gBXhEqHt0VqFmMZLkRioOPoWoPT4ay+a17tv3ZTvf5F8
hucWMEs7DQKBgQCTiZbx2cu6+OUSmevyCAO8C8WBTZV/o88AK4uyt3q7bC0c9eaa
puxJ1L7dtA/sRUXBk2cqwSlH/t27H2mdHg/Ohs9g+UyV25hZrcA3+c3rqVHmv9nb
iGS4hAME8ddo7vvGKRCXP9Sv85gZDhbjLyfzywA3Zq9ps+4dj1ZWlIer2QKBgD/g
wfrmJxS+XVoxghU7tVfAdLApiBi1RmqpqOM7H2+mtILmUT80pfVNLFqNAsq4OmGw
BTjN/tegeblP7o2CrR9SMLv6tUdkqWbz+bxLnrkflN5JyTJG1dy4Nuvr/fF4dAzE
Vjx96AaYH39XpzY6+N0zCpr+38zk2IKM+pedNijhAoGAYEwkrjhymHvf4AR96ios
b8gGKxNUFa/96CZjcOr93N9mSpMU8521Ps0w8x+cGtow23bw0JKfqP+pe9BRO64h
u0OSNTYEY0kdmWzt/BqCEswJr9k6Tce/EF//IO2igYiYgf+rhg6Ol7lnhnhlSXa/
VEJhaKzXcc9qPk330SwghWQ=
-----END PRIVATE KEY-----"""

TEST_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqmbKQJo0nVb5LkzCryNd
YrXKx1qfO3OTBvEinPFeKEIoqOLqYOc92IprkpOTi9Qxg3DW64YhGEgao0hNRu22
qVLr4S/OgTLAei6bfbZ5QrK1LYIv/wYJFYqClWatUtDsUcuY7SEcCWku1Ux1Hums
gP49lFa8WxYEBKXciuQH7K/ERGtOdlBbscWSiVWlO/QctBySRyBhbwRP96+NgzSQ
ht5UfT8G+S+9XfsLefLx1uWduEiI1NebNWUdRum6pSO5HAzTrh0nQQgQiGi8yXQ8
YGWG2iUZZMRjRq4Jl/NnX0OJ0ExOeG48F1vyhcHP0NH6BswxiOKfIpJObft0ssPq
0QIDAQAB
-----END PUBLIC KEY-----"""


@pytest.fixture
def mock_request():
    """Fixture for creating a mock request object."""
    request = Mock(spec=Request)
    request.host = "example.lambda-url.eu-central-1.on.aws"
    request.method = "POST"
    request.path = "/api/v1/customers/{identifier}/events"
    request.headers = {
        "Content-Type": "application/json",
        "Host": "example.lambda-url.eu-central-1.on.aws",
        "Date": "Thu, 05 Jan 2024 21:31:40 GMT",
    }
    return request


@pytest.fixture
def valid_signature_header():
    """Creates a valid HTTP Signature header."""
    return (
        'Signature keyId="api-gateway",algorithm="rsa-sha256",'
        'headers="(request-target) host date content-type",signature="test-signature"'
    )


class TestParseSignatureHeader:
    """Tests for parsing HTTP Signature headers."""

    def test_valid_signature_header(self):
        """Test parsing a valid signature header."""
        header = (
            'Signature keyId="api-gateway",algorithm="rsa-sha256",'
            'headers="(request-target) host date",signature="abcd1234"'
        )
        result = parse_signature_header(header)

        assert result is not None
        assert result["keyId"] == "api-gateway"
        assert result["algorithm"] == "rsa-sha256"
        assert result["headers"] == "(request-target) host date"
        assert result["signature"] == "abcd1234"

    def test_malformed_header(self):
        """Test parsing a malformed header returns None."""
        header = "Signature invalid-format"
        result = parse_signature_header(header)
        assert result is None

    def test_missing_quotes(self):
        """Test parsing header with missing quotes."""
        header = "Signature keyId=api-gateway,algorithm=rsa-sha256"
        result = parse_signature_header(header)
        assert result is not None
        assert result["keyId"] == "api-gateway"
        assert result["algorithm"] == "rsa-sha256"


class TestBuildSigningString:
    """Tests for building signing strings."""

    def test_request_target_header(self, mock_request):
        """Test building signing string with (request-target) header."""
        headers_list = ["(request-target)", "host"]
        result = build_signing_string(mock_request, headers_list)

        expected = (
            "(request-target): post /api/v1/customers/{identifier}/events\n"
            "host: example.lambda-url.eu-central-1.on.aws"
        )
        assert result == expected


class TestVerifySignatureValue:
    """Tests for signature verification."""

    def test_valid_hmac_sha256_signature(self):
        """Test valid HMAC-SHA256 signature verification (legacy mobile apps)."""
        signing_string = "(request-target): post /api/v1/test\nhost: example.com"
        key = "test-secret"

        # Create valid signature
        expected_signature = hmac.new(
            key.encode("utf-8"), signing_string.encode("utf-8"), hashlib.sha256
        ).digest()
        signature_b64 = base64.b64encode(expected_signature).decode("utf-8")

        result = verify_signature_value(
            signing_string, signature_b64, key, "hmac-sha256"
        )
        assert result is True

    def test_valid_rsa_sha256_signature(self):
        """Test valid RSA-SHA256 signature verification."""
        signing_string = "(request-target): post /api/v1/test\nhost: example.com"

        # Create signature with private key
        private_key = serialization.load_pem_private_key(
            TEST_PRIVATE_KEY.encode("utf-8"), password=None
        )
        signature_bytes = private_key.sign(
            signing_string.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")

        # Verify with public key
        result = verify_signature_value(
            signing_string, signature_b64, TEST_PUBLIC_KEY, "rsa-sha256"
        )
        assert result is True

    def test_invalid_rsa_signature(self):
        """Test invalid RSA signature returns False."""
        signing_string = "(request-target): post /api/v1/test"
        invalid_signature = base64.b64encode(b"invalid").decode("utf-8")

        result = verify_signature_value(
            signing_string, invalid_signature, TEST_PUBLIC_KEY, "rsa-sha256"
        )
        assert result is False

    def test_invalid_hmac_signature(self):
        """Test invalid HMAC signature returns False."""
        signing_string = "(request-target): post /api/v1/test"
        key = "test-secret"
        invalid_signature = base64.b64encode(b"invalid").decode("utf-8")

        result = verify_signature_value(
            signing_string, invalid_signature, key, "hmac-sha256"
        )
        assert result is False

    def test_unsupported_algorithm(self):
        """Test unsupported algorithm returns False."""
        result = verify_signature_value("test", "signature", "key", "unsupported-alg")
        assert result is False


class TestGetSigningKey:
    """Tests for getting signing keys."""

    @patch.dict("os.environ", {"API_GATEWAY_PUBLIC_KEY": TEST_PUBLIC_KEY})
    def test_api_gateway_key(self):
        """Test getting API gateway public key."""
        result = get_signing_key("api-gateway")
        assert result == TEST_PUBLIC_KEY

    def test_unknown_key_id(self):
        """Test unknown key ID returns None."""
        result = get_signing_key("unknown-key")
        assert result is None

    @patch.dict("os.environ", {})
    def test_missing_env_var(self):
        """Test missing environment variable returns None."""
        result = get_signing_key("api-gateway")
        assert result is None


class TestVerifySignature:
    """Tests for signature verification."""

    @patch("cio_lambda_proxy.auth.get_signing_key")
    @patch("cio_lambda_proxy.auth.verify_signature_value")
    def test_valid_rsa_signature(self, mock_verify_value, mock_get_key, mock_request):
        """Test valid RSA signature verification."""
        mock_request.headers["Authorization"] = (
            'Signature keyId="api-gateway",algorithm="rsa-sha256",'
            'headers="(request-target) host",signature="valid-sig"'
        )
        mock_get_key.return_value = TEST_PUBLIC_KEY
        mock_verify_value.return_value = True

        result = verify_signature(mock_request)
        assert result is True

    def test_no_authorization_header(self, mock_request):
        """Test no Authorization header returns False."""
        result = verify_signature(mock_request)
        assert result is False

    def test_non_signature_header(self, mock_request):
        """Test non-Signature header returns False."""
        mock_request.headers["Authorization"] = "Bearer jwt-token"
        result = verify_signature(mock_request)
        assert result is False


class TestVerifyRequest:
    """Tests for request verification."""

    @patch.dict("os.environ", {"SKIP_AUTH": "true"})
    def test_skip_auth_enabled(self, mock_request):
        """Test that SKIP_AUTH returns test email."""
        result = verify_request(mock_request)
        assert result is None

    def test_no_authorization_header(self, mock_request):
        """Test that missing Authorization header returns None."""
        result = verify_request(mock_request)
        assert result is None

    def test_non_signature_header(self, mock_request):
        """Test that non-Signature header returns None."""
        mock_request.headers["Authorization"] = "Bearer jwt-token"
        result = verify_request(mock_request)
        assert result is None

    def test_sigv4_header_with_email(self, mock_request):
        """Test that AWS SigV4 signed request returns email when header present."""
        mock_request.headers["Authorization"] = (
            "AWS4-HMAC-SHA256 Credential=AKIA..., SignedHeaders=host;x-amz-date, Signature=abc123"
        )
        mock_request.headers["X-User-Email"] = "sigv4-user@example.com"

        result = verify_request(mock_request)
        assert result == "sigv4-user@example.com"

    def test_sigv4_header_without_email(self, mock_request):
        """Test that AWS SigV4 request without email is treated as anonymous."""
        mock_request.headers["Authorization"] = (
            "AWS4-HMAC-SHA256 Credential=AKIA..., SignedHeaders=host;x-amz-date, Signature=abc123"
        )

        result = verify_request(mock_request)
        assert result is None

    def test_iam_protected_lambda_url_with_email(self, mock_request):
        """Test IAM-protected Lambda URL where AWS removes Authorization header but X-User-Email is present."""
        # When Lambda Function URL uses IAM auth, AWS validates SigV4 and removes Authorization header
        # Only X-User-Email is present (added by api-gateway)
        mock_request.headers["X-User-Email"] = "user@example.com"

        result = verify_request(mock_request)
        assert result == "user@example.com"

    def test_iam_protected_lambda_url_without_email(self, mock_request):
        """Test IAM-protected Lambda URL without X-User-Email (anonymous request)."""
        # No Authorization header and no X-User-Email - anonymous request
        result = verify_request(mock_request)
        assert result is None

    @patch("cio_lambda_proxy.auth.verify_signature")
    def test_signature_verification_failed(self, mock_verify_signature, mock_request):
        """Test that failed signature verification returns None."""
        mock_request.headers["Authorization"] = (
            'Signature keyId="api-gateway",algorithm="rsa-sha256",signature="invalid"'
        )
        mock_verify_signature.return_value = False

        result = verify_request(mock_request)
        assert result is None

    def test_authorized_request_with_email(self, mock_request):
        """Test authorized request with X-User-Email header."""
        # When X-User-Email is present, it takes precedence (IAM-protected Lambda URL case)
        mock_request.headers.update(
            {
                "Authorization": (
                    'Signature keyId="api-gateway",algorithm="rsa-sha256",'
                    'signature="valid"'
                ),
                "X-User-Email": "user@example.com",
            }
        )

        result = verify_request(mock_request)
        assert result == "user@example.com"

    @patch("cio_lambda_proxy.auth.verify_signature")
    def test_anonymous_request_without_email(self, mock_verify_signature, mock_request):
        """Test anonymous request without X-User-Email header."""
        mock_request.headers["Authorization"] = (
            'Signature keyId="api-gateway",algorithm="rsa-sha256",' 'signature="valid"'
        )
        mock_verify_signature.return_value = True

        result = verify_request(mock_request)
        assert result is None


# Legacy function tests
class TestLegacyFunctions:
    """Tests for legacy functions."""

    @patch("cio_lambda_proxy.auth.get_signing_key")
    @patch("cio_lambda_proxy.auth.verify_signature_value")
    def test_verify_signature_legacy(
        self, mock_verify_value, mock_get_key, mock_request
    ):
        """Test verify_signature function."""
        mock_request.headers["Authorization"] = (
            'Signature keyId="api-gateway",algorithm="rsa-sha256",'
            'headers="(request-target) host",signature="valid-sig"'
        )
        mock_get_key.return_value = TEST_PUBLIC_KEY
        mock_verify_value.return_value = True

        from cio_lambda_proxy.auth import verify_signature

        result = verify_signature(mock_request)
        assert result is True

        mock_verify_value.return_value = False
        result = verify_signature(mock_request)
        assert result is False
