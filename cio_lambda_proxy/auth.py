"""
Authentication module for verifying HTTP Signature from api-gateway.
"""

import base64
import hashlib
import hmac
import logging
import os
from typing import Any, Dict, Optional

from Crypto.Hash import SHA256  # nosec B413 # pycryptodome is secure and maintained
from Crypto.PublicKey import RSA  # nosec B413 # pycryptodome is secure and maintained
from Crypto.Signature import (  # nosec B413 # pycryptodome is secure and maintained
    pkcs1_15,
)

logger = logging.getLogger(__name__)


def get_header_case_insensitive(
    headers: Dict[str, str], header_name: str
) -> Optional[str]:
    """
    Get header value in a case-insensitive manner.
    Lambda Function URL normalizes headers to lowercase, but API Gateway preserves case.
    """
    value = headers.get(header_name)
    if value is not None:
        return value

    header_lower = header_name.lower()
    for key, val in headers.items():
        if key.lower() == header_lower:
            return val

    return None


class Request:
    """
    A simple object to represent an incoming HTTP request.
    """

    def __init__(
        self,
        host: str,
        method: str,
        path: str,
        headers: Dict[str, str],
    ):
        self.host = host
        self.method = method
        self.path = path
        self.headers = headers


def verify_request(request: Request) -> Optional[str]:
    """
    Verifies the HTTP signature and returns user email if authorized.

    Args:
        request: The request object.

    Returns:
        - str: user email if authorized (from X-User-Email header)
        - None: if anonymous (no signature or no X-User-Email header)
        - False: if signature verification failed
    """
    # Skip auth if configured
    if os.environ.get("SKIP_AUTH") == "true":
        logger.info("Authentication skipped due to SKIP_AUTH environment variable")
        # Still check for the Authorization header to distinguish authorized vs anonymous requests
        auth_header = get_header_case_insensitive(request.headers, "Authorization")
        if auth_header:
            user_email = (
                get_header_case_insensitive(request.headers, "X-User-Email")
                or "test@example.com"
            )
            return user_email
        else:
            return None  # Anonymous request

    # Check if X-User-Email header is present (added by api-gateway for authorized requests)
    # When Lambda Function URL uses IAM auth, AWS validates SigV4 and removes Authorization header
    # So we rely on X-User-Email presence as the indicator of authorized requests
    email = get_header_case_insensitive(request.headers, "X-User-Email")
    if email:
        logger.info(
            "Authenticated request from api-gateway for user: %s (via IAM-protected Lambda URL)",
            email,
        )
        return email

    auth_header = get_header_case_insensitive(request.headers, "Authorization")
    if not auth_header:
        logger.info(
            "No Authorization header and no X-User-Email - treating as anonymous request"
        )
        return None

    # Support AWS SigV4-signed requests when Lambda Function URLs are protected with IAM
    if auth_header.startswith("AWS4-HMAC-SHA256"):
        logger.info(
            "AWS SigV4 request detected without X-User-Email header - treating as anonymous"
        )
        return None

    if not auth_header.startswith("Signature "):
        logger.warning("Authorization header does not contain Signature")
        return None

    # Verify HTTP signature
    if not verify_signature(request):
        logger.error("HTTP signature verification failed")
        return None

    # Check if user email is provided (authorized request)
    email = get_header_case_insensitive(request.headers, "X-User-Email")
    if email:
        logger.info(f"Successfully authenticated user: {email}")
        return email

    logger.info("No X-User-Email header found - treating as anonymous request")
    return None


def verify_signature(request: Request) -> bool:
    """
    Verifies HTTP signature according to draft-cavage-http-signatures.

    Args:
        request: The request object

    Returns:
        True if the signature is valid, False otherwise
    """
    try:
        auth_header = (
            get_header_case_insensitive(request.headers, "Authorization") or ""
        )
        if not auth_header.startswith("Signature "):
            return False

        # Parse signature parameters
        signature_params = parse_signature_header(auth_header)
        if not signature_params:
            return False

        key_id = signature_params.get("keyId")
        algorithm = signature_params.get("algorithm")
        headers_list = signature_params.get("headers", "").split()
        signature = signature_params.get("signature")

        if not all([key_id, algorithm, signature]):
            logger.error("Missing required signature parameters")
            return False

        # Get signing key
        if not key_id:
            logger.error("Missing keyId parameter")
            return False
        signing_key = get_signing_key(key_id)
        if not signing_key:
            logger.error(f"No signing key found for keyId: {key_id}")
            return False

        # Build signing string
        signing_string = build_signing_string(request, headers_list)

        # Verify signature - cast to str since we've already checked for None
        return verify_signature_value(
            signing_string, str(signature), signing_key, str(algorithm)
        )

    except Exception as e:
        logger.error(f"Error verifying signature: {e}")
        return False


def parse_signature_header(auth_header: str) -> Optional[Dict[str, str]]:
    """
    Parses Authorization header with Signature scheme.

    Example:
    Signature keyId="api-gateway",algorithm="rsa-sha256",
    headers="(request-target) host date",signature="..."
    """
    try:
        # Remove "Signature " prefix
        sig_part = auth_header[10:]  # len("Signature ") = 10

        params = {}
        # Simple parsing - assumes proper quoting
        parts = sig_part.split(",")
        for part in parts:
            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"')
            params[key] = value

        return params
    except Exception as e:
        logger.error(f"Error parsing signature header: {e}")
        return None


def build_signing_string(request: Request, headers_list: list) -> str:
    """
    Builds the signing string according to HTTP Signatures spec.
    """
    lines = []

    for header in headers_list:
        if header == "(request-target)":
            # Special pseudo-header for method and path
            target = f"{request.method.lower()} {request.path}"
            lines.append(f"(request-target): {target}")
        else:
            # Regular header
            header_value = get_header_case_insensitive(request.headers, header)
            if header_value is not None:
                lines.append(f"{header.lower()}: {header_value}")
            else:
                logger.warning(f"Header '{header}' not found in request")

    signing_string = "\n".join(lines)
    logger.debug(f"Signing string: {signing_string}")
    return signing_string


def verify_signature_value(
    signing_string: str, signature: str, key: str, algorithm: str
) -> bool:
    """
    Verifies the actual signature value.
    """
    try:
        signature_bytes = base64.b64decode(signature)

        if algorithm == "hmac-sha256":
            # Legacy HMAC support for mobile apps
            expected = hmac.new(
                key.encode("utf-8"), signing_string.encode("utf-8"), hashlib.sha256
            ).digest()
            return hmac.compare_digest(signature_bytes, expected)
        elif algorithm == "rsa-sha256":
            # RSA support for api-gateway
            try:
                # Load public key
                public_key = RSA.import_key(key.encode("utf-8"))

                # Verify RSA signature using pycryptodome
                h = SHA256.new(signing_string.encode("utf-8"))
                pkcs1_15.new(public_key).verify(h, signature_bytes)
                return True
            except Exception as e:
                logger.error(f"RSA signature verification failed: {e}")
                return False
        else:
            logger.error(f"Unsupported signature algorithm: {algorithm}")
            return False

    except Exception as e:
        logger.error(f"Error verifying signature value: {e}")
        return False


def get_signing_key(key_id: str) -> Optional[str]:
    """
    Gets the signing key for the given key ID.
    """
    if key_id == "api-gateway":
        # Public key for requests from api-gateway (RSA verification)
        key = os.environ.get("API_GATEWAY_PUBLIC_KEY")
        if not key:
            logger.error("API_GATEWAY_PUBLIC_KEY not found in environment")
            return None
        return key
    else:
        logger.error(f"Unknown keyId: {key_id}. Only 'api-gateway' is supported.")
        return None


# Legacy JWT functions - kept for backward compatibility but not used
def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """Legacy function - deprecated in favor of HTTP Signature"""
    logger.warning("verify_jwt_token is deprecated - using HTTP Signature instead")
    return None


# Legacy functions for backward compatibility
def parse_authorization_header(auth_header: str) -> Optional[Dict[str, str]]:
    """Legacy function - now parses Signature header"""
    if auth_header.startswith("Signature "):
        return parse_signature_header(auth_header)
    return None


def get_key_id(auth_header: str) -> Optional[str]:
    """Gets key ID from Authorization header"""
    params = parse_signature_header(auth_header)
    return params.get("keyId") if params else None


def get_key(key_id: str) -> Optional[str]:
    """Gets signing key for key ID"""
    return get_signing_key(key_id)
