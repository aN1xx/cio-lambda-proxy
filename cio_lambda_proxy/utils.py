"""
Utility functions for Customer.io Lambda Proxy
"""

import json
import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def extract_identifier_from_body(body: str) -> Tuple[Optional[str], Optional[str]]:
    if not body:
        return None, None

    try:
        body_data = json.loads(body)

        identifier_fields = ["identifier", "id", "user_id", "email", "customer_id"]

        for field in identifier_fields:
            if field in body_data and body_data[field]:
                identifier = str(body_data[field])
                logger.debug(f"Found identifier '{identifier}' in field '{field}'")
                return field, identifier

        if "data" in body_data and isinstance(body_data["data"], dict):
            for field in identifier_fields:
                if field in body_data["data"] and body_data["data"][field]:
                    identifier = str(body_data["data"][field])
                    logger.debug(f"Found identifier '{identifier}' in data.{field}")
                    return "data", identifier

        logger.warning("No identifier found in request body")
        return None, None

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse request body as JSON: {str(e)}")
        return None, None
    except Exception as e:
        logger.error(f"Error extracting identifier from body: {str(e)}")
        return None, None


def get_anonymous_identifier(identifier: str) -> str:
    import hashlib

    if not identifier:
        return "unknown_anonymous"

    clean_identifier = identifier.strip()

    if clean_identifier.endswith("_anonymous"):
        return clean_identifier

    # Create a short hash to stay within Customer.io's 150 byte limit
    # Use SHA256 hash truncated to 32 characters + "anon_" prefix
    identifier_hash = hashlib.sha256(clean_identifier.encode()).hexdigest()[:32]
    anonymous_id = f"anon_{identifier_hash}"

    logger.debug(
        f"Created anonymous identifier: {anonymous_id} "
        f"(from original: {clean_identifier[:50]}...)"
    )

    return anonymous_id


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    excluded_headers = {
        "authorization",
        "host",
        "x-forwarded-for",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-amzn-trace-id",
        "x-amzn-requestid",
        "x-api-key",
        "x-user-email",
        "content-length",
        "connection",
        "cache-control",
        "accept-encoding",
    }

    sanitized = {}

    for key, value in headers.items():
        if key.lower() not in excluded_headers and value:
            sanitized[key] = value

    return sanitized


def validate_cio_path(path: str) -> bool:
    if not path:
        return False

    clean_path = path.lstrip("/").replace("api/v1/", "")

    allowed_patterns = [
        "customers/",
        "events",
        "events/",
    ]

    for pattern in allowed_patterns:
        if clean_path.startswith(pattern):
            return True

    logger.warning(f"Invalid CIO path: {path}")
    return False


def mask_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return data

    masked = data.copy()

    sensitive_fields = {
        "password",
        "token",
        "api_key",
        "authorization",
        "signature",
        "secret",
        "cio_api_key",
        "cio_site_id",
    }

    for key, value in masked.items():
        if key.lower() in sensitive_fields:
            if isinstance(value, str) and len(value) > 4:
                masked[key] = value[:4] + "***"
            else:
                masked[key] = "***"
        elif isinstance(value, dict):
            masked[key] = mask_sensitive_data(value)
        elif isinstance(value, list):
            masked[key] = [
                mask_sensitive_data(item) if isinstance(item, dict) else item
                for item in value
            ]

    return masked


def format_cio_error_response(response_text: str, status_code: int) -> Dict[str, Any]:
    try:
        error_data = json.loads(response_text) if response_text else {}
    except json.JSONDecodeError:
        error_data = {"message": response_text or "Unknown error"}

    return {
        "error": {
            "status_code": status_code,
            "message": error_data.get("message", "Customer.io API error"),
            "details": error_data.get("details", error_data) if error_data else None,
        }
    }


def is_json_content_type(content_type: str) -> bool:
    if not content_type:
        return False

    json_types = ["application/json", "application/json; charset=utf-8", "text/json"]

    return content_type.lower().strip() in json_types


def extract_path_parameters(path: str) -> Dict[str, str]:
    params = {}

    parts = path.split("/")

    for i, part in enumerate(parts):
        if part.startswith("{") and part.endswith("}"):
            param_name = part[1:-1]
            if i + 1 < len(parts):
                params[param_name] = parts[i + 1]

    return params
