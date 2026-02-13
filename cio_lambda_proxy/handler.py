"""
Universal Customer.io Lambda proxy handler
"""

import json
import logging
import os
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin

import requests  # type: ignore

from cio_lambda_proxy.auth import Request, verify_request
from cio_lambda_proxy.utils import (
    extract_identifier_from_body,
    get_anonymous_identifier,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CIO_API_MAPPINGS = {
    "track": {
        "base_url": os.environ.get(
            "CIO_TRACK_API_BASE_URL", "https://track.customer.io/api/v1/"
        ),
        "auth_type": "basic",
        "patterns": [
            # Track API endpoints for mobile app
            r"^customers/.+/events/?$",
            r"^customers/.+/attributes/?$",
            r"^customers/.+/devices/?$",
            r"^customers/.+/devices/.+/?$",
            r"^customers/.+/?$",
            # Anonymous events
            r"^events/?$",
            # Mobile app device endpoints (will be transformed)
            r"^device/?$",
            # Push notification events (mobile app notification tracking)
            r"^push/events/?$",
            r"^cio/notification_received/?$",
            r"^notification_opened/?$",
        ],
    },
    "app": {
        "base_url": os.environ.get(
            "CIO_APP_API_BASE_URL", "https://api.customer.io/v1/"
        ),
        "auth_type": "bearer",
        "patterns": [
            # App API endpoints
            r"^campaigns/.+",
            r"^newsletters/.+",
            r"^segments/.+",
            r"^exports/.+",
            r"^messages/.+",
            r"^activities/.+",  # Previously Beta API
            r"^customers/.+/activities/?$",  # Customer activities
            r"^send/email/?$",
            r"^send/push/?$",
            r"^send/sms/?$",
            r"^api_keys/?$",
            r"^workspaces/?$",
            r"^reporting/.+",
            r"^account/?$",
            # Mobile app device endpoints (will be transformed)
            r"^cio/device/?$",
        ],
    },
}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    try:
        logger.info(f"Received event: {json.dumps(event, default=str)}")

        # Support both API Gateway REST API and Lambda Function URL formats
        if "version" in event and event["version"] == "2.0":
            # Lambda Function URL / HTTP API v2.0 format
            http_method = event["requestContext"]["http"]["method"]
            path = event.get("rawPath", "")
            headers = event.get("headers", {})
            body = event.get("body", "")
            query_params = event.get("queryStringParameters") or {}
        else:
            # API Gateway REST API v1.0 format
            http_method = event.get("httpMethod", "GET")
            path = event.get("path", "")
            headers = event.get("headers", {})
            body = event.get("body", "")
            query_params = event.get("queryStringParameters") or {}

        # Verify signature and get user email (None if anonymous or failed)
        user_email = _verify_and_extract_user(event)
        # For signature authentication, both None and failed authentication
        # are treated as anonymous requests unless there are specific requirements

        is_authorized = bool(user_email)

        # Log caller information for debugging
        caller_info = _extract_caller_info(event, headers)
        logger.info(
            f"Processing {http_method} request to {path} "
            f"(authorized: {is_authorized}, user: {user_email or 'anonymous'}, "
            f"caller: {caller_info})"
        )

        cio_url, cio_headers, cio_body = _prepare_cio_request(
            http_method, path, headers, body, user_email
        )

        # Transform POST to PUT for device endpoints (Customer.io API requirement)
        if "device" in path and http_method == "POST":
            http_method = "PUT"
            logger.info("Transformed POST to PUT for device endpoint")

        if not cio_url:
            return _create_error_response(
                500,
                "Failed to prepare Customer.io request",
                getattr(context, "aws_request_id", "unknown"),
            )

        response = _make_cio_request(
            method=http_method,
            url=cio_url,
            headers=cio_headers,
            body=cio_body,
            query_params=query_params,
        )

        response.raise_for_status()
        return _create_success_response(response)

    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error from Customer.io: {e.response.text}")
        return _create_cio_error_response(
            e.response,
            getattr(context, "aws_request_id", "unknown"),
        )
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        return _create_error_response(
            500, "Internal Server Error", getattr(context, "aws_request_id", "unknown")
        )


def _verify_and_extract_user(event: Dict[str, Any]) -> Optional[str]:
    """
    Verifies JWT token and extracts user email.

    Returns:
        - str: user email if authenticated
        - None: if anonymous (no token or invalid token is ok for anonymous requests)
        - False: if authentication failed when token was provided
    """
    headers = event.get("headers", {})

    # Support both API Gateway REST API and Lambda Function URL formats
    if "version" in event and event["version"] == "2.0":
        # Lambda Function URL / HTTP API v2.0 format
        method = event["requestContext"]["http"]["method"]
        path = event.get("rawPath", "")
    else:
        # API Gateway REST API v1.0 format
        method = event.get("httpMethod", "GET")
        path = event.get("path", "")

    host = headers.get("Host", "")

    request = Request(
        host=host,
        method=method,
        path=path,
        headers=headers,
    )

    return verify_request(request)


def _determine_cio_api_type(path: str) -> Optional[Dict[str, Any]]:
    for api_name, config in CIO_API_MAPPINGS.items():
        for pattern in config["patterns"]:
            if re.match(pattern, path):
                return {
                    "name": api_name,
                    "base_url": config["base_url"],
                    "auth_type": config["auth_type"],
                }

    return None


def _prepare_cio_request(
    method: str,
    path: str,
    headers: Dict[str, str],
    body: str,
    user_email: Optional[str],
) -> Tuple[Optional[str], Dict[str, str], str]:
    # Remove both /api/v1/ and /cio/v1/ prefixes
    clean_path = re.sub(r"^/(api|cio)/v1/", "", path)
    api_config = _determine_cio_api_type(clean_path)
    if not api_config:
        logger.error(f"Unknown Customer.io API path: {clean_path}")
        return None, {}, body

    cio_headers = {
        "Content-Type": headers.get("content-type", "application/json"),
        "User-Agent": "CIO-Lambda-Proxy/2.0",
    }

    # Set authentication based on API type
    if api_config["auth_type"] == "basic":
        # Track API uses Basic Auth with Site ID and API Key
        cio_api_key = os.environ.get("CIO_API_KEY")
        cio_site_id = os.environ.get("CIO_SITE_ID")

        if not cio_api_key:
            logger.error("CIO_API_KEY not found in environment for Track API")
            return None, {}, body
        if not cio_site_id:
            logger.error("CIO_SITE_ID not found in environment for Track API")
            return None, {}, body

        import base64

        credentials = f"{cio_site_id}:{cio_api_key}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        cio_headers["Authorization"] = f"Basic {encoded_credentials}"
    else:
        # App API uses Bearer Token authentication
        cio_app_api_key = os.environ.get("CIO_APP_API_KEY")
        if not cio_app_api_key:
            logger.error("CIO_APP_API_KEY not found in environment for App API")
            return None, {}, body
        cio_headers["Authorization"] = f"Bearer {cio_app_api_key}"

    is_authorized = bool(user_email)
    processed_path, processed_body = _process_identifiers(
        clean_path, body, user_email, is_authorized
    )

    cio_url = urljoin(api_config["base_url"], processed_path)

    logger.info(f"Prepared {api_config['name']} API request: {cio_url}")
    return cio_url, cio_headers, processed_body


def _process_identifiers(
    path: str, body: str, user_email: Optional[str], is_authorized: bool
) -> Tuple[str, str]:
    # Transform mobile app device endpoint to Customer.io format
    if (
        path == "device"
        or path == "api/v1/device"
        or path == "cio/v1/device"
        or path == "cio/device"
    ):
        path = "customers/{identifier}/devices"

    # Transform mobile app notification endpoints to Customer.io push/events format
    if path == "cio/notification_received":
        path = "push/events"
    elif path == "notification_opened":
        path = "push/events"

    processed_body = body
    body_data = None

    if body:
        try:
            body_data = json.loads(body)
        except json.JSONDecodeError:
            logger.warning(
                "Could not parse body as JSON in process_identifiers, "
                "proceeding without body modification."
            )
            body_data = {}

    # Handle push/events specially - they don't use {identifier} replacement
    if path == "push/events":
        if body_data:
            # For notification_received -> delivered event
            if "notification_id" in body_data:
                body_data["delivery_id"] = body_data.get("notification_id")
                body_data["event"] = "delivered"
                if "notification_id" in body_data:
                    del body_data["notification_id"]

            # For notification_opened -> opened event
            if "fcm_token" in body_data:
                body_data["device_id"] = body_data.get("fcm_token")
                body_data["event"] = "opened"
                if "fcm_token" in body_data:
                    del body_data["fcm_token"]

            # Add timestamp if not present
            if "timestamp" not in body_data:
                import time

                body_data["timestamp"] = int(time.time())

            processed_body = json.dumps(body_data)

        return path, processed_body

    if is_authorized and user_email:
        processed_path = path.replace("{identifier}", user_email)

        if body_data:
            # Special handling for device endpoints
            if "customers/{identifier}/devices" in path:
                # For device endpoints, keep device.id as is for authorized users too
                pass
            else:
                # Regular identifier processing for other endpoints
                if "id" in body_data:
                    body_data["id"] = user_email
                if "customer_id" in body_data:
                    body_data["customer_id"] = user_email
            processed_body = json.dumps(body_data)

    else:
        # For device endpoints, use device.id as identifier
        if (
            "customers/{identifier}/devices" in path
            and body_data
            and "device" in body_data
        ):
            device_id = body_data.get("device", {}).get("id")
            if device_id:
                anonymous_id = get_anonymous_identifier(device_id)
            else:
                anonymous_id = get_anonymous_identifier("unknown_device")
        else:
            identifier_key, identifier_value = extract_identifier_from_body(body)
            if not identifier_value:
                identifier_value = "unknown"
            anonymous_id = get_anonymous_identifier(identifier_value)

        processed_path = path.replace("{identifier}", anonymous_id)

        if body_data:
            if "customers/{identifier}/devices" in path:
                pass
            else:
                # Regular identifier processing for other endpoints
                if identifier_key and identifier_key in body_data:
                    del body_data[identifier_key]
                    logger.debug(
                        f"Removed key '{identifier_key}' from body for anonymous request."
                    )

                if "id" in body_data:
                    body_data["id"] = anonymous_id
                if "customer_id" in body_data:
                    body_data["customer_id"] = anonymous_id

            processed_body = json.dumps(body_data)

    return processed_path, processed_body


def _make_cio_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: str,
    query_params: Dict[str, str],
) -> requests.Response:
    kwargs = {"headers": headers, "params": query_params, "timeout": 30}

    if body and method.upper() in ["POST", "PUT", "PATCH"]:
        kwargs["data"] = body

    logger.info(f"Making {method} request to Customer.io: {url}")

    response = requests.request(method, url, **kwargs)

    logger.info(f"Customer.io response: {response.status_code}")
    return response


def _create_success_response(cio_response: requests.Response) -> Dict[str, Any]:
    try:
        response_body = cio_response.text

        # Parse Customer.io response data
        cio_data: Dict[str, Any] = {}
        try:
            cio_data = json.loads(response_body) if response_body else {}
        except json.JSONDecodeError:
            # If Customer.io returns non-JSON, wrap it as text
            cio_data = {"message": response_body} if response_body else {}

        # Create a unified response format expected by mobile app
        unified_response = {"data": cio_data, "status": "SUCCESS"}

        return {
            "statusCode": 200,  # Always return 200 for successful proxied requests
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
                "Access-Control-Allow-Headers": (
                    "Content-Type,Authorization,X-User-Email"
                ),
            },
            "body": json.dumps(unified_response),
        }

    except Exception as e:
        logger.error(f"Error creating success response: {str(e)}")
        return _create_error_response(500, "Response processing error")


def _create_error_response(
    status_code: int, message: str, request_id: Optional[str] = None
) -> Dict[str, Any]:
    # Create unified error response format expected by mobile app
    error_response = {
        "data": {
            "error": {
                "message": message,
                "request_id": str(request_id),
                "code": status_code,
            }
        },
        "status": "ERROR",
    }

    return {
        "statusCode": 200,  # Always return 200, error info is in response body
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
            "Access-Control-Allow-Headers": ("Content-Type,Authorization,X-User-Email"),
        },
        "body": json.dumps(error_response),
    }


def _create_cio_error_response(
    cio_response: requests.Response, request_id: Optional[str] = None
) -> Dict[str, Any]:
    """Create error response from Customer.io API error with unified format."""
    try:
        # Try to parse Customer.io error response
        cio_error_data: Dict[str, Any] = {}
        try:
            cio_error_data = json.loads(cio_response.text) if cio_response.text else {}
        except json.JSONDecodeError:
            cio_error_data = {"message": cio_response.text} if cio_response.text else {}

        # Create unified error response format
        error_response = {
            "data": {
                "error": {
                    "message": cio_error_data.get("message", "Error from Customer.io"),
                    "request_id": str(request_id),
                    "code": cio_response.status_code,
                    "cio_error": cio_error_data,  # Include original Customer.io error for debugging
                }
            },
            "status": "ERROR",
        }

        return {
            "statusCode": 200,  # Always return 200, error info is in response body
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
                "Access-Control-Allow-Headers": (
                    "Content-Type,Authorization,X-User-Email"
                ),
            },
            "body": json.dumps(error_response),
        }

    except Exception as e:
        logger.error(f"Error creating Customer.io error response: {str(e)}")
        return _create_error_response(
            500, "Error processing Customer.io response", request_id
        )


def _extract_caller_info(event: Dict[str, Any], headers: Dict[str, str]) -> str:
    """Extract caller information from the event and headers for logging purposes."""
    caller_parts = []

    # Source IP address
    source_ip = None
    if "requestContext" in event:
        # API Gateway format
        if "identity" in event["requestContext"]:
            source_ip = event["requestContext"]["identity"].get("sourceIp")
        # Lambda Function URL format
        elif "http" in event["requestContext"]:
            source_ip = event["requestContext"]["http"].get("sourceIp")

    if source_ip:
        caller_parts.append(f"ip={source_ip}")

    # User Agent
    user_agent = headers.get("User-Agent") or headers.get("user-agent")
    if user_agent:
        # Truncate long user agents
        if len(user_agent) > 100:
            user_agent = user_agent[:97] + "..."
        caller_parts.append(f"ua={user_agent}")

    # CloudFront headers (if coming through CloudFront)
    cloudfront_viewer_country = headers.get("CloudFront-Viewer-Country") or headers.get(
        "cloudfront-viewer-country"
    )
    if cloudfront_viewer_country:
        caller_parts.append(f"country={cloudfront_viewer_country}")

    # X-Forwarded-For (original client IP if proxied)
    x_forwarded_for = headers.get("X-Forwarded-For") or headers.get("x-forwarded-for")
    if x_forwarded_for:
        # Take the first IP (original client)
        original_ip = x_forwarded_for.split(",")[0].strip()
        if original_ip != source_ip:
            caller_parts.append(f"original_ip={original_ip}")

    # API Gateway specific information
    if "requestContext" in event:
        request_context = event["requestContext"]

        # Request ID
        request_id = request_context.get("requestId")
        if request_id:
            caller_parts.append(f"req_id={request_id}")

        # API Gateway stage
        stage = request_context.get("stage")
        if stage:
            caller_parts.append(f"stage={stage}")

        # Account ID (helps identify the caller environment)
        account_id = request_context.get("accountId")
        if account_id:
            caller_parts.append(f"account={account_id}")

    # If we're called directly (Lambda Function URL), mention it
    if "version" in event and event["version"] == "2.0":
        caller_parts.append("source=lambda_url")
    elif "requestContext" in event and "apiId" in event["requestContext"]:
        caller_parts.append("source=api_gateway")

    return " | ".join(caller_parts) if caller_parts else "unknown"
