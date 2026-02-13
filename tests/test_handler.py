"""
Tests for universal Customer.io Lambda proxy handler
"""

import json
from unittest.mock import Mock, patch

from cio_lambda_proxy.handler import (
    _create_error_response,
    _create_success_response,
    _determine_cio_api_type,
    _process_identifiers,
    lambda_handler,
)

USER_EMAIL = "test@example.com"
ANONYMOUS_ID = "device123"
ANONYMOUS_ID_SUFFIXED = f"{ANONYMOUS_ID}_anonymous"


class TestLambdaHandler:
    @patch("cio_lambda_proxy.handler.verify_request")
    @patch("cio_lambda_proxy.handler._make_cio_request")
    def test_track_api_authorized_request(self, mock_make_request, mock_verify):
        mock_verify.return_value = "user@example.com"
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true}'
        mock_make_request.return_value = mock_response

        event = {
            "httpMethod": "POST",
            "path": "/api/v1/customers/{identifier}/events",
            "headers": {
                "Content-Type": "application/json",
                "Authorization": (
                    'Signature keyId="api-gateway",algorithm="rsa-sha256",'
                    'headers="(request-target) host date",signature="test-signature"'
                ),
                "X-User-Email": "user@example.com",
            },
            "body": '{"name": "page_view", "data": {"url": "/dashboard"}}',
            "queryStringParameters": None,
        }

        context = Mock()
        context.aws_request_id = "test-request-id"

        with patch.dict(
            "os.environ", {"CIO_API_KEY": "test-api-key", "CIO_SITE_ID": "test-site-id"}
        ):
            result = lambda_handler(event, context)

        assert result["statusCode"] == 200
        mock_make_request.assert_called_once()

        call_args, call_kwargs = mock_make_request.call_args
        # Now uses Track API for customer events
        assert "track.customer.io" in call_kwargs["url"]
        assert "user@example.com" in call_kwargs["url"]

    @patch("cio_lambda_proxy.handler.verify_request")
    @patch("cio_lambda_proxy.handler._make_cio_request")
    def test_track_api_unauthorized_request(self, mock_make_request, mock_verify):
        mock_verify.return_value = None  # Anonymous request
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true}'
        mock_make_request.return_value = mock_response

        event = {
            "httpMethod": "POST",
            "path": "/api/v1/events",
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": "test",
            },
            "body": '{"user_id": "test", "event": "test_event"}',
        }

        context = Mock()
        context.aws_request_id = "test-request-id"

        with patch.dict(
            "os.environ", {"CIO_API_KEY": "test-api-key", "CIO_SITE_ID": "test-site-id"}
        ):
            response = lambda_handler(event, context)

        assert response["statusCode"] == 200
        # Events endpoint routes to Track API for anonymous events
        call_args, call_kwargs = mock_make_request.call_args
        # Events now route to Track API instead of Beta/App API
        assert "track.customer.io" in call_kwargs["url"]

    @patch("cio_lambda_proxy.handler.verify_request")
    @patch("cio_lambda_proxy.handler._make_cio_request")
    @patch("cio_lambda_proxy.handler._prepare_cio_request")
    def test_lambda_handler_invalid_signature(
        self, mock_prepare_cio_request, mock_make_cio_request, mock_verify_request
    ):
        mock_verify_request.return_value = None  # Signature verification failed
        event = {
            "httpMethod": "POST",
            "path": "/some/path",
            "headers": {
                "Authorization": (
                    'Signature keyId="api-gateway",algorithm="rsa-sha256",'
                    'signature="invalid"'
                )
            },
        }
        context = Mock()
        context.aws_request_id = "12345"

        mock_prepare_cio_request.return_value = (
            "https://beta-api.customer.io/api/v1/events",
            {"Authorization": "Bearer test-api-key"},
            "{}",
        )
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true}'
        mock_make_cio_request.return_value = mock_response

        with patch.dict("os.environ", {"CIO_API_KEY": "test-api-key"}):
            response = lambda_handler(event, context)

        # Now treated as anonymous request, should process normally
        assert response["statusCode"] == 200
        mock_make_cio_request.assert_called_once()

    @patch("cio_lambda_proxy.handler.verify_request")
    @patch("cio_lambda_proxy.handler._make_cio_request")
    def test_lambda_handler_cio_request_fails(
        self, mock_make_cio_request, mock_verify_request
    ):
        mock_verify_request.return_value = "user@example.com"
        mock_make_cio_request.side_effect = Exception("CIO is down")
        event = {
            "httpMethod": "GET",
            "path": "/api/v1/events",
            "headers": {
                "Authorization": (
                    'Signature keyId="api-gateway",algorithm="rsa-sha256",'
                    'signature="valid"'
                )
            },
        }
        context = Mock()
        context.aws_request_id = "test-id"

        with patch.dict(
            "os.environ", {"CIO_API_KEY": "test-api-key", "CIO_SITE_ID": "test-site-id"}
        ):
            response = lambda_handler(event, context)

        assert response["statusCode"] == 200  # Always return 200 in new format
        # Check error is in response body
        body_data = json.loads(response["body"])
        assert body_data["status"] == "ERROR"
        assert body_data["data"]["error"]["message"] == "Internal Server Error"


class TestDetermineCioApiType:
    def test_track_api_customer_path(self):
        result = _determine_cio_api_type("customers/user123/events")
        assert result["name"] == "track"  # Now handled by Track API
        assert result["auth_type"] == "basic"
        assert "track.customer.io" in result["base_url"]

    def test_track_api_events_path(self):
        result = _determine_cio_api_type("events")
        assert result["name"] == "track"  # Anonymous events via Track API
        assert result["auth_type"] == "basic"
        assert "track.customer.io" in result["base_url"]

    def test_app_api_campaigns_path(self):
        result = _determine_cio_api_type("campaigns/123/metrics")
        assert result["name"] == "app"
        assert result["auth_type"] == "bearer"
        assert "api.customer.io" in result["base_url"]

    def test_unknown_path_returns_none(self):
        result = _determine_cio_api_type("unknown/endpoint")
        assert result is None


class TestPrepareCioRequest:
    @patch("cio_lambda_proxy.handler._determine_cio_api_type")
    @patch("cio_lambda_proxy.handler._process_identifiers")
    def test_track_api_authorized_request(
        self, mock_process_identifiers, mock_determine_api
    ):
        mock_determine_api.return_value = {
            "name": "track",
            "base_url": "https://track.customer.io/api/v1/",
            "auth_type": "basic",
        }
        mock_process_identifiers.return_value = (
            "customers/user@example.com/events",
            '{"name": "test"}',
        )

        with patch.dict(
            "os.environ", {"CIO_API_KEY": "test-api-key", "CIO_SITE_ID": "test-site-id"}
        ):
            from cio_lambda_proxy.handler import _prepare_cio_request

            url, headers, body = _prepare_cio_request(
                "POST",
                "/api/v1/customers/{identifier}/events",
                {"Content-Type": "application/json"},
                '{"name": "test", "data": {}}',
                "user@example.com",
            )

        assert "track.customer.io" in url  # Now uses Track API
        assert "user@example.com" in url
        assert headers["User-Agent"] == "CIO-Lambda-Proxy/2.0"
        # Track API uses Basic Auth with base64-encoded site_id:api_key
        import base64

        expected_credentials = base64.b64encode(b"test-site-id:test-api-key").decode()
        assert headers["Authorization"] == f"Basic {expected_credentials}"

    @patch("cio_lambda_proxy.handler._determine_cio_api_type")
    @patch("cio_lambda_proxy.handler._process_identifiers")
    def test_track_api_request(self, mock_process_identifiers, mock_determine_api):
        mock_determine_api.return_value = {
            "name": "track",
            "base_url": "https://track.customer.io/api/v1/",
            "auth_type": "basic",
        }
        mock_process_identifiers.return_value = ("events", '{"type": "event"}')

        with patch.dict(
            "os.environ", {"CIO_API_KEY": "test-api-key", "CIO_SITE_ID": "test-site-id"}
        ):
            from cio_lambda_proxy.handler import _prepare_cio_request

            url, headers, body = _prepare_cio_request(
                "POST",
                "/api/v1/events",
                {"Content-Type": "application/json"},
                '{"type": "event"}',
                None,
            )

        assert "track.customer.io" in url
        import base64

        expected_credentials = base64.b64encode(b"test-site-id:test-api-key").decode()
        assert headers["Authorization"] == f"Basic {expected_credentials}"

    @patch("cio_lambda_proxy.handler._determine_cio_api_type")
    @patch("cio_lambda_proxy.handler._process_identifiers")
    def test_app_api_request(self, mock_process_identifiers, mock_determine_api):
        mock_determine_api.return_value = {
            "name": "app",
            "base_url": "https://api.customer.io/v1/",
            "auth_type": "bearer",
        }
        mock_process_identifiers.return_value = (
            "campaigns/123",
            '{"type": "campaign"}',
        )

        with patch.dict("os.environ", {"CIO_APP_API_KEY": "test-app-api-key"}):
            from cio_lambda_proxy.handler import _prepare_cio_request

            url, headers, body = _prepare_cio_request(
                "GET",
                "/api/v1/campaigns/123",
                {"Content-Type": "application/json"},
                '{"type": "campaign"}',
                None,
            )

        assert "api.customer.io" in url
        assert headers["Authorization"] == "Bearer test-app-api-key"

    @patch("cio_lambda_proxy.handler._determine_cio_api_type")
    def test_missing_api_key(self, mock_determine_api):
        mock_determine_api.return_value = {
            "name": "app",
            "base_url": "https://api.customer.io/v1/",
            "auth_type": "bearer",
        }
        with patch.dict("os.environ", {}, clear=True):
            from cio_lambda_proxy.handler import _prepare_cio_request

            url, headers, body = _prepare_cio_request(
                "POST", "/api/v1/events", {}, "{}", None
            )

        assert url is None


class TestProcessIdentifiers:
    def test_authorized_identifier_replacement(self):
        path, body = _process_identifiers(
            "customers/{identifier}/events",
            '{"id": "placeholder", "data": {}}',
            "user@example.com",
            True,
        )

        assert "user@example.com" in path
        body_data = json.loads(body)
        assert body_data["id"] == "user@example.com"

    def test_unauthorized_anonymous_identifier(self):
        with patch(
            "cio_lambda_proxy.handler.extract_identifier_from_body"
        ) as mock_extract:
            with patch(
                "cio_lambda_proxy.handler.get_anonymous_identifier"
            ) as mock_anonymous:
                mock_extract.return_value = ("id", "user123")
                mock_anonymous.return_value = "user123_anonymous"

                path, body = _process_identifiers(
                    "customers/{identifier}/events", '{"id": "user123"}', None, False
                )

                assert "user123_anonymous" in path
                body_data = json.loads(body)
                assert "id" not in body_data

    def test_invalid_json_body_handling(self):
        path, body = _process_identifiers(
            "customers/{identifier}/events", "invalid json", "user@example.com", True
        )

        assert "user@example.com" in path
        assert body == "invalid json"

    def test_notification_received_path(self):
        """Test /api/v1/cio/notification_received is handled by track API"""
        path, body = _process_identifiers(
            "cio/notification_received",
            '{"notification_id": "test123"}',
            None,  # anonymous
            False,
        )

        assert path == "push/events"
        body_data = json.loads(body)
        assert body_data["delivery_id"] == "test123"
        assert body_data["event"] == "delivered"
        assert "notification_id" not in body_data
        assert "timestamp" in body_data

    def test_notification_opened_path(self):
        """Test /api/v1/notification_opened is handled by track API"""
        path, body = _process_identifiers(
            "notification_opened",
            '{"notification_id": "test456", "fcm_token": "token123"}',
            None,  # anonymous
            False,
        )

        assert path == "push/events"
        body_data = json.loads(body)
        assert body_data["delivery_id"] == "test456"
        assert body_data["device_id"] == "token123"
        assert body_data["event"] == "opened"
        assert "notification_id" not in body_data
        assert "fcm_token" not in body_data
        assert "timestamp" in body_data

    def test_cio_device_path(self):
        """Test /api/v1/cio/device is handled by app API"""
        from cio_lambda_proxy.handler import _determine_cio_api_type

        api_config = _determine_cio_api_type("cio/device")
        assert api_config is not None
        assert api_config["name"] == "app"
        assert api_config["auth_type"] == "bearer"

    def test_push_events_path_mapping(self):
        """Test push/events endpoints are mapped to track API"""
        from cio_lambda_proxy.handler import _determine_cio_api_type

        api_config = _determine_cio_api_type("push/events")
        assert api_config is not None
        assert api_config["name"] == "track"
        assert api_config["auth_type"] == "basic"

        api_config = _determine_cio_api_type("cio/notification_received")
        assert api_config is not None
        assert api_config["name"] == "track"
        assert api_config["auth_type"] == "basic"

        api_config = _determine_cio_api_type("notification_opened")
        assert api_config is not None
        assert api_config["name"] == "track"
        assert api_config["auth_type"] == "basic"


class TestMakeCioRequest:
    @patch("requests.request")
    def test_track_api_basic_auth(self, mock_request):
        from cio_lambda_proxy.handler import _make_cio_request

        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        with patch.dict(
            "os.environ", {"CIO_SITE_ID": "test-site-id", "CIO_API_KEY": "test-api-key"}
        ):
            _make_cio_request(
                "POST",
                "https://track.customer.io/api/v1/customers/test/events",
                {"Content-Type": "application/json"},
                '{"name": "test"}',
                {},
            )

        mock_request.assert_called_once()
        call_kwargs = mock_request.call_args.kwargs
        # No longer using Basic Auth, all APIs use Bearer tokens
        assert "auth" not in call_kwargs or call_kwargs.get("auth") is None

    @patch("requests.request")
    def test_app_api_bearer_auth(self, mock_request):
        from cio_lambda_proxy.handler import _make_cio_request

        mock_response = Mock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        headers = {"Authorization": "Bearer test-api-key"}

        _make_cio_request(
            "POST",
            "https://api.customer.io/v1/events",
            headers,
            '{"type": "event"}',
            {},
        )

        mock_request.assert_called_once()
        call_kwargs = mock_request.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"] == "Bearer test-api-key"


class TestResponseCreation:
    def test_create_success_response(self):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true}'

        result = _create_success_response(mock_response)

        assert result["statusCode"] == 200
        assert "Access-Control-Allow-Origin" in result["headers"]
        # Check new unified response format
        body_data = json.loads(result["body"])
        assert body_data["status"] == "SUCCESS"
        assert body_data["data"] == {"success": True}

    def test_create_error_response(self):
        result = _create_error_response(400, "Bad Request", "test-request-id")

        assert result["statusCode"] == 200  # Always return 200 in new format
        body_data = json.loads(result["body"])
        assert body_data["status"] == "ERROR"
        assert body_data["data"]["error"]["message"] == "Bad Request"
        assert body_data["data"]["error"]["request_id"] == "test-request-id"
        assert body_data["data"]["error"]["code"] == 400
