"""
Tests for utils module
"""

import json
import os
import sys

from cio_lambda_proxy.utils import (
    extract_identifier_from_body,
    extract_path_parameters,
    format_cio_error_response,
    get_anonymous_identifier,
    is_json_content_type,
    mask_sensitive_data,
    sanitize_headers,
    validate_cio_path,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestExtractIdentifier:
    def test_extract_from_id_field(self):
        body = json.dumps({"id": "user123", "name": "test"})
        result = extract_identifier_from_body(body)
        assert result == ("id", "user123")

    def test_extract_from_email_field(self):
        body = json.dumps({"email": "user@example.com", "name": "test"})
        result = extract_identifier_from_body(body)
        assert result == ("email", "user@example.com")

    def test_extract_from_user_id_field(self):
        body = json.dumps({"user_id": "12345", "name": "test"})
        result = extract_identifier_from_body(body)
        assert result == ("user_id", "12345")

    def test_extract_from_data_object(self):
        body = json.dumps(
            {"event": "test", "data": {"id": "user456", "properties": {}}}
        )
        result = extract_identifier_from_body(body)
        assert result == ("data", "user456")

    def test_extract_priority_order(self):
        body = json.dumps(
            {
                "identifier": "priority_user",
                "id": "other_user",
                "user_id": "another_user",
                "email": "user@example.com",
            }
        )
        result = extract_identifier_from_body(body)
        assert result == ("identifier", "priority_user")

    def test_extract_empty_body(self):
        result = extract_identifier_from_body("")
        assert result == (None, None)

    def test_extract_invalid_json(self):
        result = extract_identifier_from_body("invalid json")
        assert result == (None, None)

    def test_extract_no_identifier(self):
        body = json.dumps({"name": "test", "value": 123})
        result = extract_identifier_from_body(body)
        assert result == (None, None)


class TestAnonymousIdentifier:
    def test_create_anonymous_identifier(self):
        result = get_anonymous_identifier("user123")
        assert result.startswith("anon_")
        assert len(result) == 37  # "anon_" + 32 char hash

    def test_create_with_spaces(self):
        result = get_anonymous_identifier("  User 123  ")
        assert result.startswith("anon_")
        assert len(result) == 37

    def test_create_with_uppercase(self):
        result = get_anonymous_identifier("USER123")
        assert result.startswith("anon_")
        assert len(result) == 37

    def test_consistent_hashing(self):
        # Same input should produce same hash
        result1 = get_anonymous_identifier("user123")
        result2 = get_anonymous_identifier("user123")
        assert result1 == result2

    def test_different_inputs_different_hashes(self):
        # Different inputs should produce different hashes
        result1 = get_anonymous_identifier("user123")
        result2 = get_anonymous_identifier("user456")
        assert result1 != result2

    def test_already_anonymous(self):
        result = get_anonymous_identifier("user123_anonymous")
        assert result == "user123_anonymous"

    def test_empty_identifier(self):
        result = get_anonymous_identifier("")
        assert result == "unknown_anonymous"

    def test_none_identifier(self):
        result = get_anonymous_identifier(None)
        assert result == "unknown_anonymous"

    def test_length_within_limits(self):
        # Test with very long device token (like Firebase FCM token)
        long_token = (
            "fa5dmwSWsEeyglMnrzlo1I:APA91bELQ2hp6ZfUjgrj1_LzseW_5daed180PrHKFA0bY8mpbghydiK5mC"
            "YtCefXfem9MGNjWclcAlSpLB_GU8VgoacHm58RG3IvgzSmkXcuFOFtI1DgcBI"
        )
        result = get_anonymous_identifier(long_token)
        assert len(result.encode()) <= 150  # Customer.io limit
        assert result.startswith("anon_")


class TestSanitizeHeaders:
    def test_remove_excluded_headers(self):
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer token",
            "X-User-Email": "user@example.com",
            "X-Forwarded-For": "1.2.3.4",
            "Custom-Header": "value",
        }

        result = sanitize_headers(headers)

        assert "Content-Type" in result
        assert "Custom-Header" in result
        assert "Authorization" not in result
        assert "X-User-Email" not in result
        assert "X-Forwarded-For" not in result

    def test_case_insensitive_exclusion(self):
        headers = {
            "content-type": "application/json",
            "AUTHORIZATION": "Bearer token",
            "x-user-email": "user@example.com",
        }

        result = sanitize_headers(headers)

        assert "content-type" in result
        assert "AUTHORIZATION" not in result
        assert "x-user-email" not in result

    def test_empty_values(self):
        headers = {
            "Content-Type": "application/json",
            "Empty-Header": "",
            "None-Header": None,
            "Valid-Header": "value",
        }

        result = sanitize_headers(headers)

        assert "Content-Type" in result
        assert "Valid-Header" in result
        assert "Empty-Header" not in result


class TestValidatePath:
    def test_valid_customers_path(self):
        result = validate_cio_path("/api/v1/customers/user123/events")
        assert result is True

    def test_valid_events_path(self):
        result = validate_cio_path("/api/v1/events")
        assert result is True

    def test_valid_events_with_slash(self):
        result = validate_cio_path("/api/v1/events/")
        assert result is True

    def test_path_without_prefix(self):
        result = validate_cio_path("customers/user123/events")
        assert result is True

    def test_invalid_path(self):
        result = validate_cio_path("/api/v1/invalid/path")
        assert result is False

    def test_empty_path(self):
        result = validate_cio_path("")
        assert result is False


class TestMaskSensitiveData:
    def test_mask_password(self):
        data = {"username": "user", "password": "secret123", "email": "user@test.com"}
        result = mask_sensitive_data(data)
        assert result["username"] == "user"
        assert result["password"] == "secr***"
        assert result["email"] == "user@test.com"

    def test_mask_api_key(self):
        data = {"api_key": "abc123def456", "value": "normal"}
        result = mask_sensitive_data(data)
        assert result["api_key"] == "abc1***"
        assert result["value"] == "normal"

    def test_mask_short_values(self):
        data = {"secret": "abc", "token": "xy"}
        result = mask_sensitive_data(data)
        assert result["secret"] == "***"
        assert result["token"] == "***"

    def test_mask_nested_data(self):
        data = {"user": {"password": "secret123", "name": "John"}, "api_key": "key123"}
        result = mask_sensitive_data(data)
        assert result["user"]["password"] == "secr***"
        assert result["user"]["name"] == "John"
        assert result["api_key"] == "key1***"

    def test_non_dict_input(self):
        result = mask_sensitive_data("not a dict")
        assert result == "not a dict"


class TestFormatErrorResponse:
    def test_format_json_error(self):
        response_text = '{"message": "Invalid request", "code": 400}'
        result = format_cio_error_response(response_text, 400)
        assert result["error"]["status_code"] == 400
        assert result["error"]["message"] == "Invalid request"
        assert result["error"]["details"]["code"] == 400

    def test_format_text_error(self):
        response_text = "Internal server error"
        result = format_cio_error_response(response_text, 500)
        assert result["error"]["status_code"] == 500
        assert result["error"]["message"] == "Internal server error"

    def test_format_empty_response(self):
        result = format_cio_error_response("", 404)
        assert result["error"]["status_code"] == 404
        assert result["error"]["message"] == "Customer.io API error"


class TestContentType:
    def test_json_content_type(self):
        assert is_json_content_type("application/json") is True
        assert is_json_content_type("application/json; charset=utf-8") is True
        assert is_json_content_type("text/json") is True

    def test_non_json_content_type(self):
        assert is_json_content_type("text/html") is False
        assert is_json_content_type("application/xml") is False

    def test_case_insensitive(self):
        assert is_json_content_type("APPLICATION/JSON") is True
        assert is_json_content_type("Text/JSON") is True


class TestPathParameters:
    def test_extract_single_parameter(self):
        path = "/api/v1/customers/{identifier}/events"
        result = extract_path_parameters(path)
        expected = {"identifier": "events"}
        assert result == expected

    def test_extract_multiple_parameters(self):
        path = "/api/v1/customers/{customer_id}/campaigns/{campaign_id}/metrics"
        result = extract_path_parameters(path)
        expected = {"customer_id": "campaigns", "campaign_id": "metrics"}
        assert result == expected

    def test_no_parameters(self):
        path = "/api/v1/events"
        result = extract_path_parameters(path)
        assert result == {}

    def test_empty_path(self):
        path = ""
        result = extract_path_parameters(path)
        assert result == {}
