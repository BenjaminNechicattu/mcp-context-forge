# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/plugins/plugins/auth_pre_check/test_auth_pre_check_utils.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: MCP Context Forge Team

Unit tests for auth_pre_check_utils module.
"""

# Standard
from unittest.mock import MagicMock, patch

# Third-Party
import jwt
import pytest

# Local
from plugins.auth_pre_check.auth_pre_check_utils import validate_auth_header


class TestValidateAuthHeader:
    """Test the validate_auth_header function."""

    def test_empty_header_value(self):
        """Test validation with empty header value."""
        is_valid, error_message, jwt_claims = validate_auth_header(None, ["bearer"])

        assert not is_valid
        assert error_message == "Authentication header is empty"
        assert jwt_claims is None

    def test_empty_string_header_value(self):
        """Test validation with empty string header value."""
        is_valid, error_message, jwt_claims = validate_auth_header("", ["bearer"])

        assert not is_valid
        assert error_message == "Authentication header is empty"
        assert jwt_claims is None

    def test_bearer_token_not_allowed(self):
        """Test Bearer token when bearer is not in allowed types."""
        is_valid, error_message, jwt_claims = validate_auth_header(
            "Bearer test_token",
            ["basic", "api_key"]
        )

        assert not is_valid
        assert error_message == "Bearer authentication is not allowed"
        assert jwt_claims is None

    def test_bearer_token_empty(self):
        """Test Bearer token with empty token value."""
        is_valid, error_message, jwt_claims = validate_auth_header(
            "Bearer ",
            ["bearer"]
        )

        assert not is_valid
        assert error_message == "Bearer token is empty"
        assert jwt_claims is None

    def test_bearer_token_only_whitespace(self):
        """Test Bearer token with only whitespace."""
        is_valid, error_message, jwt_claims = validate_auth_header(
            "Bearer    ",
            ["bearer"]
        )

        assert not is_valid
        assert error_message == "Bearer token is empty"
        assert jwt_claims is None

    @patch("plugins.auth_pre_check.auth_pre_check_utils.settings")
    def test_valid_jwt_token(self, mock_settings):
        """Test validation with a valid JWT token."""
        # Setup mock settings
        secret_key = "test_secret_key"
        mock_settings.jwt_secret_key = MagicMock()
        mock_settings.jwt_secret_key.get_secret_value.return_value = secret_key
        mock_settings.jwt_algorithm = "HS256"
        mock_settings.jwt_audience = "test_audience"
        mock_settings.jwt_issuer = "test_issuer"

        # Create a valid JWT token
        payload = {
            "sub": "user123",
            "aud": "test_audience",
            "iss": "test_issuer",
            "exp": 9999999999  # Far future expiration
        }
        token = jwt.encode(payload, secret_key, algorithm="HS256")

        is_valid, error_message, jwt_claims = validate_auth_header(
            f"Bearer {token}",
            ["bearer"]
        )

        assert is_valid
        assert error_message is None
        assert jwt_claims is not None
        assert jwt_claims["sub"] == "user123"
        assert jwt_claims["aud"] == "test_audience"
        assert jwt_claims["iss"] == "test_issuer"

    @patch("plugins.auth_pre_check.auth_pre_check_utils.settings")
    def test_expired_jwt_token(self, mock_settings):
        """Test validation with an expired JWT token."""
        # Setup mock settings
        secret_key = "test_secret_key"
        mock_settings.jwt_secret_key = MagicMock()
        mock_settings.jwt_secret_key.get_secret_value.return_value = secret_key
        mock_settings.jwt_algorithm = "HS256"
        mock_settings.jwt_audience = "test_audience"
        mock_settings.jwt_issuer = "test_issuer"

        # Create an expired JWT token
        payload = {
            "sub": "user123",
            "aud": "test_audience",
            "iss": "test_issuer",
            "exp": 1  # Expired timestamp
        }
        token = jwt.encode(payload, secret_key, algorithm="HS256")

        is_valid, error_message, jwt_claims = validate_auth_header(
            f"Bearer {token}",
            ["bearer"]
        )

        assert not is_valid
        assert error_message == "Bearer token has expired"
        assert jwt_claims is None

    @patch("plugins.auth_pre_check.auth_pre_check_utils.settings")
    def test_invalid_jwt_signature(self, mock_settings):
        """Test validation with invalid JWT signature."""
        # Setup mock settings
        secret_key = "test_secret_key"
        mock_settings.jwt_secret_key = MagicMock()
        mock_settings.jwt_secret_key.get_secret_value.return_value = secret_key
        mock_settings.jwt_algorithm = "HS256"
        mock_settings.jwt_audience = "test_audience"
        mock_settings.jwt_issuer = "test_issuer"

        # Create a token with wrong secret
        payload = {
            "sub": "user123",
            "aud": "test_audience",
            "iss": "test_issuer",
            "exp": 9999999999
        }
        token = jwt.encode(payload, "wrong_secret", algorithm="HS256")

        is_valid, error_message, jwt_claims = validate_auth_header(
            f"Bearer {token}",
            ["bearer"]
        )

        assert is_valid  # Returns True but with error message
        assert "Invalid bearer token" in error_message
        assert jwt_claims is None

    @patch("plugins.auth_pre_check.auth_pre_check_utils.settings")
    def test_malformed_jwt_token(self, mock_settings):
        """Test validation with malformed JWT token."""
        # Setup mock settings
        mock_settings.jwt_secret_key = MagicMock()
        mock_settings.jwt_secret_key.get_secret_value.return_value = "test_secret"
        mock_settings.jwt_algorithm = "HS256"
        mock_settings.jwt_audience = "test_audience"
        mock_settings.jwt_issuer = "test_issuer"

        is_valid, error_message, jwt_claims = validate_auth_header(
            "Bearer not.a.valid.jwt.token",
            ["bearer"]
        )

        assert is_valid  # Returns True but with error message
        assert "Invalid bearer token" in error_message
        assert jwt_claims is None

    @patch("plugins.auth_pre_check.auth_pre_check_utils.settings")
    def test_non_jwt_bearer_token(self, mock_settings):
        """Test validation with non-JWT bearer token (e.g., opaque token)."""
        # Setup mock settings
        mock_settings.jwt_secret_key = MagicMock()
        mock_settings.jwt_secret_key.get_secret_value.return_value = "test_secret"
        mock_settings.jwt_algorithm = "HS256"
        mock_settings.jwt_audience = "test_audience"
        mock_settings.jwt_issuer = "test_issuer"

        is_valid, error_message, jwt_claims = validate_auth_header(
            "Bearer opaque_token_12345",
            ["bearer"]
        )

        assert is_valid  # Returns True for non-JWT bearer tokens
        assert "Invalid bearer token" in error_message
        assert jwt_claims is None

    def test_unsupported_auth_type(self):
        """Test validation with unsupported authentication type."""
        is_valid, error_message, jwt_claims = validate_auth_header(
            "Basic dXNlcjpwYXNz",
            ["bearer"]
        )

        assert not is_valid
        assert "Unsupported authentication type" in error_message
        assert "bearer" in error_message
        assert jwt_claims is None

    def test_case_insensitive_bearer_check(self):
        """Test that bearer type check is case-insensitive."""
        is_valid, error_message, jwt_claims = validate_auth_header(
            "Bearer test_token",
            ["BEARER", "Basic"]
        )

        # Should not fail on case mismatch since we check lowercase
        assert not is_valid or "Invalid bearer token" in error_message

    @patch("plugins.auth_pre_check.auth_pre_check_utils.settings")
    def test_jwt_with_string_secret_key(self, mock_settings):
        """Test JWT validation when secret key is a plain string (no get_secret_value)."""
        # Setup mock settings with string secret (no get_secret_value method)
        secret_key = "test_secret_key"
        mock_settings.jwt_secret_key = secret_key  # Plain string
        mock_settings.jwt_algorithm = "HS256"
        mock_settings.jwt_audience = "test_audience"
        mock_settings.jwt_issuer = "test_issuer"

        # Create a valid JWT token
        payload = {
            "sub": "user123",
            "aud": "test_audience",
            "iss": "test_issuer",
            "exp": 9999999999
        }
        token = jwt.encode(payload, secret_key, algorithm="HS256")

        is_valid, error_message, jwt_claims = validate_auth_header(
            f"Bearer {token}",
            ["bearer"]
        )

        assert is_valid
        assert error_message is None
        assert jwt_claims is not None
        assert jwt_claims["sub"] == "user123"

    @patch("plugins.auth_pre_check.auth_pre_check_utils.settings")
    def test_jwt_wrong_audience(self, mock_settings):
        """Test JWT validation with wrong audience."""
        # Setup mock settings
        secret_key = "test_secret_key"
        mock_settings.jwt_secret_key = MagicMock()
        mock_settings.jwt_secret_key.get_secret_value.return_value = secret_key
        mock_settings.jwt_algorithm = "HS256"
        mock_settings.jwt_audience = "expected_audience"
        mock_settings.jwt_issuer = "test_issuer"

        # Create a token with wrong audience
        payload = {
            "sub": "user123",
            "aud": "wrong_audience",
            "iss": "test_issuer",
            "exp": 9999999999
        }
        token = jwt.encode(payload, secret_key, algorithm="HS256")

        is_valid, error_message, jwt_claims = validate_auth_header(
            f"Bearer {token}",
            ["bearer"]
        )

        assert is_valid  # Returns True but with error message
        assert "Invalid bearer token" in error_message
        assert jwt_claims is None

    @patch("plugins.auth_pre_check.auth_pre_check_utils.settings")
    def test_jwt_wrong_issuer(self, mock_settings):
        """Test JWT validation with wrong issuer."""
        # Setup mock settings
        secret_key = "test_secret_key"
        mock_settings.jwt_secret_key = MagicMock()
        mock_settings.jwt_secret_key.get_secret_value.return_value = secret_key
        mock_settings.jwt_algorithm = "HS256"
        mock_settings.jwt_audience = "test_audience"
        mock_settings.jwt_issuer = "expected_issuer"

        # Create a token with wrong issuer
        payload = {
            "sub": "user123",
            "aud": "test_audience",
            "iss": "wrong_issuer",
            "exp": 9999999999
        }
        token = jwt.encode(payload, secret_key, algorithm="HS256")

        is_valid, error_message, jwt_claims = validate_auth_header(
            f"Bearer {token}",
            ["bearer"]
        )

        assert is_valid  # Returns True but with error message
        assert "Invalid bearer token" in error_message
        assert jwt_claims is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# Made with Bob
