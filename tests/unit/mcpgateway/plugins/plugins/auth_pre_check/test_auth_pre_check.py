# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/plugins/plugins/auth_pre_check/test_auth_pre_check.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: MCP Context Forge Team

Unit tests for WXO_AUTH_CHECK Plugin.
"""

# Standard
from unittest.mock import MagicMock, patch

# Third-Party
import jwt
import pytest

# First-Party
from mcpgateway.plugins.framework.models import (
    GlobalContext,
    HookType,
    HttpPreForwardingCallPayload,
    PluginConfig,
    PluginContext,
    PluginMode,
)

# Local
from plugins.auth_pre_check.auth_pre_check import (
    WxoAuthCheckConfig,
    WxoAuthCheckPlugin,
)


# Real JWT token for testing
TEST_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmMjQyZWFkZi0wZGM5LTRlYWUtYjJkNy02NWIwOWI0YjRiMTYiLCJ1c2VybmFtZSI6Ind4by5hcmNoZXJAaWJtLmNvbSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJ0ZW5hbnRfaWQiOiJkMjg1NDZlMC05NDQ0LTQyMWUtOGNiYy1kZDU4NmIyMDlkYTAiLCJ3b1RlbmFudElkIjoiZDI4NTQ2ZTAtOTQ0NC00MjFlLThjYmMtZGQ1ODZiMjA5ZGEwIiwid29Vc2VySWQiOiJmMjQyZWFkZi0wZGM5LTRlYWUtYjJkNy02NWIwOWI0YjRiMTYifQ.99rImlu-7SyMJU7eD0wz13r12LMDOr4yYJBvM5n9kSk"


class TestWxoAuthCheckConfig:
    """Test the WxoAuthCheckConfig configuration model."""

    def test_default_config(self):
        """Test default configuration values."""
        config = WxoAuthCheckConfig()

        assert config.require_auth is True
        assert config.allowed_auth_types == ["bearer"]
        assert config.check_token_format is False
        assert config.block_on_missing_auth is True
        assert config.auth_header == "Authorization"

    def test_custom_config(self):
        """Test custom configuration values."""
        config = WxoAuthCheckConfig(
            require_auth=False,
            allowed_auth_types=["bearer", "basic", "api_key"],
            check_token_format=True,
            block_on_missing_auth=False,
            auth_header="X-Custom-Auth"
        )

        assert config.require_auth is False
        assert config.allowed_auth_types == ["bearer", "basic", "api_key"]
        assert config.check_token_format is True
        assert config.block_on_missing_auth is False
        assert config.auth_header == "X-Custom-Auth"


class TestWxoAuthCheckPlugin:
    """Test the WxoAuthCheckPlugin integration."""

    @pytest.fixture
    def plugin_config(self) -> PluginConfig:
        """Create a test plugin configuration."""
        return PluginConfig(
            name="TestAuthCheck",
            description="Test Auth Check Plugin",
            author="Test",
            kind="plugins.auth_pre_check.auth_pre_check.WxoAuthCheckPlugin",
            version="1.0",
            hooks=[HookType.HTTP_PRE_FORWARDING_CALL],
            tags=["test", "auth"],
            mode=PluginMode.ENFORCE,
            priority=10,
            config={
                "require_auth": True,
                "allowed_auth_types": ["bearer"],
                "check_token_format": False,
                "block_on_missing_auth": True,
                "auth_header": "Authorization",
            },
        )

    @pytest.mark.asyncio
    async def test_missing_auth_header_blocks(self, plugin_config):
        """Test that missing authentication header blocks request when configured."""
        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-1"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert not result.continue_processing
        assert result.violation is not None
        assert result.violation.code == "MISSING_AUTH"
        assert "Missing authentication" in result.violation.reason
        assert result.metadata["auth_check"] == "failed"
        assert result.metadata["reason"] == "missing_auth"

    @pytest.mark.asyncio
    async def test_missing_auth_header_warning(self, plugin_config):
        """Test that missing authentication header logs warning when not blocking."""
        plugin_config.config["block_on_missing_auth"] = False
        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-2"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert result.continue_processing
        assert result.violation is None
        assert result.metadata["auth_check"] == "warning"
        assert result.metadata["reason"] == "missing_auth_allowed"

    @pytest.mark.asyncio
    async def test_auth_not_required(self, plugin_config):
        """Test that request passes when auth is not required."""
        plugin_config.config["require_auth"] = False
        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-3"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert result.continue_processing
        assert result.violation is None
        assert result.metadata["auth_check"] == "passed"
        assert result.metadata["auth_type"] == "none"

    @pytest.mark.asyncio
    @patch("plugins.auth_pre_check.auth_pre_check.validate_auth_header")
    async def test_valid_bearer_token(self, mock_validate, plugin_config):
        """Test successful validation with valid Bearer token."""
        # Mock successful validation with JWT claims
        jwt_claims = {
            "sub": "f242eadf-0dc9-4eae-b2d7-65b09b4b4b16",
            "username": "wxo.archer@ibm.com",
            "aud": "authenticated",
            "tenant_id": "d28546e0-9444-421e-8cbc-dd586b209da0"
        }
        mock_validate.return_value = (True, None, jwt_claims)

        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-4"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={"Authorization": f"Bearer {TEST_JWT_TOKEN}"},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert result.continue_processing
        assert result.violation is None
        assert result.metadata["auth_check"] == "passed"
        assert result.metadata["auth_type"] == "bearer"
        assert "jwt_claims" in result.metadata
        assert result.metadata["jwt_claims"]["sub"] == "f242eadf-0dc9-4eae-b2d7-65b09b4b4b16"
        assert result.metadata["jwt_claims"]["username"] == "wxo.archer@ibm.com"

        # Verify validate_auth_header was called correctly
        mock_validate.assert_called_once_with(
            f"Bearer {TEST_JWT_TOKEN}",
            allowed_types=["bearer"]
        )

    @pytest.mark.asyncio
    @patch("plugins.auth_pre_check.auth_pre_check.validate_auth_header")
    async def test_invalid_bearer_token(self, mock_validate, plugin_config):
        """Test that invalid Bearer token blocks request."""
        # Mock failed validation
        mock_validate.return_value = (False, "Invalid token signature", None)

        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-5"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={"Authorization": "Bearer invalid_token"},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert not result.continue_processing
        assert result.violation is not None
        assert result.violation.code == "INVALID_AUTH"
        assert "Invalid authentication" in result.violation.reason
        assert "Invalid token signature" in result.violation.description
        assert result.metadata["auth_check"] == "failed"
        assert result.metadata["reason"] == "invalid_auth_format"

    @pytest.mark.asyncio
    @patch("plugins.auth_pre_check.auth_pre_check.validate_auth_header")
    async def test_expired_bearer_token(self, mock_validate, plugin_config):
        """Test that expired Bearer token blocks request."""
        # Mock expired token validation
        mock_validate.return_value = (False, "Bearer token has expired", None)

        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-6"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={"Authorization": "Bearer expired_token"},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert not result.continue_processing
        assert result.violation is not None
        assert result.violation.code == "INVALID_AUTH"
        assert "Bearer token has expired" in result.violation.description

    @pytest.mark.asyncio
    @patch("plugins.auth_pre_check.auth_pre_check.validate_auth_header")
    async def test_bearer_token_without_jwt_claims(self, mock_validate, plugin_config):
        """Test Bearer token validation without JWT claims (opaque token)."""
        # Mock successful validation but no JWT claims (opaque token)
        mock_validate.return_value = (True, None, None)

        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-7"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={"Authorization": "Bearer opaque_token_12345"},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert result.continue_processing
        assert result.violation is None
        assert result.metadata["auth_check"] == "passed"
        assert result.metadata["auth_type"] == "bearer"
        assert "jwt_claims" not in result.metadata

    @pytest.mark.asyncio
    async def test_custom_auth_header(self, plugin_config):
        """Test using custom authentication header name."""
        plugin_config.config["auth_header"] = "X-API-Key"
        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-8"))

        # Request without custom header should fail
        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={"Authorization": "Bearer token"},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert not result.continue_processing
        assert result.violation is not None
        assert "X-API-Key" in result.violation.description

    @pytest.mark.asyncio
    @patch("plugins.auth_pre_check.auth_pre_check.validate_auth_header")
    async def test_multiple_allowed_auth_types(self, mock_validate, plugin_config):
        """Test with multiple allowed authentication types."""
        plugin_config.config["allowed_auth_types"] = ["bearer", "basic", "api_key"]
        mock_validate.return_value = (True, None, None)

        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-9"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={"Authorization": "Bearer token"},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert result.continue_processing
        mock_validate.assert_called_once_with(
            "Bearer token",
            allowed_types=["bearer", "basic", "api_key"]
        )

    @pytest.mark.asyncio
    async def test_permissive_mode(self, plugin_config):
        """Test plugin in permissive mode (should not block)."""
        plugin_config.mode = PluginMode.PERMISSIVE
        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-10"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        # In permissive mode, should still block based on plugin logic
        # (mode is handled by plugin manager, not the plugin itself)
        assert not result.continue_processing
        assert result.violation is not None

    @pytest.mark.asyncio
    @patch("plugins.auth_pre_check.auth_pre_check.validate_auth_header")
    async def test_violation_details(self, mock_validate, plugin_config):
        """Test that violation contains proper details."""
        mock_validate.return_value = (False, "Token validation failed", None)

        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-11"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={"Authorization": "Bearer bad_token"},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert result.violation is not None
        assert result.violation.details["url"] == "https://api.example.com/tool"
        assert result.violation.details["method"] == "POST"
        assert result.violation.details["error"] == "Token validation failed"

    @pytest.mark.asyncio
    async def test_missing_auth_violation_details(self, plugin_config):
        """Test that missing auth violation contains proper details."""
        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-12"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="GET",
            headers={},
            payload={}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert result.violation is not None
        assert result.violation.details["url"] == "https://api.example.com/tool"
        assert result.violation.details["method"] == "GET"
        assert result.violation.details["required_header"] == "Authorization"

    @pytest.mark.asyncio
    @patch("plugins.auth_pre_check.auth_pre_check.validate_auth_header")
    async def test_non_bearer_auth_type(self, mock_validate, plugin_config):
        """Test with non-Bearer authentication type."""
        mock_validate.return_value = (True, None, None)

        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-13"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={"Authorization": "ApiKey abc123"},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert result.continue_processing
        assert result.metadata["auth_type"] == "other"  # Not bearer

    @pytest.mark.asyncio
    async def test_empty_headers_dict(self, plugin_config):
        """Test with empty headers dictionary."""
        plugin = WxoAuthCheckPlugin(plugin_config)
        context = PluginContext(global_context=GlobalContext(request_id="test-14"))

        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={},
            payload={"query": "test"}
        )

        result = await plugin.http_pre_forwarding_call(payload, context)

        assert not result.continue_processing
        assert result.violation is not None
        assert result.violation.code == "MISSING_AUTH"


@pytest.mark.asyncio
async def test_integration_with_manager():
    """Test the auth_pre_check plugin with the plugin manager."""
    # First-Party
    from mcpgateway.plugins.framework.manager import PluginManager

    # Standard
    import tempfile

    # Third-Party
    import yaml

    # Create a test configuration
    config_dict = {
        "plugins": [
            {
                "name": "AuthPreCheck",
                "kind": "plugins.auth_pre_check.auth_pre_check.WxoAuthCheckPlugin",
                "description": "Auth Pre Check",
                "author": "Test",
                "version": "1.0",
                "hooks": ["http_pre_forwarding_call"],
                "tags": ["security", "auth"],
                "mode": "enforce",
                "priority": 10,
                "conditions": [{"server_ids": [], "tenant_ids": []}],
                "config": {
                    "require_auth": True,
                    "allowed_auth_types": ["bearer"],
                    "check_token_format": False,
                    "block_on_missing_auth": True,
                    "auth_header": "Authorization"
                },
            }
        ],
        "plugin_dirs": [],
        "plugin_settings": {
            "parallel_execution_within_band": False,
            "plugin_timeout": 30,
            "fail_on_plugin_error": False,
            "enable_plugin_api": True,
            "plugin_health_check_interval": 60
        },
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(config_dict, f)
        config_path = f.name

    try:
        manager = PluginManager(config_path)
        await manager.initialize()

        # Test with missing auth
        payload = HttpPreForwardingCallPayload(
            url="https://api.example.com/tool",
            method="POST",
            headers={},
            payload={"query": "test"}
        )

        global_context = GlobalContext(request_id="test-manager")

        # Use execute_hooks instead of direct method call
        result, contexts = await manager.execute_hooks(
            HookType.HTTP_PRE_FORWARDING_CALL,
            payload,
            global_context
        )

        # Verify auth check blocked the request
        assert result.violation is not None
        assert result.violation.code == "MISSING_AUTH"

        await manager.shutdown()
    finally:
        # Standard
        import os

        os.unlink(config_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# Made with Bob
