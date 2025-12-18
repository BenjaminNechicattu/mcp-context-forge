# -*- coding: utf-8 -*-
"""Location: ./plugins/wxo_connections/test_wxo_connections.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Tests for WXO Connections Plugin.
"""

# Future
from __future__ import annotations

# Standard
from unittest.mock import AsyncMock, MagicMock, patch

# Third-Party
import pytest

# First-Party
from mcpgateway.plugins.framework import (
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
)
from mcpgateway.plugins.framework.hooks.http import HttpHeaderPayload

# Local
from plugins.wxo_connections.wxo_connections import (
    WXOConnectionsConfig,
    WXOConnectionsPlugin,
)


@pytest.fixture
def plugin_config():
    """Create a basic plugin configuration."""
    return PluginConfig(
        name="WXOConnections",
        kind="plugins.wxo_connections.wxo_connections.WXOConnectionsPlugin",
        description="Test plugin",
        version="0.1.0",
        hooks=["tool_pre_invoke"],
        mode="permissive",
        priority=30,
        config={
            "service_url": "http://test.example.com/api/headers",
            "timeout": 5,
            "api_key": "test-key-123",
        }
    )


@pytest.fixture
def plugin(plugin_config):
    """Create a plugin instance."""
    return WXOConnectionsPlugin(plugin_config)


@pytest.fixture
def plugin_context():
    """Create a mock plugin context."""
    context = MagicMock(spec=PluginContext)
    context.user_id = "test-user"
    context.session_id = "test-session"
    context.global_context = MagicMock()
    return context


@pytest.fixture
def tool_payload():
    """Create a basic tool invocation payload."""
    return ToolPreInvokePayload(
        name="test_tool",
        args={"param1": "value1"},
        headers=HttpHeaderPayload(
            **{
                "X-Request-ID": "req-123",
                "Content-Type": "application/json"
            }
        )
    )


class TestWXOConnectionsConfig:
    """Test WXO Connections configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = WXOConnectionsConfig()
        assert config.service_url == "http://localhost:8080/api/headers"
        assert config.timeout == 5
        assert config.api_key is None
        assert config.tool_names is None

    def test_custom_config(self):
        """Test custom configuration values."""
        config = WXOConnectionsConfig(
            service_url="http://custom.example.com/headers",
            timeout=10,
            api_key="secret-key",
            tool_names=["tool1", "tool2"]
        )
        assert config.service_url == "http://custom.example.com/headers"
        assert config.timeout == 10
        assert config.api_key == "secret-key"
        assert config.tool_names == ["tool1", "tool2"]

    def test_timeout_validation(self):
        """Test timeout validation."""
        # Valid timeout
        config = WXOConnectionsConfig(timeout=15)
        assert config.timeout == 15

        # Invalid timeout should raise validation error
        with pytest.raises(Exception):  # Pydantic validation error
            WXOConnectionsConfig(timeout=0)

        with pytest.raises(Exception):
            WXOConnectionsConfig(timeout=31)


class TestWXOConnectionsPlugin:
    """Test WXO Connections plugin."""

    def test_plugin_initialization(self, plugin_config):
        """Test plugin initializes correctly."""
        plugin = WXOConnectionsPlugin(plugin_config)
        assert plugin._cfg.service_url == "http://test.example.com/api/headers"
        assert plugin._cfg.timeout == 5
        assert plugin._cfg.api_key == "test-key-123"

    def test_should_apply_all_tools(self, plugin):
        """Test _should_apply returns True for all tools when tool_names is None."""
        assert plugin._should_apply("any_tool") is True
        assert plugin._should_apply("another_tool") is True

    def test_should_apply_specific_tools(self, plugin_config):
        """Test _should_apply filters specific tools."""
        plugin_config.config["tool_names"] = ["tool1", "tool2"]
        plugin = WXOConnectionsPlugin(plugin_config)

        assert plugin._should_apply("tool1") is True
        assert plugin._should_apply("tool2") is True
        assert plugin._should_apply("tool3") is False

    @pytest.mark.asyncio
    async def test_fetch_headers_placeholder(self, plugin, tool_payload, plugin_context):
        """Test placeholder implementation returns empty headers."""
        headers = await plugin._fetch_headers_from_service(
            payload=tool_payload,
            context=plugin_context
        )
        assert headers == {}

    @pytest.mark.asyncio
    async def test_tool_pre_invoke_no_headers_retrieved(self, plugin, tool_payload, plugin_context):
        """Test tool_pre_invoke when no headers are retrieved."""
        result = await plugin.tool_pre_invoke(tool_payload, plugin_context)

        assert result.continue_processing is True
        assert result.modified_payload is None

    @pytest.mark.asyncio
    async def test_tool_pre_invoke_with_headers(self, plugin, tool_payload, plugin_context):
        """Test tool_pre_invoke when headers are retrieved."""
        # Mock the fetch method to return headers
        mock_headers = {
            "X-WXO-Token": "wxo-token-123",
            "X-WXO-User": "wxo-user-456"
        }

        with patch.object(plugin, '_fetch_headers_from_service', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_headers

            result = await plugin.tool_pre_invoke(tool_payload, plugin_context)

            # Verify headers were fetched with payload
            mock_fetch.assert_called_once_with(
                payload=tool_payload,
                context=plugin_context
            )

            # Verify result
            assert result.modified_payload is not None
            assert result.modified_payload.name == "test_tool"
            assert result.modified_payload.args == {"param1": "value1"}

            # Verify headers were merged
            payload_headers = result.modified_payload.headers.model_dump()
            assert "X-Request-ID" in payload_headers
            assert "X-WXO-Token" in payload_headers
            assert payload_headers["X-WXO-Token"] == "wxo-token-123"
            assert payload_headers["X-WXO-User"] == "wxo-user-456"

            # Verify metadata
            assert result.metadata["wxo_headers_injected"] is True
            assert result.metadata["header_count"] == 2
            assert result.metadata["service_url"] == "http://test.example.com/api/headers"

    @pytest.mark.asyncio
    async def test_tool_pre_invoke_skips_filtered_tool(self, plugin_config, plugin_context):
        """Test tool_pre_invoke skips tools not in tool_names filter."""
        plugin_config.config["tool_names"] = ["allowed_tool"]
        plugin = WXOConnectionsPlugin(plugin_config)

        payload = ToolPreInvokePayload(
            name="filtered_tool",
            args={},
            headers=None
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.continue_processing is True
        assert result.modified_payload is None

    @pytest.mark.asyncio
    async def test_tool_pre_invoke_error_handling(self, plugin, tool_payload, plugin_context):
        """Test tool_pre_invoke handles errors gracefully."""
        # Mock the fetch method to raise an exception
        with patch.object(plugin, '_fetch_headers_from_service', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.side_effect = Exception("Service unavailable")

            result = await plugin.tool_pre_invoke(tool_payload, plugin_context)

            # Should continue processing even on error
            assert result.continue_processing is True
            assert result.modified_payload is None
            assert "wxo_error" in result.metadata
            assert "Service unavailable" in result.metadata["wxo_error"]

    @pytest.mark.asyncio
    async def test_tool_pre_invoke_no_existing_headers(self, plugin, plugin_context):
        """Test tool_pre_invoke when payload has no existing headers."""
        payload = ToolPreInvokePayload(
            name="test_tool",
            args={"key": "value"},
            headers=None
        )

        mock_headers = {"X-WXO-Token": "token"}

        with patch.object(plugin, '_fetch_headers_from_service', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_headers

            result = await plugin.tool_pre_invoke(payload, plugin_context)

            assert result.modified_payload is not None
            payload_headers = result.modified_payload.headers.model_dump()
            assert payload_headers["X-WXO-Token"] == "token"

    @pytest.mark.asyncio
    async def test_tool_pre_invoke_header_override(self, plugin, plugin_context):
        """Test that retrieved headers can override existing headers."""
        payload = ToolPreInvokePayload(
            name="test_tool",
            args={},
            headers=HttpHeaderPayload(**{"X-Auth": "old-value"})
        )

        mock_headers = {"X-Auth": "new-value"}

        with patch.object(plugin, '_fetch_headers_from_service', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_headers

            result = await plugin.tool_pre_invoke(payload, plugin_context)

            payload_headers = result.modified_payload.headers.model_dump()
            assert payload_headers["X-Auth"] == "new-value"


class TestWXOConnectionsIntegration:
    """Integration tests for WXO Connections plugin."""

    @pytest.mark.asyncio
    async def test_multiple_tool_invocations(self, plugin, plugin_context):
        """Test plugin handles multiple tool invocations correctly."""
        mock_headers_map = {
            "tool1": {"X-Tool": "tool1-token"},
            "tool2": {"X-Tool": "tool2-token"},
        }

        # Mock fetch to return headers based on payload.name
        mock_fetch = AsyncMock(side_effect=lambda payload, context: mock_headers_map.get(payload.name, {}))

        with patch.object(plugin, '_fetch_headers_from_service', mock_fetch):
            # First tool
            payload1 = ToolPreInvokePayload(name="tool1", args={}, headers=None)
            result1 = await plugin.tool_pre_invoke(payload1, plugin_context)

            headers1 = result1.modified_payload.headers.model_dump()
            assert headers1["X-Tool"] == "tool1-token"

            # Second tool
            payload2 = ToolPreInvokePayload(name="tool2", args={}, headers=None)
            result2 = await plugin.tool_pre_invoke(payload2, plugin_context)

            headers2 = result2.modified_payload.headers.model_dump()
            assert headers2["X-Tool"] == "tool2-token"

    @pytest.mark.asyncio
    async def test_logging(self, plugin, plugin_context, caplog):
        """Test plugin logging behavior."""
        payload = ToolPreInvokePayload(name="test_tool", args={}, headers=None)

        mock_headers = {"X-Test": "value"}

        with patch.object(plugin, '_fetch_headers_from_service', new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = mock_headers

            await plugin.tool_pre_invoke(payload, plugin_context)

            # Check that info log was created
            assert any("Injected" in record.message for record in caplog.records)
