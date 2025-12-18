# -*- coding: utf-8 -*-
"""Location: ./plugins/wxo_connections/wxo_connections.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

WXO Connections Plugin.

Connects to an external service before tool invocation to retrieve
pass-through header information that will be added to the tool call.

Hook: tool_pre_invoke
"""

# Future
from __future__ import annotations

# Standard
from typing import Optional, Any, Dict, cast

# Third-Party
from pydantic import BaseModel, Field

import os

# First-Party
from mcpgateway.plugins.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)
from mcpgateway.services.logging_service import LoggingService

# Initialize logging service
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)


class WXOConnectionsConfig(BaseModel):
    """Configuration for WXO Connections plugin.

    Attributes:
        service_url: URL of the external service to connect to.
        timeout: Request timeout in seconds.
        api_key: Optional API key for authentication.
        tool_names: Optional list of tool names to apply this to (None = all tools).
    """

    service_url: str = Field(default="http://localhost:8080/api/headers")
    timeout: int = Field(default=5, ge=1, le=30)
    api_key: Optional[str] = None
    tool_names: Optional[list[str]] = None
    connection_manager_base_url: Optional[str] = os.getenv("CONNECTION_MANAGER_BASE_URL", "http://localhost:3001")


class WXOConnectionsPlugin(Plugin):
    """Connects to wxo-connection manager service to retrieve pass-through headers before tool invocation."""

    def __init__(self, config: PluginConfig) -> None:
        """Initialize the WXO Connections plugin.

        Args:
            config: Plugin configuration.
        """
        super().__init__(config)
        self._cfg = WXOConnectionsConfig(**(config.config or {}))

    def _should_apply(self, tool_name: str) -> bool:
        """Check if plugin should apply to the given tool.

        Args:
            tool_name: Name of the tool being invoked.

        Returns:
            True if plugin should apply to this tool.
        """
        if self._cfg.tool_names is None:
            return True
        return tool_name in self._cfg.tool_names

    async def _fetch_headers_from_service(self, payload: ToolPreInvokePayload, context: PluginContext) -> dict[str, str]:
        """Connect to external service and retrieve pass-through headers.

        This is a placeholder method. Implementation should:
        1. Make an HTTP request to the configured service_url
        2. Pass payload (tool_name, tool_args, incoming headers) and context
        3. Retrieve headers from the response
        4. Handle errors appropriately

        Args:
            payload: Tool invocation payload containing name, args, and headers.
            context: Plugin execution context.

        Returns:
            Dictionary of headers to pass through to the tool.

        Raises:
            Exception: If connection to service fails.
        """

        connection_id = payload.args.pop('wxo_connection_id', None)
        environment_id = payload.args.pop('wxo_environment_id', None)

        logger.info(f"[WXO Connections] Fetching headers for tool '{payload.name}' with connection_id '{connection_id}' and environment_id '{environment_id}'")
        logger.info(f"[WXO Connections] payload: {payload}")


        if connection_id:
            from plugins.wxo_connections.wxo_connections_client import get_runtime_credentials, process_credentials

            access_token = payload.args.pop('wxo_auth', None)

            # Alternatively, try to get from context state
            # this has to be fixed with https://github.com/IBM/mcp-context-forge/issues/1495
            # access_token= context.get_state("wxo_access_token", None)
            # access_token= context.state.get("wxo_access_token", None)

            if not access_token:
                logger.error(f"[WXO Connections] wxo_access_token not found in headers for tool '{payload.name}'")
                logger.error(f"[WXO Connections] Available headers: {list(payload.headers.root.keys()) if payload.headers and payload.headers.root else 'None'}")
                return {}

            # Ensure connection_id is a string
            conn_id_str = str(connection_id) if connection_id else ""
            env_str = str(environment_id) if environment_id else "draft"
            token_str = str(access_token)

            creds = await get_runtime_credentials(connection_id=conn_id_str, access_token=token_str, env=env_str)
            if not creds:
                logger.warning(f"[WXO Connections] No credentials returned from connection manager for connection_id '{connection_id}'")
                return {}

            headers, query_params = process_credentials(creds)

            # Rename X-Upstream-Authorization to Authorization for the MCP client
            # (construct_passthrough_headers already ran before plugin hook)
            if "X-Upstream-Authorization" in headers:
                headers["Authorization"] = headers.pop("X-Upstream-Authorization")
                logger.debug("[WXO Connections] Renamed X-Upstream-Authorization to Authorization")

            if headers:
                logger.info(f"[WXO Connections] Injected headers: {headers}")
            if query_params:
                logger.info(f"[WXO Connections] Injected query params: {query_params}")

            return headers

        logger.warning(f"[WXO Connections] connection not required as no connection_id provided in args for tool '{payload.name}'")
        return {}

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        """Fetch and inject pass-through headers before tool invocation.

        Args:
            payload: Tool invocation payload.
            context: Plugin execution context.

        Returns:
            Result with modified payload including retrieved headers.
        """
        if not self._should_apply(payload.name):
            logger.debug(f"[WXO Connections] Skipping tool '{payload.name}' (not in configured tool_names)")
            return ToolPreInvokeResult(continue_processing=True)

        try:
            # Fetch headers from external service
            additional_headers = await self._fetch_headers_from_service(
                payload=payload,
                context=context
            )

            if not additional_headers:
                logger.debug(f"[WXO Connections] No headers retrieved for tool '{payload.name}'")
                return ToolPreInvokeResult(continue_processing=True)

            # Merge headers into the payload
            current_headers: dict[str, str] = {}
            if payload.headers:
                dumped = payload.headers.model_dump()
                if isinstance(dumped, dict):
                    # Cast the untyped model_dump() result to a typed dict so static checkers know the item types.
                    dumped_dict = cast(Dict[Any, Any], dumped)
                    current_headers = {str(k): str(v) for k, v in dumped_dict.items()}

            # Merge additional headers (ensure all values are strings)
            merged_headers: dict[str, str] = {**current_headers, **additional_headers}

            # Create modified payload with updated headers
            from mcpgateway.plugins.framework.hooks.http import HttpHeaderPayload
            new_payload = ToolPreInvokePayload(
                name=payload.name,
                args=payload.args,
                headers=HttpHeaderPayload(root=merged_headers)
            )

            logger.info(
                f"[WXO Connections] Injected {len(additional_headers)} headers for tool '{payload.name}'"
            )

            return ToolPreInvokeResult(
                modified_payload=new_payload,
                metadata={
                    "wxo_headers_injected": True,
                    "header_count": len(additional_headers),
                    "service_url": self._cfg.service_url
                }
            )

        except Exception as e:
            logger.error(f"[WXO Connections] Failed to fetch headers for tool '{payload.name}': {e}")
            # Continue processing even if header fetch fails
            return ToolPreInvokeResult(
                continue_processing=True,
                metadata={"wxo_error": str(e)}
            )
