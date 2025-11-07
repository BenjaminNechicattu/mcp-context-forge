# -*- coding: utf-8 -*-
"""Location: ./mcpgateway/middleware/api_auth_middleware.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: MCP Context Forge Team

API Authentication Middleware.

This middleware validates authentication for incoming API requests to MCP Gateway
by invoking the auth_pre_check plugin's http_pre_forwarding_call hook.
"""

# Standard
import logging
from typing import Callable, Optional

# Third-Party
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# First-Party
from mcpgateway.config import settings
from mcpgateway.plugins.framework import (
    GlobalContext,
    HookType,
    HttpPreForwardingCallPayload,
    PluginManager,
    PluginViolationError,
)

logger = logging.getLogger(__name__)


class APIAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware to authenticate incoming API requests to MCP Gateway.

    This middleware intercepts all incoming API requests and validates
    authentication by calling the auth_pre_check plugin's http_pre_forwarding_call
    hook before allowing the request to proceed to route handlers.

    Protected paths include all API endpoints except:
    - Health check endpoints (/health, /ready)
    - Documentation endpoints (/docs, /redoc, /openapi.json)
    - Static files (/static)
    - Root path (/)

    Configuration is controlled via the plugin system and environment variables.
    """

    def __init__(
        self,
        app,
        plugin_manager: Optional[PluginManager] = None,
        require_auth: bool = True,
    ):
        """Initialize the API authentication middleware.

        Args:
            app: The ASGI application.
            plugin_manager: The plugin manager instance to use for authentication.
            require_auth: Whether authentication is required for API requests.
        """
        super().__init__(app)
        self.plugin_manager = plugin_manager
        self.require_auth = require_auth

        if not plugin_manager:
            logger.warning("No plugin manager provided - API authentication will be disabled")
            self.require_auth = False

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Intercept incoming requests and validate authentication using the plugin system.

        Args:
            request: The incoming HTTP request.
            call_next: The function to call the next middleware or endpoint.

        Returns:
            Response: Either the standard route response or a 401/403 error response.
        """
        path = request.url.path
        logger.info(f"🔵 APIAuthMiddleware.dispatch() called for {request.method} {path}")
        logger.info(f"   require_auth={self.require_auth}, plugin_manager={bool(self.plugin_manager)}")

        # Define paths that don't require authentication
        # Use exact matches for specific paths, and prefix matches for directories
        unprotected_exact = ["/health", "/ready", "/docs", "/redoc", "/openapi.json"]
        unprotected_prefixes = ["/static/", "/admin/login"]  # Note trailing slash for directories

        # Check if the request path is protected
        # Path is unprotected if it exactly matches an unprotected path OR starts with an unprotected prefix
        is_exact_match = path in unprotected_exact
        is_prefix_match = any(path.startswith(prefix) for prefix in unprotected_prefixes)
        is_protected = not (is_exact_match or is_prefix_match or path == "/")

        logger.info(f"   is_protected={is_protected} (exact={is_exact_match}, prefix={is_prefix_match})")

        # Skip authentication for unprotected paths or if auth is disabled
        if not is_protected:
            logger.info(f"   Skipping auth - unprotected path")
            return await call_next(request)

        if not self.require_auth:
            logger.info(f"   Skipping auth - require_auth=False")
            return await call_next(request)

        if not self.plugin_manager:
            logger.info(f"   Skipping auth - no plugin_manager")
            return await call_next(request)

        # Get authentication header
        auth_header_value = request.headers.get("Authorization")
        logger.info(f"   Authorization header from request: {auth_header_value[:50] if auth_header_value else 'None'}...")

        # Check for cookie-based authentication (for Swagger UI compatibility)
        cookie_token = request.cookies.get("jwt_token")
        if not auth_header_value and cookie_token:
            # Use cookie token as Bearer token
            auth_header_value = f"Bearer {cookie_token}"
            logger.info(f"   Using cookie token as Authorization header")

        # Prepare headers dict for plugin
        # Convert FastAPI headers to regular dict (case-insensitive to case-sensitive)
        headers = {}
        for key, value in request.headers.items():
            headers[key] = value

        # Ensure Authorization header is present
        if auth_header_value:
            headers["Authorization"] = auth_header_value
            logger.info(f"   Set Authorization in headers dict: {headers.get('Authorization', 'NOT SET')[:50]}...")
        else:
            logger.warning(f"   No Authorization header or cookie token found")

        # Create payload for the http_pre_forwarding_call hook
        # We're simulating an HTTP forwarding call to validate authentication
        payload = HttpPreForwardingCallPayload(
            url=str(request.url),
            method=request.method,
            headers=headers,
            payload=None,  # We don't need the body for authentication
            context={},
        )

        # Create global context for plugin execution
        global_context = GlobalContext(
            request_id=request.headers.get("X-Request-ID", "unknown"),
            user=None,  # Will be populated by the plugin if auth succeeds
            metadata={
                "source": "api_auth_middleware",
                "path": path,
                "method": request.method,
            }
        )

        try:
            # Call the http_pre_forwarding_call hook on the plugin manager
            # This will invoke all plugins that implement this hook, including auth_pre_check
            result = await self.plugin_manager.execute_hooks(
                HookType.HTTP_PRE_FORWARDING_CALL,
                payload,
                global_context,
                None,  # No local contexts needed
            )

            # Check if any plugin blocked the request
            if not result.continue_processing:
                # Authentication failed - return error response
                violation = result.violation
                if violation:
                    logger.warning(
                        f"Authentication failed for {request.method} {path}: {violation.reason}"
                    )
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": violation.description or violation.reason,
                            "code": violation.code,
                            "reason": violation.reason,
                            "details": violation.details,
                        }
                    )
                else:
                    # No violation details, return generic error
                    logger.warning(f"Authentication failed for {request.method} {path}: No violation details")
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": "Authentication validation failed",
                            "code": "AUTH_FAILED",
                        }
                    )

            # Authentication successful - add metadata to request state BEFORE calling next
            # This is critical because FastAPI dependencies are evaluated before call_next() returns
            if result.metadata:
                request.state.auth_metadata = result.metadata
                jwt_claims = result.metadata.get("jwt_claims")
                if jwt_claims:
                    request.state.jwt_claims = jwt_claims
                    logger.info(
                        f"✅ Plugin authenticated request to {path} - Setting request.state.jwt_claims"
                    )
                    logger.info(f"   JWT claims: sub={jwt_claims.get('sub')}, username={jwt_claims.get('username')}")
                else:
                    logger.warning(f"⚠️ Plugin returned metadata but no jwt_claims for {path}")
            else:
                logger.warning(f"⚠️ Plugin returned no metadata for {path}")

        except PluginViolationError as e:
            # Plugin raised a violation error
            logger.warning(f"Plugin violation for {request.method} {path}: {e.message}")
            violation = e.violation
            return JSONResponse(
                status_code=403,
                content={
                    "detail": violation.description if violation else e.message,
                    "code": violation.code if violation else "PLUGIN_VIOLATION",
                    "reason": violation.reason if violation else e.message,
                    "details": violation.details if violation else {},
                }
            )
        except Exception as e:
            # Unexpected error during plugin execution
            logger.error(f"Error during authentication for {request.method} {path}: {str(e)}")
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal authentication error",
                    "code": "AUTH_ERROR",
                    "message": str(e),
                }
            )

        # Proceed to next middleware or route handler
        return await call_next(request)


def get_api_auth_middleware_config(plugin_manager: Optional[PluginManager] = None) -> dict:
    """
    Get API authentication middleware configuration.

    Args:
        plugin_manager: The plugin manager instance.

    Returns:
        dict: Configuration dictionary with keys:
            - plugin_manager: PluginManager instance
            - require_auth: bool
    """
    # Check if API auth is enabled (default: True if auth_required is True)
    require_auth = getattr(settings, "api_auth_required", settings.auth_required)

    return {
        "plugin_manager": plugin_manager,
        "require_auth": require_auth,
    }

# Made with Bob
