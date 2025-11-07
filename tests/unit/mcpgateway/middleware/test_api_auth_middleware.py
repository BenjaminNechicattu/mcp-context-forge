"""
Unit tests for API Authentication Middleware.

Tests the integration of the auth_pre_check plugin with the API authentication middleware
to validate incoming requests using the HTTP_PRE_FORWARDING_CALL hook.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from fastapi import Request, Response
from starlette.datastructures import Headers

from mcpgateway.middleware.api_auth_middleware import APIAuthMiddleware, get_api_auth_middleware_config
from mcpgateway.plugins.framework.manager import PluginManager
from mcpgateway.plugins.framework.types import HookType, HttpPreForwardingCallResult, PluginViolation


@pytest.fixture
def mock_plugin_manager():
    """Create a mock plugin manager."""
    manager = Mock(spec=PluginManager)
    manager.execute_hooks = AsyncMock()
    return manager


@pytest.fixture
def mock_request():
    """Create a mock FastAPI request."""
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.path = "/tools"
    request.method = "GET"
    request.headers = Headers({"authorization": "Bearer test-token"})
    request.cookies = {}
    request.client = Mock()
    request.client.host = "127.0.0.1"
    request.state = Mock()
    return request


@pytest.fixture
def mock_call_next():
    """Create a mock call_next function."""
    async def call_next(request):
        return Response(content="OK", status_code=200)
    return call_next


@pytest.mark.asyncio
async def test_middleware_skips_unprotected_paths(mock_plugin_manager, mock_call_next):
    """Test that middleware skips authentication for unprotected paths."""
    middleware = APIAuthMiddleware(
        app=Mock(),
        plugin_manager=mock_plugin_manager,
        require_auth=True
    )

    # Test health endpoint
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.path = "/health"
    request.method = "GET"

    response = await middleware.dispatch(request, mock_call_next)

    assert response.status_code == 200
    mock_plugin_manager.execute_hooks.assert_not_called()


@pytest.mark.asyncio
async def test_middleware_validates_protected_paths(mock_plugin_manager, mock_request, mock_call_next):
    """Test that middleware validates authentication for protected paths."""
    # Setup successful authentication
    mock_plugin_manager.execute_hooks.return_value = HttpPreForwardingCallResult(
        continue_processing=True,
        metadata={"jwt_claims": {"sub": "user123", "username": "test@example.com"}}
    )

    middleware = APIAuthMiddleware(
        app=Mock(),
        plugin_manager=mock_plugin_manager,
        require_auth=True
    )

    response = await middleware.dispatch(mock_request, mock_call_next)

    assert response.status_code == 200
    mock_plugin_manager.execute_hooks.assert_called_once()
    assert hasattr(mock_request.state, "jwt_claims")
    assert mock_request.state.jwt_claims["sub"] == "user123"


@pytest.mark.asyncio
async def test_middleware_blocks_invalid_auth(mock_plugin_manager, mock_request, mock_call_next):
    """Test that middleware blocks requests with invalid authentication."""
    # Setup failed authentication
    violation = PluginViolation(
        code="INVALID_AUTH",
        reason="Invalid token",
        description="Token validation failed"
    )
    mock_plugin_manager.execute_hooks.return_value = HttpPreForwardingCallResult(
        continue_processing=False,
        violation=violation
    )

    middleware = APIAuthMiddleware(
        app=Mock(),
        plugin_manager=mock_plugin_manager,
        require_auth=True
    )

    response = await middleware.dispatch(mock_request, mock_call_next)

    assert response.status_code == 403
    mock_plugin_manager.execute_hooks.assert_called_once()


@pytest.mark.asyncio
async def test_middleware_handles_cookie_auth(mock_plugin_manager, mock_call_next):
    """Test that middleware handles cookie-based authentication."""
    # Setup request with cookie token
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.path = "/tools"
    request.method = "GET"
    request.headers = Headers({})  # No Authorization header
    request.cookies = {"jwt_token": "cookie-token"}
    request.client = Mock()
    request.client.host = "127.0.0.1"
    request.state = Mock()

    # Setup successful authentication
    mock_plugin_manager.execute_hooks.return_value = HttpPreForwardingCallResult(
        continue_processing=True,
        metadata={"jwt_claims": {"sub": "user123"}}
    )

    middleware = APIAuthMiddleware(
        app=Mock(),
        plugin_manager=mock_plugin_manager,
        require_auth=True
    )

    response = await middleware.dispatch(request, mock_call_next)

    assert response.status_code == 200
    # Verify the cookie token was used
    call_args = mock_plugin_manager.execute_hooks.call_args
    payload = call_args[0][1]
    assert "Bearer cookie-token" in payload.headers.get("Authorization", "")


@pytest.mark.asyncio
async def test_middleware_disabled_when_auth_not_required(mock_plugin_manager, mock_request, mock_call_next):
    """Test that middleware is disabled when auth is not required."""
    middleware = APIAuthMiddleware(
        app=Mock(),
        plugin_manager=mock_plugin_manager,
        require_auth=False
    )

    response = await middleware.dispatch(mock_request, mock_call_next)

    assert response.status_code == 200
    mock_plugin_manager.execute_hooks.assert_not_called()


def test_get_api_auth_middleware_config():
    """Test the middleware configuration helper."""
    mock_manager = Mock(spec=PluginManager)

    with patch("mcpgateway.middleware.api_auth_middleware.settings") as mock_settings:
        mock_settings.auth_required = True

        config = get_api_auth_middleware_config(plugin_manager=mock_manager)

        assert config["plugin_manager"] == mock_manager
        assert config["require_auth"] is True


@pytest.mark.asyncio
async def test_middleware_sets_state_before_call_next(mock_plugin_manager, mock_request):
    """Test that middleware sets request.state.jwt_claims BEFORE calling next middleware."""
    # Setup successful authentication
    jwt_claims = {"sub": "user123", "username": "test@example.com"}
    mock_plugin_manager.execute_hooks.return_value = HttpPreForwardingCallResult(
        continue_processing=True,
        metadata={"jwt_claims": jwt_claims}
    )

    # Track when state is set vs when call_next is called
    state_set_before_call_next = False

    async def call_next_with_check(request):
        nonlocal state_set_before_call_next
        # Check if state was set before call_next was called
        state_set_before_call_next = hasattr(request.state, "jwt_claims") and request.state.jwt_claims is not None
        return Response(content="OK", status_code=200)

    middleware = APIAuthMiddleware(
        app=Mock(),
        plugin_manager=mock_plugin_manager,
        require_auth=True
    )

    response = await middleware.dispatch(mock_request, call_next_with_check)

    assert response.status_code == 200
    assert state_set_before_call_next, "jwt_claims should be set BEFORE call_next is called"
    assert mock_request.state.jwt_claims == jwt_claims


@pytest.mark.asyncio
async def test_middleware_handles_missing_auth_header(mock_plugin_manager, mock_call_next):
    """Test that middleware handles requests without Authorization header."""
    # Setup request without auth header
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.path = "/tools"
    request.method = "GET"
    request.headers = Headers({})
    request.cookies = {}
    request.client = Mock()
    request.client.host = "127.0.0.1"
    request.state = Mock()

    # Setup failed authentication
    violation = PluginViolation(
        code="MISSING_AUTH",
        reason="Missing authentication",
        description="No Authorization header provided"
    )
    mock_plugin_manager.execute_hooks.return_value = HttpPreForwardingCallResult(
        continue_processing=False,
        violation=violation
    )

    middleware = APIAuthMiddleware(
        app=Mock(),
        plugin_manager=mock_plugin_manager,
        require_auth=True
    )

    response = await middleware.dispatch(request, mock_call_next)

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_middleware_path_protection_logic():
    """Test that path protection logic correctly identifies protected vs unprotected paths."""
    middleware = APIAuthMiddleware(
        app=Mock(),
        plugin_manager=Mock(spec=PluginManager),
        require_auth=True
    )

    async def dummy_call_next(request):
        return Response(content="OK", status_code=200)

    # Test unprotected paths
    unprotected_paths = ["/", "/health", "/ready", "/docs", "/redoc", "/openapi.json", "/static/css/style.css"]
    for path in unprotected_paths:
        request = Mock(spec=Request)
        request.url = Mock()
        request.url.path = path
        request.method = "GET"

        # Should not call plugin for unprotected paths
        with patch.object(middleware.plugin_manager, "execute_hooks") as mock_execute:
            await middleware.dispatch(request, dummy_call_next)
            mock_execute.assert_not_called()

    # Test protected paths
    protected_paths = ["/tools", "/servers", "/prompts", "/resources", "/api/v1/data"]
    for path in protected_paths:
        request = Mock(spec=Request)
        request.url = Mock()
        request.url.path = path
        request.method = "GET"
        request.headers = Headers({"authorization": "Bearer test"})
        request.cookies = {}
        request.client = Mock()
        request.client.host = "127.0.0.1"
        request.state = Mock()

        # Should call plugin for protected paths
        with patch.object(middleware.plugin_manager, "execute_hooks") as mock_execute:
            mock_execute.return_value = HttpPreForwardingCallResult(
                continue_processing=True,
                metadata={"jwt_claims": {"sub": "test"}}
            )
            await middleware.dispatch(request, dummy_call_next)
            mock_execute.assert_called_once()

# Made with Bob
