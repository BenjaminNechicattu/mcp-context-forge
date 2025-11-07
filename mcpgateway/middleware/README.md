
# MCP Gateway Middleware

This directory contains middleware components for the MCP Gateway that handle cross-cutting concerns like authentication, authorization, and request processing.

## Available Middleware

### API Authentication Middleware

**File:** [`api_auth_middleware.py`](api_auth_middleware.py)

**Purpose:** Validates incoming API requests using the plugin system before they reach route handlers.

**How It Works:**

1. Intercepts all incoming HTTP requests
2. Checks if the path requires authentication (skips health checks, docs, etc.)
3. Extracts authentication credentials from:
   - `Authorization` header (Bearer tokens)
   - `jwt_token` cookie (for Swagger UI compatibility)
4. Calls the plugin manager's `HTTP_PRE_FORWARDING_CALL` hook to validate credentials
5. Sets `request.state.jwt_claims` for downstream RBAC bypass
6. Returns 403 error if authentication fails

**Configuration:**

The middleware is automatically enabled when:
- `AUTH_REQUIRED=true` in `.env`
- `PLUGINS_ENABLED=true` in `.env`
- An authentication plugin (like `WxoAuthCheck`) is configured in `plugins/config.yaml`

**Protected vs Unprotected Paths:**

**Unprotected** (no authentication required):
- `/` - Root endpoint
- `/health` - Health check
- `/ready` - Readiness check
- `/docs` - OpenAPI documentation
- `/redoc` - ReDoc documentation
- `/openapi.json` - OpenAPI schema
- `/static/*` - Static assets
- `/admin/login` - Login page

**Protected** (authentication required):
- `/tools` - Tool management
- `/servers` - Server management
- `/prompts` - Prompt management
- `/resources` - Resource management
- All other API endpoints

**Integration with RBAC:**

The middleware works in conjunction with the RBAC (Role-Based Access Control) system:

1. **Middleware runs first** - Validates authentication using plugins
2. **Sets request state** - Stores JWT claims in `request.state.jwt_claims`
3. **RBAC checks state** - The [`get_current_user_with_permissions()`](rbac.py:70) dependency checks for `jwt_claims`
4. **RBAC bypasses validation** - If claims exist, RBAC skips its own JWT validation
5. **Route handler executes** - Request proceeds with authenticated user context

**Example Usage:**

```python
from mcpgateway.middleware.api_auth_middleware import APIAuthMiddleware, get_api_auth_middleware_config

# In main.py
if settings.auth_required and plugin_manager:
    api_auth_config = get_api_auth_middleware_config(plugin_manager=plugin_manager)
    app.add_middleware(
        APIAuthMiddleware,
        plugin_manager=api_auth_config["plugin_manager"],
        require_auth=api_auth_config["require_auth"],
    )
```

**Testing:**

```bash
# With valid token (succeeds)
curl -H "Authorization: Bearer $TOKEN" http://localhost:5555/tools

# Without token (fails with 403)
curl http://localhost:5555/tools

# Using cookie (for Swagger UI)
curl -b "jwt_token=$TOKEN" http://localhost:5555/tools
```

**Logging:**

The middleware provides detailed logging for debugging:

```
🔵 APIAuthMiddleware.dispatch() called for GET /tools
   require_auth=True, plugin_manager=True
   is_protected=True (exact=False, prefix=False)
   Authorization header from request: Bearer eyJhbGci...
   Set Authorization in headers dict: Bearer eyJhbGci...
✅ Plugin authenticated request to /tools - Setting request.state.jwt_claims
   JWT claims: sub=user123, username=test@example.com
```

**Related Files:**

- [`mcpgateway/main.py`](../main.py:992-1001) - Middleware registration
- [`mcpgateway/middleware/rbac.py`](rbac.py:98-120) - RBAC bypass logic
- [`plugins/auth_pre_check/auth_pre_check.py`](../../plugins/auth_pre_check/auth_pre_check.py) - Authentication plugin
- [`plugins/auth_pre_check/auth_pre_check_utils.py`](../../plugins/auth_pre_check/auth_pre_check_utils.py) - JWT validation utilities

**Tests:**

- [`tests/unit/mcpgateway/middleware/test_api_auth_middleware.py`](../../tests/unit/mcpgateway/middleware/test_api_auth_middleware.py) - Unit tests

### RBAC Middleware

**File:** [`rbac.py`](rbac.py)

**Purpose:** Provides role-based access control for API endpoints.

**Key Functions:**

- [`get_current_user_with_permissions()`](rbac.py:70) - FastAPI dependency for authentication
- [`require_permission()`](rbac.py:176) - Decorator for permission checks
- [`require_admin_permission()`](rbac.py:269) - Decorator for admin-only endpoints

**Integration with API Auth Middleware:**

The RBAC dependency checks for `request.state.jwt_claims` set by the API auth middleware. If present, it bypasses its own JWT validation and uses the plugin-validated claims instead.

### Token Scoping Middleware

**File:** [`token_scoping_middleware.py`](token_scoping_middleware.py)

**Purpose:** Handles token scoping for multi-tenant environments.

**Tests:**

- [`tests/unit/mcpgateway/middleware/test_token_scoping.py`](../../tests/unit/mcpgateway/middleware/test_token_scoping.py)

## Middleware Execution Order

FastAPI middleware runs in **reverse order** of registration:

1. **Last registered** → Runs first
2. **First registered** → Runs last

Current order (from first to last):
1. Security Headers Middleware
2. **API Authentication Middleware** ← Validates auth first
3. Token Scoping Middleware (if email auth enabled)
4. MCP Path Rewrite Middleware
5. Compression Middleware

## Adding New Middleware

To add new middleware:

1. Create a new file in this directory
2. Implement the middleware class with a `dispatch()` method
3. Register it in [`mcpgateway/main.py`](../main.py)
4. Add tests in [`tests/unit/mcpgateway/middleware/`](../../tests/unit/mcpgateway/middleware/)
5. Document it in this README

**Example:**

```python
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, Response

class MyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Pre-processing
        print(f"Request: {request.method} {request.url.path}")
        
        # Call next middleware/handler
        response = await call_next(request)
        
        # Post-processing
        response.headers["X-Custom-Header"] = "value"
        
        return response
```

## Best Practices

1. **Keep middleware focused** - Each middleware should handle one concern
2. **Log appropriately** - Use structured logging for debugging
3. **Handle errors gracefully** - Return proper HTTP status codes
4. **Test thoroughly** - Write unit tests for all middleware
5. **Document behavior** - Update this README when adding new middleware
6. **Consider performance** - Middleware runs on every request
7. **Use request state** - Share data between middleware using `request.state`

## Troubleshooting

### Authentication Not Working

1. Check if middleware is enabled:
   ```bash
   grep "API Authentication Middleware enabled" logs
   ```

2. Verify plugin is loaded:
   ```bash
   grep "Loaded plugin: WxoAuthCheck" logs
   ```

3. Check if path is protected:
   ```bash
   grep "is_protected=True" logs
   ```

4. Verify Authorization header is present:
   ```bash
   grep "Authorization header from request" logs
   ```

### RBAC Still Validating After Plugin Auth

1. Check if `jwt_claims` is set:
   ```bash
   grep "Setting request.state.jwt_claims" logs
   ```

2. Verify RBAC detects claims:
   ```bash
   grep "RBAC: Checking for plugin authentication" logs
   ```

3. Ensure middleware runs before RBAC:
   - Middleware should be registered AFTER RBAC dependency is defined
   - Check middleware registration order in `main.py`

### JWT Validation Errors

1. Check JWT settings in `.env`:
   - `JWT_AUDIENCE_VERIFICATION` - Set to `false` if token has no `aud` claim
   - `REQUIRE_TOKEN_EXPIRATION` - Set to `false` if token has no `exp` claim
   - `JWT_ISSUER` - Leave empty if token has no `iss` claim

2. Verify token structure:
   ```bash
   python -c "import jwt; print(jwt.decode('YOUR_TOKEN', options={'verify_signature': False}))"
   ```

## References

- [FastAPI Middleware Documentation](https://fastapi.tiangolo.com/tutorial/middleware/)
- [Starlette Middleware](https://www.starlette.io/middleware/)
- [MCP Gateway Plugin System](../../plugins/README.md)
- [RBAC Documentation](../../docs/docs/using/rbac.md)
