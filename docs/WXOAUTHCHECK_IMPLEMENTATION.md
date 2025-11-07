# WxoAuthCheck Plugin Implementation Summary

## Overview

This document summarizes the implementation of the WxoAuthCheck authentication plugin for the MCP Gateway, which validates authentication headers before HTTP requests are forwarded to tools and gateways.

## Implementation Details

### 1. Framework Extensions

**File**: [`mcpgateway/plugins/framework/models.py`](../mcpgateway/plugins/framework/models.py)

Added two new hook types to the plugin framework:

- `HTTP_PRE_FORWARDING_CALL` (line 60): Executes before HTTP requests to tools/gateways
- `HTTP_POST_FORWARDING_CALL` (line 61): Executes after HTTP requests to tools/gateways

Created corresponding payload models:

- [`HttpPreForwardingCallPayload`](../mcpgateway/plugins/framework/models.py:1125-1152): Contains URL, method, headers, payload, and context
- [`HttpPostForwardingCallPayload`](../mcpgateway/plugins/framework/models.py:1153-1180): Contains response data and context

**File**: [`mcpgateway/plugins/framework/__init__.py`](../mcpgateway/plugins/framework/__init__.py)

Exported the new payload models and result types for use by plugins.

### 2. Plugin Implementation

**File**: [`plugins/auth_pre_check/auth_pre_check.py`](../plugins/auth_pre_check/auth_pre_check.py)

Created the WxoAuthCheck plugin with the following components:

#### Configuration Model (lines 36-53)

```python
class WxoAuthCheckConfig(BasePluginConfig):
    """Configuration for WxoAuthCheck plugin."""
    
    required_auth_types: list[str] = ["bearer", "basic", "apikey"]
    allow_missing_auth: bool = False
    custom_header_name: Optional[str] = None
```

#### Plugin Class (lines 109-195)

Key features:
- Validates Bearer tokens, Basic auth, and API keys
- Supports custom authentication header names
- Configurable to allow or block requests without authentication
- Returns detailed error messages for authentication failures

#### Hook Method: `http_pre_forwarding_call` (lines 156-195)

Validates authentication headers before HTTP requests:

1. Extracts authentication headers from the request
2. Validates against configured authentication types
3. Returns `should_continue=False` if validation fails
4. Provides detailed error messages for debugging

### 3. Plugin Configuration

**File**: [`plugins/config.yaml`](../plugins/config.yaml:903-926)

```yaml
wxo_auth_check:
  enabled: true
  mode: enforce
  priority: 15
  config:
    required_auth_types:
      - bearer
      - basic
      - apikey
    allow_missing_auth: false
```

Configuration options:
- **enabled**: Plugin is active
- **mode**: `enforce` - blocks requests that fail validation
- **priority**: 15 - executes early in the hook chain
- **required_auth_types**: List of accepted authentication types
- **allow_missing_auth**: Whether to allow requests without authentication

### 4. Service Integration

**File**: [`mcpgateway/services/tool_service.py`](../mcpgateway/services/tool_service.py)

Integrated HTTP pre-forwarding hooks at three critical points:

#### REST Tool Invocations (lines 1057-1082)

Before making HTTP requests to REST tools:

```python
if self._plugin_manager:
    pre_forwarding_payload = HttpPreForwardingCallPayload(
        url=final_url,
        method=method,
        headers=headers,
        payload=payload if method != "GET" else None,
        context=global_context.model_dump() if global_context else {}
    )
    
    pre_forwarding_result = await self._plugin_manager.execute_hooks(
        HookType.HTTP_PRE_FORWARDING_CALL,
        pre_forwarding_payload,
        global_context,
        context_table
    )
    
    if not pre_forwarding_result.should_continue:
        error_msg = pre_forwarding_result.error_message or "Request blocked by authentication policy"
        raise ToolInvocationError(error_msg)
    
    # Use modified headers if plugin changed them
    if pre_forwarding_result.modified_payload and pre_forwarding_result.modified_payload.headers:
        headers = pre_forwarding_result.modified_payload.headers
```

#### MCP SSE/StreamableHTTP Connections (lines 1207-1231)

Before establishing MCP connections:

```python
if self._plugin_manager and tool_gateway:
    pre_forwarding_payload = HttpPreForwardingCallPayload(
        url=tool_gateway.url,
        method="POST",  # MCP connections use POST
        headers=headers,
        payload={"name": name, "arguments": arguments},
        context=global_context.model_dump() if global_context else {}
    )
    
    pre_forwarding_result = await self._plugin_manager.execute_hooks(
        HookType.HTTP_PRE_FORWARDING_CALL,
        pre_forwarding_payload,
        global_context,
        context_table
    )
    
    if not pre_forwarding_result.should_continue:
        error_msg = pre_forwarding_result.error_message or "Request blocked by authentication policy"
        raise ToolInvocationError(error_msg)
    
    # Use modified headers if plugin changed them
    if pre_forwarding_result.modified_payload and pre_forwarding_result.modified_payload.headers:
        headers = pre_forwarding_result.modified_payload.headers
```

### 5. Documentation

Created comprehensive documentation:

1. **Plugin Usage Guide**: [`docs/docs/plugins/auth_pre_check.md`](../docs/docs/plugins/auth_pre_check.md)
   - Configuration options
   - Usage examples
   - Authentication types
   - Error handling

2. **Integration Points**: [`docs/PLUGIN_INTEGRATION_POINTS.md`](../docs/PLUGIN_INTEGRATION_POINTS.md)
   - Where to call hooks in the codebase
   - Plugin vs middleware comparison
   - Best practices

## Authentication Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Request                          │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              MCP Gateway Receives Request                   │
│         (with Authorization/API-Key headers)                │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│           Tool Service: invoke_tool()                       │
│         Prepares HTTP request to tool/gateway               │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│    HTTP_PRE_FORWARDING_CALL Hook Triggered                  │
│         WxoAuthCheck Plugin Executes                        │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│         WxoAuthCheck Validates Headers                      │
│   • Checks for Bearer/Basic/API Key                         │
│   • Validates format and presence                           │
│   • Returns should_continue flag                            │
└─────────────────────┬───────────────────────────────────────┘
                      │
         ┌────────────┴────────────┐
         │                         │
         ▼                         ▼
┌──────────────────┐      ┌──────────────────┐
│  Valid Auth      │      │  Invalid Auth    │
│  Continue        │      │  Block Request   │
└────────┬─────────┘      └────────┬─────────┘
         │                         │
         ▼                         ▼
┌──────────────────┐      ┌──────────────────┐
│  Forward to      │      │  Return Error    │
│  Tool/Gateway    │      │  401/403         │
└──────────────────┘      └──────────────────┘
```

## Supported Authentication Types

### 1. Bearer Token

**Header Format**: `Authorization: Bearer <token>`

**Validation**:
- Checks for "Bearer " prefix
- Validates token is present after prefix
- Does not validate token content (delegated to downstream services)

**Example**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 2. Basic Authentication

**Header Format**: `Authorization: Basic <base64-encoded-credentials>`

**Validation**:
- Checks for "Basic " prefix
- Validates base64-encoded credentials are present
- Does not decode or validate credentials (delegated to downstream services)

**Example**:
```
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

### 3. API Key

**Header Format**: `X-API-Key: <api-key>` or custom header

**Validation**:
- Checks for API key header (default: `X-API-Key`)
- Supports custom header names via configuration
- Validates key is present

**Example**:
```
X-API-Key: sk_live_1234567890abcdef
```

## Configuration Options

### Plugin Mode

- **enforce**: Blocks requests that fail validation (recommended for production)
- **enforce_ignore_error**: Logs errors but allows requests to proceed
- **permissive**: Audits only, never blocks requests
- **disabled**: Plugin is inactive

### Required Auth Types

Configure which authentication types are accepted:

```yaml
required_auth_types:
  - bearer      # Accept Bearer tokens
  - basic       # Accept Basic auth
  - apikey      # Accept API keys
```

### Allow Missing Auth

Control whether requests without authentication are allowed:

```yaml
allow_missing_auth: false  # Block requests without auth (default)
allow_missing_auth: true   # Allow requests without auth
```

### Custom Header Name

Specify a custom header name for API keys:

```yaml
custom_header_name: "X-Custom-API-Key"
```

## Error Messages

The plugin provides detailed error messages for debugging:

### Missing Authentication

```
Authentication required. No valid authentication header found. 
Supported types: bearer, basic, apikey
```

### Invalid Bearer Token

```
Invalid Bearer token format. Expected: Authorization: Bearer <token>
```

### Invalid Basic Auth

```
Invalid Basic authentication format. Expected: Authorization: Basic <credentials>
```

### Missing API Key

```
API key required. Expected header: X-API-Key
```

## Integration Benefits

### 1. Centralized Authentication

- Single point of authentication validation
- Consistent enforcement across all tools and gateways
- Reduces code duplication

### 2. Flexible Configuration

- Per-environment configuration
- Easy to enable/disable
- Configurable authentication types

### 3. No Performance Impact

- Executes only when plugin manager is available
- No additional database queries
- Minimal overhead

### 4. Full Context Access

- Access to tool/gateway metadata
- Request context available
- Can modify headers if needed

## Testing Recommendations

### Unit Tests

Test the plugin in isolation:

```python
async def test_valid_bearer_token():
    """Test that valid Bearer tokens are accepted."""
    plugin = WxoAuthCheckPlugin(config)
    payload = HttpPreForwardingCallPayload(
        url="https://api.example.com",
        method="POST",
        headers={"Authorization": "Bearer valid_token"},
        payload={}
    )
    result = await plugin.http_pre_forwarding_call(payload, context)
    assert result.should_continue is True

async def test_missing_auth():
    """Test that requests without auth are blocked."""
    plugin = WxoAuthCheckPlugin(config)
    payload = HttpPreForwardingCallPayload(
        url="https://api.example.com",
        method="POST",
        headers={},
        payload={}
    )
    result = await plugin.http_pre_forwarding_call(payload, context)
    assert result.should_continue is False
    assert "Authentication required" in result.error_message
```

### Integration Tests

Test the plugin with the tool service:

```python
async def test_tool_invocation_with_auth():
    """Test that tool invocations validate authentication."""
    # Setup tool with authentication required
    tool = create_test_tool(auth_required=True)
    
    # Invoke with valid auth
    result = await tool_service.invoke_tool(
        tool_id=tool.id,
        arguments={},
        headers={"Authorization": "Bearer valid_token"}
    )
    assert result.success is True
    
    # Invoke without auth
    with pytest.raises(ToolInvocationError) as exc:
        await tool_service.invoke_tool(
            tool_id=tool.id,
            arguments={},
            headers={}
        )
    assert "Authentication required" in str(exc.value)
```

### End-to-End Tests

Test the complete flow:

```python
async def test_e2e_auth_validation():
    """Test authentication validation in complete request flow."""
    # Start gateway
    async with TestClient(app) as client:
        # Request without auth - should fail
        response = await client.post(
            "/tools/invoke",
            json={"tool_id": "test_tool", "arguments": {}}
        )
        assert response.status_code == 401
        
        # Request with valid auth - should succeed
        response = await client.post(
            "/tools/invoke",
            json={"tool_id": "test_tool", "arguments": {}},
            headers={"Authorization": "Bearer valid_token"}
        )
        assert response.status_code == 200
```

## Future Enhancements

### 1. Token Validation

Extend the plugin to validate token content:
- JWT signature verification
- Token expiration checking
- Scope/permission validation

### 2. Rate Limiting

Add rate limiting based on authentication:
- Per-token rate limits
- Per-user rate limits
- Configurable limits

### 3. Audit Logging

Enhanced logging for security audits:
- Log all authentication attempts
- Track failed authentication
- Generate security reports

### 4. OAuth Integration

Direct OAuth token validation:
- Validate OAuth tokens with provider
- Cache validation results
- Support multiple OAuth providers

## Troubleshooting

### Plugin Not Executing

**Symptom**: Authentication is not being validated

**Solutions**:
1. Check plugin is enabled in [`plugins/config.yaml`](../plugins/config.yaml)
2. Verify plugin mode is not `disabled`
3. Check plugin manager is initialized in tool service
4. Review logs for plugin loading errors

### False Positives

**Symptom**: Valid requests are being blocked

**Solutions**:
1. Check `required_auth_types` configuration
2. Verify header format matches expected format
3. Check for custom header name configuration
4. Review error messages for specific validation failures

### Performance Issues

**Symptom**: Slow request processing

**Solutions**:
1. Verify plugin priority is appropriate (lower = earlier execution)
2. Check for excessive logging
3. Review plugin mode (permissive mode has less overhead)
4. Consider caching validation results

## Related Files

- Plugin implementation: [`plugins/auth_pre_check/auth_pre_check.py`](../plugins/auth_pre_check/auth_pre_check.py)
- Framework models: [`mcpgateway/plugins/framework/models.py`](../mcpgateway/plugins/framework/models.py)
- Service integration: [`mcpgateway/services/tool_service.py`](../mcpgateway/services/tool_service.py)
- Configuration: [`plugins/config.yaml`](../plugins/config.yaml)
- Documentation: [`docs/docs/plugins/auth_pre_check.md`](../docs/docs/plugins/auth_pre_check.md)

## References

- GitHub Issue: #1019 - Implement HTTP forwarding hooks for authentication
- Plugin Framework Documentation: [`docs/docs/plugins/`](../docs/docs/plugins/)
- MCP Gateway Architecture: [`docs/docs/architecture/`](../docs/docs/architecture/)
