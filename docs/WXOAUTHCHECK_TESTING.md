# Testing WxoAuthCheck Plugin

## Understanding the Two Authentication Layers

### Layer 1: Gateway API Authentication (Already Exists)
- **Purpose**: Protects the gateway's API endpoints
- **Configuration**: `AUTH_REQUIRED=true` in `.env`
- **Validates**: Incoming requests TO the gateway
- **Error**: Returns 401 if missing/invalid JWT or Basic Auth

### Layer 2: WxoAuthCheck Plugin (What We Implemented)
- **Purpose**: Validates outgoing HTTP requests to external tools/services
- **Configuration**: `plugins/config.yaml` - `wxo_auth_check` section
- **Validates**: Outgoing requests FROM the gateway to tools
- **Error**: Blocks tool invocation if authentication headers are missing/invalid

## Prerequisites for Testing

1. **Start the gateway**:
   ```bash
   make dev
   ```

2. **Get an authentication token** for the gateway API:
   ```bash
   python -m mcpgateway.utils.create_jwt_token \
     --username admin@example.com \
     --exp 10080 \
     --secret 11759cbc89dbec64956715e10a854eb38f8b7a1775bdf68142786170f5e8b5b2
   ```

   This will output a JWT token like:
   ```
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```

3. **Set the token as an environment variable**:
   ```bash
   export MCPGATEWAY_BEARER_TOKEN="Bearer <your-token-here>"
   ```

## Test Scenario 1: List Tools (Gateway API Auth Only)

This tests the gateway's own authentication, NOT the WxoAuthCheck plugin.

```bash
# Without auth - should fail with 401
curl http://localhost:8000/tools

# With auth - should succeed
curl -H "Authorization: $MCPGATEWAY_BEARER_TOKEN" \
  http://localhost:8000/tools
```

**Expected Result**: 
- Without auth: `{"detail": "Not authenticated"}`
- With auth: List of tools

## Test Scenario 2: Create a Test Tool

Create a tool that makes HTTP requests to an external service:

```bash
curl -X POST http://localhost:8000/tools \
  -H "Authorization: $MCPGATEWAY_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test_api_call",
    "description": "Test tool for WxoAuthCheck plugin",
    "url": "https://httpbin.org/post",
    "request_type": "POST",
    "enabled": true,
    "visibility": "private"
  }'
```

## Test Scenario 3: Invoke Tool WITHOUT Authentication Headers

This is where the WxoAuthCheck plugin should block the request.

```bash
curl -X POST http://localhost:8000/tools/invoke \
  -H "Authorization: $MCPGATEWAY_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_id": "test_api_call",
    "arguments": {
      "test": "data"
    }
  }'
```

**Expected Result**: 
```json
{
  "detail": "Authentication required. No valid authentication header found. Supported types: bearer, basic, apikey"
}
```

**Why**: The tool invocation doesn't include authentication headers for the outgoing request to httpbin.org, so the WxoAuthCheck plugin blocks it.

## Test Scenario 4: Invoke Tool WITH Authentication Headers

Now include authentication headers that will be passed to the external service:

```bash
curl -X POST http://localhost:8000/tools/invoke \
  -H "Authorization: $MCPGATEWAY_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_id": "test_api_call",
    "arguments": {
      "test": "data"
    },
    "headers": {
      "Authorization": "Bearer external-service-token"
    }
  }'
```

**Expected Result**: 
```json
{
  "content": [
    {
      "type": "text",
      "text": "..."
    }
  ]
}
```

**Why**: The tool invocation includes a Bearer token in the headers, so the WxoAuthCheck plugin allows the request to proceed.

## Test Scenario 5: Check Plugin Logs

Enable debug logging to see the plugin in action:

1. **Update `.env`**:
   ```bash
   LOG_LEVEL=DEBUG
   ```

2. **Restart the gateway**:
   ```bash
   make dev
   ```

3. **Invoke a tool** and watch the logs for:
   ```
   [DEBUG] WxoAuthCheck: Validating authentication headers
   [DEBUG] WxoAuthCheck: Found Bearer token
   [DEBUG] WxoAuthCheck: Authentication validation passed
   ```

   Or if authentication is missing:
   ```
   [DEBUG] WxoAuthCheck: No valid authentication found
   [ERROR] WxoAuthCheck: Blocking request - authentication required
   ```

## Test Scenario 6: Test with Different Auth Types

### Basic Authentication

```bash
curl -X POST http://localhost:8000/tools/invoke \
  -H "Authorization: $MCPGATEWAY_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_id": "test_api_call",
    "arguments": {"test": "data"},
    "headers": {
      "Authorization": "Basic dXNlcm5hbWU6cGFzc3dvcmQ="
    }
  }'
```

### API Key

```bash
curl -X POST http://localhost:8000/tools/invoke \
  -H "Authorization: $MCPGATEWAY_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_id": "test_api_call",
    "arguments": {"test": "data"},
    "headers": {
      "X-API-Key": "sk_test_1234567890"
    }
  }'
```

## Test Scenario 7: Disable Plugin and Verify

To confirm the plugin is working, temporarily disable it:

1. **Update `plugins/config.yaml`**:
   ```yaml
   wxo_auth_check:
     enabled: false  # Changed from true
   ```

2. **Restart the gateway**

3. **Invoke tool without auth headers** - should now succeed (plugin is disabled)

4. **Re-enable the plugin** and verify it blocks again

## Verifying Plugin Integration

To verify the plugin is properly integrated in the tool service:

1. **Check the tool service code** at [`mcpgateway/services/tool_service.py`](../mcpgateway/services/tool_service.py):
   - Line 1057-1082: HTTP pre-forwarding hook for REST tools
   - Line 1207-1231: HTTP pre-forwarding hook for MCP connections

2. **Search for hook calls**:
   ```bash
   grep -n "HTTP_PRE_FORWARDING_CALL" mcpgateway/services/tool_service.py
   ```

   Should show:
   ```
   54:    HookType,
   1068:        HookType.HTTP_PRE_FORWARDING_CALL,
   1218:        HookType.HTTP_PRE_FORWARDING_CALL,
   ```

## Common Issues

### Issue 1: "Not authenticated" Error

**Symptom**: Getting 401 error when calling `/tools`

**Solution**: This is the gateway's own authentication. You need to:
1. Generate a JWT token (see Prerequisites)
2. Include it in the `Authorization` header

### Issue 2: Plugin Not Blocking Requests

**Symptom**: Tool invocations succeed even without auth headers

**Possible Causes**:
1. Plugin is disabled in `plugins/config.yaml`
2. Plugin mode is set to `permissive` instead of `enforce`
3. `allow_missing_auth` is set to `true`

**Solution**: Check plugin configuration:
```yaml
wxo_auth_check:
  enabled: true
  mode: enforce  # Must be enforce
  config:
    allow_missing_auth: false  # Must be false
```

### Issue 3: All Requests Blocked

**Symptom**: Even requests with auth headers are blocked

**Possible Causes**:
1. Auth header format is incorrect
2. Required auth types don't match what you're sending

**Solution**: Check the error message for details about what's expected

## Summary

The WxoAuthCheck plugin validates **outgoing** HTTP requests from the gateway to external tools/services. It does NOT validate **incoming** API requests to the gateway itself (that's handled by `AUTH_REQUIRED=true`).

To test the plugin:
1. Authenticate with the gateway API (get JWT token)
2. Create a test tool
3. Try invoking it without auth headers (should be blocked)
4. Try invoking it with auth headers (should succeed)
