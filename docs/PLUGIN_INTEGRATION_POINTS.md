# WxoAuthCheck Plugin Integration Points

## Overview

This document explains where and when the WxoAuthCheck plugin is called in the codebase, and compares the plugin approach vs. FastAPI middleware approach.

## Current Status: NOT YET INTEGRATED

The plugin is **implemented but not yet integrated**. The hook calls need to be added to the services that make HTTP requests.

## Where the Plugin Would Be Called

### 1. Tool Service - REST Tool Invocation

**File**: `mcpgateway/services/tool_service.py`
**Method**: `invoke_tool()` (line 902)
**Location**: Lines 1046-1049

**Current Code**:
```python
# Line 1046-1049
if method == "GET":
    response = await self._http_client.get(final_url, params=payload, headers=headers)
else:
    response = await self._http_client.request(method, final_url, json=payload, headers=headers)
```

**Where Plugin Would Be Called** (BEFORE the HTTP request):
```python
# BEFORE line 1046 - Add HTTP pre-forwarding hook
if self._plugin_manager:
    from mcpgateway.plugins.framework import (
        HttpPreForwardingCallPayload,
        HookType
    )
    
    pre_payload = HttpPreForwardingCallPayload(
        url=final_url,
        method=method,
        headers=headers,
        payload=payload if method != "GET" else None,
        context=global_context
    )
    
    pre_result = await self._plugin_manager.execute_hooks(
        HookType.HTTP_PRE_FORWARDING_CALL,
        pre_payload,
        global_context
    )
    
    if not pre_result.should_continue:
        raise PluginViolationError(pre_result.error_message)
    
    # Use modified headers if plugin changed them
    if pre_result.modified_payload:
        headers = pre_result.modified_payload.headers

# Then make the HTTP request
if method == "GET":
    response = await self._http_client.get(final_url, params=payload, headers=headers)
else:
    response = await self._http_client.request(method, final_url, json=payload, headers=headers)
```

**Context Available at This Point**:
- ✅ Tool metadata (name, URL, description, etc.)
- ✅ Request headers (including authentication)
- ✅ Request payload/arguments
- ✅ HTTP method (GET, POST, etc.)
- ✅ Final URL (after parameter substitution)
- ✅ Global context (request_id, server_id, tenant_id)
- ✅ No additional DB queries needed - all data already loaded

### 2. Tool Service - MCP Tool Invocation

**File**: `mcpgateway/services/tool_service.py`
**Method**: `invoke_tool()` (line 902)
**Location**: Lines 1125-1145 (SSE) and 1141-1145 (StreamableHTTP)

**Current Code**:
```python
# Lines 1125-1129 (SSE connection)
async with sse_client(url=server_url, headers=headers) as streams:
    async with ClientSession(*streams) as session:
        await session.initialize()
        tool_call_result = await session.call_tool(tool.original_name, arguments)

# Lines 1141-1145 (StreamableHTTP connection)
async with streamablehttp_client(url=server_url, headers=headers) as (read_stream, write_stream, _get_session_id):
    async with ClientSession(read_stream, write_stream) as session:
        await session.initialize()
        tool_call_result = await session.call_tool(tool.original_name, arguments)
```

**Where Plugin Would Be Called**:
```python
# BEFORE SSE/StreamableHTTP connection
if self._plugin_manager:
    pre_payload = HttpPreForwardingCallPayload(
        url=tool_gateway.url,
        method="POST",  # MCP uses POST
        headers=headers,
        payload={"tool": tool.original_name, "arguments": arguments},
        context=global_context
    )
    
    pre_result = await self._plugin_manager.execute_hooks(
        HookType.HTTP_PRE_FORWARDING_CALL,
        pre_payload,
        global_context
    )
    
    if not pre_result.should_continue:
        raise PluginViolationError(pre_result.error_message)

# Then make the MCP connection
async with sse_client(url=server_url, headers=headers) as streams:
    # ... rest of code
```

### 3. Gateway Service - Gateway-to-Gateway Calls

**File**: `mcpgateway/services/gateway_service.py`
**Method**: Various methods that make HTTP calls to other gateways
**Location**: Multiple locations where `httpx.AsyncClient` is used

**Example Location**: Lines 2064-2066
```python
async with client.stream("GET", gateway.url, headers=headers, timeout=timeout) as response:
    # ... handle response
```

**Where Plugin Would Be Called**:
Similar pattern - before making the HTTP request to another gateway.

### 4. OAuth Manager - Token Requests

**File**: `mcpgateway/services/oauth_manager.py`
**Methods**: `get_access_token()`, `refresh_token()`, etc.
**Location**: Lines 248-250, 347-349, etc.

**Current Code**:
```python
async with aiohttp.ClientSession() as session:
    async with session.post(token_url, data=token_data, timeout=...) as response:
        # ... handle response
```

**Where Plugin Would Be Called**:
Before making OAuth token requests (if authentication is required for the OAuth server itself).

## When the Plugin Executes

### Execution Flow

1. **User makes request** → FastAPI endpoint receives request
2. **Service layer** → `tool_service.invoke_tool()` is called
3. **Tool lookup** → Tool is fetched from database (already has all metadata)
4. **Pre-invoke plugins** → Existing tool pre-invoke plugins run (PII filter, etc.)
5. **HTTP preparation** → URL, headers, payload are prepared
6. **🔒 WxoAuthCheck Plugin** → **THIS IS WHERE OUR PLUGIN RUNS**
   - Validates authentication header exists
   - Checks authentication type is allowed
   - Validates format (Bearer, Basic, API key)
   - Can block request or allow it to proceed
7. **HTTP request** → If plugin allows, HTTP request is made
8. **Post-invoke plugins** → Existing tool post-invoke plugins run
9. **Response** → Result returned to user

### What the Plugin Has Access To

At the point where the plugin executes:

```python
HttpPreForwardingCallPayload {
    url: "https://api.example.com/endpoint",  # Final URL after substitution
    method: "POST",                            # HTTP method
    headers: {                                 # All headers including auth
        "Authorization": "Bearer token123",
        "Content-Type": "application/json",
        "X-Custom-Header": "value"
    },
    payload: {                                 # Request body/params
        "arg1": "value1",
        "arg2": "value2"
    },
    context: GlobalContext {                   # Request context
        request_id: "abc123",
        server_id: "gateway-1",
        tenant_id: "tenant-1",
        metadata: {
            TOOL_METADATA: Tool(...),          # Full tool object
            GATEWAY_METADATA: Gateway(...)     # Full gateway object (if MCP)
        }
    }
}
```

## Plugin Approach vs. Middleware Approach

### Plugin Approach (Current Implementation)

**Execution Point**: Inside service methods, right before HTTP calls

**Advantages**:
1. ✅ **No DB queries needed** - All context already loaded
2. ✅ **Full context available** - Tool metadata, gateway info, tenant, etc.
3. ✅ **Granular control** - Can apply different rules per tool/gateway
4. ✅ **Consistent with architecture** - Follows existing plugin patterns
5. ✅ **Easy to test** - Can mock context and test in isolation
6. ✅ **Flexible configuration** - Can enable/disable per deployment
7. ✅ **Access to business logic** - Can make decisions based on tool type, etc.

**Disadvantages**:
1. ❌ **Multiple integration points** - Need to add hook calls in several places
2. ❌ **Headers might be modified** - Headers could be changed before reaching plugin
3. ❌ **Requires code changes** - Need to modify service files

**Integration Effort**: Medium (5-10 integration points across 3-4 files)

### Middleware Approach (Alternative)

**Execution Point**: FastAPI middleware, before request reaches any endpoint

**Advantages**:
1. ✅ **Single implementation** - One place to add authentication logic
2. ✅ **Raw headers** - Access to unmodified HTTP headers
3. ✅ **Catches everything** - All HTTP requests go through middleware
4. ✅ **Standard pattern** - Familiar to web developers

**Disadvantages**:
1. ❌ **Multiple DB queries** - Need to parse request and fetch metadata
2. ❌ **Complex request parsing** - Must determine if it's tool/gateway/prompt call
3. ❌ **Performance overhead** - Runs on EVERY request (even non-MCP)
4. ❌ **Less context** - Harder to make intelligent decisions
5. ❌ **Less flexible** - Harder to apply different rules per tool
6. ❌ **Breaks plugin pattern** - Inconsistent with existing architecture

**Example Middleware Implementation**:
```python
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Parse request to determine type
    path = request.url.path
    
    if path.startswith("/tools/invoke/"):
        # Extract tool name from path
        tool_name = path.split("/")[-1]
        
        # DB QUERY 1: Fetch tool from database
        tool = db.query(Tool).filter(Tool.name == tool_name).first()
        
        if tool and tool.gateway_id:
            # DB QUERY 2: Fetch gateway from database
            gateway = db.query(Gateway).filter(Gateway.id == tool.gateway_id).first()
        
        # Validate authentication
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(
                status_code=401,
                content={"error": "Missing authentication"}
            )
    
    return await call_next(request)
```

**Integration Effort**: Low (1 file to modify) but high complexity

## Recommendation: Plugin Approach

**Reasons**:

1. **Performance**: No additional DB queries - context already loaded
2. **Consistency**: Follows existing plugin architecture patterns
3. **Flexibility**: Can apply different rules per tool/gateway/tenant
4. **Maintainability**: Clear separation of concerns
5. **Testability**: Easy to test with mock contexts

**Trade-off**: Requires integration at multiple points, but each integration is simple and follows the same pattern.

## Integration Checklist

To complete the integration:

- [ ] Add HTTP pre-forwarding hook to REST tool invocation (tool_service.py:1046)
- [ ] Add HTTP pre-forwarding hook to MCP SSE tool invocation (tool_service.py:1125)
- [ ] Add HTTP pre-forwarding hook to MCP StreamableHTTP tool invocation (tool_service.py:1141)
- [ ] Add HTTP pre-forwarding hook to gateway-to-gateway calls (gateway_service.py)
- [ ] Add HTTP post-forwarding hook for response validation (optional)
- [ ] Add tests for plugin integration
- [ ] Update documentation with integration examples
- [ ] Restart server to load plugin

## Example Integration Code

Here's the exact code to add at line 1046 in tool_service.py:

```python
# Add this BEFORE line 1046
if self._plugin_manager:
    from mcpgateway.plugins.framework import (
        HttpPreForwardingCallPayload,
        HookType
    )
    
    pre_payload = HttpPreForwardingCallPayload(
        url=final_url,
        method=method,
        headers=headers,
        payload=payload if method != "GET" else None,
        context=global_context
    )
    
    try:
        pre_result = await self._plugin_manager.execute_hooks(
            HookType.HTTP_PRE_FORWARDING_CALL,
            pre_payload,
            global_context
        )
        
        if not pre_result.should_continue:
            error_msg = pre_result.error_message or "Request blocked by authentication policy"
            raise ToolInvocationError(error_msg)
        
        # Use modified headers if plugin changed them
        if pre_result.modified_payload and pre_result.modified_payload.headers:
            headers = pre_result.modified_payload.headers
            
    except PluginViolationError as e:
        raise ToolInvocationError(f"Authentication validation failed: {str(e)}")

# Then the existing HTTP request code continues...
if method == "GET":
    response = await self._http_client.get(final_url, params=payload, headers=headers)
else:
    response = await self._http_client.request(method, final_url, json=payload, headers=headers)
```

## Conclusion

The plugin approach is superior for this use case because:
- It has full context without additional DB queries
- It's consistent with the existing architecture
- It's more flexible and maintainable
- The integration effort is reasonable

The middleware approach would require more complex request parsing and multiple DB queries, making it less efficient despite being in a single location.
