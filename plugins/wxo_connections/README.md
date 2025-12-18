# WXO Connections Plugin

## Overview

The WXO Connections plugin connects to an external service before tool invocation to retrieve pass-through header information that will be added to the tool call.

## Hook Point

- `tool_pre_invoke`: Intercepts tool calls before invocation to fetch and inject headers

## Configuration

```yaml
plugins:
  - name: "WXOConnections"
    kind: "plugins.wxo_connections.wxo_connections.WXOConnectionsPlugin"
    description: "Connects to external service for pass-through headers"
    version: "0.1.0"
    author: "ContextForge"
    hooks: ["tool_pre_invoke"]
    tags: ["headers", "integration", "external-service"]
    mode: "permissive"  # enforce | permissive | disabled
    priority: 30
    config:
      service_url: "http://localhost:8080/api/headers"
      timeout: 5
      api_key: "your-api-key-here"  # Optional
      tool_names: null  # Apply to all tools, or specify list ["tool1", "tool2"]
```

## Configuration Options

- **service_url** (str, default: `"http://localhost:8080/api/headers"`): URL of the external service to connect to
- **timeout** (int, default: `5`): Request timeout in seconds (1-30)
- **api_key** (str, optional): API key for authentication with the external service
- **tool_names** (list[str], optional): List of tool names to apply this plugin to. If `null`, applies to all tools.

## How It Works

1. **Pre-Invoke Hook**: When a tool is about to be invoked, the plugin intercepts the call
2. **Service Connection**: Connects to the configured external service with tool context
3. **Header Retrieval**: Fetches pass-through headers from the service response
4. **Header Injection**: Merges retrieved headers with existing headers in the tool payload
5. **Continue Processing**: Passes the modified payload to the next plugin or tool invocation

## Implementation Status

### Current

- ✅ Plugin structure and configuration
- ✅ Hook integration with `tool_pre_invoke`
- ✅ Header merging logic
- ✅ Error handling (continues on failure)
- ✅ Tool filtering by name

### TODO

- ⚠️ Actual HTTP client implementation to connect to external service
- ⚠️ Request/response format definition with service
- ⚠️ Authentication handling
- ⚠️ Retry logic for service failures
- ⚠️ Caching of headers (optional optimization)

## Placeholder Implementation

The current implementation includes a placeholder method `_fetch_headers_from_service()` that:
- Logs the intended service connection
- Returns empty headers
- Provides commented structure for actual implementation

### To Implement

Replace the placeholder in `_fetch_headers_from_service()` with actual HTTP client code:

```python
async def _fetch_headers_from_service(self, tool_name: str, tool_args: dict, context: PluginContext) -> dict[str, str]:
    import httpx
    
    async with httpx.AsyncClient(timeout=self._cfg.timeout) as client:
        request_data = {
            "tool_name": tool_name,
            "tool_args": tool_args,
            "context": {
                "user_id": context.user_id,
                "session_id": context.session_id,
            }
        }
        headers = {}
        if self._cfg.api_key:
            headers["Authorization"] = f"Bearer {self._cfg.api_key}"
        
        response = await client.post(
            self._cfg.service_url,
            json=request_data,
            headers=headers
        )
        response.raise_for_status()
        return response.json().get("headers", {})
```

## Example Use Cases

1. **Dynamic Authorization**: Fetch user-specific authorization tokens per tool
2. **Context Propagation**: Retrieve correlation IDs, trace IDs, or session tokens
3. **Rate Limiting Headers**: Get rate limit tokens from centralized service
4. **Feature Flags**: Retrieve headers that enable/disable certain features
5. **Multi-Tenant Routing**: Get tenant-specific routing headers

## Metadata

The plugin adds metadata to the result:

```python
{
    "wxo_headers_injected": True,
    "header_count": 3,
    "service_url": "http://localhost:8080/api/headers"
}
```

On error:
```python
{
    "wxo_error": "Connection timeout"
}
```

## Error Handling

- **Service Unavailable**: Logs error and continues tool invocation without additional headers
- **Timeout**: Respects configured timeout, logs error, continues processing
- **Invalid Response**: Logs error, continues with empty headers

The plugin is designed to be non-blocking - if the external service fails, tool invocation proceeds normally.

## Development

To add this plugin to your gateway:

1. Ensure the plugin directory is in your plugins path
2. Add configuration to `plugins/config.yaml`
3. Set appropriate priority (recommend 20-40 to run before tool invocation)
4. Configure service URL and authentication

## Testing

Basic unit tests should cover:
- Header retrieval and merging
- Tool name filtering
- Error handling and fallback
- Configuration validation

Integration tests should verify:
- Actual service connection
- End-to-end header propagation
- Performance under various conditions
