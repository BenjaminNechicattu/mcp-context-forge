# WXO_AUTH_CHECK Plugin

## Overview

The WXO_AUTH_CHECK plugin implements authentication validation for HTTP forwarding calls in the MCP Gateway. It validates authentication headers before HTTP requests are made to tools or downstream gateways, providing a security layer that can enforce authentication requirements.

## Features

- **Multiple Authentication Types**: Supports Bearer tokens, Basic authentication, and API keys
- **Flexible Configuration**: Can be configured to block or warn on missing/invalid authentication
- **URL Allowlist**: Supports allowlisting specific URLs that don't require authentication
- **Configurable Auth Types**: Can restrict which authentication types are allowed
- **Custom Header Support**: Configurable authentication header name (default: `Authorization`)

## Configuration

### Basic Configuration

```yaml
wxo_auth_check:
  enabled: true
  mode: enforce
  priority: 15
  config:
    require_auth: true
    allowed_auth_types:
      - bearer
      - basic
      - apikey
    block_on_missing_auth: true
    auth_header_name: "Authorization"
    allowed_unauthenticated_urls: []
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `require_auth` | boolean | `true` | Whether to require authentication for HTTP calls |
| `allowed_auth_types` | list[str] | `["bearer", "basic", "apikey"]` | List of allowed authentication types |
| `block_on_missing_auth` | boolean | `true` | Whether to block requests with missing/invalid auth |
| `auth_header_name` | string | `"Authorization"` | Name of the authentication header to check |
| `allowed_unauthenticated_urls` | list[str] | `[]` | URLs that don't require authentication |

### Plugin Modes

- **enforce**: Blocks requests with missing/invalid authentication
- **enforce_ignore_error**: Logs warnings but allows requests to proceed
- **permissive**: Only logs information about authentication status
- **disabled**: Plugin is not active

## Authentication Types

### Bearer Token

Standard OAuth 2.0 Bearer token authentication:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Basic Authentication

HTTP Basic authentication with base64-encoded credentials:

```
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

### API Key

Custom API key authentication:

```
Authorization: ApiKey sk_live_1234567890abcdef
```

## Usage Examples

### Example 1: Strict Authentication

Require authentication for all requests, block on missing auth:

```yaml
wxo_auth_check:
  enabled: true
  mode: enforce
  priority: 15
  config:
    require_auth: true
    block_on_missing_auth: true
    allowed_auth_types:
      - bearer
```

### Example 2: Permissive Mode with Warnings

Log warnings but allow requests without authentication:

```yaml
auth_pre_check:
  enabled: true
  mode: permissive
  priority: 15
  config:
    require_auth: true
    block_on_missing_auth: false
```

### Example 3: URL Allowlist

Allow specific URLs without authentication:

```yaml
wxo_auth_check:
  enabled: true
  mode: enforce
  priority: 15
  config:
    require_auth: true
    block_on_missing_auth: true
    allowed_unauthenticated_urls:
      - "https://api.example.com/health"
      - "https://api.example.com/public/*"
```

### Example 4: Custom Header Name

Use a custom authentication header:

```yaml
wxo_auth_check:
  enabled: true
  mode: enforce
  priority: 15
  config:
    require_auth: true
    auth_header_name: "X-API-Key"
    allowed_auth_types:
      - apikey
```

## Implementation Details

### Hook Type

The plugin implements the `HTTP_PRE_FORWARDING_CALL` hook, which is executed before HTTP requests are made to tools or downstream gateways.

### Validation Logic

1. **URL Check**: First checks if the URL is in the allowlist
2. **Header Presence**: Verifies the authentication header exists
3. **Format Validation**: Validates the authentication format matches allowed types
4. **Action**: Based on configuration, either blocks the request or logs a warning

### Error Handling

When authentication validation fails:

- **enforce mode**: Returns `PluginResult` with `should_continue=False` and error message
- **permissive mode**: Returns `PluginResult` with `should_continue=True` and warning message
- **enforce_ignore_error mode**: Logs error but allows request to proceed

## Integration with Tool Service

The plugin integrates with the tool service's HTTP forwarding mechanism. When a tool invocation requires an HTTP call:

1. Tool service prepares the HTTP request
2. `HTTP_PRE_FORWARDING_CALL` hook is triggered
3. AUTH_PRE_CHECK plugin validates authentication
4. If validation passes, HTTP request proceeds
5. If validation fails (enforce mode), request is blocked with error

## Security Considerations

### Best Practices

1. **Use enforce mode in production**: Ensures authentication is required
2. **Minimize allowlist**: Only add URLs that truly don't need authentication
3. **Use specific auth types**: Restrict `allowed_auth_types` to what your system uses
4. **Monitor logs**: Review authentication failures regularly
5. **Rotate credentials**: Implement credential rotation policies

### Limitations

- Plugin validates header presence and format, not credential validity
- Actual credential verification should be done by the downstream service
- Plugin doesn't handle token expiration or refresh
- URL allowlist uses simple string matching (not regex)

## Troubleshooting

### Common Issues

**Issue**: Requests are blocked even with valid authentication

**Solution**: Check that:
- The authentication type is in `allowed_auth_types`
- The header name matches `auth_header_name`
- The authentication format is correct (e.g., "Bearer token", not just "token")

**Issue**: Allowlist URLs not working

**Solution**: Ensure:
- URLs in allowlist match exactly (including protocol and path)
- Use wildcards (*) for pattern matching if needed
- Check for trailing slashes in URLs

**Issue**: Plugin not executing

**Solution**: Verify:
- Plugin is enabled in configuration
- Plugin mode is not "disabled"
- Plugin priority is set correctly
- HTTP forwarding hooks are implemented in tool service

## Related Documentation

- [Plugin Framework](../architecture/plugins.md)
- [HTTP Forwarding Hooks](../architecture/http-forwarding-hooks.md)
- [Tool Service](../architecture/tool-service.md)
- [Authentication Architecture](../architecture/authentication.md)

## Contributing

To contribute improvements to the AUTH_PRE_CHECK plugin:

1. Review the plugin implementation in `plugins/auth_pre_check/`
2. Add tests in `plugins/auth_pre_check/tests/`
3. Update this documentation with new features
4. Submit a pull request with DCO sign-off

## License

This plugin is part of the MCP Context Forge project and is licensed under the same terms.
