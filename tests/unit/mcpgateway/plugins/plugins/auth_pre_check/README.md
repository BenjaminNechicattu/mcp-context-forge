# Auth Pre-Check Plugin Unit Tests

This directory contains comprehensive unit tests for the `auth_pre_check` plugin.

## Test Files

### `test_auth_pre_check_utils.py`
Tests for the utility functions in `auth_pre_check_utils.py`:

- **Empty/Invalid Headers**: Tests validation with `None`, empty strings, and whitespace
- **Bearer Token Validation**: Tests for allowed/disallowed bearer tokens
- **JWT Token Validation**: Tests for valid JWT tokens with proper claims extraction
- **Expired Tokens**: Tests for expired JWT token detection
- **Invalid Signatures**: Tests for JWT tokens with invalid signatures
- **Malformed Tokens**: Tests for malformed JWT tokens
- **Non-JWT Bearer Tokens**: Tests for opaque bearer tokens
- **Unsupported Auth Types**: Tests for unsupported authentication types
- **Case Sensitivity**: Tests for case-insensitive bearer type checking
- **Secret Key Handling**: Tests for both SecretStr and plain string secret keys
- **Wrong Audience/Issuer**: Tests for JWT tokens with incorrect audience or issuer

### `test_auth_pre_check.py`
Tests for the main plugin in `auth_pre_check.py`:

- **Configuration Tests**: Tests for default and custom plugin configurations
- **Missing Auth Header**: Tests blocking and warning modes when auth is missing
- **Auth Not Required**: Tests when authentication is not required
- **Valid Bearer Tokens**: Tests successful validation with valid JWT tokens
- **Invalid Bearer Tokens**: Tests blocking of invalid tokens
- **Expired Tokens**: Tests blocking of expired tokens
- **Opaque Tokens**: Tests handling of non-JWT bearer tokens
- **Custom Auth Headers**: Tests using custom header names (e.g., `X-API-Key`)
- **Multiple Auth Types**: Tests with multiple allowed authentication types
- **Permissive Mode**: Tests plugin behavior in permissive mode
- **Violation Details**: Tests that violations contain proper error details
- **Integration Tests**: Tests plugin integration with the plugin manager

## Test Token

The tests use a real JWT token for realistic testing:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmMjQyZWFkZi0wZGM5LTRlYWUtYjJkNy02NWIwOWI0YjRiMTYiLCJ1c2VybmFtZSI6Ind4by5hcmNoZXJAaWJtLmNvbSIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJ0ZW5hbnRfaWQiOiJkMjg1NDZlMC05NDQ0LTQyMWUtOGNiYy1kZDU4NmIyMDlkYTAiLCJ3b1RlbmFudElkIjoiZDI4NTQ2ZTAtOTQ0NC00MjFlLThjYmMtZGQ1ODZiMjA5ZGEwIiwid29Vc2VySWQiOiJmMjQyZWFkZi0wZGM5LTRlYWUtYjJkNy02NWIwOWI0YjRiMTYifQ.99rImlu-7SyMJU7eD0wz13r12LMDOr4yYJBvM5n9kSk
```

Decoded payload:
```json
{
  "sub": "f242eadf-0dc9-4eae-b2d7-65b09b4b4b16",
  "username": "wxo.archer@ibm.com",
  "aud": "authenticated",
  "tenant_id": "d28546e0-9444-421e-8cbc-dd586b209da0",
  "woTenantId": "d28546e0-9444-421e-8cbc-dd586b209da0",
  "woUserId": "f242eadf-0dc9-4eae-b2d7-65b09b4b4b16"
}
```

## Running Tests

Run all auth_pre_check tests:
```bash
make test
```

Run specific test file:
```bash
pytest tests/unit/mcpgateway/plugins/plugins/auth_pre_check/test_auth_pre_check.py -v
```

Run specific test:
```bash
pytest tests/unit/mcpgateway/plugins/plugins/auth_pre_check/test_auth_pre_check.py::TestWxoAuthCheckPlugin::test_valid_bearer_token -v
```

## Coverage

The tests provide comprehensive coverage of:
- All configuration options
- All validation paths (success and failure)
- Edge cases (empty strings, whitespace, malformed tokens)
- Integration with the plugin framework
- Error handling and violation reporting

## Test Structure

Tests follow the project's testing conventions:
- Use `pytest` with async support
- Mock external dependencies (settings, JWT validation)
- Use fixtures for common test data
- Clear test names describing what is being tested
- Comprehensive assertions for all expected behaviors
