# WXO Auth Pre-Check Plugin

## Overview

The `WXO_AUTH_CHECK` plugin provides JWT-based authentication with automatic tenant-to-team mapping for multi-tenant environments. It validates WXO (Watson Orchestrate) JWTs, extracts tenant information, and generates internal team tokens for subsequent API operations.

**Key Features:**
- JWT validation with configurable verification options
- Automatic tenant-to-team mapping (tenant_id = team_slug)
- Auto-creation of teams and users for new tenants
- Team token generation for seamless API access
- Comprehensive audit logging
- Strict mode for enhanced security

## Architecture

### Simplified Tenant-Team Mapping

The plugin uses a **direct 1:1 mapping** where `tenant_id` equals `team_slug`:
- **No separate mapping table** required
- **Simplified lookups** - just check if team with `slug == tenant_id` exists
- **Atomic team creation** - team is created with `slug == tenant_id`

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Client Request with WXO JWT                                   │
│    Authorization: Bearer <WXO_JWT>                               │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. http_auth_resolve_user Hook                                   │
│    • Validate JWT format and signature                           │
│    • Decode JWT and extract claims                               │
│    • Extract woTenantId from claims                              │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Tenant-Team Resolution                                        │
│    • Check if team exists with slug == tenant_id                 │
│    • If not exists AND auto_create_teams=true:                   │
│      - Create user in email_users table                          │
│      - Create team with slug == tenant_id                        │
│      - Add user as team owner                                    │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Team Token Generation                                         │
│    • Generate JWT with team context                              │
│    • Payload includes:                                           │
│      - sub: team_slug                                            │
│      - team_slug: team_slug                                      │
│      - tenant_id: tenant_id                                      │
│      - token_type: "team_token"                                  │
│      - Original JWT claims (prefixed with wxo_)                  │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. Synthetic User Creation                                       │
│    • Return EmailUser-compatible dict:                           │
│      - email: from JWT claims                                    │
│      - full_name: from JWT claims                                │
│      - is_admin: true (team users get admin privileges)          │
│      - team_slug, tenant_id, team_token in context              │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. Subsequent API Calls                                          │
│    Client can use team_token for all API operations              │
│    Authorization: Bearer <team_token>                            │
└─────────────────────────────────────────────────────────────────┘
```

## How It Works Now

### 1. JWT Validation (`validate_auth_header`)

Validates Bearer tokens against configured JWT settings:

```python
decode_options = {
    "verify_signature": True,
    "verify_exp": settings.require_token_expiration,
    "verify_aud": settings.jwt_audience_verification,
    "verify_iss": False,  # Optional issuer verification
}

claims = jwt.decode(token, secret_key,
    algorithms=[settings.jwt_algorithm],
    options=decode_options,
    audience=settings.jwt_audience if settings.jwt_audience_verification else None
)
```

### 2. Tenant-Team Lookup (`get_tenant_team_slug`)

**Simplified approach** - directly checks if team exists:

```python
def get_tenant_team_slug(tenant_id: str | None) -> str | None:
    """Check if team exists with slug == tenant_id."""
    team = db.query(EmailTeam).filter(EmailTeam.slug == tenant_id).first()
    return tenant_id if team else None
```

### 3. Team Creation (`create_team`)

**Atomic creation** with tenant_id as team_slug:

```python
async def create_team(tenant_id: str, user_email: str) -> str:
    """Create team with slug == tenant_id.
    
    Note: The team_slug parameter is DEPRECATED and ignored.
    tenant_id is always used as the team_slug.
    """
    
    # 1. Ensure user exists in email_users table
    existing_user = db.query(EmailUser).filter(EmailUser.email == user_email).first()
    
    if not existing_user:
        # Create user with Argon2 hashed password (using Argon2 PasswordHasher directly)
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        password_hash = ph.hash("changeme")
        
        new_user = EmailUser(
            email=user_email,
            password_hash=password_hash,
            full_name=user_email.split('@')[0],  # Extract from email prefix
            is_active=True,
            is_admin=True,  # Grant admin privileges to JWT-authenticated users
            email_verified_at=utc_now()  # Auto-verify since authenticated via JWT
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info(f"Created user '{user_email}' with default password 'changeme'")
    
    # 2. Create team with tenant_id as BOTH name and slug
    team = await team_service.create_team(
        name=tenant_id,  # Use tenant_id as team name (not a descriptive name)
        description=f"Team for tenant {tenant_id}",
        created_by=user_email,
        visibility="private",
        max_members=None  # No limit by default
    )
    
    return team.slug  # Returns tenant_id (they are equal)
```

### 4. Team Token Generation (`generate_team_token`)

Creates a JWT for subsequent API operations:

```python
def generate_team_token(team_slug: str, tenant_id: str, 
                       expiry_minutes: int = 60,
                       jwt_claims: dict | None = None) -> str:
    """Generate team token with team context."""
    
    payload = {
        "sub": team_slug,
        "team_slug": team_slug,
        "tenant_id": tenant_id,
        "token_type": "team_token",
        "iat": int(now.timestamp()),
        "exp": int(expiry.timestamp()),
    }
    
    # Include original JWT claims with wxo_ prefix
    if jwt_claims:
        for claim_key in ["email", "username", "name", "woTenantId"]:
            if claim_key in jwt_claims:
                payload[f"wxo_{claim_key}"] = jwt_claims[claim_key]
    
    return jwt.encode(payload, secret_key, algorithm=settings.jwt_algorithm)
```

## Configuration

### Plugin Configuration (`plugins/config.yaml`)

```yaml
plugins:
  - name: WXO_AUTH_CHECK
    enabled: true
    hooks:
      - http_auth_resolve_user  # Custom authentication
      - http_post_request       # Audit logging
    config:
      require_auth: true
      allowed_auth_types:
        - bearer
      check_token_format: true
      block_on_missing_auth: true
      auth_header: "Authorization"
      auto_create_teams: true
      audit_auth_attempts: true
      strict_mode: true
      team_token_expiry_minutes: 60
```

### MCP Gateway Settings (`.env`)

```bash
# JWT Configuration
JWT_SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
JWT_AUDIENCE=your-audience
JWT_ISSUER=your-issuer

# Token Validation
REQUIRE_TOKEN_EXPIRATION=true
JWT_AUDIENCE_VERIFICATION=true

# Team Configuration
MAX_MEMBERS_PER_TEAM=100
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `require_auth` | bool | `true` | Whether authentication is required |
| `allowed_auth_types` | list[str] | `["bearer"]` | Allowed auth types |
| `check_token_format` | bool | `true` | Validate JWT structure |
| `block_on_missing_auth` | bool | `true` | Block requests without auth |
| `auth_header` | str | `"Authorization"` | Header to check |
| `auto_create_teams` | bool | `true` | Auto-create teams for new tenants |
| `audit_auth_attempts` | bool | `true` | Log all auth attempts |
| `strict_mode` | bool | `true` | Deny on invalid tokens |
| `team_token_expiry_minutes` | int | `60` | Team token TTL |

## JWT Claims

The plugin extracts user information from JWT claims in priority order:

### User Email/Username
1. `email`
2. `username`
3. `preferred_username`
4. `upn`
5. `unique_name`
6. `sub`
7. Fallback: `team-{team_slug}@wxo.system`

### Full Name
1. `name`
2. `full_name`
3. `given_name`
4. Fallback: `Team {team_slug}`

### Tenant ID (Required)
- `woTenantId` - **Required** claim for tenant/team mapping
  - This value becomes both the `team_slug` and team `name`
  - Must be a valid slug format (lowercase, alphanumeric, hyphens)

### Permissions
- `is_admin` - Defaults to `true` for JWT-authenticated users

## Database Operations

### Tables Used

The plugin interacts with these existing tables:

1. **`email_users`** - User accounts
   - Primary key: `email`
   - Stores: `password_hash` (Argon2), `full_name`, `is_active`, `is_admin`, `email_verified_at`

2. **`email_teams`** - Team definitions
   - Primary key: `id`
   - Key fields: `slug` (set to `tenant_id`), `name` (also set to `tenant_id`), `created_by` (FK to `email_users.email`)

3. **`email_team_members`** - Team memberships
   - Links users to teams with roles
   - Foreign keys: `team_id` → `email_teams.id`, `user_email` → `email_users.email`

4. **`email_team_member_history`** - Audit trail
   - Tracks membership changes over time

### Team Creation Flow

1. **User Creation** (if user doesn't exist):
   ```sql
   INSERT INTO email_users (
       email, password_hash, full_name, 
       is_active, is_admin, email_verified_at
   ) VALUES (?, ?, ?, true, true, NOW());
   ```

2. **Team Creation**:
   ```sql
   INSERT INTO email_teams (
       name, slug, description, created_by,
       is_personal, visibility, is_active
   ) VALUES (?, ?, ?, ?, false, 'private', true);
   ```

3. **Team Membership**:
   ```sql
   INSERT INTO email_team_members (
       team_id, user_email, role, joined_at, is_active
   ) VALUES (?, ?, 'owner', NOW(), true);
   ```

4. **Membership History**:
   ```sql
   INSERT INTO email_team_member_history (
       team_member_id, team_id, user_email,
       role, action, action_by, action_timestamp
   ) VALUES (?, ?, ?, 'owner', 'added', ?, NOW());
   ```

### No Mapping Table Required

**Previous approach** (deprecated):
```sql
-- Old: Required separate mapping table (NO LONGER USED)
CREATE TABLE tenant_team_mapping (
    mapping_id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    team_slug VARCHAR(255) NOT NULL,
    UNIQUE(tenant_id, team_slug)
);
```

**Current approach** (simplified):
```sql
-- New: Direct lookup in email_teams using tenant_id as slug
SELECT id, name, slug, created_by, visibility 
FROM email_teams 
WHERE slug = :tenant_id AND is_active = true;
```

**Why this works:**
- `tenant_id` from JWT → used directly as `team.slug`
- No translation needed
- Single source of truth
- Fewer database queries

## Comparison with Custom Auth Example

The plugin follows the same pattern as `plugins/examples/custom_auth_example/custom_auth.py`:

| Feature | Custom Auth Example | WXO Auth Check |
|---------|-------------------|----------------|
| Header transformation | ✅ `http_pre_request` | ❌ Not needed |
| Custom authentication | ✅ `http_auth_resolve_user` | ✅ `http_auth_resolve_user` |
| Response headers | ✅ `http_post_request` | ✅ `http_post_request` (audit) |
| API key mapping | ✅ Config-based | ❌ Not needed |
| Tenant management | ❌ | ✅ Auto-create teams |
| Token exchange | ❌ | ✅ WXO JWT → Team token |
| Strict mode | ✅ | ✅ |

## Benefits of This Approach

1. **No core changes needed** - Uses existing plugin framework hooks
2. **Proper separation of concerns** - Authentication logic in the right hook (`http_auth_resolve_user`)
3. **Flexible fallback** - Can fall back to standard auth when `strict_mode=false`
4. **Extensible** - Easy to add more authentication methods
5. **Auditable** - Built-in logging and monitoring via `http_post_request` hook
6. **Tenant-aware** - Automatic team management for multi-tenancy
7. **Simplified architecture** - Direct `tenant_id` → `team_slug` mapping eliminates mapping table
8. **Fewer database operations** - No JOIN required, just direct slug lookup
9. **Token exchange** - WXO JWT → internal team token for subsequent calls
10. **Idempotent** - Safe to call multiple times for same tenant

## Testing

### Test with curl

```bash
# 1. Generate a test WXO JWT (requires jwt CLI tool)
export WXO_TOKEN=$(jwt encode \
  --secret "your-secret-key" \
  --alg HS256 \
  --exp +1h \
  '{"sub":"user@example.com","woTenantId":"tenant-123","email":"user@example.com","name":"Test User"}')

# 2. Make initial request with WXO JWT
curl -X GET "http://localhost:8000/api/v1/servers" \
  -H "Authorization: Bearer $WXO_TOKEN" \
  -v

# 3. Extract team_token from response metadata (if returned)
export TEAM_TOKEN="<extracted_team_token>"

# 4. Use team_token for subsequent requests
curl -X GET "http://localhost:8000/api/v1/tools" \
  -H "Authorization: Bearer $TEAM_TOKEN"
```

### Verify Team Creation

```bash
# Check if team was created
curl -X GET "http://localhost:8000/api/v1/teams" \
  -H "Authorization: Bearer $TEAM_TOKEN"

# Check team membership
curl -X GET "http://localhost:8000/api/v1/teams/{team_id}/members" \
  -H "Authorization: Bearer $TEAM_TOKEN"
```

### Test Auto-Creation

```bash
# First request with new tenant_id will auto-create:
# 1. User in email_users table
# 2. Team with slug == tenant_id
# 3. Team membership with role=owner
# 4. Team token for subsequent requests

curl -X GET "http://localhost:8000/api/v1/servers" \
  -H "Authorization: Bearer <new_tenant_jwt>" \
  -v

# Check logs for:
# [WXO_AUTH] Extracted tenant ID: new-tenant-id
# [WXO_AUTH] Creating team for tenant new-tenant-id
# [WXO_AUTH] Created team 'new-tenant-id' for tenant new-tenant-id
# [WXO_AUTH] Generated team token for team 'new-tenant-id'
```

## Troubleshooting

### Common Issues

**1. Missing woTenantId in JWT**
```
Error: Missing tenant ID in WXO token
Solution: Ensure JWT contains woTenantId claim
```

**2. Team Creation Fails**
```
Error: user_email is required to create a team
Solution: JWT must contain email claim for user creation
```

**3. Invalid JWT Signature**
```
Error: Invalid bearer token: Signature verification failed
Solution: Check JWT_SECRET_KEY matches token signing key
```

**4. Expired Token**
```
Error: Bearer token has expired
Solution: Generate new JWT with valid expiration
```

**5. Foreign Key Constraint Error**
```
Error: FOREIGN KEY constraint failed
Solution: Ensure user is created before team creation (handled automatically)
```

### Debug Logging

Enable verbose logging in `.env`:

```bash
LOG_LEVEL=DEBUG
```

Look for these log patterns:
```
[WXO_AUTH] Validating authentication header: Bearer ...
[WXO_AUTH] JWT decoded successfully. Claims keys: [...]
[WXO_AUTH] Extracted tenant ID: tenant-123
[WXO_AUTH] Creating team for tenant tenant-123
[WXO_AUTH] Created team 'tenant-123' for tenant tenant-123
[WXO_AUTH] Generated team token for team 'tenant-123'
[WXO_AUTH] Token exchange completed successfully
```

## Migration from Old Implementation

If you have existing teams created with the old approach:

### Scenario 1: Teams with suffix (e.g., `tenant-123-team`)

**Option A: Update slugs** (recommended for production with existing data)
```sql
-- Backup first!
CREATE TABLE email_teams_backup AS SELECT * FROM email_teams;

-- Update team slugs to remove suffix
UPDATE email_teams 
SET slug = REPLACE(slug, '-team', '')
WHERE slug LIKE '%-team' AND is_active = true;

-- Verify
SELECT id, name, slug FROM email_teams WHERE slug NOT LIKE '%-team';
```

**Option B: Recreate teams** (for development/testing)
```sql
-- Delete old teams (CASCADE will handle members and history)
DELETE FROM email_teams WHERE slug LIKE '%-team';

-- New teams will be auto-created with correct slug format
```

### Scenario 2: Fresh installation

No migration needed! Just:
1. Enable the plugin in `plugins/config.yaml`
2. Set `auto_create_teams: true`
3. Teams will be created automatically on first JWT authentication

### Deprecated Functions

These functions are kept for backwards compatibility but do nothing:

```python
# DEPRECATED: No-op, returns True
create_mapping_table()

# DEPRECATED: No-op, logs warning
create_tenant_team_mapping(tenant_id, team_slug)
```

**Removal timeline:** These will be removed in v2.0.0

## Security Considerations

1. **JWT Secret Protection**
   - Use strong, randomly generated `JWT_SECRET_KEY` (minimum 32 characters)
   - Rotate keys periodically (every 90 days recommended)
   - Never commit secrets to version control
   - Use environment variables or secret management systems

2. **Token Expiration**
   - Set appropriate `team_token_expiry_minutes` (default: 60, max recommended: 1440)
   - Enable `REQUIRE_TOKEN_EXPIRATION=true` in production
   - Short-lived tokens reduce exposure window

3. **Audience Verification**
   - Enable `JWT_AUDIENCE_VERIFICATION=true` in production
   - Configure correct `JWT_AUDIENCE` value matching your WXO environment
   - Prevents token reuse across different systems

4. **Strict Mode**
   - Keep `strict_mode: true` in production
   - Prevents fallback to weak authentication methods
   - Ensures all requests are properly authenticated

5. **Default Passwords**
   - Auto-created users get Argon2-hashed password `"changeme"`
   - Users should either:
     - Change password immediately if using traditional login
     - Continue using JWT authentication (recommended)
   - Consider disabling password login entirely for JWT-authenticated users

6. **User Permissions**
   - JWT-authenticated users are granted `is_admin=true` by default
   - Review and adjust permissions based on your security model
   - Consider implementing role-based access control (RBAC) based on JWT claims

7. **Audit Logging**
   - Keep `audit_auth_attempts: true` enabled
   - Monitor logs for suspicious patterns
   - Integrate with SIEM systems for security monitoring

## References

- [Custom Auth Example](../examples/custom_auth_example/custom_auth.py)
- [Plugin Framework Documentation](../../docs/docs/plugins/framework.md)
- [Team Management Service](../../mcpgateway/services/team_management_service.py)
- [JWT Authentication](../../mcpgateway/auth.py)
- [Simplification Notes](./SIMPLIFICATION_NOTES.md)
