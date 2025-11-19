"""Location: ./plugins/auth_pre_check/auth_pre_check.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: MCP Context Forge Team

WXO_AUTH_CHECK Plugin.

This plugin implements authentication and tenant/team management for HTTP requests.
It validates WXO JWT tokens, exchanges them for team tokens, and manages team-based access.

Flow:
1. Validate WXO JWT token
2. Extract tenant ID from JWT claims
3. Get or create team for tenant
4. Generate team token for subsequent requests
5. Return team context (no user creation)

Hooks:
- http_auth_resolve_user: Validates WXO JWT and exchanges for team token
- http_post_request: Audits authentication attempts and logs results
"""

# Future
from __future__ import annotations

# Standard
import logging
from datetime import datetime, timezone
from typing import Any

# Third-Party
from pydantic import BaseModel

# First-Party
from mcpgateway.db import get_db
from mcpgateway.plugins.framework import (
    HttpAuthResolveUserPayload,
    HttpPostRequestPayload,
    HttpPostRequestResult,
    HttpPreRequestPayload,
    HttpPreRequestResult,
    Plugin,
    PluginConfig,
    PluginContext,
    PluginResult,
    PluginViolation,
    PluginViolationError,
)

# Local
from .auth_pre_check_utils import (
    create_team,
    generate_team_token,
    get_tenant_team_slug,
    validate_auth_header,
)

# Use explicit logger name to ensure visibility
logger = logging.getLogger("mcpgateway.plugins.auth_pre_check")


class WxoAuthCheckConfig(BaseModel):
    """Configuration for WXO_AUTH_CHECK plugin.

    Attributes:
        require_auth: Whether authentication is required for all requests.
        allowed_auth_types: List of allowed authentication types (e.g., ["bearer"]).
        check_token_format: Whether to validate token format (e.g., JWT structure).
        block_on_missing_auth: Whether to block requests with missing authentication.
        auth_header: Authentication header name to check (default: "Authorization").
        auto_create_teams: Whether to automatically create teams for new tenants.
        audit_auth_attempts: Whether to log authentication attempts in post-request hook.
        strict_mode: If True, deny auth when token is invalid (instead of falling back).
        team_token_expiry_minutes: Expiry time for generated team tokens (default: 60).
    """

    require_auth: bool = True
    allowed_auth_types: list[str] = ["bearer"]
    check_token_format: bool = True
    block_on_missing_auth: bool = True  # Block missing auth for team-based flow
    auth_header: str = "Authorization"
    auto_create_teams: bool = True
    audit_auth_attempts: bool = True
    strict_mode: bool = True  # Block invalid tokens in team-based flow
    team_token_expiry_minutes: int = 60


class WxoAuthCheckPlugin(Plugin):
    """Plugin to validate authentication and manage tenant/team mappings."""

    def __init__(self, config: PluginConfig) -> None:
        """Initialize the WXO_AUTH_CHECK plugin.

        Args:
            config: Plugin configuration.
        """
        super().__init__(config)
        self._cfg = WxoAuthCheckConfig(**(config.config or {}))
        logger.info("[WXO_AUTH] WxoAuthCheckPlugin initialized for team-based auth")

    async def http_auth_resolve_user(
        self,
        payload: HttpAuthResolveUserPayload,
        context: PluginContext,
    ) -> PluginResult[dict]:
        """Exchange WXO JWT for team token.

        This hook validates WXO JWT tokens and exchanges them for team tokens.
        No user creation occurs - authentication is purely team-based.

        Flow:
        1. Validate WXO JWT token
        2. Extract tenant ID from claims
        3. Get or create team for tenant
        4. Generate team token
        5. Return team context for subsequent operations

        Args:
            payload: Auth resolution payload with credentials and headers.
            context: Plugin execution context.

        Returns:
            Result with team context if successful.

        Raises:
            PluginViolationError: If authentication fails.
        """
        logger.info("[WXO_AUTH] ========== Team Token Exchange Started ==========")
        logger.info(f"[WXO_AUTH] Credentials present: {payload.credentials is not None}")

        # Check for Bearer credentials
        if not payload.credentials or payload.credentials.get("scheme") != "Bearer":
            logger.warning("[WXO_AUTH] Missing Bearer credentials")
            raise PluginViolationError(
                message="Bearer authentication required",
                violation=PluginViolation(
                    reason="Missing authentication",
                    description="Request requires Bearer authentication with WXO JWT",
                    code="MISSING_AUTH",
                    details={"required_scheme": "Bearer", "required_token_type": "WXO_JWT"},
                ),
            )

        # Extract token
        token = payload.credentials.get("credentials")
        if not token:
            logger.warning("[WXO_AUTH] Bearer token is empty")
            raise PluginViolationError(
                message="Bearer token is empty",
                violation=PluginViolation(
                    reason="Empty token",
                    description="Bearer token cannot be empty",
                    code="EMPTY_TOKEN",
                ),
            )

        # Validate WXO JWT token
        auth_header = f"Bearer {token}"
        is_valid, error_message, jwt_claims = validate_auth_header(
            auth_header, allowed_types=self._cfg.allowed_auth_types
        )

        if not is_valid or not jwt_claims:
            logger.warning(f"[WXO_AUTH] WXO JWT validation failed: {error_message}")
            raise PluginViolationError(
                message=f"Invalid WXO JWT: {error_message}",
                violation=PluginViolation(
                    reason="Invalid authentication",
                    description=error_message or "WXO JWT validation failed",
                    code="INVALID_WXO_JWT",
                    details={"error": error_message},
                ),
            )

        logger.info("[WXO_AUTH] WXO JWT validated successfully")

        # Extract tenant ID from JWT claims
        tenant_id: str | None = jwt_claims.get("woTenantId")
        if not tenant_id:
            logger.error(f"[WXO_AUTH] Missing woTenantId in JWT claims: {list(jwt_claims.keys())}")
            raise PluginViolationError(
                message="Missing tenant ID in WXO token",
                violation=PluginViolation(
                    reason="Invalid token",
                    description="WXO token must contain woTenantId claim",
                    code="MISSING_TENANT_ID",
                    details={"available_claims": list(jwt_claims.keys())},
                ),
            )

        logger.info(f"[WXO_AUTH] Extracted tenant ID: {tenant_id}")

        # Get or create team for tenant
        # Note: get_tenant_team_slug() uses get_db() internally
        team_slug: str | None = get_tenant_team_slug(tenant_id)
        logger.info(f"[WXO_AUTH] Team lookup for tenant {tenant_id}: found={team_slug is not None}")

        if not team_slug and self._cfg.auto_create_teams:
            try:
                # Extract user email for team creation (required for FK constraint)
                user_email = (
                    jwt_claims.get("email")
                    or jwt_claims.get("username")
                    or jwt_claims.get("preferred_username")
                    or jwt_claims.get("upn")
                    or jwt_claims.get("unique_name")
                    or jwt_claims.get("sub")
                )

                logger.info(f"[WXO_AUTH] Creating team for tenant {tenant_id} with user_email={user_email}")

                # Create team (function handles its own DB session via get_db())
                team_slug = await create_team(
                    tenant_id=tenant_id,
                    user_email=user_email,
                )

                logger.info(f"[WXO_AUTH] ✅ Successfully created team '{team_slug}' for tenant {tenant_id}")

                # Verify team was actually created
                verification_slug = get_tenant_team_slug(tenant_id)
                if verification_slug != team_slug:
                    logger.error(f"[WXO_AUTH] Team verification failed! Expected {team_slug}, got {verification_slug}")
                    raise PluginViolationError(
                        message="Team verification failed",
                        violation=PluginViolation(
                            reason="Team verification failed",
                            description=f"Team created but verification failed: expected {team_slug}, got {verification_slug}",
                            code="TEAM_VERIFICATION_FAILED",
                            details={"expected": team_slug, "actual": verification_slug},
                        ),
                    )

                logger.info(f"[WXO_AUTH] ✅ Team creation verified: {verification_slug}")

            except PluginViolationError:
                # Re-raise plugin violations as-is
                raise
            except Exception as e:
                logger.error(f"[WXO_AUTH] ❌ Failed to create team for tenant {tenant_id}: {e}", exc_info=True)
                raise PluginViolationError(
                    message=f"Failed to create team: {e}",
                    violation=PluginViolation(
                        reason="Team creation failed",
                        description=f"Could not create team for tenant {tenant_id}: {str(e)}",
                        code="TEAM_CREATION_FAILED",
                        details={"tenant_id": tenant_id, "error": str(e)},
                    ),
                )

        if not team_slug:
            logger.error(f"[WXO_AUTH] No team found for tenant {tenant_id} and auto-creation disabled")
            raise PluginViolationError(
                message=f"No team found for tenant {tenant_id}",
                violation=PluginViolation(
                    reason="Team not found",
                    description=f"No team exists for tenant {tenant_id} and auto-creation is disabled",
                    code="TEAM_NOT_FOUND",
                    details={"tenant_id": tenant_id},
                ),
            )

        logger.info(f"[WXO_AUTH] Using team_slug: {team_slug}")

        # Extract user email BEFORE generating token (needed for token ownership)
        user_email = (
            jwt_claims.get("email")
            or jwt_claims.get("username")
            or jwt_claims.get("preferred_username")
            or jwt_claims.get("upn")
            or jwt_claims.get("unique_name")
            or jwt_claims.get("sub")
            or f"team-{team_slug}@wxo.system"  # Fallback synthetic email
        )

        # Generate team token for subsequent operations using TokenCatalogService
        try:
            team_token = await generate_team_token(
                team_slug=team_slug,
                tenant_id=tenant_id,
                user_email=user_email,
                expiry_minutes=self._cfg.team_token_expiry_minutes,
            )
            logger.info(f"[WXO_AUTH] Generated team token for team '{team_slug}' (user: {user_email})")

        except Exception as e:
            logger.error(f"[WXO_AUTH] Failed to generate team token: {e}", exc_info=True)
            raise PluginViolationError(
                message=f"Failed to generate team token: {e}",
                violation=PluginViolation(
                    reason="Token generation failed",
                    description=f"Could not generate team token for team {team_slug}",
                    code="TOKEN_GENERATION_FAILED",
                    details={"team_slug": team_slug, "error": str(e)},
                ),
            )

        # Extract full name from JWT claims
        full_name = (
            jwt_claims.get("name")
            or jwt_claims.get("full_name")
            or jwt_claims.get("given_name")
            or f"Team {team_slug}"
        )

        # Look up the team in the database to get its UUID
        # The team was created/retrieved using tenant_id as the slug
        # We need the database-generated UUID (team.id) for gateway registration
        from mcpgateway.db import EmailTeam

        db_gen = get_db()
        db = next(db_gen)
        try:
            team_record = db.query(EmailTeam).filter(EmailTeam.slug == team_slug).first()
            if team_record:
                team_id_for_gateway = team_record.id
                logger.info(f"[WXO_AUTH] Found team in database: UUID={team_id_for_gateway}, slug={team_slug}")
            else:
                # Fallback: use tenant_id if team not found (shouldn't happen)
                team_id_for_gateway = tenant_id
                logger.warning(f"[WXO_AUTH] Team not found in database for slug '{team_slug}', using tenant_id as fallback")
        finally:
            db_gen.close()

        # Store team_id in both plugin context AND global context
        # The global context state is accessible to other parts of the application
        # This allows the gateway registration endpoint to retrieve the team_id
        context.set_state("team_id", team_id_for_gateway)
        context.set_state("wxo_tenant_id", tenant_id)
        context.set_state("team_slug", team_slug)
        context.set_state("wxo_access_token", token)

        # Also store in global context for broader access
        context.global_context.state["team_id"] = team_id_for_gateway
        context.global_context.state["wxo_tenant_id"] = tenant_id
        context.global_context.state["team_slug"] = team_slug
        context.global_context.state["team_token"] = team_token  # Store for http_pre_request
        context.global_context.state["wxo_access_token"] = token  # Store for http_pre_request

        logger.info("[WXO_AUTH] Stored team context in plugin state and global context for downstream access")

        # Return synthetic user with team context embedded
        # The auth system requires an EmailUser-compatible dict
        logger.info("[WXO_AUTH] ========== Token exchange completed successfully ==========")
        logger.info(f"[WXO_AUTH] team_slug={team_slug}, team_id={team_id_for_gateway}, tenant_id={tenant_id}")

        return PluginResult(
            modified_payload={
                "email": user_email,
                "full_name": full_name,
                "is_admin": True,  # Team-authenticated users get admin privileges
                "is_active": True,
                "password_hash": "",  # Not used for team token auth
                "email_verified_at": datetime.now(timezone.utc),
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
                # Additional team context (accessible via request.state)
                "team_slug": team_slug,
                "team_id": team_id_for_gateway,  # Use tenant_id as team_id
                "tenant_id": tenant_id,
                "team_token": team_token,
                "auth_type": "wxo_team",
            },
            metadata={
                "auth_check": "passed",
                "auth_method": "wxo_team_exchange",
                "tenant_id": tenant_id,
                "team_slug": team_slug,
                "team_id": team_id_for_gateway,  # Use tenant_id as team_id
                "token_exchanged": True,
                "team_token": team_token,  # Include in metadata for downstream use
                "token_expires_at": datetime.now(timezone.utc).timestamp() + (self._cfg.team_token_expiry_minutes * 60),
            },
            continue_processing=False,  # Token exchanged, authentication complete
        )

    async def http_post_request(
        self, payload: HttpPostRequestPayload, context: PluginContext
    ) -> HttpPostRequestResult:
        """Audit authentication attempts after request completion.

        Args:
            payload: HTTP post-request payload with response details.
            context: Plugin execution context.

        Returns:
            Result with audit metadata.
        """
        if not self._cfg.audit_auth_attempts:
            return HttpPostRequestResult(continue_processing=True)

        # Extract auth header for logging
        auth_header = None
        for key, value in payload.headers.root.items():
            if key.lower() == self._cfg.auth_header.lower():
                auth_header = value
                break
        auth_present = bool(auth_header)

        # Log authentication attempt
        logger.info(
            f"[WXO_AUTH] Auth audit: {payload.method} {payload.path} -> {payload.status_code} "
            f"(auth_present={auth_present}, client={payload.client_host})"
        )

        metadata = {
            "plugin": "WxoAuthCheck",
            "hook": "http_post_request",
            "path": payload.path,
            "method": payload.method,
            "status_code": payload.status_code,
            "auth_present": auth_present,
            "auth_type": "wxo_team",
            "client_host": payload.client_host,
        }

        # Check if authentication failed
        if payload.status_code in (401, 403):
            metadata["auth_failed"] = True
            logger.warning(
                f"[WXO_AUTH] Team authentication failed for {payload.path}: status {payload.status_code}"
            )

        return HttpPostRequestResult(
            continue_processing=True,
            metadata=metadata,
        )

    async def http_pre_request(
        self, payload: HttpPreRequestPayload, context: PluginContext
    ) -> HttpPreRequestResult:
        """Inject team token and context headers into requests.

        This hook intercepts requests and injects team-related headers from the
        WXO authentication context. The team token and IDs are added as custom
        headers that downstream handlers can use.

        NOTE: http_pre_request can ONLY modify headers, not request body.
        Body modification is not supported by the ASGI middleware layer.

        Args:
            payload: HTTP pre-request payload with method, path, and headers.
            context: Plugin execution context with team state.

        Returns:
            Result with modified headers containing team token and context.
        """
        logger.info(f"[WXO_AUTH] http_pre_request called: {payload.method} {payload.path}")

        # Get team context from global context (set during http_auth_resolve_user)
        team_id = context.global_context.state.get("team_id")
        tenant_id = context.global_context.state.get("wxo_tenant_id")
        team_slug = context.global_context.state.get("team_slug")
        team_token = context.global_context.state.get("team_token")

        logger.info(f"[WXO_AUTH] Team context from global state: team_id={team_id}, tenant_id={tenant_id}, team_slug={team_slug}, team_token={'***' if team_token else None}")
        logger.debug(f"[WXO_AUTH] Global context state keys: {list(context.global_context.state.keys())}")

        if not team_id:
            # No WXO team context available, let request proceed unchanged
            logger.debug("[WXO_AUTH] No team context available, skipping header injection")
            return HttpPreRequestResult(continue_processing=True)

        # Inject team context as custom headers
        try:
            from mcpgateway.plugins.framework import HttpHeaderPayload

            # Create modified headers with team context
            modified_headers = {}

            # Add team identification headers
            modified_headers["X-Team-Id"] = str(team_id)
            modified_headers["X-Tenant-Id"] = str(tenant_id)

            if team_slug:
                modified_headers["X-Team-Slug"] = str(team_slug)

            # Add team token if available (for downstream MCP server authentication)
            if team_token:
                modified_headers["X-Team-Token"] = str(team_token)
                logger.info("[WXO_AUTH] ✅ Injecting team token into headers")

            logger.info(f"[WXO_AUTH] ✅ Injected team headers: {list(modified_headers.keys())}")
            logger.debug(f"[WXO_AUTH] Team header values: team_id={team_id}, tenant_id={tenant_id}, team_slug={team_slug}")

            return HttpPreRequestResult(
                continue_processing=True,
                modified_payload=HttpHeaderPayload(root=modified_headers),
                metadata={
                    "team_headers_injected": True,
                    "team_id": team_id,
                    "tenant_id": tenant_id,
                    "team_slug": team_slug,
                    "team_token_injected": bool(team_token),
                },
            )

        except Exception as e:
            logger.error(f"[WXO_AUTH] ❌ Failed to inject team headers: {e}", exc_info=True)

        # If injection fails, continue unchanged
        logger.warning("[WXO_AUTH] Proceeding without team header injection")
        return HttpPreRequestResult(continue_processing=True)


# Made with Bob
