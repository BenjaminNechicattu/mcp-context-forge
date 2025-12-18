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
from importlib import metadata
import logging
from datetime import datetime, timezone, timedelta
from typing import Any
import uuid

# Third-Party
from pydantic import BaseModel

# First-Party
from mcpgateway.db import get_db
from mcpgateway.plugins.framework import (
    HttpAuthResolveUserPayload,
    HttpHeaderPayload,
    HttpPostRequestPayload,
    HttpPostRequestResult,
    HttpPreRequestPayload,
    HttpPreRequestResult,
    Plugin,
    PluginConfig,
    PluginContext,
    PluginResult,
)
from mcpgateway.services.token_catalog_service import TokenCatalogService

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

    def _extract_user_info(self, jwt_claims: dict[str, Any], team_slug: str) -> tuple[str, str]:
        """Extract user email and full name from JWT claims."""
        user_email = (
            jwt_claims.get("email")
            or jwt_claims.get("username")
            or jwt_claims.get("preferred_username")
            or jwt_claims.get("upn")
            or jwt_claims.get("unique_name")
            or jwt_claims.get("sub")
            or f"team-{team_slug}@wxo.system"
        )

        full_name = (
            jwt_claims.get("name")
            or jwt_claims.get("full_name")
            or jwt_claims.get("given_name")
            or f"Team {team_slug}"
        )
        return user_email, full_name

    async def http_auth_resolve_user(
        self,
        payload: HttpAuthResolveUserPayload,
        context: PluginContext,
    ) -> PluginResult[dict[str, Any]]:
        """Resolve user from cached context set by http_pre_request.

        This hook now allows standard JWT auth flow to continue so that
        get_team_from_token() can extract team_id from the team token payload.

        The team token was already injected in http_pre_request, so we just
        let the standard auth flow validate it and extract the team context.

        Args:
            payload: Auth resolution payload with credentials and headers.
            context: Plugin execution context.

        Returns:
            Always returns continue_processing=True to allow standard auth flow.
        """
        # Don't intercept auth resolution - let standard JWT flow handle it
        # The team token has already been injected by http_pre_request
        logger.debug("[WXO_AUTH] http_auth_resolve_user: continuing to standard JWT flow")
        return PluginResult(continue_processing=True)

    async def http_post_request(
        self, payload: HttpPostRequestPayload, context: PluginContext
    ) -> HttpPostRequestResult:
        """Audit authentication attempts and inject response headers after request completion.

        Args:
            payload: HTTP post-request payload with response details.
            context: Plugin execution context.

        Returns:
            Result with audit metadata and modified response headers.
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

        # Check if this is a successful gateway creation request
        modified_headers: dict[str, str] = {}
        if payload.method == "POST" and "/gateways" in payload.path and payload.status_code == 200:
            # Get team_id from global context
            team_id = context.global_context.state.get("team_id")
            if team_id:
                modified_headers["X-Team-Id"] = str(team_id)
                logger.info(f"[WXO_AUTH] Added team_id {team_id} to gateway creation response headers")
                metadata["team_id_injected"] = True

        return HttpPostRequestResult(
            continue_processing=True,
            modified_payload=HttpHeaderPayload(root=modified_headers) if modified_headers else None,
            metadata=metadata,
        )

    async def http_pre_request(
        self, payload: HttpPreRequestPayload, context: PluginContext
    ) -> HttpPreRequestResult:
        """Inject team token and context headers into requests.

        This hook intercepts requests and injects team-related headers from the
        WXO authentication context. The team token and IDs are added as custom
        headers that downstream handlers can use.

        It performs the token exchange here to ensure headers are available
        before the request is processed by the router or downstream services.

        Args:
            payload: HTTP pre-request payload with method, path, and headers.
            context: Plugin execution context with team state.

        Returns:
            Result with modified headers containing team token and context.
        """
        logger.info(f"[WXO_AUTH] http_pre_request called: {payload.method} {payload.path}")

        # Check for Authorization header
        auth_header = self._get_auth_header(payload.headers.root)
        logger.info(f"[WXO_AUTH] auth_header : {auth_header}")

        if not auth_header:
            logger.debug("[WXO_AUTH] No auth header found in pre_request")
            return HttpPreRequestResult(continue_processing=True)

        # Validate WXO JWT token
        is_valid, error_message, jwt_claims = validate_auth_header(
            auth_header, allowed_types=self._cfg.allowed_auth_types
        )

        if not is_valid or not jwt_claims:
            logger.warning(f"[WXO_AUTH] Pre-check validation failed: {error_message}")
            return HttpPreRequestResult(continue_processing=True)

        # Extract tenant ID
        tenant_id = (
            jwt_claims.get("woTenantId")
            or jwt_claims.get("user", {}).get("tenantId")
            or (jwt_claims.get("user") if isinstance(jwt_claims.get("user"), str) else None)
            or "default-tenant"
        )
        logger.info(f"[WXO_AUTH] tenant_id : {tenant_id}")

        # Get or create team for tenant
        team_slug, team_id_for_gateway = get_tenant_team_slug(tenant_id)
        logger.info(f"[WXO_AUTH] team_slug : {team_slug}")
        logger.info(f"[WXO_AUTH] team_id_for_gateway : {team_id_for_gateway}")

        if not team_slug and self._cfg.auto_create_teams:
            try:
                user_email = (
                    jwt_claims.get("email")
                    or jwt_claims.get("username")
                    or jwt_claims.get("preferred_username")
                    or jwt_claims.get("upn")
                    or jwt_claims.get("unique_name")
                    or jwt_claims.get("sub")
                )
                team_slug = await create_team(tenant_id=tenant_id, user_email=user_email)
                logger.info(f"[WXO_AUTH] Created team '{team_slug}' in pre_request")
                # Fetch the team_id after creation
                from mcpgateway.db import EmailTeam
                db_gen = get_db()
                db = next(db_gen)
                try:
                    team_record = db.query(EmailTeam).filter(EmailTeam.slug == team_slug).first()
                    if team_record:
                        team_id_for_gateway = team_record.id
                        logger.info(f"[WXO_AUTH] Retrieved team UUID {team_id_for_gateway} for newly created team '{team_slug}'")
                    else:
                        logger.error(f"[WXO_AUTH] Failed to retrieve team UUID for newly created team '{team_slug}'")
                        return HttpPreRequestResult(continue_processing=True)
                finally:
                    db_gen.close()
            except Exception as e:
                logger.error(f"[WXO_AUTH] Failed to create team in pre_request: {e}")
                return HttpPreRequestResult(continue_processing=True)

        if not team_slug:
            logger.error(f"[WXO_AUTH] No team_slug available after lookup/creation")
            return HttpPreRequestResult(continue_processing=True)

        # If team_id not set (team already existed), it was retrieved from get_tenant_team_slug
        if not team_id_for_gateway:
            logger.error(f"[WXO_AUTH] team_id_for_gateway is None - this should not happen")
            return HttpPreRequestResult(continue_processing=True)

        # Extract user info from JWT
        user_email = (
            jwt_claims.get("email")
            or jwt_claims.get("username")
            or jwt_claims.get("preferred_username")
            or jwt_claims.get("upn")
            or jwt_claims.get("unique_name")
            or jwt_claims.get("sub")
            or f"team-{team_slug}@wxo.system"
        )

        # CRITICAL: Normalize email to lowercase to match database schema and lookup logic
        # The EmailAuthService.get_user_by_email() converts to lowercase, so we must store lowercase
        user_email = user_email.lower() if user_email else user_email
        logger.info(f"[WXO_AUTH] user_email : {user_email}")

        full_name = (
            jwt_claims.get("name")
            or jwt_claims.get("full_name")
            or jwt_claims.get("given_name")
            or f"Team {team_slug} User"
        )

        # Generate team token (team already exists at this point)
        try:
            db_gen = get_db()
            db = next(db_gen)

            # Ensure user exists - create if necessary
            from mcpgateway.db import EmailUser
            existing_user = db.query(EmailUser).filter(EmailUser.email == user_email).first()

            user_created = False
            if not existing_user:
                logger.info(f"[WXO_AUTH] Creating user '{user_email}' for team token generation")
                new_user = EmailUser(
                    email=user_email,
                    full_name=full_name,
                    password_hash="",  # No password for WXO users
                    is_active=True,
                    is_admin=False,
                    email_verified_at=datetime.now(timezone.utc),
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                user_created = True
                logger.info(f"[WXO_AUTH] User '{user_email}' created successfully (id: {new_user.id if hasattr(new_user, 'id') else 'N/A'})")
            else:
                logger.info(f"[WXO_AUTH] User '{user_email}' already exists")

            # Ensure user is a member of the team
            from mcpgateway.db import EmailTeamMember
            from mcpgateway.services.team_management_service import TeamManagementService

            membership = db.query(EmailTeamMember).filter(
                EmailTeamMember.team_id == team_id_for_gateway,
                EmailTeamMember.user_email == user_email,
                EmailTeamMember.is_active == True
            ).first()

            logger.info(f"[WXO_AUTH] membership : {membership}")

            if not membership:
                logger.info(f"[WXO_AUTH] User '{user_email}' is not a team member, adding to team '{team_slug}'")
                try:
                    team_service = TeamManagementService(db)
                    # Add user as owner if they created the team, otherwise as member
                    role = "owner" if user_created else "member"
                    await team_service.add_member_to_team(
                        team_id=team_id_for_gateway,
                        user_email=user_email,
                        role=role,
                        invited_by=user_email  # Self-join for WXO authenticated users
                    )
                    logger.info(f"[WXO_AUTH] Successfully added user '{user_email}' as {role} of team '{team_slug}'")
                except Exception as member_error:
                    logger.error(f"[WXO_AUTH] Failed to add user to team: {member_error}", exc_info=True)
                    # Don't fail the request - try to create token anyway
            else:
                logger.info(f"[WXO_AUTH] User '{user_email}' is already a member of team '{team_slug}'")

            # Assign platform_admin role for WXO users (global scope with all permissions)
            try:
                from mcpgateway.services.role_service import RoleService
                role_service = RoleService(db)

                # Get the platform_admin role (created during bootstrap)
                admin_role = await role_service.get_role_by_name("platform_admin", "global")
                if not admin_role:
                    logger.warning("[WXO_AUTH] platform_admin role not found - creating it")
                    admin_role = await role_service.create_role(
                        name="platform_admin",
                        description="Platform administrator with all permissions",
                        scope="global",
                        permissions=["*"],  # All permissions
                        created_by="system",
                        is_system_role=True,
                    )

                # Check if user already has platform_admin role (global scope)
                existing_assignment = await role_service.get_user_role_assignment(
                    user_email=user_email,
                    role_id=admin_role.id,
                    scope="global",
                    scope_id=None
                )

                if not existing_assignment or not existing_assignment.is_active:
                    await role_service.assign_role_to_user(
                        user_email=user_email,
                        role_id=admin_role.id,
                        scope="global",
                        scope_id=None,
                        granted_by=user_email
                    )
                    logger.info(f"[WXO_AUTH] Assigned platform_admin role (all permissions) to '{user_email}'")
                else:
                    logger.info(f"[WXO_AUTH] User '{user_email}' already has platform_admin role")

            except Exception as role_error:
                logger.error(f"[WXO_AUTH] Failed to assign RBAC role: {role_error}", exc_info=True)
                # Don't fail the request - user can still access the system

            # Use the generate_team_token utility which handles caching and token generation
            logger.info(f"[WXO_AUTH] Generating team token for user_email='{user_email}', team_id={team_id_for_gateway}, team_slug='{team_slug}'")

            team_token = await generate_team_token(
                team_slug=team_slug,
                tenant_id=tenant_id,
                user_email=user_email,
                expiry_minutes=self._cfg.team_token_expiry_minutes,
            )

            logger.info(f"[WXO_AUTH] team_token : {team_token}")
            logger.info(f"[WXO_AUTH] Generated/retrieved team token for team '{team_slug}' (tenant: {tenant_id})")

            db_gen.close()
        except Exception as e:
            logger.error(f"[WXO_AUTH] Failed to generate token in pre_request: {e}", exc_info=True)
            return HttpPreRequestResult(continue_processing=True)

        # Store in global context
        token_str = auth_header.replace("Bearer ", "").strip()
        context.global_context.state["team_id"] = team_id_for_gateway
        context.global_context.state["wxo_tenant_id"] = tenant_id
        context.global_context.state["team_slug"] = team_slug
        context.global_context.state["team_token"] = team_token
        context.global_context.state["wxo_access_token"] = token_str
        context.state["wxo_access_token"] = token_str

        # Also store user info for resolve_user to use
        context.global_context.state["user_email"] = user_email
        context.global_context.state["jwt_claims"] = jwt_claims

        logger.info(f"[WXO_AUTH] jwt_claims : {jwt_claims}")
        logger.info(f"[WXO_AUTH] token_str : {token_str}")

        # Inject Headers
        from mcpgateway.plugins.framework import HttpHeaderPayload

        modified_headers = dict(payload.headers.root)

        modified_headers["X-Team-Id"] = str(team_id_for_gateway)
        modified_headers["X-Tenant-Id"] = str(tenant_id)
        modified_headers["X-Team-Slug"] = str(team_slug)
        modified_headers["X-Team-Token"] = str(team_token)
        modified_headers["X-WXO-Access-Token"] = str(token_str)

        # Update the Authorization header to use the team token
        # The standard auth flow (get_current_user) will validate this token
        # and extract team_id from the JWT payload's "teams" claim
        if team_token:
            modified_headers["authorization"] = f"Bearer {team_token}"
            logger.info("[WXO_AUTH] ✅ Updated Authorization header with team token")

        logger.info(f"[WXO_AUTH] ✅ Injected team headers in pre_request: {list(modified_headers.keys())}")
        logger.info(f"[WXO_AUTH] ✅ Injected headers in pre_request: {list(modified_headers)}")
        logger.info(f"[WXO_AUTH] ✅ tenant_id: {list(tenant_id)}")
        logger.info(f"[WXO_AUTH] ✅ slug: {list(team_slug)}")


        return HttpPreRequestResult(
            continue_processing=True,
            modified_payload=HttpHeaderPayload(root=modified_headers),
            metadata={
                "team_headers_injected": True,
                "team_id": team_id_for_gateway,
                "tenant_id": tenant_id,
                "team_slug": team_slug,
            },
        )

    def _get_auth_header(self, headers: dict[str, str]) -> str | None:
        """Extract authentication header case-insensitively."""
        for key, value in headers.items():
            if key.lower() == self._cfg.auth_header.lower():
                return value
        return None


# Made with Bob
