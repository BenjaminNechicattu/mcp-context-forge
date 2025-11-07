# -*- coding: utf-8 -*-
"""Location: ./plugins/auth_pre_check/auth_pre_check.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: MCP Context Forge Team

WXO_AUTH_CHECK Plugin.

This plugin implements authentication pre-check hooks for HTTP forwarding calls.
It validates authentication headers, checks for required credentials, and can
enforce authentication policies before HTTP requests are made to tools or gateways.

Hook: http_pre_forwarding_call
"""

# Future
from __future__ import annotations

# Standard
from typing import Any

# Third-Party
from pydantic import BaseModel

# First-Party
from mcpgateway.plugins.framework import (
    HttpPreForwardingCallPayload,
    HttpPreForwardingCallResult,
    Plugin,
    PluginConfig,
    PluginContext,
    PluginViolation,
)

# Local
from .auth_pre_check_utils import validate_auth_header, get_tenant_team_slug, create_mapping_table, create_team, create_tenant_team_mapping


class WxoAuthCheckConfig(BaseModel):
    """Configuration for WXO_AUTH_CHECK plugin.

    Attributes:
        require_auth: Whether authentication is required for all requests.
        allowed_auth_types: List of allowed authentication types (e.g., ["bearer", "basic", "api_key"]).
        check_token_format: Whether to validate token format (e.g., JWT structure).
        block_on_missing_auth: Whether to block requests with missing authentication.
        custom_auth_header: Custom authentication header name to check (default: "Authorization").
    """

    require_auth: bool = True
    allowed_auth_types: list[str] = ["bearer"]
    check_token_format: bool = False
    block_on_missing_auth: bool = True
    auth_header: str = "Authorization"

class WxoAuthCheckPlugin(Plugin):
    """Plugin to validate authentication before HTTP forwarding calls."""

    def __init__(self, config: PluginConfig) -> None:
        """Initialize the WXO_AUTH_CHECK plugin.

        Args:
            config: Plugin configuration.
        """
        super().__init__(config)
        self._cfg = WxoAuthCheckConfig(**(config.config or {}))

        try :
        # create table for tenant_team_mapping if not exit.
            create_mapping_table()
        except Exception as e :
            raise Exception(f"Failed to create table for tenant_team_mapping: {e}")

    async def http_pre_forwarding_call(self, payload: HttpPreForwardingCallPayload, context: PluginContext) -> HttpPreForwardingCallResult:
        """Validate authentication before HTTP forwarding call.

        Args:
            payload: HTTP pre-forwarding payload containing request details.
            context: Plugin execution context.

        Returns:
            Result indicating whether to continue processing or block the request.
        """

        print("##### http_pre_forwarding_call")
        # Get authentication header
        auth_header = payload.headers.get(self._cfg.auth_header)
        metadata : dict[str, Any] = {}

        # Check if authentication is required
        if self._cfg.require_auth and not auth_header:
            if self._cfg.block_on_missing_auth:
                violation = PluginViolation(
                    reason="Missing authentication",
                    description=f"Request to {payload.url} requires authentication but no {self._cfg.auth_header} header was provided",
                    code="MISSING_AUTH",
                    details={
                        "url": payload.url,
                        "method": payload.method,
                        "required_header": self._cfg.auth_header,
                    }
                )
                return HttpPreForwardingCallResult(
                    continue_processing=False,
                    violation=violation,
                    metadata={"auth_check": "failed", "reason": "missing_auth"}
                )
            else:
                print("##### continue_processing warning")

                # Log warning but allow request
                return HttpPreForwardingCallResult(
                    continue_processing=True,
                    metadata={"auth_check": "warning", "reason": "missing_auth_allowed"}
                )

        # Check if authentication is valid
        is_valid, error_message, jwt_claims = validate_auth_header(auth_header, allowed_types=self._cfg.allowed_auth_types)
        if not is_valid:
            violation = PluginViolation(
                reason="Invalid authentication",
                description=f"Authentication validation failed: {error_message}",
                code="INVALID_AUTH",
                details={
                    "url": payload.url,
                    "method": payload.method,
                    "error": error_message,
                }
            )
            return HttpPreForwardingCallResult(
                continue_processing=False,
                violation=violation,
                metadata={"auth_check": "failed", "reason": "invalid_auth_format"}
            )

        # Build metadata with JWT claims if available
        metadata.update({
            "auth_check": "passed",
            "auth_type": "bearer" if auth_header and auth_header.startswith("Bearer ") else "other"
        })
        if jwt_claims:
            metadata["jwt_claims"] = jwt_claims

        print("##### got claims")


        # get_tenant_team_slug_id
        try:
            tenant_id: str | None = jwt_claims.get("woTenantId", None) if jwt_claims else None
            team_slug: str = get_tenant_team_slug(tenant_id) if tenant_id else ""

            print(f"##### {team_slug=}")
            print(f"##### {tenant_id=}")


            if tenant_id and not team_slug:

                print(f"##### creating team and maping")

                # Get user email from JWT claims for team creation
                # Try multiple possible email claim locations in JWT
                user_email = None
                if jwt_claims:
                    # Try common email claim fields in order of preference
                    user_email = (
                        jwt_claims.get("email") or
                        jwt_claims.get("username") or  # WXO uses 'username' for email
                        jwt_claims.get("preferred_username") or
                        jwt_claims.get("upn") or  # User Principal Name (common in Azure AD)
                        jwt_claims.get("unique_name") or
                        jwt_claims.get("sub")  # Last resort: sub might be email in some systems
                    )

                if not user_email:
                    claims_info = f"Available claims: {list(jwt_claims.keys())}" if jwt_claims else "No JWT claims available"
                    raise ValueError(f"Cannot create team: user email not found in JWT claims (checked: email, preferred_username, upn, unique_name, sub). {claims_info}")

                # Validate that we got an email address, not a UUID
                if "@" not in str(user_email):
                    claims_info = f"JWT claims: {list(jwt_claims.keys())}" if jwt_claims else "No JWT claims"
                    raise ValueError(f"Cannot create team: extracted value '{user_email}' is not a valid email address. {claims_info}")

                # create team (await since it's now async, pass user_email)
                team_slug = await create_team(tenant_id, user_email=user_email)
                print("create team done.")

                # create tenant team mapping
                create_tenant_team_mapping(tenant_id, team_slug)
                print("maping team done.")

        except Exception as e:
            violation: PluginViolation = PluginViolation(
                reason="Invalid authentication",
                description=f"Authentication validation failed: {e}",
                code="INVALID_AUTH",
                details={
                        "url": payload.url,
                        "method": payload.method,
                        "error": error_message,
                })
            return HttpPreForwardingCallResult(
                continue_processing=False,
                violation =  violation,
                metadata={"auth_check": "failed", "reason": "invalid_auth_format"}
            )

        print("###### leaving pre auth check")

        # Authentication check passed
        return HttpPreForwardingCallResult(
            continue_processing=True,
            metadata=metadata
        )

# Made with Bob
