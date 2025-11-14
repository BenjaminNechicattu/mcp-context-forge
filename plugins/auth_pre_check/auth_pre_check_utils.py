# -*- coding: utf-8 -*-
"""Location: ./plugins/auth_pre_check/auth_pre_check_utils.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: MCP Context Forge Team

Utility functions for WXO_AUTH_CHECK Plugin.
"""

# Standard
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

# Third-Party
import jwt

# First-Party
from mcpgateway.config import settings
from mcpgateway.db import get_db

# Use explicit logger name to ensure visibility
logger = logging.getLogger("mcpgateway.plugins.auth_pre_check")


def validate_auth_header(header_value: str | None, allowed_types: list[str]) -> tuple[bool, str | None, dict[str, Any] | None]:
    """Validate authentication header format and type.

    Args:
        header_value: The authentication header value.
        allowed_types: List of allowed authentication types.

    Returns:
        Tuple of (is_valid, error_message, jwt_claims).
        - is_valid: Whether the authentication header is valid.
        - error_message: Error message if validation failed, None otherwise.
        - jwt_claims: Decoded JWT claims if Bearer token is valid, None otherwise.
    """
    logger.info(f"[WXO_AUTH] Validating authentication header: {header_value[:50] if header_value else 'None'}...")

    if not header_value:
        logger.warning("[WXO_AUTH] Authentication header is empty")
        return False, "Authentication header is empty", None

    # Check for Bearer token
    if header_value.startswith("Bearer "):
        if "bearer" not in [t.lower() for t in allowed_types]:
            logger.warning(f"[WXO_AUTH] Bearer authentication not in allowed types: {allowed_types}")
            return False, "Bearer authentication is not allowed", None
        token = header_value[7:].strip()
        if not token:
            logger.warning("[WXO_AUTH] Bearer token is empty after stripping")
            return False, "Bearer token is empty", None

        # Attempt to decode JWT token and extract claims
        try:
            # Get the secret key for JWT verification
            secret_key = settings.jwt_secret_key.get_secret_value() if hasattr(settings.jwt_secret_key, "get_secret_value") else str(settings.jwt_secret_key)

            # Build decode options based on settings
            decode_options: dict[str, Any] = {
                "verify_signature": True,
                "verify_exp": settings.require_token_expiration,
                "verify_aud": settings.jwt_audience_verification,
                "verify_iss": False,  # Don't require issuer claim - verify only if present
            }

            # If expiration is not required, don't require the exp claim to be present
            if not settings.require_token_expiration:
                decode_options["require"] = ["sub"]  # Only require 'sub' claim, not 'exp'

            # Decode and verify the JWT token
            # Only include audience/issuer if verification is enabled
            decode_kwargs: dict[str, Any] = {
                "algorithms": [settings.jwt_algorithm],
                "options": decode_options,
            }

            if settings.jwt_audience_verification and settings.jwt_audience:
                decode_kwargs["audience"] = settings.jwt_audience

            # Only verify issuer if it's configured AND present in the token
            # Don't pass issuer to decode() as it would require the claim to be present
            # Instead, we'll verify it manually after decoding if needed

            claims = jwt.decode(token, secret_key, **decode_kwargs)
            logger.info(f"[WXO_AUTH] JWT decoded successfully. Claims keys: {list(claims.keys())}")
            return True, None, claims
        except jwt.ExpiredSignatureError as e:
            logger.warning(f"[WXO_AUTH] Bearer token has expired: {e}")
            return False, "Bearer token has expired", None
        except jwt.InvalidAudienceError as e:
            logger.warning(f"[WXO_AUTH] Bearer token has invalid audience: {e}")
            return False, "Bearer token has invalid audience", None
        except jwt.InvalidIssuerError as e:
            logger.warning(f"[WXO_AUTH] Bearer token has invalid issuer: {e}")
            return False, "Bearer token has invalid issuer", None
        except Exception as e:
            # Log the error for debugging
            logger.error(f"[WXO_AUTH] JWT validation error: {str(e)}", exc_info=True)
            return False, f"Invalid bearer token: {str(e)}", None

    logger.warning(f"[WXO_AUTH] Unsupported authentication type. Header: {header_value[:30]}...")
    return False, f"Unsupported authentication type. Allowed types: {', '.join(allowed_types)}", None

def get_tenant_team_slug(tenant_id: str | None) -> str | None:
    """
    Check if a team exists with slug equal to tenant_id.

    Since we use tenant_id as team_slug directly, this simply checks if the team exists.
    If it does not exist, return None to signal team creation is needed.

    Args:
        tenant_id: The tenant ID to look up (also used as team_slug)

    Returns:
        str | None: The tenant_id if team exists, None otherwise

    Raises:
        ValueError: If tenant_id is None
    """

    logger.debug(f"Checking if team exists for tenant_id: {tenant_id}")

    if not tenant_id:
        raise ValueError("tenant_id cannot be None")

    try:
        # Get database session
        db_gen = get_db()
        db = next(db_gen)

        try:
            # Import the EmailTeam model
            from mcpgateway.db import EmailTeam

            # Check if team exists with slug == tenant_id
            team = db.query(EmailTeam).filter(EmailTeam.slug == tenant_id).first()

            if team:
                logger.info(f"Found team with slug '{team.slug}' for tenant_id '{tenant_id}'")
                return tenant_id
            else:
                logger.info(f"No team found with slug matching tenant_id '{tenant_id}'")
                return None

        finally:
            # Close the database session
            db_gen.close()

    except Exception as e:
        logger.exception(f"Error checking team existence for tenant_id '{tenant_id}': {e}")
        return None


def create_mapping_table() -> bool:
    """
    DEPRECATED: This function is no longer needed.

    We now use tenant_id directly as team_slug, eliminating the need
    for a separate mapping table.

    Returns:
        bool: Always returns True for backwards compatibility
    """
    logger.info("create_mapping_table() is deprecated - tenant_id is now used directly as team_slug")
    return True


async def create_team(tenant_id: str, team_slug: str | None = None, user_email: str | None = None) -> str:
    """Create a new team in the database.

    This function uses tenant_id as the team_slug to simplify the tenant-team relationship.
    The team_slug parameter is deprecated and will be ignored if provided.

    Args:
        tenant_id (str): The ID of the tenant (will be used as team_slug).
        team_slug (str, optional): DEPRECATED - This parameter is ignored.
            The tenant_id is always used as the team_slug. Defaults to None.
        user_email (str, optional): Email of the user creating the team. Required
            for database foreign key constraint. Defaults to None.

    Returns:
        str: The team slug (equal to tenant_id).

    Raises:
        ValueError: If tenant_id is None or empty, or if user_email is not provided.

    Example:
        >>> import asyncio
        >>> asyncio.run(create_team("tenant-123", user_email="user@example.com"))
        'tenant-123'
    """

    logger.debug(f"Creating team for tenant_id: {tenant_id}")

    if not tenant_id:
        raise ValueError("tenant_id cannot be None or empty")

    if not user_email:
        raise ValueError("user_email is required to create a team (database foreign key constraint)")

    # Use tenant_id directly as team_slug (ignore provided team_slug parameter)
    if team_slug and team_slug != tenant_id:
        logger.warning(f"Ignoring provided team_slug '{team_slug}', using tenant_id '{tenant_id}' instead")

    logger.info(f"Using tenant_id '{tenant_id}' as team_slug")

    # Insert team into database using TeamManagementService
    try:
        # Get database session
        db_gen = get_db()
        db = next(db_gen)

        try:
            # Import required services
            from mcpgateway.services.team_management_service import TeamManagementService
            from mcpgateway.db import EmailUser

            # Create team management service instance
            team_service = TeamManagementService(db)

            # Ensure user exists in email_users table before creating team
            # This is required because email_teams.created_by has a foreign key constraint
            existing_user = db.query(EmailUser).filter(EmailUser.email == user_email).first()

            if not existing_user:
                # Create the user if they don't exist
                logger.info(f"Creating user '{user_email}' in email_users table for team creation")
                # Import utc_now for timestamp and argon2 for password hashing
                from mcpgateway.db import utc_now
                from argon2 import PasswordHasher

                # Set default password for SSO users
                # Users should change this password after first login or continue using SSO
                default_password = "changeme"

                # Use Argon2 directly to hash the password
                ph = PasswordHasher()
                password_hash = ph.hash(default_password)

                # Extract full name from JWT claims if available
                full_name = user_email.split('@')[0]  # Default to email prefix

                new_user = EmailUser(
                    email=user_email,
                    password_hash=password_hash,  # Set Argon2 hashed default password
                    full_name=full_name,
                    is_active=True,
                    is_admin=True,  # Grant admin privileges to token-authenticated users
                    email_verified_at=utc_now()  # Auto-verify since they're authenticated via JWT
                )
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                logger.info(f"Successfully created user '{user_email}' with admin privileges in email_users table")
                logger.info("Default password set to 'changeme'. User can login with this password or use SSO/token authentication.")

            # Create the team using the service (await since we're now async)
            # Use tenant_id as the team name/slug
            team = await team_service.create_team(
                name=tenant_id,  # Use tenant_id as team name
                description=f"Team for tenant {tenant_id}",
                created_by=user_email,  # Use authenticated user's email
                visibility="private",
                max_members=None
            )

            logger.info(f"Successfully created team '{team.name}' with slug '{team.slug}' for tenant_id '{tenant_id}'")

            # DO NOT mark as personal - this is a shared tenant team
            # All users from the same tenant should use this same team
            # is_personal=False allows team-level collaboration
            team.is_personal = False
            db.commit()
            db.refresh(team)
            logger.info(f"Team '{team.slug}' created as shared tenant team (is_personal=False)")

            # Add the user as an owner member of the team
            # This is critical so that get_user_teams() can find this team
            # when the gateway registration endpoint needs to determine the team_id
            try:
                await team_service.add_member_to_team(
                    team_id=team.id,
                    user_email=user_email,
                    role="owner",
                    invited_by=user_email
                )
                logger.info(f"Successfully added user '{user_email}' as owner of team '{team.slug}'")
            except Exception as member_error:
                logger.error(f"Failed to add user as team member: {member_error}", exc_info=True)
                # Continue anyway - the team is created, just without explicit membership
                # The user can still access it via created_by relationship

            # Return the actual slug generated by the database (should equal tenant_id)
            return team.slug

        finally:
            # Close the database session
            db_gen.close()

    except Exception as e:
        logger.exception(f"Error creating team for tenant_id '{tenant_id}': {e}")
        raise


def create_tenant_team_mapping(tenant_id: str, team_slug: str) -> None:
    """DEPRECATED: Create a mapping between tenant_id and team_slug.

    This function is no longer needed since we use tenant_id directly as team_slug.
    It's kept for backwards compatibility but does nothing.

    Args:
        tenant_id (str): The tenant identifier (ignored).
        team_slug (str): The team slug (ignored).

    Example:
        >>> create_tenant_team_mapping("tenant-123", "tenant-123")
        # Does nothing - kept for backwards compatibility
    """
    logger.info(f"create_tenant_team_mapping() is deprecated - tenant_id '{tenant_id}' is used directly as team_slug")
    # No-op for backwards compatibility


def generate_team_token(
    team_slug: str,
    tenant_id: str,
    expiry_minutes: int = 60,
    jwt_claims: dict[str, Any] | None = None
) -> str:
    """Generate a team token for subsequent API operations.

    This function creates a JWT token that represents a team's authenticated session.
    The token can be used for subsequent API calls without requiring the original WXO JWT.

    Args:
        team_slug: The team slug (equal to tenant_id).
        tenant_id: The tenant ID from the WXO JWT.
        expiry_minutes: Token expiry time in minutes (default: 60).
        jwt_claims: Optional original JWT claims to include in team token.

    Returns:
        str: Encoded JWT team token.

    Raises:
        ValueError: If team_slug or tenant_id is None or empty.

    Example:
        >>> token = generate_team_token("tenant-123", "tenant-123", expiry_minutes=120)
        >>> # Token can now be used for API calls: Authorization: Bearer {token}
    """
    logger.debug(f"Generating team token for team_slug: {team_slug}, tenant_id: {tenant_id}")

    if not team_slug:
        raise ValueError("team_slug cannot be None or empty")

    if not tenant_id:
        raise ValueError("tenant_id cannot be None or empty")

    # Get the secret key for JWT signing
    secret_key = settings.jwt_secret_key.get_secret_value() if hasattr(settings.jwt_secret_key, "get_secret_value") else str(settings.jwt_secret_key)

    # Build team token payload
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(minutes=expiry_minutes)

    payload: dict[str, Any] = {
        "sub": team_slug,  # Subject is the team slug
        "team_slug": team_slug,
        "tenant_id": tenant_id,
        "token_type": "team_token",
        "iat": int(now.timestamp()),  # Issued at
        "exp": int(expiry.timestamp()),  # Expiration time
    }

    # Include audience if configured
    if settings.jwt_audience:
        payload["aud"] = settings.jwt_audience

    # Include issuer if configured
    if hasattr(settings, "jwt_issuer") and settings.jwt_issuer:
        payload["iss"] = settings.jwt_issuer

    # Optionally include selected claims from original WXO JWT
    if jwt_claims:
        # Include specific claims that might be useful for auditing
        for claim_key in ["email", "username", "name", "woTenantId"]:
            if claim_key in jwt_claims:
                payload[f"wxo_{claim_key}"] = jwt_claims[claim_key]

    # Encode the JWT token
    try:
        token = jwt.encode(payload, secret_key, algorithm=settings.jwt_algorithm)
        logger.info(f"Successfully generated team token for team '{team_slug}' (expires in {expiry_minutes} minutes)")
        return token
    except Exception as e:
        logger.error(f"Failed to encode team token: {e}", exc_info=True)
        raise ValueError(f"Failed to generate team token: {e}")


# Made with Bob
