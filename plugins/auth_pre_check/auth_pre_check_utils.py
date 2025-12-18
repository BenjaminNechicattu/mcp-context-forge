# -*- coding: utf-8 -*-
"""Location: ./plugins/auth_pre_check/auth_pre_check_utils.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: MCP Context Forge Team

Utility functions for WXO_AUTH_CHECK Plugin.
"""

# Standard
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

# Third-Party
import jwt
from cryptography.fernet import Fernet, InvalidToken

# First-Party
from mcpgateway.config import settings
from mcpgateway.db import get_db

# SQL helpers
from sqlalchemy import text

# Use explicit logger name to ensure visibility
logger = logging.getLogger("mcpgateway.plugins.auth_pre_check")

# Team token expiry (in days) for the cached team tokens
WXO_TEAM_TOKEN_EXPIRY_DAYS = 60


def _get_token_cipher() -> Fernet:
    """Return a Fernet cipher for encrypting/decrypting team tokens.

    Uses TOKEN_ENCRYPTION_KEY from environment or settings.
    """
    import os
    
    # Try to get from environment variable first
    raw_key = os.environ.get("TOKEN_ENCRYPTION_KEY")
    
    # Fallback to settings if available
    if not raw_key and hasattr(settings, "token_encryption_key"):
        raw_key = (
            settings.token_encryption_key.get_secret_value()
            if hasattr(settings.token_encryption_key, "get_secret_value")
            else settings.token_encryption_key
        )
    
    # Fallback to JWT_SECRET_KEY if TOKEN_ENCRYPTION_KEY not available
    if not raw_key:
        raw_key = (
            settings.jwt_secret_key.get_secret_value()
            if hasattr(settings.jwt_secret_key, "get_secret_value")
            else str(settings.jwt_secret_key)
        )
        logger.warning(
            "[WXO_AUTH] TOKEN_ENCRYPTION_KEY not found, using JWT_SECRET_KEY for token encryption"
        )

    if not raw_key:
        raise RuntimeError(
            "[WXO_AUTH] No encryption key available (TOKEN_ENCRYPTION_KEY or JWT_SECRET_KEY)"
        )

    if isinstance(raw_key, str):
        raw_key = raw_key.encode("utf-8")
    
    # Fernet requires a URL-safe base64-encoded 32-byte key
    # If the key is not in the correct format, derive it
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    import base64
    
    # Ensure we have exactly 32 bytes for Fernet
    if len(raw_key) != 32:
        # Derive a 32-byte key using SHA256
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(raw_key)
        raw_key = digest.finalize()
    
    # Encode as URL-safe base64
    fernet_key = base64.urlsafe_b64encode(raw_key)
    
    return Fernet(fernet_key)


def encrypt_team_token(raw_token: str) -> str:
    """Encrypt a raw JWT token for storage in the database."""
    cipher = _get_token_cipher()
    encrypted = cipher.encrypt(raw_token.encode("utf-8"))
    return encrypted.decode("utf-8")


def decrypt_team_token(encrypted_token: str) -> str:
    """Decrypt an encrypted JWT token retrieved from the database."""
    cipher = _get_token_cipher()
    decrypted = cipher.decrypt(encrypted_token.encode("utf-8"))
    return decrypted.decode("utf-8")


def _ensure_team_token_table_exists(db) -> None:
    """Ensure the wxo_team_tokens table exists.

    This uses a simple CREATE TABLE IF NOT EXISTS statement.
    """
    try:
        db.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS wxo_team_tokens (
                    id VARCHAR(36) PRIMARY KEY,
                    tenant_id VARCHAR NOT NULL,
                    team_id VARCHAR(36) NOT NULL,
                    user_email VARCHAR NOT NULL,
                    encrypted_token TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
        )
        db.commit()
        logger.debug("[WXO_AUTH] Ensured wxo_team_tokens table exists")
    except Exception as e:
        logger.error(
            "[WXO_AUTH] Failed to ensure wxo_team_tokens table exists: %s",
            e,
            exc_info=True,
        )
        db.rollback()


def _ensure_team_token_index_exists(db) -> None:
    """Ensure the lookup index exists on wxo_team_tokens.

    Uses PostgreSQL's CREATE INDEX IF NOT EXISTS for safety.
    """
    try:
        db.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS ix_wxo_team_tokens_lookup
                ON wxo_team_tokens (team_id, user_email, tenant_id)
                """
            )
        )
        db.commit()
        logger.debug("[WXO_AUTH] Ensured index ix_wxo_team_tokens_lookup exists")
    except Exception as e:
        logger.warning(
            "[WXO_AUTH] Failed to ensure team token index exists: %s",
            e,
            exc_info=True,
        )
        db.rollback()


def _get_cached_team_token(
    db, team_id: str, tenant_id: str, user_email: str
) -> dict[str, Any] | None:
    """Fetch a cached team token row for (team_id, tenant_id, user_email).

    Returns a dict with keys: id, encrypted_token, expires_at; or None.
    """
    try:
        result = db.execute(
            text(
                """
                SELECT id, encrypted_token, expires_at
                FROM wxo_team_tokens
                WHERE team_id = :team_id
                  AND tenant_id = :tenant_id
                  AND user_email = :user_email
                """
            ),
            {
                "team_id": team_id,
                "tenant_id": tenant_id,
                "user_email": user_email,
            },
        )
        row = result.first()
        if not row:
            return None

        row_id, encrypted_token, expires_at = row[0], row[1], row[2]
        return {
            "id": row_id,
            "encrypted_token": encrypted_token,
            "expires_at": expires_at,
        }
    except Exception as e:
        logger.error(
            "[WXO_AUTH] Failed to fetch cached team token: %s", e, exc_info=True
        )
        return None


def _upsert_cached_team_token(
    db,
    existing_row_id: str | None,
    team_id: str,
    tenant_id: str,
    user_email: str,
    raw_token: str,
    expires_at: datetime,
) -> None:
    """Insert or update the cached team token row."""
    encrypted_token = encrypt_team_token(raw_token)
    now = datetime.now(timezone.utc)

    try:
        if existing_row_id:
            # Update existing record
            db.execute(
                text(
                    """
                    UPDATE wxo_team_tokens
                    SET encrypted_token = :encrypted_token,
                        expires_at = :expires_at,
                        updated_at = :updated_at
                    WHERE id = :id
                    """
                ),
                {
                    "encrypted_token": encrypted_token,
                    "expires_at": expires_at,
                    "updated_at": now,
                    "id": existing_row_id,
                },
            )
            logger.debug(
                "[WXO_AUTH] Updated cached team token row id=%s for team_id=%s, user=%s",
                existing_row_id,
                team_id,
                user_email,
            )
        else:
            # Insert new record
            new_id = str(uuid.uuid4())
            db.execute(
                text(
                    """
                    INSERT INTO wxo_team_tokens
                        (id, tenant_id, team_id, user_email, encrypted_token,
                         expires_at, created_at, updated_at)
                    VALUES
                        (:id, :tenant_id, :team_id, :user_email, :encrypted_token,
                         :expires_at, :created_at, :updated_at)
                    """
                ),
                {
                    "id": new_id,
                    "tenant_id": tenant_id,
                    "team_id": team_id,
                    "user_email": user_email,
                    "encrypted_token": encrypted_token,
                    "expires_at": expires_at,
                    "created_at": now,
                    "updated_at": now,
                },
            )
            logger.debug(
                "[WXO_AUTH] Inserted new cached team token row id=%s for team_id=%s, user=%s",
                new_id,
                team_id,
                user_email,
            )

        db.commit()
        logger.debug(
            "[WXO_AUTH] Token metadata cached: tenant_id=%s, team_id=%s, user=%s, expires_at=%s",
            tenant_id,
            team_id,
            user_email,
            expires_at,
        )
    except Exception as e:
        logger.error(
            "[WXO_AUTH] Failed to upsert cached team token: %s", e, exc_info=True
        )
        db.rollback()


def normalize_tenant_id_to_slug(tenant_id: str) -> str:
    """Normalize tenant_id to slug format.

    Handles tenant_id structures like:
    - Single UUID: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    - Compound UUID: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx_yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy'

    The normalization converts underscores to hyphens to match slug format,
    but preserves the internal UUID structure.

    Args:
        tenant_id (str): The tenant identifier to normalize.

    Returns:
        str: Normalized slug format with underscores replaced by hyphens.
    """
    if not tenant_id:
        return tenant_id

    # Replace all underscores with hyphens for slug compatibility
    normalized = tenant_id.replace("_", "-")

    logger.debug(f"[WXO_AUTH] Normalized tenant_id '{tenant_id}' -> '{normalized}'")
    return normalized


def validate_auth_header(
    header_value: str | None, allowed_types: list[str]
) -> tuple[bool, str | None, dict[str, Any] | None]:
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
    logger.info(
        f"[WXO_AUTH] Validating authentication header: {header_value[:50] if header_value else 'None'}..."
    )

    if not header_value:
        logger.warning("[WXO_AUTH] Authentication header is empty")
        return False, "Authentication header is empty", None

    # Check for Bearer token
    if header_value.lower().startswith("bearer "):
        if "bearer" not in [t.lower() for t in allowed_types]:
            logger.warning(
                f"[WXO_AUTH] Bearer authentication not in allowed types: {allowed_types}"
            )
            return False, "Bearer authentication is not allowed", None
        token = header_value[7:].strip()
        if not token:
            logger.warning("[WXO_AUTH] Bearer token is empty after stripping")
            return False, "Bearer token is empty", None

        # Attempt to decode JWT token and extract claims (without signature verification)
        try:
            # Decode JWT without signature verification but verify expiration
            decode_options: dict[str, Any] = {
                "verify_signature": False,  # Skip signature verification
                "verify_exp": True,  # Verify expiration - IMPORTANT for security
                "verify_aud": False,  # Skip audience verification
                "verify_iss": False,  # Skip issuer verification
            }

            # Decode the JWT token without signature verification but with expiry check
            claims = jwt.decode(
                token,
                options=decode_options,
            )
            logger.info(
                f"[WXO_AUTH] JWT decoded successfully. Claims keys: {list(claims.keys())}"
            )
            return True, None, claims
        except jwt.ExpiredSignatureError as e:
            logger.warning(f"[WXO_AUTH] Bearer token has expired: {e}")
            return False, "Bearer token has expired", None
        except Exception as e:
            logger.error(f"[WXO_AUTH] JWT validation error: {str(e)}", exc_info=True)
            return False, f"Invalid bearer token: {str(e)}", None

    logger.warning(
        f"[WXO_AUTH] Unsupported authentication type. Header: {header_value[:30]}..."
    )
    return (
        False,
        f"Unsupported authentication type. Allowed types: {', '.join(allowed_types)}",
        None,
    )


def get_tenant_team_slug(tenant_id: str | None) -> tuple[str, str] | tuple[None, None]:
    """
    Check if a team exists with slug equal to tenant_id.

    Since we use tenant_id as team_slug directly, this simply checks if the team exists.
    If it does not exist, return (None, None) to signal team creation is needed.
    """

    logger.debug(f"Checking if team exists for tenant_id: {tenant_id}")

    if not tenant_id:
        raise ValueError("tenant_id cannot be None")

    try:
        db_gen = get_db()
        db = next(db_gen)

        try:
            from mcpgateway.db import EmailTeam

            normalized_slug = normalize_tenant_id_to_slug(tenant_id)

            team = db.query(EmailTeam).filter(EmailTeam.slug == normalized_slug).first()

            if team:
                logger.info(
                    f"[WXO_AUTH] Found team with slug '{team.slug}' (UUID: {team.id}) for tenant_id '{tenant_id}'"
                )
                return normalized_slug, team.id
            else:
                logger.info(
                    f"[WXO_AUTH] No team found with slug matching tenant_id '{tenant_id}'"
                )
                return None, None

        finally:
            db_gen.close()

    except Exception as e:
        logger.exception(
            f"[WXO_AUTH] Error checking team existence for tenant_id '{tenant_id}': {e}"
        )
        return None, None


def create_mapping_table() -> bool:
    """
    DEPRECATED: This function is no longer needed.

    We now use tenant_id directly as team_slug, eliminating the need
    for a separate mapping table.
    """
    logger.info(
        "[WXO_AUTH] create_mapping_table() is deprecated - tenant_id is now used directly as team_slug"
    )
    return True


async def create_team(
    tenant_id: str, team_slug: str | None = None, user_email: str | None = None
) -> str:
    """Create a new team in the database.

    This function uses tenant_id as the team_slug to simplify the tenant-team relationship.
    The team_slug parameter is deprecated and will be ignored if provided.
    
    The team is created with a synthetic tenant-scoped user as the owner for consistency.
    """

    logger.debug(f"[WXO_AUTH] Creating team for tenant_id: {tenant_id}")

    if not tenant_id:
        raise ValueError("[WXO_AUTH] tenant_id cannot be None or empty")

    if not user_email:
        raise ValueError(
            "[WXO_AUTH] user_email is required to add as team member (will be added after team creation)"
        )

    user_email = user_email.lower() if user_email else user_email
    logger.debug(f"[WXO_AUTH] Normalized user_email to lowercase: {user_email}")

    if team_slug and team_slug != tenant_id:
        logger.warning(
            f"[WXO_AUTH] Ignoring provided team_slug '{team_slug}', using tenant_id '{tenant_id}' instead"
        )

    logger.info(f"[WXO_AUTH] Using tenant_id '{tenant_id}' as team_slug")

    # Use synthetic tenant-scoped email for team ownership
    tenant_scoped_email = f"{tenant_id}@wxo.com".lower()
    logger.info(
        f"[WXO_AUTH] Team will be created with synthetic owner: {tenant_scoped_email}"
    )

    try:
        db_gen = get_db()
        db = next(db_gen)

        try:
            from mcpgateway.services.team_management_service import (
                TeamManagementService,
            )
            from mcpgateway.db import EmailUser, EmailTeam, utc_now
            from argon2 import PasswordHasher

            team_service = TeamManagementService(db)

            # Ensure synthetic tenant-scoped user exists (team owner)
            synthetic_user = (
                db.query(EmailUser).filter(EmailUser.email == tenant_scoped_email).first()
            )

            if not synthetic_user:
                logger.info(
                    f"[WXO_AUTH] Creating synthetic tenant-scoped user '{tenant_scoped_email}' as team owner"
                )
                ph = PasswordHasher()
                password_hash = ph.hash("changeme")

                synthetic_user = EmailUser(
                    email=tenant_scoped_email,
                    password_hash=password_hash,
                    full_name=f"WXO Tenant {tenant_id}",
                    is_active=True,
                    is_admin=True,
                    email_verified_at=utc_now(),
                )
                db.add(synthetic_user)
                db.commit()
                db.refresh(synthetic_user)
                logger.info(
                    f"[WXO_AUTH] Created synthetic user '{tenant_scoped_email}' for team ownership"
                )

            # Ensure real user exists (will be added as team member)
            existing_user = (
                db.query(EmailUser).filter(EmailUser.email == user_email).first()
            )

            if not existing_user:
                logger.info(
                    f"[WXO_AUTH] Creating user '{user_email}' in email_users table"
                )
                ph = PasswordHasher()
                password_hash = ph.hash("changeme")
                full_name = user_email.split("@")[0]

                new_user = EmailUser(
                    email=user_email,
                    password_hash=password_hash,
                    full_name=full_name,
                    is_active=True,
                    is_admin=True,
                    email_verified_at=utc_now(),
                )
                db.add(new_user)
                db.commit()
                db.refresh(new_user)
                logger.info(
                    f"[WXO_AUTH] Successfully created user '{user_email}' with admin privileges"
                )

            try:
                # Create team with synthetic user as owner
                team = await team_service.create_team(
                    name=tenant_id,
                    description=f"Team for tenant {tenant_id}",
                    created_by=tenant_scoped_email,  # Synthetic user owns the team
                    visibility="public",
                    max_members=None,
                )
                logger.info(
                    f"[WXO_AUTH] Successfully created team '{team.name}' with slug '{team.slug}' for tenant_id '{tenant_id}'"
                )
            except Exception as create_error:
                if "duplicate key" in str(create_error).lower() or "unique constraint" in str(
                    create_error
                ).lower():
                    logger.info(
                        f"[WXO_AUTH] Team already exists for tenant_id '{tenant_id}', fetching existing team"
                    )
                    normalized_slug = normalize_tenant_id_to_slug(tenant_id)
                    team = (
                        db.query(EmailTeam)
                        .filter(EmailTeam.slug == normalized_slug)
                        .first()
                    )
                    if not team:
                        raise ValueError(
                            f"[WXO_AUTH] Team with slug '{normalized_slug}' should exist but was not found"
                        ) from create_error
                    logger.info(
                        f"[WXO_AUTH] Retrieved existing team '{team.name}' with slug '{team.slug}'"
                    )
                else:
                    raise

            team.is_personal = False
            db.commit()
            db.refresh(team)
            logger.info(
                f"[WXO_AUTH]Team '{team.slug}' created as shared tenant team (is_personal=False)"
            )

            # Add the real user as an owner member (in addition to synthetic owner)
            try:
                await team_service.add_member_to_team(
                    team_id=team.id,
                    user_email=user_email,
                    role="owner",
                    invited_by=tenant_scoped_email,  # Invited by synthetic user
                )
                logger.info(
                    f"[WXO_AUTH] Successfully added real user '{user_email}' as owner of team '{team.slug}'"
                )
            except Exception as member_error:
                logger.error(
                    f"[WXO_AUTH] Failed to add user as team member: {member_error}",
                    exc_info=True,
                )

            return team.slug

        finally:
            db_gen.close()

    except Exception as e:
        logger.exception(
            f"[WXO_AUTH] Error creating team for tenant_id '{tenant_id}': {e}"
        )
        raise


def create_tenant_team_mapping(tenant_id: str, team_slug: str) -> None:
    """DEPRECATED: Create a mapping between tenant_id and team_slug.

    This function is no longer needed since we use tenant_id directly as team_slug.
    It's kept for backwards compatibility but does nothing.
    """
    logger.info(
        f"[WXO_AUTH] create_tenant_team_mapping() is deprecated - tenant_id '{tenant_id}' is used directly as team_slug"
    )
    # No-op for backwards compatibility


async def generate_team_token(
    team_slug: str,
    tenant_id: str,
    user_email: str,
    expiry_minutes: int = 60,
) -> str:
    """Generate (or reuse) a tenant-scoped team token using the TokenCatalogService.

    Behavior:
        - Uses a synthetic tenant-scoped email: f"{tenant_id}@wxo.com" as the
          token owner and cache key, regardless of the caller's user_email.
        - Look up an existing team token in wxo_team_tokens for
          (team_id, tenant_id, synthetic_email).
        - If found and not expired, decrypt and return it.
        - If not found or expired:
            * Create a new token via TokenCatalogService with 60 days expiry.
            * Insert/update the wxo_team_tokens row with encrypted token + expires_at.
            * Return the new token.

    Args:
        team_slug: The team slug (equal to tenant_id).
        tenant_id: The tenant ID from the WXO JWT.
        user_email: Email of the caller (used only for logging).
        expiry_minutes: DEPRECATED - kept for API compatibility. Actual expiry
            is controlled by WXO_TEAM_TOKEN_EXPIRY_DAYS (60 days).

    Returns:
        str: Encoded JWT team token with full service layer support.
    """
    logger.debug(
        "[WXO_AUTH] Generating tenant-scoped team token for team_slug: %s, tenant_id: %s, caller_user: %s",
        team_slug,
        tenant_id,
        user_email,
    )

    if not team_slug:
        raise ValueError("[WXO_AUTH] team_slug cannot be None or empty")
    if not tenant_id:
        raise ValueError("[WXO_AUTH] tenant_id cannot be None or empty")
    if not user_email:
        raise ValueError("[WXO_AUTH] user_email cannot be None or empty")

    # Tenant-scoped synthetic email for token ownership and caching
    tenant_scoped_email = f"{tenant_id}@wxo.com".lower()
    logger.debug(
        "[WXO_AUTH] Using synthetic tenant-scoped email '%s' for token ownership",
        tenant_scoped_email,
    )

    try:
        db_gen = get_db()
        db = next(db_gen)

        try:
            from mcpgateway.services.token_catalog_service import (
                TokenCatalogService,
                TokenScope,
            )
            from mcpgateway.db import EmailTeam, EmailUser, utc_now
            from argon2 import PasswordHasher

            # Ensure datastore and index exist
            _ensure_team_token_table_exists(db)
            _ensure_team_token_index_exists(db)

            # Resolve team
            team = db.query(EmailTeam).filter(EmailTeam.slug == team_slug).first()
            if not team:
                raise ValueError(f"[WXO_AUTH] Team not found for slug: {team_slug}")

            team_id = str(team.id)  # store as string in cache table
            now = datetime.now(timezone.utc)

            # Ensure synthetic tenant-scoped user exists for token ownership
            from mcpgateway.db import EmailTeamMember
            from mcpgateway.services.team_management_service import TeamManagementService
            
            synthetic_user = db.query(EmailUser).filter(EmailUser.email == tenant_scoped_email).first()
            user_was_created = False
            
            if not synthetic_user:
                logger.info(
                    "[WXO_AUTH] Creating synthetic tenant-scoped user '%s' for token ownership",
                    tenant_scoped_email,
                )
                ph = PasswordHasher()
                password_hash = ph.hash("changeme")  # Default password (not used for token auth)
                
                synthetic_user = EmailUser(
                    email=tenant_scoped_email,
                    password_hash=password_hash,
                    full_name=f"WXO Tenant {tenant_id}",
                    is_active=True,
                    is_admin=True,
                    email_verified_at=utc_now(),
                )
                db.add(synthetic_user)
                db.commit()
                db.refresh(synthetic_user)
                user_was_created = True
                logger.info(
                    "[WXO_AUTH] Created synthetic user '%s' for tenant-scoped token generation",
                    tenant_scoped_email,
                )
            
            # Ensure synthetic user is a member of the team
            membership = db.query(EmailTeamMember).filter(
                EmailTeamMember.team_id == team.id,
                EmailTeamMember.user_email == tenant_scoped_email,
                EmailTeamMember.is_active == True
            ).first()
            
            if not membership:
                logger.info(
                    "[WXO_AUTH] Adding synthetic user '%s' as owner of team '%s'",
                    tenant_scoped_email,
                    team_slug,
                )
                try:
                    team_service = TeamManagementService(db)
                    await team_service.add_member_to_team(
                        team_id=team.id,
                        user_email=tenant_scoped_email,
                        role="owner",
                        invited_by=tenant_scoped_email,
                    )
                    logger.info(
                        "[WXO_AUTH] Successfully added synthetic user '%s' as owner of team '%s'",
                        tenant_scoped_email,
                        team_slug,
                    )
                except Exception as member_error:
                    logger.error(
                        "[WXO_AUTH] Failed to add synthetic user to team: %s",
                        member_error,
                        exc_info=True,
                    )
                    raise ValueError(
                        f"[WXO_AUTH] Cannot create token: synthetic user not a team member"
                    ) from member_error

            # 1. Try cached token (tenant-scoped)
            logger.debug(
                "[WXO_AUTH] Looking up cached token with team_id=%s, tenant_id=%s, user_email=%s",
                team_id,
                tenant_id,
                tenant_scoped_email,
            )
            existing_token_row = _get_cached_team_token(
                db=db,
                team_id=team_id,
                tenant_id=tenant_id,
                user_email=tenant_scoped_email,
            )

            if existing_token_row:
                logger.debug(
                    "[WXO_AUTH] Found existing cached team token row for team_id=%s, tenant_scoped_email=%s",
                    team_id,
                    tenant_scoped_email,
                )
                expires_at = existing_token_row["expires_at"]
                if expires_at and expires_at > now:
                    try:
                        raw_token = decrypt_team_token(
                            existing_token_row["encrypted_token"]
                        )
                        logger.info(
                            "[WXO_AUTH] Reusing valid cached tenant-scoped team token for team '%s'",
                            team_slug,
                        )
                        return raw_token
                    except InvalidToken as e:
                        logger.warning(
                            "[WXO_AUTH] Stored tenant-scoped team token could not be decrypted (%s); regenerating",
                            e,
                        )
                else:
                    logger.info(
                        "[WXO_AUTH] Cached tenant-scoped team token expired at %s; regenerating",
                        expires_at,
                    )

            # 2. Generate new token via TokenCatalogService
            token_service = TokenCatalogService(db)
            scope = TokenScope(
                server_id=None,
                permissions=["*"],
                ip_restrictions=[],
                time_restrictions={},
                usage_limits={},
            )

            expiry_days = WXO_TEAM_TOKEN_EXPIRY_DAYS
            # Use timedelta with exact 60 days to ensure proper calculation
            expires_at = now + timedelta(days=expiry_days, hours=0, minutes=0, seconds=0, microseconds=0)

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
            unique_suffix = str(uuid.uuid4())[:8]
            token_name = f"[WXO_AUTH] wxo-team-token-{timestamp}-{unique_suffix}"

            api_token, raw_token = await token_service.create_token(
                user_email=tenant_scoped_email,  # tenant-scoped owner
                name=token_name,
                description=(
                    f"[WXO_AUTH] WXO tenant-scoped team token for tenant {tenant_id} "
                    f"(auto-generated, {expiry_days} days expiry)"
                ),
                scope=scope,
                expires_in_days=expiry_days,
                tags=["wxo", "team-token", f"tenant:{tenant_id}"],
                team_id=team.id,
            )

            logger.info(
                "[WXO_AUTH] Successfully generated tenant-scoped team token for team '%s' "
                "(ID: %s, expires in %s days, synthetic_email=%s, caller_user=%s)",
                team_slug,
                api_token.id,
                expiry_days,
                tenant_scoped_email,
                user_email,
            )

            existing_id = existing_token_row["id"] if existing_token_row else None
            _upsert_cached_team_token(
                db=db,
                existing_row_id=existing_id,
                team_id=team_id,
                tenant_id=tenant_id,
                user_email=tenant_scoped_email,
                raw_token=raw_token,
                expires_at=expires_at,
            )

            return raw_token

        finally:
            db_gen.close()

    except Exception as e:
        logger.error(
            "[WXO_AUTH] Failed to generate tenant-scoped team token: %s", e, exc_info=True
        )
        raise ValueError(f"[WXO_AUTH] Failed to generate team token: {e}")

# Made with Bob
