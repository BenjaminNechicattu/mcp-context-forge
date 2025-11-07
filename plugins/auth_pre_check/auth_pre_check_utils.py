# -*- coding: utf-8 -*-
"""Location: ./plugins/auth_pre_check/auth_pre_check_utils.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: MCP Context Forge Team

Utility functions for WXO_AUTH_CHECK Plugin.
"""

# Standard
import logging
from typing import Any, Optional

# Third-Party
import jwt

# First-Party
from mcpgateway.config import settings
from mcpgateway.db import get_db

logger = logging.getLogger(__name__)


def validate_auth_header(header_value: str | None, allowed_types: list[str]) -> tuple[bool, Optional[str], Optional[dict[str, Any]]]:
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

    print("##### validate_auth_header")

    if not header_value:
        return False, "Authentication header is empty", None

    # Check for Bearer token
    if header_value.startswith("Bearer "):
        if "bearer" not in [t.lower() for t in allowed_types]:
            return False, "Bearer authentication is not allowed", None
        token = header_value[7:].strip()
        if not token:
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
            return True, None, claims
        except jwt.ExpiredSignatureError:
            return False, "Bearer token has expired", None
        except jwt.InvalidAudienceError:
            return False, "Bearer token has invalid audience", None
        except jwt.InvalidIssuerError:
            return False, "Bearer token has invalid issuer", None
        except Exception as e:
            # Log the error for debugging
            logger.error(f"JWT validation error: {str(e)}")
            return False, f"Invalid bearer token: {str(e)}", None


    return False, f"Unsupported authentication type. Allowed types: {', '.join(allowed_types)}", None

def get_tenant_team_slug(tenant_id: str | None) -> str:
    """
    Check if the tenant_id and team slug mapping exists in tenant_team_mapping table in the database.
    If it does not exist, return an empty string.
    If it does exist, return the team slug.

    Args:
        tenant_id: The tenant ID to look up

    Returns:
        str: The team slug if found, empty string otherwise

    Raises:
        ValueError: If tenant_id is None
    """

    print("##### get_tenant_team_slug")

    if not tenant_id:
        raise ValueError("tenant_id cannot be None")

    try:
        team_slug = ""

        # Get database session
        db_gen = get_db()
        db = next(db_gen)

        try:
            # Note: This assumes a tenant_team_mapping table exists with columns:
            # - tenant_id (String)
            # - team_slug (String)
            # If the table doesn't exist yet, you'll need to create it via Alembic migration

            # Query the database for the tenant_id and team slug mapping
            # Using SQLAlchemy text() for raw SQL since the table might not have an ORM model yet
            from sqlalchemy import text

            query = text("SELECT team_slug FROM tenant_team_mapping WHERE tenant_id = :tenant_id")
            result = db.execute(query, {"tenant_id": tenant_id})
            row = result.fetchone()

            # Get team slug value if found
            if row:
                team_slug = row[0]
                logger.info(f"Found team_slug '{team_slug}' for tenant_id '{tenant_id}'")
            else:
                logger.info(f"No team_slug found for tenant_id '{tenant_id}'")

        finally:
            # Close the database session
            db_gen.close()

    except Exception as e:
        logger.exception(f"Error querying tenant_team_mapping for tenant_id '{tenant_id}': {e}")
        return ""

    return team_slug


def create_mapping_table() -> bool:
    """
    Create the tenant_team_mapping table in the database if it doesn't exist.

    This table stores the mapping between tenant IDs and team slugs.

    Table structure:
        - mapping_id (Integer, Primary Key, Auto-increment): Unique identifier for each mapping
        - tenant_id (String, Not Null, Indexed): The tenant identifier
        - team_slug (String, Not Null): The corresponding team slug
        - created_at (DateTime): Timestamp when the mapping was created
        - updated_at (DateTime): Timestamp when the mapping was last updated
        - UNIQUE constraint on (tenant_id, team_slug) combination
        - Index on tenant_id for faster lookups

    Returns:
        bool: True if table was created successfully or already exists, False on error
    """
    try:
        # Get database session
        db_gen = get_db()
        db = next(db_gen)

        try:
            from sqlalchemy import text

            # Create table with proper schema
            # Using IF NOT EXISTS to make this idempotent
            # Using SERIAL for PostgreSQL compatibility (works with both PostgreSQL and SQLite via SQLAlchemy)
            create_table_sql = text("""
                CREATE TABLE IF NOT EXISTS tenant_team_mapping (
                    mapping_id SERIAL PRIMARY KEY,
                    tenant_id VARCHAR(255) NOT NULL,
                    team_slug VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(tenant_id, team_slug)
                )
            """)

            # Create index on tenant_id for faster lookups
            create_index_sql = text("""
                CREATE INDEX IF NOT EXISTS idx_tenant_id
                ON tenant_team_mapping(tenant_id)
            """)

            db.execute(create_table_sql)
            db.execute(create_index_sql)

            db.execute(create_table_sql)
            db.commit()

            logger.info("Successfully created or verified tenant_team_mapping table")
            return True

        finally:
            # Close the database session
            db_gen.close()

    except Exception as e:
        logger.exception(f"Error creating tenant_team_mapping table: {e}")
        return False


async def create_team(tenant_id: str, team_slug: str | None = None, user_email: str | None = None) -> str:
    """Create a new team in the database.

    This function generates a team slug if not provided and ensures the team
    is properly registered in the system. The team slug is derived from the
    tenant_id if not explicitly provided.

    Args:
        tenant_id (str): The ID of the tenant.
        team_slug (str, optional): The slug of the team. If None, generates
            a slug based on tenant_id. Defaults to None.
        user_email (str, optional): Email of the user creating the team. Required
            for database foreign key constraint. Defaults to None.

    Returns:
        str: The team slug (either provided or generated).

    Raises:
        ValueError: If tenant_id is None or empty, or if user_email is not provided.

    Example:
        >>> import asyncio
        >>> asyncio.run(create_team("tenant-123", user_email="user@example.com"))
        'tenant-123-team'
        >>> asyncio.run(create_team("tenant-456", "custom-team", "user@example.com"))
        'custom-team'
    """

    print("##### create_team")

    if not tenant_id:
        raise ValueError("tenant_id cannot be None or empty")

    if not user_email:
        raise ValueError("user_email is required to create a team (database foreign key constraint)")

    # Generate team_slug from tenant_id if not provided
    if not team_slug:
        team_slug = f"{tenant_id}-team"
        logger.info(f"Generated team_slug '{team_slug}' for tenant_id '{tenant_id}'")
    else:
        logger.info(f"Using provided team_slug '{team_slug}' for tenant_id '{tenant_id}'")

    # Insert team into database using TeamManagementService
    try:
        # Get database session
        db_gen = get_db()
        db = next(db_gen)

        try:
            # Import TeamManagementService
            from mcpgateway.services.team_management_service import TeamManagementService

            # Create team management service instance
            team_service = TeamManagementService(db)

            # Create the team using the service (await since we're now async)
            # Use the authenticated user's email as created_by to satisfy foreign key constraint
            team = await team_service.create_team(
                name=team_slug,
                description=f"Team for tenant {tenant_id}",
                created_by=user_email,  # Use authenticated user's email
                visibility="private",
                max_members=None
            )

            logger.info(f"Successfully created team '{team.name}' with slug '{team.slug}' for tenant_id '{tenant_id}'")

            # Return the actual slug generated by the database
            return team.slug

        finally:
            # Close the database session
            db_gen.close()

    except Exception as e:
        logger.exception(f"Error creating team for tenant_id '{tenant_id}': {e}")
        raise

    return team_slug


def create_tenant_team_mapping(tenant_id: str, team_slug: str) -> None:
    """Create a mapping between tenant_id and team_slug in the database.

    This function inserts a new record into the tenant_team_mapping table,
    establishing the relationship between a tenant and their team. If the
    mapping already exists, it will be skipped due to the UNIQUE constraint.

    Args:
        tenant_id (str): The tenant identifier to map.
        team_slug (str): The team slug to associate with the tenant.

    Raises:
        ValueError: If tenant_id or team_slug is None or empty.
        Exception: If database operation fails.

    Example:
        >>> create_tenant_team_mapping("tenant-123", "engineering-team")
    """
    if not tenant_id:
        raise ValueError("tenant_id cannot be None or empty")
    if not team_slug:
        raise ValueError("team_slug cannot be None or empty")

    try:
        # Get database session
        db_gen = get_db()
        db = next(db_gen)

        try:
            from sqlalchemy import text

            # Insert the mapping into the database
            # Using INSERT ... ON CONFLICT DO NOTHING for PostgreSQL compatibility
            # (works with both PostgreSQL and modern SQLite)
            insert_sql = text("""
                INSERT INTO tenant_team_mapping (tenant_id, team_slug)
                VALUES (:tenant_id, :team_slug)
                ON CONFLICT (tenant_id, team_slug) DO NOTHING
            """)

            result = db.execute(insert_sql, {"tenant_id": tenant_id, "team_slug": team_slug})
            db.commit()

            # Check if a row was inserted (rowcount > 0 means new mapping created)
            rows_affected = getattr(result, "rowcount", 0)
            if rows_affected > 0:
                logger.info(f"Created tenant_team_mapping: tenant_id='{tenant_id}', team_slug='{team_slug}'")
            else:
                logger.info(f"Tenant_team_mapping already exists: tenant_id='{tenant_id}', team_slug='{team_slug}'")

        finally:
            # Close the database session
            db_gen.close()

    except Exception as e:
        logger.exception(f"Error creating tenant_team_mapping for tenant_id '{tenant_id}' and team_slug '{team_slug}': {e}")
        raise

# Made with Bob
