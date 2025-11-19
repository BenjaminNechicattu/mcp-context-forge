

import base64
from typing import Dict, Any, Optional


def basic_auth(username: str, password: str) -> str:
    """
    Encode username and password for Basic Authentication.

    Args:
        username: The username for authentication
        password: The password for authentication

    Returns:
        Base64 encoded credentials string
    """
    credentials = f"{username}:{password}"
    return base64.b64encode(credentials.encode()).decode()


const PASS_THROUGH_HEADER = "X-Upstream-Authorization"


def process_credentials(creds: Dict[str, Any], headers: Optional[Dict[str, str]] = None, query_params: Optional[Dict[str, str]] = None) -> tuple[Dict[str, str], Dict[str, str]]:
    """
    Process various authentication credentials and return updated headers/query parameters.

    Args:
        creds: Dictionary containing authentication credentials with auth type as keys
        headers: Optional dictionary of existing headers to update
        query_params: Optional dictionary of existing query parameters to update

    Returns:
        Tuple of (headers, query_params) dictionaries with authentication data

    Supported authentication types:
        - basic_auth: username/password authentication
        - bearer_token: Bearer token authentication
        - api_key_auth: API key in header, cookie, or query
        - key_value_creds: Custom key-value pairs in headers
        - oauth2: OAuth2 access token authentication
    """
    # Initialize dictionaries if not provided
    if headers is None:
        headers = {}
    else:
        headers = headers.copy()  # Create a copy to avoid modifying the original

    if query_params is None:
        query_params = {}
    else:
        query_params = query_params.copy()  # Create a copy to avoid modifying the original

    # Loop over credentials and process them
    for auth_type, raw_details in creds.items():
        if not isinstance(raw_details, dict):
            print(f"invalid credential details for {auth_type}: {raw_details}")
            continue

        details = raw_details

        if auth_type == "basic_auth":
            username = details.get("username")
            password = details.get("password")
            if isinstance(username, str) and isinstance(password, str):
                headers[PASS_THROUGH_HEADER] = f"Basic {basic_auth(username, password)}"

        elif auth_type == "bearer_token":
            token = details.get("token")
            if isinstance(token, str):
                headers[PASS_THROUGH_HEADER] = f"Bearer {token}"

        elif auth_type == "api_key_auth":
            location = details.get("in")
            name = details.get("name")
            api_key = details.get("api_key")
            if isinstance(location, str) and isinstance(name, str) and isinstance(api_key, str):
                if location == "HEADER":
                    headers[PASS_THROUGH_HEADER] = api_key
                elif location == "COOKIE":
                    headers["Cookie"] = f"{name}={api_key}"
                elif location == "QUERY":
                    query_params[name] = api_key

        elif auth_type == "key_value_creds":
            for key, val in details.items():
                if isinstance(val, str):
                    headers[key] = val

        elif auth_type == "oauth2":
            token = details.get("access_token")
            if isinstance(token, str):
                headers[PASS_THROUGH_HEADER] = f"Bearer {token}"

    return headers, query_params

# Made with Bob


def get_runtime_credentials(self, connection_id: str, env: str = "draft") -> Dict:
    """
    Get runtime credentials from connection manager for a specific connection.

    Args:
        connection_id: Connection ID to get credentials for
        env: Environment (e.g., 'live', 'draft')

    Returns:
        Dict[str, Any]: Credentials from connection manager
    """
    response = None
    try:
        url = f"{self.connections_url}/api/v1/orchestrate/connections/applications/runtime_credentials?connection_id={connection_id}&env={env}"
        headers = self._get_headers()

        _logger.info(f"[WXO Connections] Getting credentials from connection manager for connection_id: {connection_id}")
        response = requests.get(
            url,
            headers=headers,
            timeout=(CONNECT_TIMEOUT_SEC, READ_TIMEOUT_SEC)
        )

        return response.json()
    except Exception as e:
        _logger.error(f"Unexpected error getting credentials for connection_id {connection_id}: {e}")
        if response is not None:
            try:
                return response.json()
            except:
                pass
        return {}

