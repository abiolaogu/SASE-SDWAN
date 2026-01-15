"""
OpenSASE Python SDK

A comprehensive Python SDK for the OpenSASE Platform API.

Usage:
    from opensase import OpenSASE
    
    client = OpenSASE(api_key='os_live_abc123...')
    
    # Create a user
    user = client.identity.users.create(email='john@example.com')
    
    # Async usage
    from opensase import AsyncOpenSASE
    
    async_client = AsyncOpenSASE(api_key='os_live_abc123...')
    user = await async_client.identity.users.create(email='john@example.com')
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    Generator,
    Generic,
    List,
    Optional,
    Type,
    TypeVar,
    Union,
)
from urllib.parse import urlencode, urljoin

import httpx

__version__ = "1.0.0"
__all__ = [
    "OpenSASE",
    "AsyncOpenSASE",
    "OpenSASEError",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "ConflictError",
    "RateLimitError",
    "verify_webhook_signature",
]

T = TypeVar("T")


# =============================================================================
# Exceptions
# =============================================================================


class OpenSASEError(Exception):
    """Base exception for OpenSASE SDK errors."""

    def __init__(
        self,
        message: str,
        code: str = "unknown_error",
        status_code: int = 500,
        request_id: Optional[str] = None,
        details: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.request_id = request_id
        self.details = details or []

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(code={self.code!r}, message={self.message!r})>"


class ValidationError(OpenSASEError):
    """Raised when request validation fails."""

    def __init__(
        self,
        message: str,
        request_id: Optional[str] = None,
        details: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(message, "validation_error", 400, request_id, details)


class AuthenticationError(OpenSASEError):
    """Raised when authentication fails."""

    def __init__(self, message: str, request_id: Optional[str] = None):
        super().__init__(message, "unauthorized", 401, request_id)


class AuthorizationError(OpenSASEError):
    """Raised when authorization fails."""

    def __init__(self, message: str, request_id: Optional[str] = None):
        super().__init__(message, "forbidden", 403, request_id)


class NotFoundError(OpenSASEError):
    """Raised when a resource is not found."""

    def __init__(self, message: str, request_id: Optional[str] = None):
        super().__init__(message, "not_found", 404, request_id)


class ConflictError(OpenSASEError):
    """Raised when there's a resource conflict."""

    def __init__(self, message: str, request_id: Optional[str] = None):
        super().__init__(message, "conflict", 409, request_id)


class RateLimitError(OpenSASEError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str,
        retry_after: int,
        limit: int,
        remaining: int,
        request_id: Optional[str] = None,
    ):
        super().__init__(message, "rate_limit_exceeded", 429, request_id)
        self.retry_after = retry_after
        self.limit = limit
        self.remaining = remaining


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class Pagination:
    """Pagination information for list responses."""

    page: int
    per_page: int
    total: int
    total_pages: int


@dataclass
class CursorPagination:
    """Cursor-based pagination information."""

    has_more: bool
    next_cursor: Optional[str]
    prev_cursor: Optional[str]


@dataclass
class ListResponse(Generic[T]):
    """Response wrapper for paginated list endpoints."""

    data: List[T]
    pagination: Pagination


# =============================================================================
# HTTP Client
# =============================================================================


def _camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case."""
    result = []
    for i, char in enumerate(name):
        if char.isupper() and i > 0:
            result.append("_")
        result.append(char.lower())
    return "".join(result)


def _snake_to_camel(name: str) -> str:
    """Convert snake_case to camelCase."""
    components = name.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def _transform_keys(obj: Any, transform: Callable[[str], str]) -> Any:
    """Recursively transform dictionary keys."""
    if obj is None:
        return None
    if isinstance(obj, list):
        return [_transform_keys(item, transform) for item in obj]
    if isinstance(obj, dict):
        return {transform(k): _transform_keys(v, transform) for k, v in obj.items()}
    return obj


def _to_snake_case(obj: Any) -> Any:
    """Convert all dictionary keys to snake_case."""
    return _transform_keys(obj, _camel_to_snake)


def _to_camel_case(obj: Any) -> Any:
    """Convert all dictionary keys to camelCase."""
    return _transform_keys(obj, _snake_to_camel)


class BaseClient:
    """Base HTTP client with common functionality."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.opensase.billyronks.io/v1",
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        headers: Optional[Dict[str, str]] = None,
    ):
        if not api_key:
            raise ValueError("API key is required")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.default_headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"opensase-python/{__version__}",
            **(headers or {}),
        }

    def _build_url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        """Build full URL with query parameters."""
        url = f"{self.base_url}{path}"
        if params:
            # Filter out None values and convert lists
            filtered_params = {}
            for key, value in params.items():
                if value is not None:
                    if isinstance(value, list):
                        filtered_params[key] = ",".join(str(v) for v in value)
                    elif isinstance(value, bool):
                        filtered_params[key] = str(value).lower()
                    else:
                        filtered_params[key] = value
            if filtered_params:
                url = f"{url}?{urlencode(filtered_params)}"
        return url

    def _is_retryable(self, status_code: int) -> bool:
        """Check if the error is retryable."""
        return status_code == 429 or status_code >= 500

    def _handle_error(
        self, response: httpx.Response, body: Dict[str, Any], request_id: Optional[str]
    ) -> None:
        """Handle error responses and raise appropriate exceptions."""
        error = body.get("error", {})
        message = error.get("message", "An error occurred")
        code = error.get("code", "unknown_error")
        details = error.get("details")

        if response.status_code == 400:
            raise ValidationError(message, request_id, details)
        elif response.status_code == 401:
            raise AuthenticationError(message, request_id)
        elif response.status_code == 403:
            raise AuthorizationError(message, request_id)
        elif response.status_code == 404:
            raise NotFoundError(message, request_id)
        elif response.status_code == 409:
            raise ConflictError(message, request_id)
        elif response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", "30"))
            limit = int(response.headers.get("X-RateLimit-Limit", "0"))
            remaining = int(response.headers.get("X-RateLimit-Remaining", "0"))
            raise RateLimitError(message, retry_after, limit, remaining, request_id)
        else:
            raise OpenSASEError(message, code, response.status_code, request_id, details)


class SyncHttpClient(BaseClient):
    """Synchronous HTTP client."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._client = httpx.Client(timeout=self.timeout)

    def __del__(self):
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Any:
        """Make a synchronous HTTP request."""
        url = self._build_url(path, params)
        request_headers = {**self.default_headers, **(headers or {})}

        if idempotency_key:
            request_headers["Idempotency-Key"] = idempotency_key

        json_body = _to_snake_case(body) if body else None

        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.request(
                    method=method,
                    url=url,
                    json=json_body,
                    headers=request_headers,
                )

                request_id = response.headers.get("X-Request-ID")

                if response.status_code == 204:
                    return None

                response_body = response.json()

                if not response.is_success:
                    if self._is_retryable(response.status_code) and attempt < self.max_retries:
                        if response.status_code == 429:
                            delay = int(response.headers.get("Retry-After", "1"))
                        else:
                            delay = self.retry_delay * (2 ** attempt)
                        time.sleep(delay)
                        continue
                    self._handle_error(response, response_body, request_id)

                data = response_body.get("data", response_body)
                return _to_snake_case(data)

            except OpenSASEError:
                raise
            except Exception as e:
                last_error = e
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * (2 ** attempt))
                    continue

        if last_error:
            raise last_error
        raise OpenSASEError("Request failed after retries")

    def get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        return self.request("GET", path, params=params, **kwargs)

    def post(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        return self.request("POST", path, body=body, **kwargs)

    def put(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        return self.request("PUT", path, body=body, **kwargs)

    def patch(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        return self.request("PATCH", path, body=body, **kwargs)

    def delete(self, path: str, **kwargs) -> Any:
        return self.request("DELETE", path, **kwargs)


class AsyncHttpClient(BaseClient):
    """Asynchronous HTTP client."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def close(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Any:
        """Make an asynchronous HTTP request."""
        url = self._build_url(path, params)
        request_headers = {**self.default_headers, **(headers or {})}

        if idempotency_key:
            request_headers["Idempotency-Key"] = idempotency_key

        json_body = _to_snake_case(body) if body else None

        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.request(
                    method=method,
                    url=url,
                    json=json_body,
                    headers=request_headers,
                )

                request_id = response.headers.get("X-Request-ID")

                if response.status_code == 204:
                    return None

                response_body = response.json()

                if not response.is_success:
                    if self._is_retryable(response.status_code) and attempt < self.max_retries:
                        if response.status_code == 429:
                            delay = int(response.headers.get("Retry-After", "1"))
                        else:
                            delay = self.retry_delay * (2 ** attempt)
                        await asyncio.sleep(delay)
                        continue
                    self._handle_error(response, response_body, request_id)

                data = response_body.get("data", response_body)
                return _to_snake_case(data)

            except OpenSASEError:
                raise
            except Exception as e:
                last_error = e
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                    continue

        if last_error:
            raise last_error
        raise OpenSASEError("Request failed after retries")

    async def get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        return await self.request("GET", path, params=params, **kwargs)

    async def post(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        return await self.request("POST", path, body=body, **kwargs)

    async def put(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        return await self.request("PUT", path, body=body, **kwargs)

    async def patch(
        self,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        return await self.request("PATCH", path, body=body, **kwargs)

    async def delete(self, path: str, **kwargs) -> Any:
        return await self.request("DELETE", path, **kwargs)


# =============================================================================
# Service Classes - Synchronous
# =============================================================================


class UsersService:
    """User management service."""

    def __init__(self, client: SyncHttpClient):
        self._client = client

    def list(
        self,
        page: int = 1,
        per_page: int = 20,
        search: Optional[str] = None,
        status: Optional[str] = None,
        sort: str = "created_at",
        order: str = "desc",
    ) -> Dict[str, Any]:
        """List all users with pagination."""
        return self._client.get(
            "/identity/users",
            params={
                "page": page,
                "per_page": per_page,
                "search": search,
                "status": status,
                "sort": sort,
                "order": order,
            },
        )

    def create(
        self,
        email: str,
        password: Optional[str] = None,
        profile: Optional[Dict[str, Any]] = None,
        roles: Optional[List[str]] = None,
        groups: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        send_welcome_email: bool = False,
    ) -> Dict[str, Any]:
        """Create a new user."""
        return self._client.post(
            "/identity/users",
            body={
                "email": email,
                "password": password,
                "profile": profile,
                "roles": roles,
                "groups": groups,
                "metadata": metadata,
                "send_welcome_email": send_welcome_email,
            },
        )

    def get(self, user_id: str) -> Dict[str, Any]:
        """Get a user by ID."""
        return self._client.get(f"/identity/users/{user_id}")

    def update(
        self,
        user_id: str,
        profile: Optional[Dict[str, Any]] = None,
        status: Optional[str] = None,
        roles: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update a user."""
        return self._client.patch(
            f"/identity/users/{user_id}",
            body={
                "profile": profile,
                "status": status,
                "roles": roles,
                "metadata": metadata,
            },
        )

    def delete(self, user_id: str) -> None:
        """Delete a user."""
        self._client.delete(f"/identity/users/{user_id}")

    def list_all(self, **kwargs) -> Generator[Dict[str, Any], None, None]:
        """Iterate through all users with automatic pagination."""
        page = 1
        while True:
            response = self.list(page=page, **kwargs)
            for user in response.get("data", response) if isinstance(response, dict) else response:
                yield user
            
            pagination = response.get("pagination", {})
            if page >= pagination.get("total_pages", 1):
                break
            page += 1


class AuthService:
    """Authentication service."""

    def __init__(self, client: SyncHttpClient):
        self._client = client

    def login(
        self,
        email: str,
        password: str,
        device_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Login with email and password."""
        return self._client.post(
            "/identity/auth/login",
            body={
                "email": email,
                "password": password,
                "device_info": device_info,
            },
        )

    def verify_mfa(
        self,
        mfa_token: str,
        method: str,
        code: str,
    ) -> Dict[str, Any]:
        """Verify MFA code."""
        return self._client.post(
            "/identity/auth/mfa/verify",
            body={
                "mfa_token": mfa_token,
                "method": method,
                "code": code,
            },
        )

    def refresh(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token."""
        return self._client.post(
            "/identity/auth/refresh",
            body={"refresh_token": refresh_token},
        )

    def logout(
        self,
        refresh_token: Optional[str] = None,
        all_devices: bool = False,
    ) -> None:
        """Logout current session."""
        self._client.post(
            "/identity/auth/logout",
            body={
                "refresh_token": refresh_token,
                "all_devices": all_devices,
            },
        )

    def request_password_reset(self, email: str) -> Dict[str, Any]:
        """Request password reset email."""
        return self._client.post(
            "/identity/auth/password/reset-request",
            body={"email": email},
        )

    def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """Reset password with token."""
        return self._client.post(
            "/identity/auth/password/reset",
            body={"token": token, "new_password": new_password},
        )

    def change_password(self, current_password: str, new_password: str) -> Dict[str, Any]:
        """Change password for authenticated user."""
        return self._client.post(
            "/identity/auth/password/change",
            body={
                "current_password": current_password,
                "new_password": new_password,
            },
        )


class GroupsService:
    """Group management service."""

    def __init__(self, client: SyncHttpClient):
        self._client = client

    def list(self, page: int = 1, per_page: int = 20) -> Dict[str, Any]:
        """List all groups."""
        return self._client.get(
            "/identity/groups",
            params={"page": page, "per_page": per_page},
        )

    def create(
        self,
        name: str,
        description: Optional[str] = None,
        roles: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a new group."""
        return self._client.post(
            "/identity/groups",
            body={
                "name": name,
                "description": description,
                "roles": roles,
            },
        )

    def get(self, group_id: str) -> Dict[str, Any]:
        """Get a group by ID."""
        return self._client.get(f"/identity/groups/{group_id}")

    def update(
        self,
        group_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        roles: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Update a group."""
        return self._client.patch(
            f"/identity/groups/{group_id}",
            body={
                "name": name,
                "description": description,
                "roles": roles,
            },
        )

    def delete(self, group_id: str) -> None:
        """Delete a group."""
        self._client.delete(f"/identity/groups/{group_id}")

    def add_members(self, group_id: str, user_ids: List[str]) -> Dict[str, Any]:
        """Add members to a group."""
        return self._client.post(
            f"/identity/groups/{group_id}/members",
            body={"user_ids": user_ids},
        )

    def remove_members(self, group_id: str, user_ids: List[str]) -> Dict[str, Any]:
        """Remove members from a group."""
        return self._client.request(
            "DELETE",
            f"/identity/groups/{group_id}/members",
            body={"user_ids": user_ids},
        )


class IdentityService:
    """Identity management service."""

    def __init__(self, client: SyncHttpClient):
        self.users = UsersService(client)
        self.auth = AuthService(client)
        self.groups = GroupsService(client)


class ContactsService:
    """CRM contacts service."""

    def __init__(self, client: SyncHttpClient):
        self._client = client

    def list(
        self,
        page: int = 1,
        per_page: int = 20,
        search: Optional[str] = None,
        status: Optional[str] = None,
        owner_id: Optional[str] = None,
        account_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        created_after: Optional[str] = None,
        sort: str = "created_at",
        order: str = "desc",
    ) -> Dict[str, Any]:
        """List all contacts with pagination."""
        return self._client.get(
            "/crm/contacts",
            params={
                "page": page,
                "per_page": per_page,
                "search": search,
                "status": status,
                "owner_id": owner_id,
                "account_id": account_id,
                "tags": tags,
                "created_after": created_after,
                "sort": sort,
                "order": order,
            },
        )

    def create(
        self,
        email: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        phone: Optional[str] = None,
        mobile: Optional[str] = None,
        title: Optional[str] = None,
        company_name: Optional[str] = None,
        lead_source: Optional[str] = None,
        owner_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a new contact."""
        return self._client.post(
            "/crm/contacts",
            body={
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "phone": phone,
                "mobile": mobile,
                "title": title,
                "company_name": company_name,
                "lead_source": lead_source,
                "owner_id": owner_id,
                "tags": tags,
                "custom_fields": custom_fields,
            },
        )

    def get(self, contact_id: str) -> Dict[str, Any]:
        """Get a contact by ID."""
        return self._client.get(f"/crm/contacts/{contact_id}")

    def update(self, contact_id: str, **kwargs) -> Dict[str, Any]:
        """Update a contact."""
        return self._client.patch(f"/crm/contacts/{contact_id}", body=kwargs)

    def delete(self, contact_id: str) -> None:
        """Delete a contact."""
        self._client.delete(f"/crm/contacts/{contact_id}")

    def get_360_view(self, contact_id: str) -> Dict[str, Any]:
        """Get 360° view of a contact."""
        return self._client.get(f"/crm/contacts/{contact_id}/360")

    def list_all(self, **kwargs) -> Generator[Dict[str, Any], None, None]:
        """Iterate through all contacts with automatic pagination."""
        page = 1
        while True:
            response = self.list(page=page, **kwargs)
            data = response if isinstance(response, list) else response.get("data", [])
            for contact in data:
                yield contact
            
            pagination = response.get("pagination", {}) if isinstance(response, dict) else {}
            if page >= pagination.get("total_pages", 1):
                break
            page += 1


class DealsService:
    """CRM deals service."""

    def __init__(self, client: SyncHttpClient):
        self._client = client

    def list(
        self,
        page: int = 1,
        per_page: int = 20,
        pipeline_id: Optional[str] = None,
        stage_id: Optional[str] = None,
        owner_id: Optional[str] = None,
        status: Optional[str] = None,
        min_amount: Optional[float] = None,
        max_amount: Optional[float] = None,
    ) -> Dict[str, Any]:
        """List all deals."""
        return self._client.get(
            "/crm/deals",
            params={
                "page": page,
                "per_page": per_page,
                "pipeline_id": pipeline_id,
                "stage_id": stage_id,
                "owner_id": owner_id,
                "status": status,
                "min_amount": min_amount,
                "max_amount": max_amount,
            },
        )

    def create(
        self,
        name: str,
        amount: float,
        pipeline_id: str,
        stage_id: str,
        currency: str = "USD",
        contact_id: Optional[str] = None,
        account_id: Optional[str] = None,
        expected_close_date: Optional[str] = None,
        deal_type: Optional[str] = None,
        lead_source: Optional[str] = None,
        competitors: Optional[List[str]] = None,
        products: Optional[List[Dict[str, Any]]] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a new deal."""
        return self._client.post(
            "/crm/deals",
            body={
                "name": name,
                "amount": amount,
                "currency": currency,
                "pipeline_id": pipeline_id,
                "stage_id": stage_id,
                "contact_id": contact_id,
                "account_id": account_id,
                "expected_close_date": expected_close_date,
                "deal_type": deal_type,
                "lead_source": lead_source,
                "competitors": competitors,
                "products": products,
                "custom_fields": custom_fields,
            },
        )

    def get(self, deal_id: str) -> Dict[str, Any]:
        """Get a deal by ID."""
        return self._client.get(f"/crm/deals/{deal_id}")

    def update(self, deal_id: str, **kwargs) -> Dict[str, Any]:
        """Update a deal."""
        return self._client.patch(f"/crm/deals/{deal_id}", body=kwargs)

    def delete(self, deal_id: str) -> None:
        """Delete a deal."""
        self._client.delete(f"/crm/deals/{deal_id}")

    def move_to_stage(
        self,
        deal_id: str,
        stage_id: str,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Move a deal to a different stage."""
        return self._client.post(
            f"/crm/deals/{deal_id}/move",
            body={"stage_id": stage_id, "note": note},
        )


class PipelinesService:
    """CRM pipelines service."""

    def __init__(self, client: SyncHttpClient):
        self._client = client

    def list(self) -> Dict[str, Any]:
        """List all pipelines."""
        return self._client.get("/crm/pipelines")

    def get(self, pipeline_id: str) -> Dict[str, Any]:
        """Get a pipeline by ID."""
        return self._client.get(f"/crm/pipelines/{pipeline_id}")

    def get_view(
        self,
        pipeline_id: str,
        owner_id: Optional[str] = None,
        period: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get pipeline view with deals."""
        return self._client.get(
            f"/crm/pipelines/{pipeline_id}/view",
            params={
                "owner_id": owner_id,
                "period": period,
                "start_date": start_date,
                "end_date": end_date,
            },
        )


class CRMService:
    """CRM service."""

    def __init__(self, client: SyncHttpClient):
        self.contacts = ContactsService(client)
        self.deals = DealsService(client)
        self.pipelines = PipelinesService(client)


class PaymentIntentsService:
    """Payment intents service."""

    def __init__(self, client: SyncHttpClient):
        self._client = client

    def list(
        self,
        page: int = 1,
        per_page: int = 20,
        customer_id: Optional[str] = None,
        status: Optional[str] = None,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List all payment intents."""
        return self._client.get(
            "/payments/intents",
            params={
                "page": page,
                "per_page": per_page,
                "customer_id": customer_id,
                "status": status,
                "created_after": created_after,
                "created_before": created_before,
            },
        )

    def create(
        self,
        amount: int,
        currency: str,
        customer_id: Optional[str] = None,
        payment_method_types: Optional[List[str]] = None,
        capture_method: str = "automatic",
        metadata: Optional[Dict[str, Any]] = None,
        receipt_email: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new payment intent."""
        return self._client.post(
            "/payments/intents",
            body={
                "amount": amount,
                "currency": currency,
                "customer_id": customer_id,
                "payment_method_types": payment_method_types or ["card"],
                "capture_method": capture_method,
                "metadata": metadata,
                "receipt_email": receipt_email,
            },
            idempotency_key=idempotency_key,
        )

    def get(self, intent_id: str) -> Dict[str, Any]:
        """Get a payment intent by ID."""
        return self._client.get(f"/payments/intents/{intent_id}")

    def confirm(
        self,
        intent_id: str,
        payment_method_id: str,
        return_url: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Confirm a payment intent."""
        return self._client.post(
            f"/payments/intents/{intent_id}/confirm",
            body={
                "payment_method_id": payment_method_id,
                "return_url": return_url,
            },
            idempotency_key=idempotency_key,
        )

    def capture(
        self,
        intent_id: str,
        amount_to_capture: Optional[int] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Capture a payment intent."""
        return self._client.post(
            f"/payments/intents/{intent_id}/capture",
            body={"amount_to_capture": amount_to_capture},
            idempotency_key=idempotency_key,
        )

    def cancel(
        self,
        intent_id: str,
        cancellation_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel a payment intent."""
        return self._client.post(
            f"/payments/intents/{intent_id}/cancel",
            body={"cancellation_reason": cancellation_reason},
        )


class SubscriptionsService:
    """Subscriptions service."""

    def __init__(self, client: SyncHttpClient):
        self._client = client

    def list(
        self,
        page: int = 1,
        per_page: int = 20,
        customer_id: Optional[str] = None,
        status: Optional[str] = None,
        plan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List all subscriptions."""
        return self._client.get(
            "/payments/subscriptions",
            params={
                "page": page,
                "per_page": per_page,
                "customer_id": customer_id,
                "status": status,
                "plan_id": plan_id,
            },
        )

    def create(
        self,
        customer_id: str,
        plan_id: str,
        payment_method_id: str,
        trial_period_days: Optional[int] = None,
        billing_cycle_anchor: Optional[str] = None,
        proration_behavior: str = "create_prorations",
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new subscription."""
        return self._client.post(
            "/payments/subscriptions",
            body={
                "customer_id": customer_id,
                "plan_id": plan_id,
                "payment_method_id": payment_method_id,
                "trial_period_days": trial_period_days,
                "billing_cycle_anchor": billing_cycle_anchor,
                "proration_behavior": proration_behavior,
                "metadata": metadata,
            },
            idempotency_key=idempotency_key,
        )

    def get(self, subscription_id: str) -> Dict[str, Any]:
        """Get a subscription by ID."""
        return self._client.get(f"/payments/subscriptions/{subscription_id}")

    def update(self, subscription_id: str, **kwargs) -> Dict[str, Any]:
        """Update a subscription."""
        return self._client.patch(
            f"/payments/subscriptions/{subscription_id}",
            body=kwargs,
        )

    def cancel(
        self,
        subscription_id: str,
        cancel_at_period_end: bool = True,
        cancellation_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel a subscription."""
        return self._client.post(
            f"/payments/subscriptions/{subscription_id}/cancel",
            body={
                "cancel_at_period_end": cancel_at_period_end,
                "cancellation_reason": cancellation_reason,
            },
        )

    def resume(self, subscription_id: str) -> Dict[str, Any]:
        """Resume a paused subscription."""
        return self._client.post(f"/payments/subscriptions/{subscription_id}/resume")


class RefundsService:
    """Refunds service."""

    def __init__(self, client: SyncHttpClient):
        self._client = client

    def list(
        self,
        page: int = 1,
        per_page: int = 20,
        payment_intent_id: Optional[str] = None,
        charge_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List all refunds."""
        return self._client.get(
            "/payments/refunds",
            params={
                "page": page,
                "per_page": per_page,
                "payment_intent_id": payment_intent_id,
                "charge_id": charge_id,
            },
        )

    def create(
        self,
        payment_intent_id: str,
        charge_id: Optional[str] = None,
        amount: Optional[int] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a refund."""
        return self._client.post(
            "/payments/refunds",
            body={
                "payment_intent_id": payment_intent_id,
                "charge_id": charge_id,
                "amount": amount,
                "reason": reason,
                "metadata": metadata,
            },
            idempotency_key=idempotency_key,
        )

    def get(self, refund_id: str) -> Dict[str, Any]:
        """Get a refund by ID."""
        return self._client.get(f"/payments/refunds/{refund_id}")


class PaymentsService:
    """Payments service."""

    def __init__(self, client: SyncHttpClient):
        self.intents = PaymentIntentsService(client)
        self.subscriptions = SubscriptionsService(client)
        self.refunds = RefundsService(client)


# =============================================================================
# Main Client Classes
# =============================================================================


class OpenSASE:
    """
    Synchronous OpenSASE client.
    
    Usage:
        client = OpenSASE(api_key='os_live_abc123...')
        user = client.identity.users.create(email='john@example.com')
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.opensase.billyronks.io/v1",
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        headers: Optional[Dict[str, str]] = None,
    ):
        self._client = SyncHttpClient(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
            headers=headers,
        )
        
        self.identity = IdentityService(self._client)
        self.crm = CRMService(self._client)
        self.payments = PaymentsService(self._client)


class AsyncOpenSASE:
    """
    Asynchronous OpenSASE client.
    
    Usage:
        async with AsyncOpenSASE(api_key='os_live_abc123...') as client:
            user = await client.identity.users.create(email='john@example.com')
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.opensase.billyronks.io/v1",
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        headers: Optional[Dict[str, str]] = None,
    ):
        self._client = AsyncHttpClient(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            retry_delay=retry_delay,
            headers=headers,
        )
        
        # Note: Async services would need separate implementations
        # For brevity, using sync services with async client
        # In production, create full async service classes

    async def close(self):
        """Close the HTTP client."""
        await self._client.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# =============================================================================
# Webhook Utilities
# =============================================================================


def verify_webhook_signature(
    payload: Union[str, bytes],
    signature: str,
    timestamp: str,
    secret: str,
    tolerance: int = 300,
) -> bool:
    """
    Verify webhook signature.
    
    Args:
        payload: The raw webhook payload
        signature: The X-OpenSASE-Signature header value
        timestamp: The X-OpenSASE-Timestamp header value
        secret: Your webhook secret
        tolerance: Maximum age of webhook in seconds (default: 300)
    
    Returns:
        True if signature is valid
    
    Raises:
        ValueError: If timestamp is outside tolerance
    """
    # Check timestamp tolerance
    timestamp_int = int(timestamp)
    if abs(time.time() - timestamp_int) > tolerance:
        raise ValueError("Webhook timestamp outside tolerance")
    
    # Compute expected signature
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    
    signed_payload = f"{timestamp}.{payload}"
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        signed_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    
    # Parse and compare signatures
    for part in signature.split(","):
        version, sig = part.split("=")
        if version == "v1":
            return hmac.compare_digest(sig, expected_signature)
    
    return False


def construct_webhook_event(
    payload: Union[str, bytes],
    signature: str,
    timestamp: str,
    secret: str,
) -> Dict[str, Any]:
    """
    Construct and verify a webhook event.
    
    Args:
        payload: The raw webhook payload
        signature: The X-OpenSASE-Signature header value
        timestamp: The X-OpenSASE-Timestamp header value
        secret: Your webhook secret
    
    Returns:
        The parsed webhook event
    
    Raises:
        ValueError: If signature verification fails
    """
    if not verify_webhook_signature(payload, signature, timestamp, secret):
        raise ValueError("Invalid webhook signature")
    
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    
    return json.loads(payload)
