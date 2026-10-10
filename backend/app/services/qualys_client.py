"""Qualys Code Asset API client for PatchOrder.

Provides authenticated access to the Qualys /csapi/v1.3/code endpoints
to retrieve code scan records and associated vulnerability findings.

When Qualys credentials are not configured the client operates in
*mock / unconfigured* mode and returns clearly labelled placeholder data
so that the rest of the application can still be demonstrated.

Important:
- Never log client_secret or raw Bearer tokens.
- Never fabricate CVE IDs or real scan UUIDs.
- All HTTP requests use httpx with explicit timeouts.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

from app.core.config import QualysConfig, qualys_config

logger = logging.getLogger("patchorder.qualys")


class QualysAuthError(Exception):
    """Raised when Qualys JWT authentication fails."""


class QualysAPIError(Exception):
    """Raised for non-auth HTTP errors from the Qualys API."""


class QualysClient:
    """Thin client over the Qualys Code Asset API (v1.3).

    Instantiate once and reuse; the JWT is fetched lazily and cached for
    the session.  In unconfigured mode every method returns mock data
    with ``configured: False`` in the response.
    """

    def __init__(self, config: Optional[QualysConfig] = None) -> None:
        self._cfg = config or qualys_config
        self._token: Optional[str] = None
        self._token_fetched_at: Optional[datetime] = None

    # ── Internal Helpers ────────────────────────────────────────────────────

    def _unconfigured_response(self, endpoint: str) -> Dict[str, Any]:
        return {
            "configured": False,
            "endpoint": endpoint,
            "message": (
                "Qualys credentials are not configured. "
                "Set QUALYS_PLATFORM, QUALYS_CLIENT_ID, and QUALYS_CLIENT_SECRET "
                "environment variables to enable live scanning."
            ),
            "data": None,
        }

    def _check_httpx(self) -> None:
        if not _HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required for Qualys API calls. "
                "Install it with: pip install httpx"
            )

    async def _get_token(self) -> str:
        """Fetch (or return cached) JWT Bearer token from Qualys auth endpoint."""
        self._check_httpx()
        if self._token and self._token_fetched_at:
            age = (datetime.now(timezone.utc) - self._token_fetched_at).total_seconds()
            if age < 3300:  # tokens valid ~60 min; refresh at 55 min
                return self._token

        auth_url = f"{self._cfg.base_url()}/auth"
        logger.info("Fetching Qualys JWT token from %s", auth_url)
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                auth_url,
                data={
                    "username": self._cfg.client_id,
                    "password": self._cfg.client_secret,
                    "token": "true",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if resp.status_code == 401:
            raise QualysAuthError("Qualys authentication failed — check QUALYS_CLIENT_ID and QUALYS_CLIENT_SECRET")
        if resp.status_code != 200:
            raise QualysAuthError(f"Qualys auth returned HTTP {resp.status_code}")
        token = resp.text.strip()
        if not token:
            raise QualysAuthError("Qualys auth returned an empty token")
        self._token = token
        self._token_fetched_at = datetime.now(timezone.utc)
        logger.info("Qualys JWT obtained successfully (length=%d)", len(token))
        return token

    def _auth_headers(self, token: str) -> Dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    async def _get_json(self, path: str, params: Optional[Dict] = None) -> Any:
        """Authenticated GET to a Qualys API path, returns parsed JSON."""
        self._check_httpx()
        token = await self._get_token()
        url = f"{self._cfg.base_url()}{path}"
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(url, headers=self._auth_headers(token), params=params or {})
        if resp.status_code == 401:
            raise QualysAuthError("Qualys API returned 401 — token may have expired")
        if resp.status_code == 403:
            raise QualysAPIError("Qualys API returned 403 — insufficient permissions for this endpoint")
        if resp.status_code == 404:
            return None
        if not resp.is_success:
            raise QualysAPIError(f"Qualys API error {resp.status_code}: {resp.text[:200]}")
        return resp.json()

    # ── Public API Methods ───────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """Return True when credentials are present and non-placeholder."""
        return self._cfg.is_configured()

    async def list_code_scans(
        self,
        page_size: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List code scan records from GET /csapi/v1.3/code.

        Returns a dict with ``configured``, ``total``, and ``items`` keys.
        """
        if not self.is_configured():
            return self._unconfigured_response("/csapi/v1.3/code")
        try:
            data = await self._get_json(
                "/csapi/v1.3/code",
                params={"pageSize": page_size, "offset": offset},
            )
            items = data if isinstance(data, list) else data.get("data", data.get("list", []))
            return {
                "configured": True,
                "total": len(items),
                "items": items,
            }
        except (QualysAuthError, QualysAPIError) as exc:
            logger.error("list_code_scans failed: %s", exc)
            raise

    async def get_code_scan_details(self, uuid: str) -> Optional[Dict[str, Any]]:
        """Retrieve metadata for a single code scan by UUID."""
        if not self.is_configured():
            return None
        return await self._get_json(f"/csapi/v1.3/code/{uuid}")

    async def get_code_scan_vulns(self, uuid: str) -> Dict[str, Any]:
        """Retrieve vulnerability findings for a code scan UUID."""
        if not self.is_configured():
            return self._unconfigured_response(f"/csapi/v1.3/code/{uuid}/vuln/stats")
        data = await self._get_json(f"/csapi/v1.3/code/{uuid}/vuln/stats")
        return {
            "configured": True,
            "uuid": uuid,
            "data": data,
        }

    async def find_scan_for_commit(
        self,
        repo_url: str,
        commit_sha: str,
    ) -> Optional[Dict[str, Any]]:
        """Search all code scan records for one matching repo_url + commit_sha.

        Qualys does not expose a direct commit-SHA query parameter, so we
        list all scans and filter locally.
        Returns the first matching scan record or None.
        """
        if not self.is_configured():
            return None

        offset = 0
        page_size = 50
        while True:
            result = await self.list_code_scans(page_size=page_size, offset=offset)
            items = result.get("items", [])
            if not items:
                break
            for item in items:
                # Qualys code asset record typically has repositoryUrl and commitSha fields
                item_repo = item.get("repositoryUrl") or item.get("repository_url", "")
                item_sha = item.get("commitSha") or item.get("commit_sha", "")
                if item_repo == repo_url and item_sha == commit_sha:
                    return item
            if len(items) < page_size:
                break
            offset += page_size

        return None
