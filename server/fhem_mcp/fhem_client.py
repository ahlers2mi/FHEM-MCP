"""HTTP-Client zur abgeschotteten FHEMWEB-Instanz.

Ruft ausschließlich das vom Modul 98_MCP.pm registrierte Kommando ``mcp`` auf:

    mcp <token> <base64(json)>

Das Token wird nicht im Server gehalten, sondern pro Aufruf übergeben.
CSRF (fwcsrf) wird automatisch behandelt.
"""

from __future__ import annotations

import base64
import json
import ssl
from typing import Any

import httpx

from .config import settings


class FhemError(RuntimeError):
    """Vom FHEM-Modul gemeldeter Fehler (ok=false)."""

    def __init__(self, message: str, code: int = 400) -> None:
        super().__init__(message)
        self.code = code


class FhemClient:
    def __init__(self) -> None:
        auth = None
        if settings.fhem_user is not None:
            auth = (settings.fhem_user, settings.fhem_password or "")

        verify: bool | ssl.SSLContext | str = settings.fhem_verify_tls
        if settings.fhem_ca_file:
            verify = settings.fhem_ca_file

        self._client = httpx.AsyncClient(
            auth=auth,
            verify=verify,
            timeout=settings.request_timeout,
        )
        self._csrf: str | None = None

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _ensure_csrf(self) -> None:
        if self._csrf:
            return
        # FHEMWEB liefert das CSRF-Token im Antwort-Header X-FHEM-csrfToken.
        resp = await self._client.get(settings.fhem_url, params={"XHR": "1"})
        self._csrf = resp.headers.get("X-FHEM-csrfToken")

    async def call(self, token: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Führt eine MCP-Aktion in FHEM aus und liefert die geparste Antwort."""
        b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        cmd = f"mcp {token} {b64}"

        result = await self._request(cmd)
        return result

    async def _request(self, cmd: str, _retry: bool = True) -> dict[str, Any]:
        await self._ensure_csrf()
        params = {"cmd": cmd, "XHR": "1"}
        if self._csrf:
            params["fwcsrf"] = self._csrf

        resp = await self._client.get(settings.fhem_url, params=params)

        # CSRF aktualisieren, falls FHEMWEB ein neues Token mitschickt.
        new_csrf = resp.headers.get("X-FHEM-csrfToken")
        if new_csrf:
            self._csrf = new_csrf

        text = resp.text.strip()

        # Abgelaufenes/fehlendes CSRF -> einmal neu holen und wiederholen.
        if "csrf" in text.lower() and "token" in text.lower() and _retry:
            self._csrf = None
            return await self._request(cmd, _retry=False)

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FhemError(
                f"unexpected non-JSON response from FHEM: {text[:200]!r}"
            ) from exc

        if not data.get("ok", False):
            raise FhemError(data.get("error", "unknown error"), data.get("code", 400))
        return data


# Modulweiter Singleton, von Server und OAuth-Routen gemeinsam genutzt.
client = FhemClient()
