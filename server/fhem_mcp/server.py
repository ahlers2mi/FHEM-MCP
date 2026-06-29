"""FastMCP-Server: übersetzt MCP-Tool-Aufrufe in FHEM-Aktionen.

Das Bearer-Token wird über eine ASGI-Middleware aus dem Authorization-Header
gelesen, in einer ContextVar abgelegt und von den Tools bei jedem Aufruf an
FHEM durchgereicht. Der Server speichert es nicht.
"""

from __future__ import annotations

import contextvars
from typing import Any

import uvicorn
from mcp.server.fastmcp import FastMCP

from .config import settings
from .fhem_client import FhemClient, FhemError

# Pro Request gesetztes Bearer-Token (von der Middleware befüllt).
_current_token: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_token", default=None
)

mcp = FastMCP("fhem-mcp")
_client = FhemClient()


def _token() -> str:
    token = _current_token.get()
    if not token:
        raise FhemError(
            "missing bearer token – Authorization: Bearer <token> erforderlich "
            "(in FHEM per 'set <mcp> grant' erzeugen)",
            401,
        )
    return token


async def _call(payload: dict[str, Any]) -> dict[str, Any]:
    return await _client.call(_token(), payload)


# ---------------------------------------------------------------------------
# Tools – Geräte lesen
# ---------------------------------------------------------------------------
@mcp.tool()
async def ping() -> dict[str, Any]:
    """Verbindung und Token prüfen."""
    return await _call({"action": "ping"})


@mcp.tool()
async def list_devices(type: str = "") -> dict[str, Any]:
    """Freigegebene Geräte auflisten (Räume MCP / MCP_rw).

    Optional nach FHEM-TYPE filtern (z. B. 'CUL_HM', 'MQTT2_DEVICE').
    Liefert je Gerät name, type, alias, room, state und writable.
    """
    return await _call({"action": "list_devices", "type": type})


@mcp.tool()
async def get_device(name: str) -> dict[str, Any]:
    """Details eines freigegebenen Geräts: readings, attributes, internals,
    state und die möglichen set-Befehle (possibleSets)."""
    return await _call({"action": "get_device", "device": name})


# ---------------------------------------------------------------------------
# Tools – Geräte steuern (write scope)
# ---------------------------------------------------------------------------
@mcp.tool()
async def set_device(name: str, command: str, args: str = "") -> dict[str, Any]:
    """set <name> <command> [args] – nur für steuerbare Geräte (Raum MCP_rw).

    Beispiel: set_device('Lampe_Wohnzimmer', 'on'); set_device('Heizung',
    'desired-temp', '21.5'). Befehlsverkettung/Perl/Shell ist gesperrt.
    """
    return await _call(
        {"action": "set_device", "device": name, "command": command, "args": args}
    )


@mcp.tool()
async def set_attribute(device: str, attribute: str, value: str) -> dict[str, Any]:
    """attr <device> <attribute> <value> – nur für steuerbare Geräte.
    Das Attribut 'room' kann nicht geändert werden (Allowlist-Schutz)."""
    return await _call(
        {
            "action": "set_attribute",
            "device": device,
            "attribute": attribute,
            "value": value,
        }
    )


@mcp.tool()
async def set_reading(device: str, reading: str, value: str) -> dict[str, Any]:
    """setreading <device> <reading> <value> – nur für steuerbare Geräte."""
    return await _call(
        {
            "action": "set_reading",
            "device": device,
            "reading": reading,
            "value": value,
        }
    )


@mcp.tool()
async def delete_reading(device: str, reading: str) -> dict[str, Any]:
    """deletereading <device> <reading> – nur für steuerbare Geräte."""
    return await _call(
        {"action": "delete_reading", "device": device, "reading": reading}
    )


# ---------------------------------------------------------------------------
# Tools – Dateien (CSS/JS; .pm nur mit admin-Scope)
# ---------------------------------------------------------------------------
@mcp.tool()
async def list_files() -> dict[str, Any]:
    """Einzeln freigegebene Dateien auflisten (Attribut allowFiles)."""
    return await _call({"action": "list_files"})


@mcp.tool()
async def read_file(path: str) -> dict[str, Any]:
    """Inhalt einer freigegebenen Datei lesen (relativ zum FHEM-Basisverzeichnis,
    z. B. 'www/pgm2/mystyle.css'). Datei muss in allowFiles stehen."""
    return await _call({"action": "read_file", "path": path})


@mcp.tool()
async def write_file(path: str, content: str) -> dict[str, Any]:
    """Eine freigegebene Datei schreiben. CSS/JS benötigen den write-Scope,
    .pm-Module zusätzlich den admin-Scope. Datei muss in allowFiles stehen."""
    return await _call({"action": "write_file", "path": path, "content": content})


# ---------------------------------------------------------------------------
# Tools – define/modify (admin scope, separat gegated)
# ---------------------------------------------------------------------------
@mcp.tool()
async def define_device(device: str, definition: str) -> dict[str, Any]:
    """defmod <device> <definition> – legt ein Gerät an/aktualisiert es.
    Erfordert den admin-Scope und adminScopeAllowed=1 in FHEM. <definition>
    ist '<TYPE> <args...>' (ohne führendes 'define <name>')."""
    return await _call(
        {"action": "define_device", "device": device, "definition": definition}
    )


@mcp.tool()
async def modify_device(device: str, definition: str) -> dict[str, Any]:
    """modify <device> <definition> – ändert die Definition eines Geräts.
    Erfordert den admin-Scope und adminScopeAllowed=1 in FHEM."""
    return await _call(
        {"action": "modify_device", "device": device, "definition": definition}
    )


# ---------------------------------------------------------------------------
# ASGI-Middleware: Bearer-Token aus dem Authorization-Header lesen
# ---------------------------------------------------------------------------
class BearerTokenMiddleware:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") == "http":
            headers = dict(scope.get("headers") or [])
            raw = headers.get(b"authorization", b"").decode("latin-1")
            token = raw[7:].strip() if raw.lower().startswith("bearer ") else None
            _current_token.set(token)
        await self.app(scope, receive, send)


def build_app() -> Any:
    mcp.settings.streamable_http_path = settings.mcp_path
    app = mcp.streamable_http_app()
    return BearerTokenMiddleware(app)


def main() -> None:
    uvicorn.run(build_app(), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
