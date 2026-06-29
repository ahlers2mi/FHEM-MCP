"""Starlette-Routen für den OAuth-Authorization-Server + Consent-Seite."""

from __future__ import annotations

import html
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .config import settings
from .fhem_client import FhemError, client
from .oauth import OAuthError, store

# Pfade (relativ zur öffentlichen Basis-URL)
PATH_PROTECTED_RESOURCE = "/.well-known/oauth-protected-resource"
PATH_AUTH_SERVER = "/.well-known/oauth-authorization-server"
PATH_REGISTER = "/register"
PATH_AUTHORIZE = "/authorize"
PATH_TOKEN = "/token"


def base_url(request: Request) -> str:
    if settings.public_url:
        return settings.public_url.rstrip("/")
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    return f"{proto}://{host}"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
async def protected_resource_metadata(request: Request) -> Response:
    b = base_url(request)
    return JSONResponse(
        {
            "resource": b,
            "authorization_servers": [b],
            "scopes_supported": ["fhem"],
            "bearer_methods_supported": ["header"],
        }
    )


async def authorization_server_metadata(request: Request) -> Response:
    b = base_url(request)
    return JSONResponse(
        {
            "issuer": b,
            "authorization_endpoint": b + PATH_AUTHORIZE,
            "token_endpoint": b + PATH_TOKEN,
            "registration_endpoint": b + PATH_REGISTER,
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["fhem"],
        }
    )


# ---------------------------------------------------------------------------
# Dynamic Client Registration (RFC 7591)
# ---------------------------------------------------------------------------
async def register(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)

    redirect_uris = body.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return JSONResponse(
            {"error": "invalid_redirect_uri",
             "error_description": "redirect_uris required"},
            status_code=400,
        )

    c = store.register_client([str(u) for u in redirect_uris])
    return JSONResponse(
        {
            "client_id": c.client_id,
            "redirect_uris": c.redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
        status_code=201,
    )


# ---------------------------------------------------------------------------
# Authorization endpoint + Consent-Seite
# ---------------------------------------------------------------------------
_CONSENT_PAGE = """\
<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FHEM-MCP – Zugriff erlauben</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;color:#222}}
 h1{{font-size:1.4rem}} .err{{background:#fdecea;color:#b3261e;padding:.6rem .8rem;border-radius:.4rem}}
 label{{display:block;margin:1rem 0 .3rem;font-weight:600}}
 input[type=text]{{width:100%;padding:.6rem;font-size:1rem;box-sizing:border-box}}
 button{{margin-top:1.2rem;padding:.6rem 1.2rem;font-size:1rem;cursor:pointer}}
 .hint{{color:#555;font-size:.9rem}}
</style></head><body>
<h1>FHEM-MCP – Zugriff für Claude erlauben</h1>
<p class="hint">Erzeuge in FHEM ein Token mit <code>set &lt;mcp&gt; grant read</code>
(bzw. <code>write</code>/<code>admin</code>) und füge es hier ein. Der Zugriff
gilt so lange, wie das Token in FHEM gültig ist.</p>
{error}
<form method="post" action="{action}">
{hidden}
<label for="t">FHEM-Token</label>
<input id="t" type="text" name="fhem_token" autocomplete="off" autofocus required>
<button type="submit">Zugriff erlauben</button>
</form>
</body></html>
"""

_AUTH_FIELDS = ("client_id", "redirect_uri", "state", "code_challenge",
                "code_challenge_method", "scope", "response_type")


def _render_consent(request: Request, params: dict[str, str], error: str = "") -> HTMLResponse:
    hidden = "\n".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(params.get(k, ""))}">'
        for k in _AUTH_FIELDS
    )
    err = f'<p class="err">{html.escape(error)}</p>' if error else ""
    page = _CONSENT_PAGE.format(action=PATH_AUTHORIZE, hidden=hidden, error=err)
    return HTMLResponse(page)


def _validate_authorize(params: dict[str, str]) -> str | None:
    """Gibt eine Fehlermeldung zurück oder None, wenn alles passt."""
    if params.get("response_type") != "code":
        return "response_type muss 'code' sein."
    if params.get("code_challenge_method", "S256") != "S256":
        return "Nur PKCE S256 wird unterstützt."
    if not params.get("code_challenge"):
        return "code_challenge (PKCE) fehlt."
    c = store.clients.get(params.get("client_id", ""))
    if c is None:
        return "Unbekannte client_id."
    if params.get("redirect_uri") not in c.redirect_uris:
        return "redirect_uri nicht registriert."
    return None


async def authorize(request: Request) -> Response:
    """Dispatcher: GET zeigt die Consent-Seite, POST verarbeitet sie."""
    if request.method == "POST":
        return await authorize_post(request)
    return await authorize_get(request)


async def authorize_get(request: Request) -> Response:
    params = {k: request.query_params.get(k, "") for k in _AUTH_FIELDS}
    err = _validate_authorize(params)
    if err:
        return JSONResponse({"error": "invalid_request", "error_description": err},
                            status_code=400)
    return _render_consent(request, params)


async def authorize_post(request: Request) -> Response:
    form = await request.form()
    params = {k: str(form.get(k, "")) for k in _AUTH_FIELDS}
    err = _validate_authorize(params)
    if err:
        return JSONResponse({"error": "invalid_request", "error_description": err},
                            status_code=400)

    fhem_token = str(form.get("fhem_token", "")).strip()
    if not fhem_token:
        return _render_consent(request, params, "Bitte ein FHEM-Token eingeben.")

    # FHEM-Token gegen FHEM prüfen (ping verlangt nur read).
    try:
        await client.call(fhem_token, {"action": "ping"})
    except FhemError as e:
        return _render_consent(request, params,
                               f"FHEM lehnt das Token ab: {e} (Code {e.code}).")
    except Exception as e:  # Netzwerk/Proxy
        return _render_consent(request, params, f"FHEM nicht erreichbar: {e}")

    code = store.create_code(
        client_id=params["client_id"],
        redirect_uri=params["redirect_uri"],
        code_challenge=params["code_challenge"],
        fhem_token=fhem_token,
        scope=params.get("scope") or "fhem",
    )
    q = {"code": code}
    if params.get("state"):
        q["state"] = params["state"]
    sep = "&" if "?" in params["redirect_uri"] else "?"
    return RedirectResponse(params["redirect_uri"] + sep + urlencode(q), status_code=302)


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------
async def token(request: Request) -> Response:
    form = await request.form()
    grant_type = str(form.get("grant_type", ""))

    try:
        if grant_type == "authorization_code":
            ac = store.consume_code(
                code=str(form.get("code", "")),
                client_id=str(form.get("client_id", "")),
                redirect_uri=str(form.get("redirect_uri", "")),
                verifier=str(form.get("code_verifier", "")),
            )
            result = store.issue_tokens(ac.fhem_token, ac.scope)
        elif grant_type == "refresh_token":
            result = store.refresh_tokens(str(form.get("refresh_token", "")))
        else:
            raise OAuthError("unsupported_grant_type", f"grant_type '{grant_type}'")
    except OAuthError as e:
        return JSONResponse(
            {"error": e.error, "error_description": e.description},
            status_code=e.status,
            headers={"Cache-Control": "no-store"},
        )

    return JSONResponse(result, headers={"Cache-Control": "no-store"})
