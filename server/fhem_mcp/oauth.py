"""OAuth 2.1 Authorization Server für den FHEM-MCP-Server.

Macht den Server zu einem (kleinen, spec-konformen) Authorization Server, wie
ihn Claudes Custom-Connector erwartet: OAuth 2.1, PKCE (S256), Discovery über
RFC 9728 / RFC 8414 und Dynamic Client Registration (RFC 7591).

Authentifizierung des Nutzers im Consent-Schritt: Es wird ein in FHEM erzeugtes
Token (`set <mcp> grant <scope>`) abgefragt und gegen FHEM geprüft. Ist es
gültig, gibt der Server ein eigenes Access-Token aus, das intern auf genau
dieses FHEM-Token abgebildet wird. So bleibt FHEM die alleinige autorisierende
Instanz; der MCP-Server hält die Zuordnung nur flüchtig im Speicher.

Alle Stores sind in-memory: ein Neustart verwirft Clients/Codes/Tokens
(gewollt, passend zu den ephemeren FHEM-Tokens).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

# --- TTLs -------------------------------------------------------------------
AUTH_CODE_TTL = 300            # 5 min
ACCESS_TOKEN_TTL = 3600        # 1 h (FHEM erzwingt zusätzlich die Token-Gültigkeit)
REFRESH_TOKEN_TTL = 86400      # 24 h (Refresh klappt nur, solange das FHEM-Token gilt)


def _now() -> float:
    return time.time()


def _tok(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def verify_pkce(verifier: str, challenge: str) -> bool:
    """S256: base64url(sha256(verifier)) == challenge (ohne Padding)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(expected, challenge)


@dataclass
class Client:
    client_id: str
    redirect_uris: list[str]


@dataclass
class AuthCode:
    client_id: str
    redirect_uri: str
    code_challenge: str
    fhem_token: str
    scope: str
    expires_at: float


@dataclass
class Token:
    fhem_token: str
    scope: str
    expires_at: float


@dataclass
class OAuthStore:
    clients: dict[str, Client] = field(default_factory=dict)
    codes: dict[str, AuthCode] = field(default_factory=dict)
    access: dict[str, Token] = field(default_factory=dict)
    refresh: dict[str, Token] = field(default_factory=dict)

    # --- Dynamic Client Registration ---------------------------------------
    def register_client(self, redirect_uris: list[str]) -> Client:
        client = Client(client_id=_tok(16), redirect_uris=redirect_uris)
        self.clients[client.client_id] = client
        return client

    # --- Authorization code ------------------------------------------------
    def create_code(
        self, client_id: str, redirect_uri: str, code_challenge: str,
        fhem_token: str, scope: str,
    ) -> str:
        code = _tok()
        self.codes[code] = AuthCode(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            fhem_token=fhem_token,
            scope=scope,
            expires_at=_now() + AUTH_CODE_TTL,
        )
        return code

    def consume_code(
        self, code: str, client_id: str, redirect_uri: str, verifier: str,
    ) -> AuthCode:
        self._purge()
        ac = self.codes.get(code)
        if ac is None:
            raise OAuthError("invalid_grant", "unknown or expired code")
        # Code ist Einmalgebrauch
        del self.codes[code]
        if ac.client_id != client_id or ac.redirect_uri != redirect_uri:
            raise OAuthError("invalid_grant", "client/redirect mismatch")
        if not verify_pkce(verifier, ac.code_challenge):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        return ac

    # --- Token issuance ----------------------------------------------------
    def issue_tokens(self, fhem_token: str, scope: str) -> dict[str, Any]:
        at = _tok()
        rt = _tok()
        self.access[at] = Token(fhem_token, scope, _now() + ACCESS_TOKEN_TTL)
        self.refresh[rt] = Token(fhem_token, scope, _now() + REFRESH_TOKEN_TTL)
        return {
            "access_token": at,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "refresh_token": rt,
            "scope": scope,
        }

    def refresh_tokens(self, refresh_token: str) -> dict[str, Any]:
        self._purge()
        rt = self.refresh.get(refresh_token)
        if rt is None:
            raise OAuthError("invalid_grant", "unknown or expired refresh token")
        # Rotation: alten Refresh entwerten
        del self.refresh[refresh_token]
        return self.issue_tokens(rt.fhem_token, rt.scope)

    # --- Resource-Server-Seite ---------------------------------------------
    def resolve_access_token(self, access_token: str) -> str | None:
        """Access-Token -> zugrundeliegendes FHEM-Token (oder None)."""
        t = self.access.get(access_token)
        if t is None:
            return None
        if t.expires_at <= _now():
            del self.access[access_token]
            return None
        return t.fhem_token

    def _purge(self) -> None:
        now = _now()
        for store in (self.codes, self.access, self.refresh):
            for k in [k for k, v in store.items() if v.expires_at <= now]:
                del store[k]


class OAuthError(Exception):
    def __init__(self, error: str, description: str = "", status: int = 400) -> None:
        super().__init__(description or error)
        self.error = error
        self.description = description
        self.status = status


store = OAuthStore()
