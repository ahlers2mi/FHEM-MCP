"""Konfiguration über Umgebungsvariablen (Docker/Portainer-freundlich)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="FHEMMCP_", env_file=".env")

    # Basis-URL der (abgeschotteten) FHEMWEB-Instanz, inkl. /fhem-Pfad.
    # Beispiel: http://fhem:8083/fhem  –  nur im internen Docker-Netz erreichbar.
    fhem_url: str = "http://fhem:8083/fhem"

    # Optionale HTTP-Basic-Auth der FHEMWEB-Instanz (empfohlen).
    fhem_user: str | None = None
    fhem_password: str | None = None

    # TLS, falls FHEMWEB per https läuft.
    fhem_verify_tls: bool = True
    fhem_ca_file: str | None = None

    # Timeout für FHEM-Aufrufe (Sekunden).
    request_timeout: float = 15.0

    # Bind-Adresse des MCP-Servers (hinter dem Reverse Proxy).
    host: str = "0.0.0.0"
    port: int = 8000

    # Streamable-HTTP-Pfad, unter dem der MCP-Endpunkt erreichbar ist.
    mcp_path: str = "/mcp"


settings = Settings()
