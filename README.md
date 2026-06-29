# FHEM-MCP

Ein aus dem Internet erreichbarer **Model-Context-Protocol-Server für FHEM** –
damit Claude FHEM-Geräte lesen, steuern und (gegated) Konfiguration/Dateien
ändern kann. Die Autorisierung liegt **vollständig in FHEM** (Modul
`98_MCP.pm`); der Server reicht nur durch.

> **Status:** v0.2.0 – zwei Auth-Wege werden unterstützt:
> **Bearer-Header** (Claude Code) und **OAuth 2.1** (claude.ai-App/Desktop als
> Custom Connector).

---

## Architektur

```
Claude (Claude Code)
   │  HTTPS, Streamable-HTTP MCP, Authorization: Bearer <token>
   ▼
Reverse Proxy (TLS, auf der NAS)          ← einziger Punkt aus dem Internet
   ▼
MCP-Server (Docker/Portainer)             ← stateless bzgl. Autorisierung
   │  reicht das Bearer-Token pro Aufruf an FHEM durch
   ▼  HTTP, nur im internen Docker-Netz
FHEMWEB (eigene, abgeschottete Instanz)   ← basicAuth, allowedCommands=mcp
   ▼
98_MCP.pm                                 ← die Sicherheits-Zentrale
   - Token prüfen (Hash, Ablauf, Scope)
   - Geräte-Allowlist (Räume MCP / MCP_rw)
   - Datei-Allowlist (allowFiles)
   - Aktion ausführen + Audit-Log
```

**Kernprinzip:** FHEM ist die einzige Stelle, die autorisiert. Ein
kompromittierter MCP-Container kann nichts, was Token + Allowlist nicht
ohnehin erlauben.

---

## Sicherheitsmodell

| Schicht | Maßnahme |
|---|---|
| Transport | Nur der MCP-Container ist im Internet erreichbar (Reverse Proxy, TLS). **Niemals FHEMWEB direkt exponieren.** |
| Server-Zugang | Bearer-Token bei jedem Aufruf nötig (von Claude Code gesendet). |
| Consent / Ablauf | Token wird **in FHEM von Hand erzeugt** (`set <mcp> grant`) und ist standardmäßig 1 h gültig → kein Dauerzugriff. |
| Token-Speicherung | Nur als **SHA-256-Hash** und **nur im RAM**. Landet weder in `fhem.cfg`/Statefile noch im Git. FHEM-Neustart verwirft alle Tokens. |
| Scopes | `read` (lesen) · `write` (set/attr/setreading + CSS/JS schreiben) · `admin` (define/modify + `.pm` schreiben). |
| Geräte-Allowlist | Raum `MCP` = nur lesbar, Raum `MCP_rw` = steuerbar (Default deny). |
| Datei-Allowlist | Attribut `allowFiles`, jede Datei einzeln freigeben; `..`/absolute Pfade gesperrt. |
| Kein Generik-Tool | Kein „beliebigen FHEM-Befehl ausführen". Nur strukturierte, geprüfte Aktionen; Injection-Zeichen werden abgewiesen. |
| RCE-Schutz | `define`/`modify` und `.pm`-Schreiben hängen am `admin`-Scope **und** `adminScopeAllowed=1` **und** einem best-effort Pattern-Filter. |
| Audit | Jede Aktion → FHEM-Log + Reading `lastAction`. Not-Aus: `set <mcp> revoke`. |

> **Restrisiko `admin`:** define/modify/`.pm` sind effektiv volle Kontrolle
> über FHEM (Perl-/Shell-Blöcke). Den admin-Scope nur kurz und bewusst
> vergeben; `adminScopeAllowed` standardmäßig auf 0 lassen.

---

## Verfügbare MCP-Tools

| Tool | Scope | Beschreibung |
|---|---|---|
| `ping` | read | Verbindung/Token prüfen |
| `list_devices(type?)` | read | Freigegebene Geräte (Räume MCP/MCP_rw) |
| `get_device(name)` | read | Readings, Attribute, State, mögliche set-Befehle |
| `set_device(name, command, args?)` | write | `set <name> <command> [args]` (nur MCP_rw) |
| `set_attribute(device, attribute, value)` | write | `attr …` (nur MCP_rw, außer `room`) |
| `set_reading(device, reading, value)` | write | `setreading …` |
| `delete_reading(device, reading)` | write | `deletereading …` |
| `list_files()` | read | Freigegebene Dateien (`allowFiles`) |
| `read_file(path)` | read | Datei lesen |
| `write_file(path, content)` | write¹ | Datei schreiben (¹`.pm` ⇒ admin) |
| `define_device(device, definition)` | admin | `defmod …` |
| `modify_device(device, definition)` | admin | `modify …` |

---

## Installation

### 1. FHEM-Modul

```
update add https://raw.githubusercontent.com/ahlers2mi/FHEM-MCP/main/controls_MCP.txt
update
```

oder manuell `FHEM/98_MCP.pm` nach `/opt/fhem/FHEM/` kopieren, dann `reload 98_MCP`.

Anschließend in FHEM:

```
define mcp MCP
attr mcp defaultTtl 60
# Geräte freigeben: in den Raum legen
attr Lampe_Wohnzimmer room MCP_rw     # lesbar + steuerbar
attr Aussentemperatur room MCP        # nur lesbar
# Dateien freigeben (optional)
attr mcp allowFiles www/pgm2/mystyle.css
```

### 2. Abgeschottete FHEMWEB-Instanz für den MCP-Server (empfohlen)

```
define WEBmcp FHEMWEB 8083 global
attr WEBmcp basicAuth <base64(user:pass)>
define allowedMCP allowed
attr allowedMCP validFor WEBmcp
attr allowedMCP allowedCommands mcp
attr allowedMCP basicAuth <base64(user:pass)>
```

Diese Instanz nur im internen Docker-/LAN-Netz erreichbar machen.

### 3. MCP-Server (Docker/Portainer)

`.env.example` → `.env` kopieren und anpassen, dann als Portainer-Stack
(`docker-compose.yml`) deployen. Den Reverse Proxy auf den Container
(`fhem-mcp:8000`, Pfad `/mcp`) zeigen lassen – **nicht** auf FHEMWEB.

### 4a. Anbinden über Claude Code (Bearer-Header)

```
# Token in FHEM erzeugen:
set mcp grant read 60          # bzw. write / admin

# Ausgegebenes Token eintragen:
claude mcp add --transport http fhem https://fhem-mcp.example.com/mcp \
  --header "Authorization: Bearer <token>"
```

Nach Ablauf (Default 1 h) erneut `set mcp grant …` und den Header aktualisieren.

### 4b. Anbinden über die claude.ai-App / Desktop (OAuth)

Voraussetzung: `FHEMMCP_OAUTH_ENABLED=true` (Default) und – falls der Reverse
Proxy keine korrekten `X-Forwarded-*`-Header setzt – `FHEMMCP_PUBLIC_URL` auf die
externe URL.

1. In der App einen **Custom Connector** mit der MCP-URL anlegen
   (`https://fhem-mcp.example.com/mcp`).
2. Die App startet automatisch den OAuth-Flow (Discovery, Dynamic Client
   Registration, PKCE) und öffnet die **Consent-Seite** des Servers.
3. Dort das in FHEM erzeugte Token (`set mcp grant read`) einfügen → der Server
   prüft es gegen FHEM und stellt ein Access-Token aus.

Der Server implementiert dafür einen kleinen OAuth-2.1-Authorization-Server
(`/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`,
`/register`, `/authorize`, `/token`). FHEM bleibt die alleinige autorisierende
Instanz – das Access-Token wird intern nur auf das FHEM-Token abgebildet.

### 4c. Anbinden über VS Code mit GitHub Copilot Chat (MCP)

VS Code ab Version 1.99 mit der GitHub-Copilot-Erweiterung unterstützt
MCP-Server direkt im Editor. Die Konfiguration erfolgt über eine
workspace-lokale Datei `.vscode/mcp.json`.

> **Hinweis:** Dieser Weg funktioniert nur für **lokale VS-Code-Clients**.
> **GitHub.com Copilot Chat** im Browser unterstützt keine direkte Verbindung
> zu externen MCP-Endpunkten – eine URL in `.github/copilot-setup-steps.yml`
> genügt dafür nicht.

**Voraussetzungen:**

- VS Code ≥ 1.99
- GitHub-Copilot-Erweiterung (aktuelle Version)
- VS-Code-Einstellung `chat.mcp.enabled: true` (Standardmäßig aktiviert ab 1.99)

**Schritt-für-Schritt:**

1. Token in FHEM erzeugen:

   ```
   set mcp grant read 60    # oder write / admin
   ```

2. Die mitgelieferte Vorlage `.vscode/mcp.json` in deinen Workspace kopieren
   und die URL anpassen (Token wird beim ersten Verbindungsaufbau von VS Code
   abgefragt und sicher gespeichert):

   ```json
   {
     "servers": {
       "fhem": {
         "type": "http",
         "url": "https://fhem-mcp.example.com/mcp",
         "headers": {
           "Authorization": "Bearer ${input:fhemToken}"
         }
       }
     },
     "inputs": [
       {
         "id": "fhemToken",
         "type": "promptString",
         "description": "FHEM MCP Token (in FHEM: set mcp grant read)",
         "password": true
       }
     ]
   }
   ```

3. VS Code lädt die Konfiguration automatisch. Den Server in der Copilot-Chat-
   Seitenleiste unter **Tools** aktivieren.

4. Im Copilot-Chat stehen jetzt FHEM-Tools wie `ping`, `list_devices` und
   `get_device` zur Verfügung.

---

## Komponenten

- `FHEM/98_MCP.pm` – Autorisierungs-Zentrale (Token, Scopes, Allowlists, Audit).
- `server/` – Python-MCP-Server (FastMCP, Streamable-HTTP), FHEMWEB-Client.
- `Dockerfile`, `docker-compose.yml`, `.env.example` – Deployment.
- `.vscode/mcp.json` – Vorlage für VS Code Copilot Chat (MCP-Konfiguration, URL anpassen).
- `controls_MCP.txt` – FHEM-Update (per GitHub-Action gepflegt, nicht manuell).

---

## Lizenz

Das FHEM-Modul steht unter GPL v2 oder höher (wie FHEM).
