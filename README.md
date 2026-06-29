# FHEM-MCP

Ein aus dem Internet erreichbarer **Model-Context-Protocol-Server für FHEM** –
damit Claude FHEM-Geräte lesen, steuern und (gegated) Konfiguration/Dateien
ändern kann. Die Autorisierung liegt **vollständig in FHEM** (Modul
`98_MCP.pm`); der Server reicht nur durch.

> **Status:** v0.1.0 – Grundgerüst. Auth über Bearer-Header (Claude Code).
> OAuth für die claude.ai-App ist als Ausbaustufe vorgesehen.

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

### 4. In Claude Code anbinden

```
# Token in FHEM erzeugen:
set mcp grant read 60          # bzw. write / admin

# Ausgegebenes Token eintragen:
claude mcp add --transport http fhem https://fhem-mcp.example.com/mcp \
  --header "Authorization: Bearer <token>"
```

Nach Ablauf (Default 1 h) erneut `set mcp grant …` und den Header aktualisieren.

---

## Komponenten

- `FHEM/98_MCP.pm` – Autorisierungs-Zentrale (Token, Scopes, Allowlists, Audit).
- `server/` – Python-MCP-Server (FastMCP, Streamable-HTTP), FHEMWEB-Client.
- `Dockerfile`, `docker-compose.yml`, `.env.example` – Deployment.
- `controls_MCP.txt` – FHEM-Update (per GitHub-Action gepflegt, nicht manuell).

---

## Lizenz

Das FHEM-Modul steht unter GPL v2 oder höher (wie FHEM).
