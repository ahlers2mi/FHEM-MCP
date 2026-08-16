# FHEM-MCP – Projektwissen

MCP-Server für FHEM: ein aus dem Internet erreichbarer Model-Context-Protocol-
Server, über den Claude (App, Claude Code, Open WebUI, VS Code) FHEM lesen und
steuern kann. Die **Autorisierung liegt vollständig in FHEM** (`98_MCP.pm`); der
Python-Server reicht das Token nur durch.

## Arbeitsweise (wichtig)

### Version bei jeder Änderung anheben – immer, ungefragt

Bei **jeder funktionalen Änderung** (Feature, Fix, Verhaltensänderung) die
Version anheben, ohne dass der Nutzer danach fragen muss. Nur bei reinen
Doku-/Kommentar-Änderungen kann sie stehen bleiben.

- **Patch** (0.4.0 → 0.4.1): Fehlerbehebungen, kleine Diagnose-Helfer.
- **Minor** (0.4.1 → 0.5.0): neues Tool, neues Attribut, neue Funktion.

**Alle vier Stellen** müssen zusammenpassen (sonst meldet `ping` eine andere
Version als das Gerät):

| Datei | Stelle |
|---|---|
| `FHEM/98_MCP.pm` | Kopfzeile `# Version:  v0.4.1` |
| `FHEM/98_MCP.pm` | `$hash->{FVERSION} = "98_MCP.pm:v0.4.1";` in `MCP_Define` |
| `FHEM/98_MCP.pm` | `version => "0.4.1"` in `MCP_ping` |
| `server/fhem_mcp/__init__.py` | `__version__` |
| `server/pyproject.toml` | `version` |

Danach `controls_MCP.txt` neu erzeugen (Größe muss exakt stimmen):

```bash
SIZE=$(wc -c < FHEM/98_MCP.pm); DATE=$(date -u +"%Y-%m-%d_%H:%M:%S")
echo "UPD ${DATE} ${SIZE} FHEM/98_MCP.pm" > controls_MCP.txt
```

Syntaxcheck des Moduls (FHEM-Globals fehlen standalone, daher `require`):

```bash
perl -e 'use strict; use warnings;
  use vars qw($readingFnAttributes $init_done %cmds %defs %attr $unicodeEncoding);
  require "./FHEM/98_MCP.pm"; print "ok\n";'
```

### Auslieferung über anonymous.4open.science

Das Repo ist privat, FHEM-`update` läuft daher über einen Anon-Spiegel.
**Der Spiegel schreibt `github.com`-URLs im Dateiinhalt um** (in seine eigene
Anon-URL). Dadurch wächst die `.pm` gegenüber der in `controls_MCP.txt`
vermerkten Größe und `update` bricht ab:

```
Got 29938 bytes for FHEM/98_MCP.pm, expected 29928 -> aborting.
```

Deshalb: **keine `github.com`-URL in `98_MCP.pm`** (auch nicht in der
commandref). Der Autorname o. Ä. wird *nicht* angetastet und ist unkritisch.

## Architektur

```
Claude → Reverse Proxy (Synology, TLS) → MCP-Container (Docker/Portainer)
      → FHEMWEB (abgeschottet) → 98_MCP.pm (Token, Allowlist, Audit)
```

Der Container ist der **einzige** Dienst nach außen; FHEMWEB nie direkt
exponieren.

### Zwei Auth-Wege

- **OAuth 2.1** (claude.ai-App/Desktop): der Server ist selbst ein kleiner
  Authorization-Server (Discovery, Dynamic Client Registration, PKCE S256). Die
  **Consent-Seite fragt das FHEM-Token ab** (`set mcp grant …`) und prüft es per
  `ping` gegen FHEM. FHEM bleibt die alleinige autorisierende Instanz.
- **Bearer-Header** (Claude Code, Open WebUI, VS Code): das FHEM-Token direkt als
  `Authorization: Bearer <token>`. Die Connector-UI der claude.ai-App kann
  **keinen** statischen Bearer-Token – dort geht nur OAuth.

## Token-Semantik (mehrfach Stolperstein gewesen)

- Gespeichert wird **nur der SHA-256-Hash**, nie der Klartext. Der Klartext wird
  bei `grant` **einmalig** ausgegeben und ist nicht erneut anzeigbar.
- **Abgelaufene Tokens werden bewusst NICHT gelöscht** – weder im Speicher noch
  im Keyvalue-Store. Grund: `set <name> extend <id|name>` reaktiviert sie, der
  **Token-String bleibt gleich**, ein verbundener Client muss sich also *nicht*
  neu einrichten. Genau das ist der Alltagsworkflow des Nutzers.
  Aufgeräumt wird ausschließlich explizit über `revokeExpired`.
  → Beim Ändern von Lade-/Speicherlogik: Speicher- und Store-Verhalten müssen
  **identisch** sein, sonst ist ein abgelaufenes Token nach dem Neustart weg.
- `attr persistTokens 1` legt die Hashes im FHEM-Keyvalue-Store ab
  (`setKeyValue`, **nicht** in `fhem.cfg` → kein Git-Leak).
- **Nie speichern, bevor geladen wurde** (`helper{tokensLoaded}`): sonst
  überschreibt ein früher Zugriff während des Starts den Store mit leer.
- Geladen wird über `NotifyFn` (`global:INITIALIZED`) **und** lazy bei jedem
  Zugriff (`MCP_ensureLoaded`), damit es nicht an einem Event hängt.
- `defaultTtl` 60 min ist für dauerhafte Clients zu kurz → in der Praxis
  `maxTtl`/`defaultTtl` hochsetzen.
- Diagnose bei Problemen: **`get <name> persistState`** (Attribut, Ladeflag,
  Store-Inhalt, Schreibtest) – erst messen, dann fixen.

## Allowlist

- Räume: `readRoom` (nur lesbar) / `writeRoom` (steuerbar), Default deny.
  Beim Nutzer: `readRoom *`, `writeRoom System->mcp_rw`.
- **`*`** als Raumname gibt alle Geräte frei. Das **MCP-Gerät selbst ist nie
  schreibbar** (sonst könnte man per `set_device` Tokens widerrufen).
- `define_device` legt neue Geräte automatisch in den `writeRoom`, sonst wäre das
  frisch angelegte Gerät sofort wieder außerhalb der Allowlist.
- `set_attribute room …` hängt den `writeRoom` automatisch an, damit sich ein
  Gerät nicht selbst aus der Allowlist wirft.
- Dateien einzeln über `allowFiles` (Glob `*` je Pfadsegment, kein `..`).
  `.pm` schreiben verlangt zusätzlich `admin` + `adminScopeAllowed=1` (= RCE).

## Fallstricke (real aufgetreten)

- **FHEMWEB-`widgetList` sendet komma-getrennt**: die GUI schickt
  `extend Claude-App,60` als *ein* Argument. `MCP_Set` zerlegt Argumente daher
  zusätzlich an Kommas (so macht es auch `53_mideaAC.pm`).
- **UTF-8 beim Schreiben**: der Python-Server muss
  `json.dumps(..., ensure_ascii=False)` nutzen. Mit `\uXXXX` dekodiert
  `from_json` zu Unicode-Zeichen, die im Byte-Modus-FHEM zu kaputten Einzelbytes
  werden (`ä` → `0xE4` statt `0xC3 0xA4`). Zusätzlich normalisiert
  `MCP_normReq` die dekodierten Strings (analog FHEM-DoRemote).
- **`reload 98_MCP` leert Modul-Variablen**: `$MCP_singleton` war danach undef →
  alle Aufrufe `no MCP device defined`. Fallback über `devspec2array("TYPE=MCP")`.
- **DNS-Rebinding-Schutz des MCP-SDK**: hinter dem Reverse Proxy kommt der
  öffentliche Host-Header an → `421 Misdirected Request`. Deshalb
  `transport_security` mit `enable_dns_rebinding_protection=False` sowie
  `json_response`/`stateless_http` (proxy-freundlich, kein SSE-Buffering).
- **`get_device` liefert `def` + Internals** – ohne die DEF kann ein Client
  notify/DOIF nicht umbauen und muss den Nutzer um `list <dev>` bitten.

## Deployment (Synology + Portainer)

- Reverse Proxy läuft auf dem **Host** → Port muss veröffentlicht werden:
  `ports: "127.0.0.1:${FHEMMCP_HOSTPORT:-8000}:8000"` (nur `expose` reicht
  nicht). An `127.0.0.1` gebunden, damit der Dienst nicht im LAN offen ist.
- **`pull_policy: build`** – das Image liegt in keiner Registry; ohne das
  scheitert der Redeploy mit `pull access denied`. In Portainer beim Update
  „Re-pull image" **nicht** anhaken.
- **Kein fester `container_name`**, sonst kollidiert ein zweiter Stack (der
  Nutzer betreibt Main und Solar parallel).
- `FHEMMCP_PUBLIC_URL` setzen, wenn der Proxy keine `X-Forwarded-*`-Header
  liefert (die OAuth-Discovery muss die externe URL nennen).
- Code-Änderungen am Server erfordern einen **Neubau** des Images; Änderungen am
  Modul nur `reload 98_MCP`. Bei kombinierten Änderungen (z. B. UTF-8-Fix)
  müssen **beide** aktualisiert werden.
