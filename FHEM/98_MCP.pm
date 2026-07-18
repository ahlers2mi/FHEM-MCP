##############################################################################
# 98_MCP.pm
#
# FHEM-seitige Autorisierungs-Zentrale fuer den FHEM-MCP-Server.
#
# Der MCP-Server (Docker/Portainer, im Internet erreichbar) haelt KEINE
# Berechtigungen. Er reicht das vom Client (Claude) mitgeschickte Bearer-Token
# bei jedem Aufruf an FHEM durch. Dieses Modul entscheidet allein, ob eine
# Aktion erlaubt ist:
#
#   * Token-Pruefung   - gueltig? abgelaufen? ausreichender Scope?
#   * Geraete-Allowlist - liegt das Geraet im Lese-/Schreib-Raum?
#   * Aktion ausfuehren - read / set / attr / define / modify im erlaubten Rahmen
#   * Audit-Log         - jede Aktion wird protokolliert
#
# Sicherheits-Eckpunkte:
#   * Tokens werden NUR als SHA-256-Hash und NUR im Speicher gehalten
#     ($hash->{helper}{tokens}). Sie landen weder in der fhem.cfg noch im
#     Statefile - also auch nicht im (auto-gepushten) Git-Repo. Bei einem
#     FHEM-Neustart sind alle Tokens weg (gewollt: ephemere 1-h-Grants).
#   * Es gibt KEIN generisches "fuehre beliebigen FHEM-Befehl aus"-Tool.
#     Nur strukturierte, gepruefte Aktionen.
#   * define/modify sind effektiv RCE (Perl-/Shell-Bloecke). Sie verlangen
#     den getrennten admin-Scope UND das Attribut adminScopeAllowed=1 UND
#     passieren einen (best-effort) Pattern-Filter. Restrisiko bleibt -
#     admin-Token nur kurz und bewusst vergeben.
#
# Kommando fuer den MCP-Server:
#   mcp <token> <base64(json)>
#   -> liefert eine JSON-Antwort. In FHEMWEB sollte dieses Kommando per
#      eigenem, eingeschraenktem WEB-Zugang (allowed/allowedCommands) nur dem
#      MCP-Container erlaubt werden.
#
# Autor:    ahlers2mi
# Version:  v0.2.0
# Lizenz:   GPL v2 oder hoeher (wie FHEM)
##############################################################################

package main;

use strict;
use warnings;

use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA  qw(sha256_hex);
use JSON;
use Encode ();

use vars qw($readingFnAttributes $init_done %cmds %defs %attr $unicodeEncoding);

# Scope-Hierarchie (kumulativ): admin schliesst write ein, write schliesst
# read ein.
my %MCP_scopeLevel = ( read => 1, write => 2, admin => 3 );

# Welcher Scope wird je Aktion mindestens gebraucht?
my %MCP_actionLevel = (
    ping          => 1,
    list_devices  => 1,
    get_device    => 1,
    set_device    => 2,
    set_attribute => 2,
    set_reading   => 2,
    delete_reading=> 2,
    list_files    => 1,
    read_file     => 1,
    search_log    => 1,
    write_file    => 2,   # .pm-Dateien verlangen zusaetzlich admin (s. MCP_writeFile)
    define_device => 3,
    modify_device => 3,
);

# Singleton-Name merken, damit das Kommando "mcp" das zustaendige Geraet
# findet (es gibt sinnvollerweise nur eines).
my $MCP_singleton;

# ----------------------------------------------------------------------------
# MCP_Initialize
# ----------------------------------------------------------------------------
sub MCP_Initialize {
    my ($hash) = @_;

    $hash->{DefFn}   = \&MCP_Define;
    $hash->{UndefFn} = \&MCP_Undef;
    $hash->{SetFn}   = \&MCP_Set;
    $hash->{GetFn}   = \&MCP_Get;
    $hash->{AttrFn}  = \&MCP_Attr;

    $hash->{AttrList} =
          "disable:1,0 " .
          "readRoom " .            # Raumname fuer NUR-lesbar (Default MCP)
          "writeRoom " .           # Raumname fuer steuerbar  (Default MCP_rw)
          "allowFiles:textField-long " . # einzeln freigegebene Dateien (eine pro Zeile, *-Glob)
          "logFile " .             # alternatives Logfile fuer search_log (Default: global logfile)
          "defaultTtl " .          # Default-Gueltigkeit eines Grants in Minuten (60)
          "maxTtl " .              # Obergrenze fuer ttl in Minuten (1440)
          "adminScopeAllowed:1,0 " . # define/modify global erlauben (Default 0)
          "adminDenyPattern:textField-long " . # Regex, der define/modify ablehnt
          $readingFnAttributes;

    # FHEM-Kommando "mcp" registrieren. Der MCP-Server ruft es ueber FHEMWEB
    # auf: ?cmd=mcp <token> <base64-json>
    $cmds{mcp} = {
        Fn  => "MCP_command",
        Hlp => "<token> <base64-json>,interne Schnittstelle fuer den MCP-Server",
    };
}

# ----------------------------------------------------------------------------
# MCP_Define   "define <name> MCP"
# ----------------------------------------------------------------------------
sub MCP_Define {
    my ($hash, $def) = @_;
    my @param = split('[ \t]+', $def);

    $hash->{FVERSION} = "98_MCP.pm:v0.2.0";

    return "Usage: define <name> MCP" if(int(@param) != 2);

    $hash->{helper}{tokens} = {} if(!defined($hash->{helper}{tokens}));
    $MCP_singleton = $hash->{NAME};

    readingsBeginUpdate($hash);
    readingsBulkUpdateIfChanged($hash, "state",       "active");
    readingsBulkUpdateIfChanged($hash, "activeTokens", 0);
    readingsEndUpdate($hash, 0);

    return undef;
}

sub MCP_Undef {
    my ($hash, $name) = @_;
    $MCP_singleton = undef if(defined($MCP_singleton) && $MCP_singleton eq $name);
    return undef;
}

# ----------------------------------------------------------------------------
# MCP_Set
#   grant <scope> [ttlMinutes]  -> erzeugt ein Token, gibt es EINMAL zurueck
#   revoke                      -> alle Tokens sofort ungueltig
#   revokeExpired               -> abgelaufene Tokens aufraeumen
# ----------------------------------------------------------------------------
sub MCP_Set {
    my ($hash, $name, $cmd, @args) = @_;
    return "\"set $name\" needs at least one argument" if(!defined($cmd));

    # FHEMWEB fuegt die Werte eines widgetList-Widgets mit Komma zu EINEM
    # Argument zusammen (die GUI sendet z. B. "extend Claude-App,60"). Argumente
    # daher zusaetzlich an Kommas zerlegen - so funktionieren GUI und
    # Kommandozeile gleich (Namen/Scopes/ttl enthalten ohnehin keine Kommas).
    @args = grep { defined($_) && $_ ne "" } map { split(/,/, $_) } @args;

    # Set-Widgets fuer die FHEMWEB-Detailseite. widgetList kombiniert mehrere
    # Eingaben in EINEM Befehl:
    #   grant  = Scope-Dropdown + ttl-Dropdown + Namens-Textfeld
    #   extend = Dropdown (Name bzw. id) + ttl-Dropdown
    #   revoke = Dropdown (all + Name bzw. id)
    # Die Zahl vor jedem Teil-Widget = Anzahl der dazugehoerigen Tokens
    # (Widgetname + Optionen), genau wie bei setList eines Klimageraets.
    # Auswahlwert je Token: bevorzugt der Name (wenn gesetzt UND eindeutig),
    # sonst die id - so bleibt die Auswahl eindeutig und ohne Leerzeichen.
    # extend/revoke akzeptieren beides.
    my $toks = $hash->{helper}{tokens};
    my @keys = sort { ($toks->{$a}{issued} // 0) <=> ($toks->{$b}{issued} // 0) }
               keys %$toks;
    my %namecount;
    $namecount{ $toks->{$_}{name} }++ foreach grep { ($toks->{$_}{name} // "") ne "" } @keys;
    my @sel = grep { defined($_) && /^[\w.\-]+$/ }
              map {
                  my $t = $toks->{$_};
                  (defined($t->{name}) && $t->{name} ne "" && ($namecount{$t->{name}} // 0) == 1)
                      ? $t->{name} : $t->{id}
              } @keys;

    my $ttlW    = "6,select,60,120,240,720,1440";        # 1 (select) + 5 Werte
    my $grantW  = "grant:widgetList,4,select,read,write,admin,$ttlW,1,textField";
    my $extendW = @sel
        ? "extend:widgetList," . (1 + scalar(@sel)) . ",select," . join(",", @sel) . ",$ttlW"
        : "extend:textField";
    my $revokeW = @sel
        ? "revoke:select,all," . join(",", @sel)
        : "revoke:textField";

    my $list = "$grantW $extendW $revokeW revokeExpired:noArg";

    if($cmd eq "grant") {
        my $scope = shift(@args) // "read";
        return "unknown scope '$scope', choose read|write|admin"
            if(!$MCP_scopeLevel{$scope});

        if($scope eq "admin" && !AttrVal($name, "adminScopeAllowed", 0)) {
            return "admin scope is disabled. Set 'attr $name adminScopeAllowed 1' ".
                   "first (enables define/modify = full control - use briefly!).";
        }

        # restliche Argumente: erste reine Zahl = ttl (Minuten), Rest = Name.
        my $maxTtl = AttrVal($name, "maxTtl", 1440);
        my ($ttl, @nameparts);
        foreach my $a (@args) {
            if(!defined($ttl) && $a =~ /^\d+$/) { $ttl = $a; }
            else                                { push @nameparts, $a; }
        }
        $ttl = AttrVal($name, "defaultTtl", 60) if(!defined($ttl));
        $ttl = $maxTtl if($ttl > $maxTtl);
        $ttl = 1       if($ttl < 1);
        # Name als einzelnes Auswahl-Token nutzbar machen: Leer-/Sonderzeichen
        # zu '-' (damit er im FHEMWEB-select-Widget und als Argument funktioniert).
        my $tname = join("-", @nameparts);
        $tname =~ s/[^\w.\-]+/-/g;
        $tname =~ s/^-+|-+$//g;

        my $token = MCP_randToken();
        my $id    = MCP_shortId($hash);
        my $exp   = time() + $ttl * 60;
        $hash->{helper}{tokens}{ sha256_hex($token) } = {
            id     => $id,
            name   => $tname,
            scope  => $scope,
            exp    => $exp,
            issued => time(),
        };

        MCP_refreshCount($hash);
        readingsSingleUpdate($hash, "lastGrant",
            FmtDateTime(time())." id=$id".($tname ne "" ? " name=$tname" : "").
            " scope=$scope ttl=${ttl}min", 1);
        Log3($name, 3, "$name: granted token id=$id".($tname ne "" ? " name=$tname" : "").
                       " scope=$scope ttl=${ttl}min (expires ".FmtDateTime($exp).")");

        # Das Klartext-Token wird genau hier EINMAL ausgegeben. Es wird nirgends
        # gespeichert - danach nur noch sein Hash (Klartext nicht wieder zeigbar).
        return
            "Token  (id=$id".($tname ne "" ? ", name='$tname'" : "").
            ", scope=$scope, gueltig ${ttl} min, laeuft ".FmtDateTime($exp)." ab):\n\n".
            "$token\n\n".
            "Verlaengern (Token bleibt gueltig, kein Neu-Verbinden noetig):\n".
            "  set $name extend $id [minuten]\n".
            "Liste/Status:  get $name tokens\n".
            "Dieses Token wird NICHT erneut angezeigt.";
    }

    if($cmd eq "extend") {
        my $sel = shift(@args);
        return "usage: set $name extend <id|name> [minuten]"
            if(!defined($sel) || $sel eq "");
        my $maxTtl = AttrVal($name, "maxTtl", 1440);
        my $ttl    = shift(@args);
        $ttl = AttrVal($name, "defaultTtl", 60) if(!defined($ttl) || $ttl !~ /^\d+$/);
        $ttl = $maxTtl if($ttl > $maxTtl);
        $ttl = 1       if($ttl < 1);

        my @h = MCP_findTokenHashes($hash, $sel);
        return "kein Token mit id/name '$sel' (siehe: get $name tokens)" if(!@h);
        return "'$sel' passt auf ".scalar(@h)." Tokens - bitte die id verwenden ".
               "(get $name tokens)" if(@h > 1);

        my $exp = time() + $ttl * 60;
        $hash->{helper}{tokens}{$h[0]}{exp} = $exp;
        MCP_refreshCount($hash);
        Log3($name, 3, "$name: extended token '$sel' by ${ttl}min");
        return "Token '$sel' verlaengert: laeuft jetzt ".FmtDateTime($exp).
               " ab (${ttl} min).";
    }

    if($cmd eq "revoke") {
        my $sel = shift(@args);
        if(!defined($sel) || $sel eq "" || lc($sel) eq "all") {
            my $n = scalar(keys %{$hash->{helper}{tokens}});
            $hash->{helper}{tokens} = {};
            MCP_refreshCount($hash);
            Log3($name, 3, "$name: revoked all tokens ($n)");
            return "$n Token(s) widerrufen.";
        }
        my @h = MCP_findTokenHashes($hash, $sel);
        return "kein Token mit id/name '$sel'" if(!@h);
        delete $hash->{helper}{tokens}{$_} foreach (@h);
        MCP_refreshCount($hash);
        Log3($name, 3, "$name: revoked ".scalar(@h)." token(s) '$sel'");
        return scalar(@h)." Token(s) zu '$sel' widerrufen.";
    }

    if($cmd eq "revokeExpired") {
        my $n = MCP_purgeExpired($hash);
        MCP_refreshCount($hash);
        return "$n abgelaufene(s) Token entfernt.";
    }

    return "Unknown argument $cmd, choose one of $list";
}

# ----------------------------------------------------------------------------
# MCP_Attr  - validiert Schalter/Zahlen
# ----------------------------------------------------------------------------
sub MCP_Attr {
    my ($cmd, $name, $attrName, $attrValue) = @_;

    if($cmd eq "set" && ($attrName eq "disable" || $attrName eq "adminScopeAllowed")) {
        return "Invalid value $attrValue for $attrName. Must be 0 or 1."
            if($attrValue !~ /^[01]$/);
    }
    if($cmd eq "set" && ($attrName eq "defaultTtl" || $attrName eq "maxTtl")) {
        return "Invalid value $attrValue for $attrName. Must be a positive integer (minutes)."
            if($attrValue !~ /^\d+$/ || $attrValue < 1);
    }
    if($cmd eq "set" && $attrName eq "adminDenyPattern") {
        my $ok = eval { qr/$attrValue/; 1 };
        return "adminDenyPattern is not a valid regex: $@" if(!$ok);
    }
    return undef;
}

# ============================================================================
# Token-Helfer
# ============================================================================

# Kryptografisch zufaelliges Token (32 Byte) als base64url-String.
sub MCP_randToken {
    my $bytes;
    if(open(my $fh, "<", "/dev/urandom")) {
        binmode($fh);
        read($fh, $bytes, 32);
        close($fh);
    }
    if(!defined($bytes) || length($bytes) < 32) {
        # Fallback (sollte auf Linux nie noetig sein).
        $bytes = "";
        $bytes .= pack("N", int(rand(2**32))) for(1..8);
    }
    my $tok = encode_base64($bytes, "");
    $tok =~ tr{+/}{-_};      # base64url
    $tok =~ s/=+$//;
    return $tok;
}

# Zaehlt nur aktive (nicht abgelaufene) Tokens. Abgelaufene werden NICHT
# geloescht, damit sie per "extend" reaktiviert werden koennen (Aufraeumen
# explizit ueber "revokeExpired").
sub MCP_refreshCount {
    my ($hash) = @_;
    my $now = time();
    my $n = scalar grep { $hash->{helper}{tokens}{$_}{exp} > $now }
                   keys %{$hash->{helper}{tokens}};
    readingsSingleUpdate($hash, "activeTokens", $n, 1);
    return $n;
}

# Token-Hashes finden, deren id ODER name dem Selektor entspricht.
sub MCP_findTokenHashes {
    my ($hash, $sel) = @_;
    my @h;
    foreach my $k (keys %{$hash->{helper}{tokens}}) {
        my $t = $hash->{helper}{tokens}{$k};
        push @h, $k if(($t->{id} // "") eq $sel || ($t->{name} // "") eq $sel);
    }
    return @h;
}

# Kurze, eindeutige id (6 hex) fuer Anzeige/extend/revoke.
sub MCP_shortId {
    my ($hash) = @_;
    my %used = map { ($hash->{helper}{tokens}{$_}{id} // "") => 1 }
               keys %{$hash->{helper}{tokens}};
    foreach my $try (1..50) {
        my $bytes;
        if(open(my $fh, "<", "/dev/urandom")) {
            binmode($fh); read($fh, $bytes, 3); close($fh);
        }
        my $id = (defined($bytes) && length($bytes) == 3)
                   ? unpack("H6", $bytes)
                   : sprintf("%06x", int(rand(2**24)));
        return $id if(!$used{$id});
    }
    return sprintf("%06x", int(rand(2**24)));
}

sub MCP_purgeExpired {
    my ($hash) = @_;
    my $now = time();
    my $n = 0;
    foreach my $h (keys %{$hash->{helper}{tokens}}) {
        if($hash->{helper}{tokens}{$h}{exp} <= $now) {
            delete $hash->{helper}{tokens}{$h};
            $n++;
        }
    }
    return $n;
}

# Token pruefen -> liefert das Scope-Level (Zahl) oder undef.
sub MCP_tokenLevel {
    my ($hash, $token) = @_;
    return undef if(!defined($token) || $token eq "");
    my $h = sha256_hex($token);
    my $t = $hash->{helper}{tokens}{$h};
    return undef if(!$t);
    # Abgelaufenes Token nicht loeschen (extend soll es reaktivieren koennen),
    # nur als ungueltig behandeln.
    return undef if($t->{exp} <= time());
    return $MCP_scopeLevel{ $t->{scope} };
}

# ----------------------------------------------------------------------------
# MCP_Get  - get <name> tokens : Liste der Tokens (ohne Klartext)
# ----------------------------------------------------------------------------
sub MCP_Get {
    my ($hash, $name, $cmd, @args) = @_;
    return "\"get $name\" needs at least one argument" if(!defined($cmd));
    return MCP_tokenTable($hash) if($cmd eq "tokens");
    return "Unknown argument $cmd, choose one of tokens:noArg";
}

# Texttabelle aller Tokens (Klartext ist nicht gespeichert und nicht zeigbar).
sub MCP_tokenTable {
    my ($hash) = @_;
    my $toks = $hash->{helper}{tokens};
    my $now  = time();
    my @keys = sort { ($toks->{$a}{issued} // 0) <=> ($toks->{$b}{issued} // 0) }
               keys %$toks;
    return "Keine Tokens vorhanden." if(!@keys);

    my $fmt = "%-8s %-18s %-6s %-19s %s";
    my @rows = sprintf($fmt, "id", "name", "scope", "laeuft ab", "status");
    push @rows, "-" x 72;
    foreach my $k (@keys) {
        my $t   = $toks->{$k};
        my $rem = int(($t->{exp} - $now) / 60);
        my $status = $rem > 0 ? "aktiv (${rem} min)" : "ABGELAUFEN";
        push @rows, sprintf($fmt,
            $t->{id} // "-",
            (defined($t->{name}) && $t->{name} ne "") ? $t->{name} : "-",
            $t->{scope} // "-",
            FmtDateTime($t->{exp}),
            $status);
    }
    return join("\n", @rows);
}

# ============================================================================
# Allowlist-Helfer (Raeume)
# ============================================================================

sub MCP_readRoom  { return AttrVal($_[0], "readRoom",  "MCP");    }
sub MCP_writeRoom { return AttrVal($_[0], "writeRoom", "MCP_rw"); }

sub MCP_devRooms {
    my ($dev) = @_;
    return () if(!defined($defs{$dev}));
    return grep { /\S/ } split(/\s*,\s*/, AttrVal($dev, "room", ""));
}

# darf das Geraet gelesen werden? (liegt im Lese- ODER Schreib-Raum)
sub MCP_canRead {
    my ($name, $dev) = @_;
    my %r = map { $_ => 1 } MCP_devRooms($dev);
    return ($r{ MCP_readRoom($name) } || $r{ MCP_writeRoom($name) }) ? 1 : 0;
}

# darf das Geraet geschrieben werden? (liegt im Schreib-Raum)
sub MCP_canWrite {
    my ($name, $dev) = @_;
    my %r = map { $_ => 1 } MCP_devRooms($dev);
    return $r{ MCP_writeRoom($name) } ? 1 : 0;
}

# ============================================================================
# Kommando-Schnittstelle:  mcp <token> <base64(json)>
# ============================================================================
sub MCP_command {
    my ($cl, $param) = @_;

    my $name = $MCP_singleton;
    return MCP_err("no MCP device defined") if(!defined($name) || !$defs{$name});
    my $hash = $defs{$name};

    return MCP_err("disabled") if(IsDisabled($name));

    $param = "" if(!defined($param));
    my ($token, $b64) = split(/\s+/, $param, 2);
    return MCP_err("usage: mcp <token> <base64-json>") if(!defined($b64) || $b64 eq "");

    # Payload dekodieren
    my $json = eval { decode_base64($b64) };
    return MCP_err("base64 decode failed") if(!defined($json) || $json eq "");
    my $req = eval { from_json($json) };
    return MCP_err("json parse failed") if($@ || ref($req) ne "HASH");

    # UTF-8 normalisieren (wie in FHEM-DoRemote): from_json liefert die UTF-8-
    # Oktette utf8-geflaggt zurueck. Im Byte-Modus muss das Flag weg (sonst
    # laufen length/syswrite auseinander -> kaputte Umlaute), im Unicode-Modus
    # werden die Oktette zu Zeichen dekodiert.
    MCP_normReq($req);

    my $action = $req->{action} // "";
    my $need   = $MCP_actionLevel{$action};
    return MCP_err("unknown action '$action'") if(!defined($need));

    # Token / Scope pruefen
    my $level = MCP_tokenLevel($hash, $token);
    return MCP_err("invalid or expired token", 401) if(!defined($level));
    return MCP_err("insufficient scope for '$action'", 403) if($level < $need);

    # Audit-Log (Token wird NICHT geloggt)
    my $dev = $req->{device} // "";
    Log3($name, 3, "$name: action=$action device=$dev");
    readingsSingleUpdate($hash, "lastAction",
        FmtDateTime(time())." $action".($dev ? " $dev" : ""), 1);

    my $res = eval { MCP_dispatch($hash, $name, $action, $req, $level) };
    if($@) {
        Log3($name, 2, "$name: action=$action failed: $@");
        return MCP_err("internal error: $@");
    }
    return $res;
}

sub MCP_dispatch {
    my ($hash, $name, $action, $req, $level) = @_;

    return MCP_ping()                       if($action eq "ping");
    return MCP_listDevices($name, $req)     if($action eq "list_devices");
    return MCP_getDevice($name, $req)       if($action eq "get_device");
    return MCP_setDevice($name, $req)       if($action eq "set_device");
    return MCP_setAttribute($name, $req)    if($action eq "set_attribute");
    return MCP_setReading($name, $req)      if($action eq "set_reading");
    return MCP_deleteReading($name, $req)   if($action eq "delete_reading");
    return MCP_listFiles($name, $req)       if($action eq "list_files");
    return MCP_readFile($name, $req)        if($action eq "read_file");
    return MCP_searchLog($name, $req)       if($action eq "search_log");
    return MCP_writeFile($name, $req, $level) if($action eq "write_file");
    return MCP_defineDevice($name, $req)    if($action eq "define_device");
    return MCP_modifyDevice($name, $req)    if($action eq "modify_device");

    return MCP_err("unhandled action '$action'");
}

# ----------------------------------------------------------------------------
# Aktionen
# ----------------------------------------------------------------------------
sub MCP_ping {
    return MCP_ok({ pong => 1, version => "0.1.0" });
}

sub MCP_listDevices {
    my ($name, $req) = @_;

    my $readRoom  = MCP_readRoom($name);
    my $writeRoom = MCP_writeRoom($name);

    my %seen;
    my @devs = grep { !$seen{$_}++ }
               (devspec2array("room=$readRoom"), devspec2array("room=$writeRoom"));

    # optionaler Typ-Filter
    my $typeFilter = $req->{type};

    my @out;
    foreach my $d (@devs) {
        next if(!defined($defs{$d}));
        my $type = $defs{$d}{TYPE} // "";
        next if(defined($typeFilter) && $typeFilter ne "" && $type ne $typeFilter);
        push @out, {
            name    => $d,
            type    => $type,
            alias   => AttrVal($d, "alias", ""),
            room    => AttrVal($d, "room", ""),
            state   => ReadingsVal($d, "state", ($defs{$d}{STATE} // "")),
            writable => MCP_canWrite($name, $d) ? JSON::true : JSON::false,
        };
    }
    return MCP_ok({ devices => \@out, count => scalar(@out) });
}

sub MCP_getDevice {
    my ($name, $req) = @_;
    my $dev = $req->{device} // "";
    return MCP_err("device required") if($dev eq "");
    return MCP_err("no such device '$dev'") if(!defined($defs{$dev}));
    return MCP_err("device '$dev' not in allowlist", 403) if(!MCP_canRead($name, $dev));

    my $h = $defs{$dev};

    my %readings;
    if(defined($h->{READINGS})) {
        foreach my $r (keys %{$h->{READINGS}}) {
            next if($r =~ /^\./);   # versteckte Readings ueberspringen
            $readings{$r} = {
                val  => $h->{READINGS}{$r}{VAL},
                time => $h->{READINGS}{$r}{TIME},
            };
        }
    }

    my %attrs;
    if(defined($attr{$dev})) {
        %attrs = %{$attr{$dev}};
    }

    my @sets = split(/\s+/, getAllSets($dev) // "");

    # Internals (skalare Werte) - enthaelt u.a. DEF, das fuer notify/DOIF/at
    # die eigentliche Definition (Trigger + Code) ist. Refs (READINGS/helper)
    # und Punkt-/sensible Keys werden uebersprungen.
    my %internals;
    foreach my $k (keys %$h) {
        next if(ref($h->{$k}) || !defined($h->{$k}));
        next if($k =~ /^\./);
        next if($k =~ /(?:pass|passwd|password|secret|token|apikey|^key$)/i);
        $internals{$k} = $h->{$k};
    }

    return MCP_ok({
        name        => $dev,
        type        => ($h->{TYPE} // ""),
        def         => ($h->{DEF} // ""),
        state       => ReadingsVal($dev, "state", ($h->{STATE} // "")),
        readings    => \%readings,
        attributes  => \%attrs,
        internals   => \%internals,
        possibleSets=> \@sets,
        writable    => MCP_canWrite($name, $dev) ? JSON::true : JSON::false,
    });
}

sub MCP_setDevice {
    my ($name, $req) = @_;
    my $dev = $req->{device} // "";
    my $cmd = $req->{command} // "";
    return MCP_err("device required")  if($dev eq "");
    return MCP_err("command required") if($cmd eq "");
    return MCP_err("no such device '$dev'") if(!defined($defs{$dev}));
    return MCP_err("device '$dev' not writable (not in writeRoom)", 403)
        if(!MCP_canWrite($name, $dev));

    # args ist optional (Array oder String)
    my $args = $req->{args};
    my $argStr = ref($args) eq "ARRAY" ? join(" ", @$args)
               : defined($args)        ? "$args"
               :                          "";

    # Schutz: keine Befehlsverkettung / Perl / Shell ueber set einschleusen.
    return MCP_err("illegal characters in command/args", 400)
        if("$cmd $argStr" =~ /[;{}\$`]/);

    my $line = "set $dev $cmd".($argStr ne "" ? " $argStr" : "");
    my $ret  = AnalyzeCommand(undef, $line);
    $ret = "" if(!defined($ret));
    return MCP_err("set failed: $ret") if($ret =~ /\S/);

    return MCP_ok({
        executed => $line,
        state    => ReadingsVal($dev, "state", ($defs{$dev}{STATE} // "")),
    });
}

sub MCP_setAttribute {
    my ($name, $req) = @_;
    my $dev   = $req->{device}    // "";
    my $aname = $req->{attribute} // "";
    my $aval  = $req->{value};
    $aval = "" if(!defined($aval));
    return MCP_err("device required")    if($dev eq "");
    return MCP_err("attribute required") if($aname eq "");
    return MCP_err("no such device '$dev'") if(!defined($defs{$dev}));
    return MCP_err("device '$dev' not writable (not in writeRoom)", 403)
        if(!MCP_canWrite($name, $dev));

    # room darf gesetzt werden, aber das Geraet darf sich nicht selbst aus der
    # Allowlist werfen: enthaelt der neue Wert weder read- noch writeRoom, wird
    # der writeRoom automatisch ergaenzt (Geraet bleibt steuerbar).
    if($aname eq "room") {
        my %r = map { $_ => 1 } grep { /\S/ } split(/\s*,\s*/, $aval);
        if(!$r{ MCP_readRoom($name) } && !$r{ MCP_writeRoom($name) }) {
            $aval = ($aval ne "" ? "$aval," : "") . MCP_writeRoom($name);
        }
    }

    my $ret = AnalyzeCommand(undef, "attr $dev $aname $aval");
    $ret = "" if(!defined($ret));
    return MCP_err("attr failed: $ret") if($ret =~ /\S/);
    return MCP_ok({ executed => "attr $dev $aname $aval" });
}

sub MCP_setReading {
    my ($name, $req) = @_;
    my $dev = $req->{device}  // "";
    my $rd  = $req->{reading} // "";
    my $val = $req->{value};
    $val = "" if(!defined($val));
    return MCP_err("device required")  if($dev eq "");
    return MCP_err("reading required") if($rd eq "");
    return MCP_err("no such device '$dev'") if(!defined($defs{$dev}));
    return MCP_err("device '$dev' not writable (not in writeRoom)", 403)
        if(!MCP_canWrite($name, $dev));
    return MCP_err("illegal reading name", 400) if($rd !~ /^[\w.-]+$/);

    my $ret = AnalyzeCommand(undef, "setreading $dev $rd $val");
    $ret = "" if(!defined($ret));
    return MCP_err("setreading failed: $ret") if($ret =~ /\S/);
    return MCP_ok({ executed => "setreading $dev $rd ..." });
}

sub MCP_deleteReading {
    my ($name, $req) = @_;
    my $dev = $req->{device}  // "";
    my $rd  = $req->{reading} // "";
    return MCP_err("device required")  if($dev eq "");
    return MCP_err("reading required") if($rd eq "");
    return MCP_err("no such device '$dev'") if(!defined($defs{$dev}));
    return MCP_err("device '$dev' not writable (not in writeRoom)", 403)
        if(!MCP_canWrite($name, $dev));
    return MCP_err("illegal reading name", 400) if($rd !~ /^[\w.*-]+$/);

    my $ret = AnalyzeCommand(undef, "deletereading $dev $rd");
    $ret = "" if(!defined($ret));
    return MCP_err("deletereading failed: $ret") if($ret =~ /\S/);
    return MCP_ok({ executed => "deletereading $dev $rd" });
}

# ----------------------------------------------------------------------------
# Datei-Zugriff (CSS/JS, spaeter .pm). Allowlist ueber Attribut allowFiles:
# eine Pfad-Zeile pro Datei, '*'-Glob (matcht innerhalb eines Pfadsegments).
# Pfade sind relativ zum FHEM-Basisverzeichnis (wie im FHEMWEB-Editor),
# z. B. "www/pgm2/fhemweb_custom_link.js" oder "FHEM/98_MCP.pm".
# ----------------------------------------------------------------------------

# Pfad gegen die allowFiles-Liste pruefen. Lehnt Traversal (..) grundsaetzlich ab.
sub MCP_fileAllowed {
    my ($name, $path) = @_;
    return 0 if(!defined($path) || $path eq "");
    return 0 if($path =~ m{(^|/)\.\.(/|$)});   # kein Path-Traversal
    return 0 if($path =~ m{^/});               # keine absoluten Pfade

    foreach my $line (split(/\n/, AttrVal($name, "allowFiles", ""))) {
        $line =~ s/^\s+//; $line =~ s/\s+$//;
        next if($line eq "" || $line =~ /^#/);
        (my $re = $line) =~ s{([^\w/*.-])}{\\$1}g;  # Sonderzeichen escapen
        $re =~ s/\*/[^\/]*/g;                       # '*' -> ein Segment
        return 1 if($path =~ /^$re$/);
    }
    return 0;
}

sub MCP_allowedFileList {
    my ($name) = @_;
    my @out;
    foreach my $line (split(/\n/, AttrVal($name, "allowFiles", ""))) {
        $line =~ s/^\s+//; $line =~ s/\s+$//;
        next if($line eq "" || $line =~ /^#/);
        push @out, $line;
    }
    return @out;
}

sub MCP_listFiles {
    my ($name, $req) = @_;
    my @patterns = MCP_allowedFileList($name);
    return MCP_ok({ patterns => \@patterns, count => scalar(@patterns) });
}

sub MCP_readFile {
    my ($name, $req) = @_;
    my $path = $req->{path} // "";
    return MCP_err("path required") if($path eq "");
    return MCP_err("file '$path' not in allowFiles", 403)
        if(!MCP_fileAllowed($name, $path));

    my ($err, @lines) = FileRead($path);
    return MCP_err("read failed: $err") if(defined($err) && $err ne "");
    return MCP_ok({ path => $path, content => join("\n", @lines) });
}

sub MCP_writeFile {
    my ($name, $req, $level) = @_;
    my $path    = $req->{path} // "";
    my $content = $req->{content};
    return MCP_err("path required")    if($path eq "");
    return MCP_err("content required") if(!defined($content));
    return MCP_err("file '$path' not in allowFiles", 403)
        if(!MCP_fileAllowed($name, $path));

    # .pm-Module schreiben = effektiv RCE -> verlangt admin-Scope UND die
    # globale Freischaltung adminScopeAllowed, auch wenn die Datei freigegeben ist.
    if($path =~ /\.pm$/i) {
        return MCP_err("writing .pm modules requires the admin scope", 403)
            if(!defined($level) || $level < $MCP_scopeLevel{admin});
        return MCP_err("admin scope is disabled on the device", 403)
            if(!AttrVal($name, "adminScopeAllowed", 0));
        Log3($name, 2, "$name: ADMIN write_file $path");
    }

    my @lines = split(/\n/, $content, -1);
    my $err = FileWrite($path, @lines);
    return MCP_err("write failed: $err") if(defined($err) && $err ne "");
    return MCP_ok({ path => $path, bytes => length($content),
                    note => "Datei geschrieben. CSS/JS: im Browser neu laden; ".
                            ".pm: 'reload' in FHEM noetig." });
}

# ----------------------------------------------------------------------------
# search_log: durchsucht das FHEM-System-Logfile (global logfile).
#   pattern     optionaler Perl-Regex (Default: alle Zeilen)
#   ignoreCase  1 = Gross-/Kleinschreibung ignorieren
#   limit       max. zurueckgegebene (juengste) Treffer (Default 100, max 1000)
# Ein alternatives Logfile kann per Attribut logFile gesetzt werden.
# Tokens werden aus den Zeilen entfernt (falls FHEMWEB das mcp-Kommando loggt).
# ----------------------------------------------------------------------------
sub MCP_scrubLog {
    my ($l) = @_;
    # "mcp <token> <base64>" (Leerzeichen, %20 oder + getrennt) redigieren.
    $l =~ s/\bmcp(?:\s|%20|\+)+\S+(?:(?:\s|%20|\+)+\S+)?/mcp <redacted>/g;
    return $l;
}

sub MCP_searchLog {
    my ($name, $req) = @_;

    my $lf = AttrVal($name, "logFile", "") || AttrVal("global", "logfile", "");
    return MCP_err("no logfile configured (global logfile)") if($lf eq "" || $lf eq "-");
    my $file = ResolveDateWildcards($lf, localtime());

    my $limit = $req->{limit};
    $limit = 100 if(!defined($limit) || $limit !~ /^\d+$/);
    $limit = 1000 if($limit > 1000);
    $limit = 1    if($limit < 1);

    my $pattern = $req->{pattern};
    my $re;
    if(defined($pattern) && $pattern ne "") {
        $re = $req->{ignoreCase} ? eval { qr/$pattern/i } : eval { qr/$pattern/ };
        return MCP_err("invalid pattern: $@", 400) if(!$re);
    }

    my ($err, @lines) = FileRead($file);
    return MCP_err("read log failed: $err") if(defined($err) && $err ne "");

    my @hits = defined($re) ? grep { $_ =~ $re } @lines : @lines;
    my $total = scalar(@hits);
    @hits = @hits[ -$limit .. -1 ] if(@hits > $limit);   # juengste N
    @hits = map { MCP_scrubLog($_) } @hits;

    return MCP_ok({
        file         => $file,
        totalMatches => $total,
        returned     => scalar(@hits),
        matches      => \@hits,
    });
}

# define/modify: admin-Scope, global per Attribut freigeschaltet, best-effort
# Pattern-Filter gegen offensichtliche RCE. Restrisiko bleibt - siehe Kopf.
sub MCP_defineDevice { return MCP_defmod(@_, 0); }
sub MCP_modifyDevice { return MCP_defmod(@_, 1); }

sub MCP_defmod {
    my ($name, $req, $isModify) = @_;

    return MCP_err("admin scope is disabled on the device", 403)
        if(!AttrVal($name, "adminScopeAllowed", 0));

    my $dev = $req->{device}     // "";
    my $def = $req->{definition} // "";   # bei define: "<TYPE> <args...>"; bei modify: neue args
    return MCP_err("device required") if($dev eq "");
    return MCP_err("definition required") if($def eq "" && !$isModify);

    # best-effort Schutz gegen Shell/Perl-Ausbruch
    my $deny = AttrVal($name, "adminDenyPattern",
                       'system\s*\(|`|qx[\s({/]|\bexec\b|\bopen\b|->\s*system');
    if("$def" =~ /$deny/) {
        return MCP_err("definition rejected by adminDenyPattern", 400);
    }

    # cfg-Stil tolerieren (wie 98_Commands): ;; -> ; , \-Zeilenfortsetzung weg
    $def =~ s/\\\r?\n/\n/g;
    $def =~ s/;;/;/g;

    my $line = $isModify ? "modify $dev $def" : "defmod $dev $def";
    my $ret  = AnalyzeCommand(undef, $line);
    $ret = "" if(!defined($ret));
    return MCP_err(($isModify ? "modify" : "define")." failed: $ret") if($ret =~ /\S/);

    # Neu angelegtes Geraet automatisch in den writeRoom legen, damit es sofort
    # in der Allowlist ist und weiterbearbeitet werden kann (sonst: anlegen und
    # dann kein Zugriff mehr). Vorhandene Raeume bleiben erhalten.
    my $assigned = "";
    if(!$isModify) {
        my $wr = MCP_writeRoom($name);
        my %r  = map { $_ => 1 } MCP_devRooms($dev);
        if(!$r{$wr} && !$r{ MCP_readRoom($name) }) {
            my $cur = AttrVal($dev, "room", "");
            my $new = $cur ne "" ? "$cur,$wr" : $wr;
            AnalyzeCommand(undef, "attr $dev room $new");
            $assigned = $wr;
        }
    }

    Log3($name, 2, "$name: ADMIN ".($isModify?"modify":"define")." $dev".
                   ($assigned ne "" ? " (room+=$assigned)" : ""));
    return MCP_ok({ executed => ($isModify ? "modify $dev" : "defmod $dev"),
                    device => $dev,
                    assignedRoom => $assigned });
}

# ----------------------------------------------------------------------------
# UTF-8-Normalisierung der dekodierten Request-Strings (siehe MCP_command).
# ----------------------------------------------------------------------------
sub MCP_normStr {
    my ($s) = @_;
    return $s if(!defined($s) || ref($s));
    if(!$unicodeEncoding) {
        # Byte-Modus: Flag entfernen, Oktette (z. B. c3 a4) unveraendert lassen.
        utf8::downgrade($s, 1);
    } elsif(!utf8::is_utf8($s)) {
        # Unicode-Modus: UTF-8-Oktette zu Zeichen dekodieren.
        $s = Encode::decode("UTF-8", $s);
    }
    return $s;
}

sub MCP_normReq {
    my ($x) = @_;
    if(ref($x) eq "HASH")  { $x->{$_} = MCP_normReq($x->{$_}) for keys %$x; return $x; }
    if(ref($x) eq "ARRAY") { @$x = map { MCP_normReq($_) } @$x;             return $x; }
    return MCP_normStr($x);
}

# ----------------------------------------------------------------------------
# JSON-Antwort-Helfer
# ----------------------------------------------------------------------------
sub MCP_ok {
    my ($data) = @_;
    $data = {} if(!defined($data));
    $data->{ok} = JSON::true;
    return to_json($data);
}

sub MCP_err {
    my ($msg, $code) = @_;
    $code //= 400;
    return to_json({ ok => JSON::false, error => $msg, code => $code });
}

1;

=pod
=item helper
=item summary    Authorization gateway for the internet-facing FHEM MCP server
=item summary_DE Autorisierungs-Zentrale fuer den internet-erreichbaren FHEM-MCP-Server
=begin html

<a id="MCP"></a>
<h3>MCP</h3>
<ul>
  <p>
    <b>MCP</b> ist die FHEM-seitige Autorisierungs-Zentrale fuer den
    FHEM-MCP-Server (ein im Internet erreichbarer
    Model-Context-Protocol-Server, der Claude den Zugriff auf FHEM erlaubt).
  </p>
  <p>
    Der MCP-Server haelt selbst keine Berechtigungen, sondern reicht das vom
    Client mitgeschickte Bearer-Token bei jedem Aufruf an FHEM durch. Dieses
    Modul entscheidet allein ueber Token-Gueltigkeit, Scope und die
    Geraete-Allowlist.
  </p>
  <p><b>Sicherheitsmodell</b></p>
  <ul>
    <li>Tokens existieren nur als SHA-256-Hash und nur im Speicher. Sie landen
        weder in der <code>fhem.cfg</code> noch im Statefile (und damit nicht
        im Git). Ein FHEM-Neustart verwirft alle Tokens (gewollt ephemer).</li>
    <li>Geraete-Allowlist ueber Raeume: Raum <code>MCP</code> = nur lesbar,
        Raum <code>MCP_rw</code> = les- und steuerbar (konfigurierbar ueber die
        Attribute <code>readRoom</code>/<code>writeRoom</code>).</li>
    <li>Scopes: <code>read</code> (lesen), <code>write</code>
        (set/attr/setreading) und <code>admin</code> (zusaetzlich
        define/modify - effektiv volle Kontrolle, deshalb getrennt und per
        <code>adminScopeAllowed</code> abgesichert).</li>
  </ul>

  <a id="MCP-define"></a>
  <b>Define</b>
  <ul>
    <code>define &lt;name&gt; MCP</code><br><br>
    Beispiel: <code>define mcp MCP</code>
  </ul>
  <br>

  <a id="MCP-set"></a>
  <b>Set</b>
  <ul>
    <li><a id="MCP-set-grant"></a><b>grant</b> <code>read|write|admin
        [ttlMinuten] [name]</code> &ndash; erzeugt ein Token und gibt es
        <i>einmalig</i> im Dialog aus (danach nur noch der Hash; der Klartext
        kann nicht erneut angezeigt werden). Optional ein <i>Name</i> (z. B.
        <code>Claude-App</code>) zur Wiedererkennung und eine
        <i>ttl</i> in Minuten (Default <code>defaultTtl</code>=60, max
        <code>maxTtl</code>). Reihenfolge egal: die reine Zahl ist die ttl, der
        Rest der Name. Beispiel: <code>set mcp grant read 1440 Claude-App</code>.
        Jedes Token bekommt eine kurze <code>id</code> (im Dialog/in der Liste).</li>
    <li><a id="MCP-set-extend"></a><b>extend</b> <code>&lt;id|name&gt;
        [minuten]</code> &ndash; verlaengert die Gueltigkeit (reaktiviert auch
        ein bereits abgelaufenes, noch nicht aufgeraeumtes Token). Der
        Token-<i>String</i> bleibt unveraendert &ndash; ein verbundener Client
        muss sich also <b>nicht</b> neu authentifizieren. Beispiel:
        <code>set mcp extend 1a2b3c 1440</code>.</li>
    <li><a id="MCP-set-revoke"></a><b>revoke</b> <code>[&lt;id|name&gt;|all]</code>
        &ndash; widerruft ein bestimmtes Token (per id oder name) bzw. ohne
        Argument / mit <code>all</code> <b>alle</b> (Not-Aus).</li>
    <li><a id="MCP-set-revokeExpired"></a><b>revokeExpired</b> &ndash; entfernt
        abgelaufene Tokens endgueltig (danach nicht mehr per extend
        reaktivierbar).</li>
  </ul>
  <br>

  <a id="MCP-get"></a>
  <b>Get</b>
  <ul>
    <li><a id="MCP-get-tokens"></a><b>tokens</b> &ndash; listet alle Tokens mit
        <code>id</code>, <code>name</code>, <code>scope</code>, Ablaufzeitpunkt
        und Status (aktiv/abgelaufen). Der Token-Klartext wird dabei nicht
        angezeigt (nur der Hash ist gespeichert).</li>
  </ul>
  <br>

  <a id="MCP-attr"></a>
  <b>Attributes</b>
  <ul>
    <li><a id="MCP-attr-readRoom"></a><b>readRoom</b> &ndash; Raumname fuer
        nur-lesbare Geraete (Default <code>MCP</code>).</li>
    <li><a id="MCP-attr-writeRoom"></a><b>writeRoom</b> &ndash; Raumname fuer
        steuerbare Geraete (Default <code>MCP_rw</code>). Diese sind implizit
        auch lesbar.</li>
    <li><a id="MCP-attr-allowFiles"></a><b>allowFiles</b> &ndash; einzeln
        freigegebene Dateien fuer Lese-/Schreibzugriff (eine Pfad-Zeile pro
        Datei, relativ zum FHEM-Basisverzeichnis wie im FHEMWEB-Editor;
        <code>*</code>-Glob matcht innerhalb eines Pfadsegments; <code>#</code>
        leitet Kommentare ein). Beispiel:
        <code>www/pgm2/mystyle.css</code>. <code>..</code> und absolute Pfade
        werden abgewiesen. Lesen verlangt <code>read</code>, Schreiben
        <code>write</code>; das Schreiben von <code>.pm</code>-Dateien verlangt
        zusaetzlich den <code>admin</code>-Scope und
        <code>adminScopeAllowed=1</code> (Modul-Schreiben = RCE).</li>
    <li><a id="MCP-attr-logFile"></a><b>logFile</b> &ndash; alternatives Logfile
        fuer die Aktion <code>search_log</code> (Default: das <code>global
        logfile</code>). Datumsplatzhalter wie <code>%Y</code>/<code>%m</code>
        werden aufgeloest.</li>
    <li><a id="MCP-attr-defaultTtl"></a><b>defaultTtl</b> &ndash;
        Standard-Gueltigkeit eines Grants in Minuten (Default 60).</li>
    <li><a id="MCP-attr-maxTtl"></a><b>maxTtl</b> &ndash; Obergrenze fuer die
        ttl in Minuten (Default 1440).</li>
    <li><a id="MCP-attr-adminScopeAllowed"></a><b>adminScopeAllowed</b> 1|0
        &ndash; erlaubt das Vergeben des <code>admin</code>-Scopes (define/
        modify). Default 0. <b>Vorsicht:</b> admin = effektiv volle Kontrolle
        ueber FHEM (Perl-/Shell-Bloecke). Nur kurz und bewusst aktivieren.</li>
    <li><a id="MCP-attr-adminDenyPattern"></a><b>adminDenyPattern</b> &ndash;
        Regex, der define/modify-Eingaben ablehnt (best-effort Schutz gegen
        offensichtliche RCE; Default blockiert u. a. <code>system(</code>,
        Backticks, <code>qx</code>, <code>exec</code>, <code>open</code>).</li>
    <li><b>disable</b> 1|0 &ndash; deaktiviert die gesamte Schnittstelle.</li>
  </ul>
  <br>

  <a id="MCP-readings"></a>
  <b>Readings</b>
  <ul>
    <li><b>state</b> &ndash; active.</li>
    <li><b>activeTokens</b> &ndash; Anzahl aktuell gueltiger Tokens.</li>
    <li><b>lastGrant</b> &ndash; Zeitpunkt/Scope/ttl des letzten Grants
        (ohne Token).</li>
    <li><b>lastAction</b> &ndash; zuletzt ausgefuehrte MCP-Aktion (Audit).</li>
  </ul>
</ul>

=end html
=cut
