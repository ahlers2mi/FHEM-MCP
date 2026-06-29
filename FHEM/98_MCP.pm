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
# Version:  v0.1.0
# Lizenz:   GPL v2 oder hoeher (wie FHEM)
##############################################################################

package main;

use strict;
use warnings;

use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA  qw(sha256_hex);
use JSON;

use vars qw($readingFnAttributes $init_done %cmds %defs %attr);

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
    $hash->{AttrFn}  = \&MCP_Attr;

    $hash->{AttrList} =
          "disable:1,0 " .
          "readRoom " .            # Raumname fuer NUR-lesbar (Default MCP)
          "writeRoom " .           # Raumname fuer steuerbar  (Default MCP_rw)
          "allowFiles:textField-long " . # einzeln freigegebene Dateien (eine pro Zeile, *-Glob)
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

    $hash->{FVERSION} = "98_MCP.pm:v0.1.0";

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

    my $list = "grant:read,write,admin revoke:noArg revokeExpired:noArg";

    if($cmd eq "grant") {
        my $scope = shift(@args) // "read";
        return "unknown scope '$scope', choose read|write|admin"
            if(!$MCP_scopeLevel{$scope});

        if($scope eq "admin" && !AttrVal($name, "adminScopeAllowed", 0)) {
            return "admin scope is disabled. Set 'attr $name adminScopeAllowed 1' ".
                   "first (enables define/modify = full control - use briefly!).";
        }

        my $defTtl = AttrVal($name, "defaultTtl", 60);
        my $maxTtl = AttrVal($name, "maxTtl", 1440);
        my $ttl    = shift(@args);
        $ttl = $defTtl if(!defined($ttl) || $ttl !~ /^\d+$/);
        $ttl = $maxTtl if($ttl > $maxTtl);
        $ttl = 1       if($ttl < 1);

        my $token = MCP_randToken();
        my $exp   = time() + $ttl * 60;
        $hash->{helper}{tokens}{ sha256_hex($token) } = {
            scope  => $scope,
            exp    => $exp,
            issued => time(),
        };

        MCP_refreshCount($hash);
        readingsSingleUpdate($hash, "lastGrant",
            FmtDateTime(time())." scope=$scope ttl=${ttl}min", 1);
        Log3($name, 3, "$name: granted token scope=$scope ttl=${ttl}min ".
                       "(expires ".FmtDateTime($exp).")");

        # Das Klartext-Token wird genau hier EINMAL ausgegeben (im FHEMWEB-
        # Dialog). Es wird nirgends gespeichert - danach nur noch sein Hash.
        return
            "Token (scope=$scope, gueltig ${ttl} min, laeuft ".FmtDateTime($exp).
            " ab):\n\n$token\n\n".
            "Im Claude-Code-MCP-Client als Bearer-Header eintragen, z. B.:\n".
            "  claude mcp add --transport http fhem <URL> \\\n".
            "    --header \"Authorization: Bearer $token\"\n\n".
            "Dieses Token wird NICHT erneut angezeigt.";
    }

    if($cmd eq "revoke") {
        my $n = scalar(keys %{$hash->{helper}{tokens}});
        $hash->{helper}{tokens} = {};
        MCP_refreshCount($hash);
        Log3($name, 3, "$name: revoked all tokens ($n)");
        return "$n Token(s) widerrufen.";
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

sub MCP_refreshCount {
    my ($hash) = @_;
    MCP_purgeExpired($hash);
    my $n = scalar(keys %{$hash->{helper}{tokens}});
    readingsSingleUpdate($hash, "activeTokens", $n, 1);
    return $n;
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
    if($t->{exp} <= time()) {
        delete $hash->{helper}{tokens}{$h};
        MCP_refreshCount($hash);
        return undef;
    }
    return $MCP_scopeLevel{ $t->{scope} };
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

    return MCP_ok({
        name        => $dev,
        type        => ($h->{TYPE} // ""),
        state       => ReadingsVal($dev, "state", ($h->{STATE} // "")),
        readings    => \%readings,
        attributes  => \%attrs,
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

    # Nicht erlauben, ein Geraet aus dem Allowlist-Raum herauszuschreiben.
    return MCP_err("changing 'room' is not allowed via MCP", 403)
        if($aname eq "room");

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

    Log3($name, 2, "$name: ADMIN ".($isModify?"modify":"define")." $dev");
    return MCP_ok({ executed => ($isModify ? "modify $dev" : "defmod $dev"),
                    device => $dev });
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
    <a href="https://github.com/ahlers2mi/FHEM-MCP">FHEM-MCP-Server</a> (ein im
    Internet erreichbarer Model-Context-Protocol-Server, der Claude den
    Zugriff auf FHEM erlaubt).
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
        [ttlMinuten]</code> &ndash; erzeugt ein Token und gibt es <i>einmalig</i>
        im Dialog aus (danach nur noch der Hash). Default-Gueltigkeit ueber
        <code>defaultTtl</code> (60 min), begrenzt durch <code>maxTtl</code>.
        Das Token in den Claude-Code-MCP-Client als
        <code>Authorization: Bearer &lt;token&gt;</code>-Header eintragen.</li>
    <li><a id="MCP-set-revoke"></a><b>revoke</b> &ndash; widerruft sofort alle
        Tokens (Not-Aus).</li>
    <li><a id="MCP-set-revokeExpired"></a><b>revokeExpired</b> &ndash; entfernt
        abgelaufene Tokens.</li>
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
