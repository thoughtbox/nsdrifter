#!/bin/sh
# shellcheck disable=SC2016,SC2329
# SC2016: the embedded perl/awk programs and regexes are single-quoted on purpose.
# SC2329: inventory_* functions are called indirectly as "inventory_$stage".
# Read-only NetScaler/FreeBSD inventory collector. Output is consumed by the
# management-side Bash script; do not run output through a terminal pager.
#
# It can be installed on the ADC and run as a file, or streamed by the runner
# (COLLECT_MODE=stream) so nothing is stored on the appliance. In stream mode
# the runner prepends variable assignments overriding the defaults below.
#
# NetScaler 14.1's /bin/sh segfaults while parsing a *top-level* pipeline that
# contains a compound command (e.g. 'cmd | while ...; done'), whether the
# script comes from a file or stdin. Every such pipeline lives inside a
# function body; keep it that way and check edits on an ADC with 'sh -n'.

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH

# /nsconfig is a symlink to /flash/nsconfig on NetScaler and is not followed;
# its contents are inventoried under /flash. /var is scanned minus large or
# fast-changing trees; /var/python/bin is kept, its library tree is not.
SCAN_ROOTS=${SCAN_ROOTS:-"/nsconfig /flash /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin /lib /usr/lib /usr/local/lib /etc /root /netscaler /var /tmp"}
EXCLUDE_RE=${EXCLUDE_RE:-'^/var/(log|nslog|core|nstrace|run|cache|db|pgsql|nsproflog|nssynclog|crash|python/(lib|include)|mastools/logs)(/|$)'}
MAX_HASH_SIZE=${MAX_HASH_SIZE:-104857600}
SUID_ROOTS=${SUID_ROOTS:-/}
# Trees whose file contents (up to 2 MiB, minus EXCLUDE_RE) are searched for
# generic webshell/implant primitives; the runner separates vendor matches.
MARKER_ROOTS=${MARKER_ROOTS:-"/var /netscaler/portal /tmp"}
MARKER_RE=${MARKER_RE:-'passthru[[:space:]]*\(|shell_exec[[:space:]]*\(|proc_open[[:space:]]*\(|eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_)|assert[[:space:]]*\([[:space:]]*\$_|create_function[[:space:]]*\(|array_filter\(|base64_decode\(|http_status_code\(|/dev/tcp/|pty\.spawn'}
# Generic tampering strings in configuration and startup files under
# /flash/nsconfig and /etc (after NCSC-NL's CVE-2025-6543 checks).
CONFIG_MARKER_RE=${CONFIG_MARKER_RE:-'python3? -c|httpd\.conf|zlib\.decompress|base64\.b85decode|base64\.b64decode|apachectl graceful'}
# Optional known-indicator patterns, set by the runner from iocs.conf in
# stream mode: file contents (IOCMARKER) and log lines (LOGHIT KNOWN_IOC).
IOC_MARKER_RE=${IOC_MARKER_RE:-}
IOC_LOG_RE=${IOC_LOG_RE:-}
# Root-filesystem files (a memory disk rebuilt at every boot) whose inode
# changed later than this many seconds after boot are reported.
POSTBOOT_GRACE=${POSTBOOT_GRACE:-900}
LOG_HUNT=${LOG_HUNT:-1}
# Set by the runner in stream mode: regex matching its own past invocations
# in bash.log, so they are not reported as suspicious shell commands.
OWN_RUN_RE=${OWN_RUN_RE:-}

BOOT=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/.*sec = \([0-9]*\),.*/\1/p')

# NetScaler's FreeBSD image ships without stat(1) and readlink(1), but has
# perl. One perl process stats (and hashes) every path read from stdin.
# Modes:
#   FILE     FILE path type size mtime uid gid mode:hash, plus
#            PCAP path size mtime for packet captures (pcap/pcapng magic), and
#            POSTBOOT path type ctime mtime mode for root-fs files (not
#            directories, not /tmp) whose inode changed after boot
#   SCRIPT   SCRIPT path size mtime mode hash
#   SUID     SUID path mode uid gid hash
#   PERSIST  PERSISTENCE path mtime-iso hash
# mode is octal permission bits including setuid/setgid/sticky, no leading
# zeros (755, 4555, 1777). Paths containing '|' or tab become WARN lines.
PERL_META='
use strict; use warnings; no warnings "uninitialized";
use POSIX qw(strftime);
my ($mode, $max, $boot, $grace) = @ARGV; @ARGV = ();
my $have_sha = eval { require Digest::SHA; 1 };
my $rootdev = (lstat "/")[0];
my %type = (0100000, "Regular File", 0040000, "Directory", 0120000, "Symbolic Link",
            0020000, "Character Device", 0060000, "Block Device", 0010000, "Fifo File",
            0140000, "Socket");
sub digest {
    my ($p, $size) = @_;
    return "SKIPPED_SIZE" if $size > $max;
    if ($have_sha) {
        my $d = eval { Digest::SHA->new(256)->addfile($p, "b")->hexdigest };
        return defined $d ? $d : "HASH_ERROR";
    }
    open(my $fh, "-|", "sha256", "-q", $p) or return "NO_HASH_TOOL";
    my $d = <$fh>; close $fh; chomp $d;
    return length $d ? $d : "HASH_ERROR";
}
while (my $p = <STDIN>) {
    chomp $p;
    if ($p =~ /[|\t]/) { print "WARN\tUNSUPPORTED_PATH\t$p\n"; next }
    my @s = lstat $p or next;
    my $fmt = $s[2] & 0170000;
    my $t = $type{$fmt} || "Unknown";
    my $perm = sprintf "%o", $s[2] & 07777;
    if ($mode eq "FILE") {
        my $h = $fmt == 0100000 ? digest($p, $s[7]) : $fmt == 0120000 ? "link:" . readlink($p) : "-";
        print join("\t", "FILE", $p, $t, $s[7], $s[9], $s[4], $s[5], "$perm:$h"), "\n";
        if ($fmt == 0100000 && $s[7] >= 24 && open(my $fh, "<:raw", $p)) {
            my $magic = ""; read($fh, $magic, 4); close $fh;
            print join("\t", "PCAP", $p, $s[7], $s[9]), "\n"
                if unpack("H8", $magic) =~ /^(d4c3b2a1|a1b2c3d4|4d3cb2a1|a1b23c4d|0a0d0d0a)$/;
        }
        print join("\t", "POSTBOOT", $p, $t, $s[10], $s[9], $perm), "\n"
            if $boot && $s[0] == $rootdev && $s[10] > $boot + $grace
               && $fmt != 0040000 && $p !~ m{^/tmp(/|$)};
    } elsif ($mode eq "SCRIPT") {
        print join("\t", "SCRIPT", $p, $s[7], $s[9], $perm, digest($p, $s[7])), "\n";
    } elsif ($mode eq "SUID") {
        print join("\t", "SUID", $p, $perm, $s[4], $s[5], digest($p, $s[7])), "\n";
    } elsif ($mode eq "PERSIST") {
        print join("\t", "PERSISTENCE", $p, strftime("%Y-%m-%dT%H:%M:%S%z", localtime $s[9]), digest($p, $s[7])), "\n";
    }
}
'
file_meta() { perl -e "$PERL_META" "$1" "$MAX_HASH_SIZE" "${BOOT:-0}" "$POSTBOOT_GRACE"; }

# Keep duplicate process rows so worker-count changes remain visible.
# -ww: never truncate the command column; one -o per column, since FreeBSD
# treats everything after 'user=' as header text.
# The collector's own processes are excluded: its branch of the process tree
# (the CLI process that started it, the transport pipeline, this shell,
# ps/awk/sort and subshells) and the sshd session processes above it
# ('sshd: user@...'), but not other branches under those sshd processes.
# With SSH connection sharing (ControlMaster) an administrator's interactive
# shell runs under the same sshd session and must still be reported.
# Without an sshd session ancestor only this shell and its children are.
inventory_processes() {
    ps -axww -o user= -o pid= -o ppid= -o command= 2>/dev/null | awk -v self=$$ '
    {
      user=$1; pid=$2; ppid=$3
      $1=""; $2=""; $3=""
      sub(/^[ \t]+/, "", $0)
      if (user == "") next
      n++; U[n]=user; P[n]=pid; PP[n]=ppid; C[n]=$0
      par[pid]=ppid; cmd[pid]=$0
    }
    END {
      top=self; p=self; insession=0
      while ((p in par) && par[p] > 1) {
        q=par[p]
        if (cmd[q] ~ /^sshd: [^ ]+@/) { insession=1; break }
        p=q
      }
      if (insession) {
        top=p
        for (s=q; (s in par) && cmd[s] ~ /^sshd: [^ ]+@/; s=par[s]) { ex[s]=1; sshd_only[s]=1 }
      }
      ex[top]=1
      do {
        changed=0
        for (i=1; i<=n; i++) if (!(P[i] in ex) && (PP[i] in ex) && !(PP[i] in sshd_only)) { ex[P[i]]=1; changed=1 }
      } while (changed)
      for (i=1; i<=n; i++) if (!(P[i] in ex)) print "PROCESS\t" U[i] "\t" P[i] "\t" PP[i] "\t" C[i]
    }' | sort
}

# Filenames containing newlines are split by find and are not supported.
inventory_files() {
    for root in $SCAN_ROOTS; do
        [ -e "$root" ] || [ -L "$root" ] || continue
        find -x "$root" -print 2>/dev/null
    done | grep -Ev "$EXCLUDE_RE" | file_meta FILE
}

# Setuid/setgid files anywhere on local filesystems, not only under SCAN_ROOTS.
inventory_suid() {
    for root in $SUID_ROOTS; do
        [ -e "$root" ] || continue
        find "$root" \( ! -fstype local -o -path /proc -o -path /dev \) -prune -o \
            -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null
    done | sort -u | file_meta SUID
}

inventory_sockets() {
    if command -v sockstat >/dev/null 2>&1; then
        sockstat -46 -l 2>/dev/null | awk 'NR>1 {print "LISTENER\t" $0}'
        sockstat -46 2>/dev/null | awk 'NR>1 {print "SOCKET\t" $0}'
    elif command -v netstat >/dev/null 2>&1; then
        netstat -an 2>/dev/null | awk '/LISTEN|ESTABLISHED|SYN_SENT|SYN_RECEIVED/ {print "SOCKET\t" $0}'
    fi
}

inventory_persistence() {
    for f in /nsconfig/ns.conf /nsconfig/rc.netscaler /nsconfig/nsbefore.sh /nsconfig/nsafter.sh \
             /nsconfig/crontab /nsconfig/ssh/authorized_keys /etc/crontab /etc/rc.conf \
             /etc/httpd.conf /root/.ssh/authorized_keys /var/cron/tabs/* /var/pubkey/*/.ssh/authorized_keys*; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done | file_meta PERSIST
}

# Persistence-relevant configuration lines, one CONF record per line, so the
# runner can report added lines exactly. Cron tables, startup scripts and SSH
# keys are emitted whole (minus comments); httpd and ns.conf are filtered to
# the directives that matter. ns.conf password hashes are redacted.
inventory_conf() {
    for f in /etc/crontab /nsconfig/crontab /var/cron/tabs/* /nsconfig/rc.netscaler \
             /nsconfig/nsbefore.sh /nsconfig/nsafter.sh /etc/rc.conf /etc/rc.local \
             /nsconfig/ssh/authorized_keys /root/.ssh/authorized_keys /var/pubkey/*/.ssh/authorized_keys*; do
        [ -f "$f" ] || continue
        awk -v f="$f" '{ gsub(/\t/, " "); sub(/^ +/, "") } $0 != "" && $0 !~ /^#/ { print "CONF\t" f "\t" $0 }' "$f"
    done
    for f in /etc/httpd*.conf; do
        [ -f "$f" ] || continue
        awk -v f="$f" '{ gsub(/\t/, " "); sub(/^ +/, "") }
            /^(# *php_(admin_)?(flag|value)|php_(admin_)?(flag|value)|Alias|AliasMatch|ScriptAlias|ScriptAliasMatch|<Files|<FilesMatch|<Directory|<Location|AddHandler|AddType|SetHandler|Action|LoadModule|Include|RewriteRule)/ { print "CONF\t" f "\t" $0 }' "$f"
    done
    [ -f /nsconfig/ns.conf ] || return 0
    awk '{ gsub(/\t/, " ") }
        /^(add|set|bind) system (user|group)|^add ssh|^set system parameter|^add (authentication|aaa) |^(add|set) ns ip6? .*-mgmtAccess|^add (system )?cmdPolicy|^add shell/ {
          line=$0
          if (line ~ /^(add|set) system user [^ ]+ [^ ]+ -encrypted/) {
            n=split(line, w, " "); w[5]="<hash>"; line=w[1]
            for (i=2; i<=n; i++) line=line " " w[i]
          }
          print "CONF\t/nsconfig/ns.conf\t" line
        }' /nsconfig/ns.conf
}

# Webshell/implant markers in file contents under MARKER_ROOTS, and
# tampering markers in configuration/startup files (CONFMARK). The installed
# collector itself is skipped, since it contains the marker strings.
marker_grep() {
    tr '\n' '\0' | xargs -0 grep -IHoE -m 1 "$2" 2>/dev/null | awk -v tag="$1" '
        { i=index($0, ":"); p=substr($0, 1, i-1); m=substr($0, i+1)
          if (p ~ /[|\t]/ || seen[p]++) next
          gsub(/\t/, " ", m); print tag "\t" p "\t" substr(m, 1, 120) }'
}

# Appends a fourth field to MARKER records: whether the file passes a base64
# string literal to a decoder (PHP base64_decode, Python b64decode, Perl
# decode_base64), as webshells do to hide a payload, rather than decoding
# variables as ordinary code does. "-" when none, otherwise the number of
# literals, the longest one's length and the start of its decoded content
# (non-printable bytes shown as ".").
PERL_B64='
use strict; use warnings; use MIME::Base64;
while (my $l = <STDIN>) {
    chomp $l;
    my ($tag, $p, $m) = split /\t/, $l, 3;
    my ($n, $max, $preview) = (0, 0, "");
    if (open(my $fh, "<:raw", $p)) {
        local $/; my $d = <$fh>; close $fh;
        while ($d =~ /(?:base64_decode|b64decode|decode_base64)\s*\(\s*(["\x27])([A-Za-z0-9+\/=\s]{16,}?)\1/g) {
            (my $b = $2) =~ s/\s+//g;
            $n++;
            next if length $b <= $max;
            $max = length $b;
            ($preview = substr(decode_base64($b), 0, 60)) =~ s/[^\x20-\x7e]/./g;
        }
    }
    print join("\t", $tag, $p, $m, $n ? "literals=$n longest=$max decoded=$preview" : "-"), "\n";
}
'

inventory_markers() {
    self=; [ -f "$0" ] && self=$0
    for root in $MARKER_ROOTS; do
        [ -d "$root" ] || continue
        find -x "$root" -type f -size -2048k -print 2>/dev/null
    done | grep -Ev "$EXCLUDE_RE" | grep -vxF "${self:-/nonexistent}" | marker_grep MARKER "$MARKER_RE" |
        perl -e "$PERL_B64"
    for root in /flash/nsconfig /etc; do
        [ -d "$root" ] || continue
        find -x "$root" -type f -size -2048k -print 2>/dev/null
    done | grep -vxE '/etc/rc|/etc/rc\.conf\.defaults' | grep -vxF "${self:-/nonexistent}" |
        grep -v '/nsconfig/scripts/ns-inventory\.sh$' | marker_grep CONFMARK "$CONFIG_MARKER_RE"
    [ -n "$IOC_MARKER_RE" ] || return 0
    for root in $MARKER_ROOTS /flash/nsconfig /etc; do
        [ -d "$root" ] || continue
        find -x "$root" -type f -size -2048k -print 2>/dev/null
    done | grep -Ev "$EXCLUDE_RE" | grep -vxF "${self:-/nonexistent}" | marker_grep IOCMARKER "$IOC_MARKER_RE"
}

# Server-side scripts (PHP and XHTML, plus extensions httpd.conf maps to PHP)
# anywhere under /var, /netscaler/portal, /tmp and /flash, regardless of
# EXCLUDE_RE: stock NetScaler has them only in the admin GUI. Reported
# webshell locations include /var/netscaler/logon, /var/netscaler/gui/vpn
# (/netscaler/ns_gui/vpn), /var/vpn/themes and /var/nsproflog.
inventory_scripts() {
    extra=$(awk '($1 == "AddType" || $1 == "AddHandler") && $2 ~ /^application\/x-httpd-php/ { for (i=3; i<=NF; i++) if ($i ~ /^\.?[A-Za-z0-9]+$/) { sub(/^\./, "", $i); print $i } }' \
        /etc/httpd*.conf 2>/dev/null | grep -vxE 'phps?')
    set --
    for e in php php3 php4 php5 php7 php8 phtml phar xhtml $extra; do
        [ $# -gt 0 ] && set -- "$@" -o
        set -- "$@" -iname "*.$e"
    done
    find -x /var /netscaler/portal /tmp /flash -type f \( "$@" \) -print 2>/dev/null |
        grep -v '^/var/netscaler/gui/admin_ui/' | file_meta SCRIPT
}

# Packet-engine core dumps: crashes accompany memory-corruption exploitation
# attempts (e.g. CVE-2025-6543). CORE path size mtime.
inventory_cores() {
    find /var/core -iname 'NSPPE*' -type f 2>/dev/null | perl -ne '
        chomp; my @s = stat $_ or next; print join("\t", "CORE", $_, $s[7], $s[9]), "\n"'
}

# NetScaler ships .signedexe.manifest files (e.g. /netscaler, /var/python,
# /var/perl5): binary lists of relative path, NUL, raw SHA-256 digest. Every
# listed file is verified; one INTEGRITY summary per manifest and one
# INTEGRITY_FAIL per mismatching or missing file.
PERL_MANIFEST='
use strict; use warnings; use Digest::SHA;
while (my $m = <STDIN>) {
    chomp $m;
    open(my $fh, "<:raw", $m) or next;
    local $/; my $d = <$fh>; close $fh;
    (my $base = $m) =~ s{/[^/]+$}{};
    my ($n, $bad, $missing) = (0, 0, 0);
    while ($d =~ /([\x20-\x7e]{2,}?)\0(.{32})/sg) {
        my ($rel, $want) = ($1, unpack("H64", $2));
        # Records start with a length byte, which may be printable.
        $rel = substr($rel, 1) if !-e "$base/$rel" && -e "$base/" . substr($rel, 1);
        my $f = "$base/$rel"; $n++;
        if (!-f $f) { $missing++; print "INTEGRITY_FAIL\t$f\tMISSING\t$want\t-\n"; next }
        my $got = eval { Digest::SHA->new(256)->addfile($f, "b")->hexdigest } || "HASH_ERROR";
        next if $got eq $want;
        $bad++; print "INTEGRITY_FAIL\t$f\tMISMATCH\t$want\t$got\n";
    }
    print "INTEGRITY\t$m\t$n\t$bad\t$missing\n";
}
'

inventory_integrity() {
    perl -MDigest::SHA -e 1 2>/dev/null || return 0
    find -x / /var /flash -maxdepth 3 -name .signedexe.manifest -type f 2>/dev/null | sort -u |
        perl -e "$PERL_MANIFEST"
}

without_own_runs() {
    if [ -n "$OWN_RUN_RE" ]; then grep -avE "$OWN_RUN_RE"; else cat; fi
}

# Search current and rotated (gzip) logs for exploitation traces. One LOGHIT
# record per (file, check) with the match count, and up to three LOGSAMPLE
# records with the first matching lines, truncated.
log_check() {
    name=$1 re=$2; shift 2
    for f in "$@"; do
        [ -f "$f" ] || continue
        case "$f" in *.gz) gzip -dc "$f" 2>/dev/null ;; *) cat "$f" 2>/dev/null ;; esac |
            grep -aE "$re" | without_own_runs |
            awk -v f="$f" -v n="$name" '
              { c++; if (c <= 3) { s=$0; gsub(/\t/, " ", s); smp[c]=substr(s, 1, 400) } }
              END { if (c) { print "LOGHIT\t" f "\t" n "\t" c
                             for (i=1; i<=c && i<=3; i++) print "LOGSAMPLE\t" f "\t" n "\t" smp[i] } }'
    done
}

inventory_logs() {
    [ "$LOG_HUNT" = 1 ] || return 0
    # Log poisoning through the packet-engine watchdog (pitboss) messages.
    log_check NSPPE_INJECTION 'NSPPE[;`$|&]|heartbeatsNSPPE|died NSPPE|\$\{IFS\}|pitboss.*b64decode|User[^"]*(missed too many heartbeats|unexpectedly died)' \
        /var/log/ns.log* /var/log/messages*
    log_check NSPPE_CRASH 'pitboss NOT restarting NSPPE' /var/log/messages*
    log_check DTLS_EXPLOIT_ATTEMPT 'SSL_HANDSHAKE_FAILURE.*DTLSv1\.0.*Internal Error' /var/log/ns.log*
    log_check WEB_COMMAND_INJECTION '\$\{IFS\}|b64decode|base64 -d|openssl (enc|base64)|/bin/sh|[|;] *(sh|bash|php|perl|python)[ ;"]|curl |wget |passthru|PD9waH' \
        /var/log/httpaccess*.log* /var/log/httperror*.log*
    log_check WEB_BASE64_BLOB '[A-Za-z0-9+/]{120,}={0,2}' /var/log/httpaccess*.log*
    # Requests for server-side scripts or .sig files in portal/download trees,
    # and static-asset requests carrying base64 PHP ("PD9...") in a header.
    log_check WEBSHELL_REQUEST 'LogonPoint/custom/[^ ]*\.(php[0-9]?|phtml|xhtml|pl|py|cgi)|/vpns?/[^ ]*\.(php[0-9]?|phtml|xhtml|sig)[ ?]|\.(ico|css|png|gif|jpg|js)[^"]*"[^"]*"[^"]*PD9' \
        /var/log/httpaccess*.log* /var/log/httperror*.log*
    # Commands run through the CLI 'shell' command (e.g. over SSH) are audited
    # in ns.log rather than bash.log.
    log_check CLI_SHELL_COMMAND 'CMD_EXECUTED.*Command "shell .*(chmod +[0-7]?[2467][0-7]{3} |chmod +[ugoa]*\+[rwx]*s|b64decode|base64 -d|openssl (enc|base64) .*-d|curl |wget |fetch -o|[|] *(sh|bash|perl|python[0-9.]*|php)( |$|")|nc -e|/dev/tcp/|echo [A-Za-z0-9+/=]{100,})' \
        /var/log/ns.log*
    log_check SYSTEM_USER_CHANGE 'CMD_EXECUTED.*Command "(add system user|set system user|bind system user [^ ]+ superuser)' /var/log/ns.log*
    log_check SHELL_COMMAND 'chmod +[0-7]?[2467][0-7]{3} |chmod +[ugoa]*\+[rwx]*s|b64decode|base64 -d|openssl (enc|base64) .*-d|curl |wget |fetch -o|[|] *(sh|bash|perl|python[0-9.]*|php)( |$|")|nc -e|/dev/tcp/|php_flag engine on|kill -HUP|httpd\.conf' \
        /var/log/bash.log*
    [ -n "$IOC_LOG_RE" ] || return 0
    log_check KNOWN_IOC "$IOC_LOG_RE" /var/log/ns.log* /var/log/messages* /var/log/httpaccess*.log* \
        /var/log/httperror*.log* /var/log/bash.log*
}

if ! command -v perl >/dev/null 2>&1; then
    printf 'WARN\tNO_PERL\tfile, setuid and persistence inventory unavailable\n'
fi

printf 'META\tHOST\t%s\n' "$(hostname 2>/dev/null || echo unknown)"
printf 'META\tTIME\t%s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || date)"
printf 'META\tBOOT\t%s\n' "${BOOT:-unknown}"

# STAGE records mark progress for the runner's -progress display.
for stage in processes files suid sockets persistence conf scripts markers cores integrity logs; do
    printf 'STAGE\t%s\n' "$stage"
    "inventory_$stage"
done

exit 0
