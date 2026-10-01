#!/usr/bin/env bash
# shellcheck disable=SC2329  # compare_* functions are called via compare_optional "$fn"
# Centralized NetScaler drift and post-compromise hunting runner.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
COLLECTOR=${COLLECTOR:-"$HERE/ns-inventory.sh"}
STATE_ROOT=${STATE_ROOT:-"${XDG_STATE_HOME:-$HOME/.local/state}/netscaler-hunt"}
COLLECT_MODE=${COLLECT_MODE:-stream}
REMOTE_PATH=${REMOTE_PATH:-/nsconfig/scripts/ns-inventory.sh}
SSH_USER=${SSH_USER:-nsroot}
SSH_OPTS=${SSH_OPTS:-}
MAX_HASH_SIZE=${MAX_HASH_SIZE:-104857600}
ALLOWLIST_DEFAULT=${ALLOWLIST_DEFAULT:-"$HERE/allowlist.default"}
use_iocs=1
show_progress=0

# Collector settings forwarded in stream mode when set in this environment.
STREAM_VARS=(SCAN_ROOTS EXCLUDE_RE SUID_ROOTS MARKER_ROOTS MARKER_RE CONFIG_MARKER_RE POSTBOOT_GRACE LOG_HUNT)

# Optional known-indicator layer (see iocs.conf); the generic checks below do
# not depend on it.
IOC_FILE=${IOC_FILE:-"$HERE/iocs.conf"}
# Trees served by the appliance's web server (see Alias/Directory in httpd.conf).
WEBROOT_RE='^/(netscaler/ns_gui|netscaler/portal|var/netscaler/logon|var/netscaler/gui|var/netscaler/help|var/vpns?|var/ns_gui|var/gui)/'
# Vendor trees whose stock content matches webshell markers (e.g. shell_exec,
# eval($_ in Perl modules, base64_decode( in the ADM agent).
VENDOR_MARKER_RE='^/(var/netscaler/gui/admin_ui|netscaler/ns_gui/admin_ui|var/netscaler/websocketd|netscaler/websocketd|var/perl5|var/mastools)/'
SCRIPT_EXT_RE='\.(php[0-9]?|phtml|phar|pl|py|pyc|cgi|sh|bash|jsp|lua)$'
BINARY_EXT_RE='\.(so|elf|bin)$'
INTERP_RE='^(sh|bash|csh|tcsh|ksh|zsh|dash|perl[0-9.]*|python[0-9.]*|php[0-9.]*|ruby[0-9.]*|lua[0-9.]*|node)$'
# httpd <Files>/<FilesMatch> blocks for dot-files other than the stock .ht*.
HIDDEN_FILES_RE='^<Files[[:space:]]+"?\.([^h]|h[^t])'
HIDDEN_FILESMATCH_RE='^<FilesMatch[[:space:]]+"?\^\\?\.([^h]|h[^t])'
SUSPICIOUS_CMD_RE='b64decode|base64 -d|openssl (enc|base64) .*-d|/dev/tcp/|nc -e|(curl|wget|fetch)[^|]*\|[[:space:]]*(sh|bash|perl|python[0-9.]*|php)([[:space:]]|$)'

usage() {
    cat <<USAGE
Usage: $0 [-nocolour] {baseline|check|hunt} HOST [HOST ...]

  baseline  Collect and save trusted baseline(s) on this management host
  check     Compare current inventory with saved baseline(s), and hunt
  hunt      Collect and run current-state checks without requiring baseline

Options:
  -nocolour, --no-colour   Plain output (also: -nocolor, --no-color, NO_COLOR=1)
  --colour, --color        Colour even when stdout is not a terminal
  -noiocs, --no-iocs       Generic checks only; skip the known-indicator list
  -progress, --progress    Show collection progress on stderr
  -h, --help               Show this help

Output markers: [!] HIGH, [*] WARNING, [i] INFO, [+] no drift, [-] review item,
[x] error. Colour is used by default when stdout is a terminal.

Environment:
  STATE_ROOT       Local trusted state directory (default: ~/.local/state/netscaler-hunt)
  COLLECT_MODE     stream (default: send the collector over SSH on each run; nothing
                   stored on the ADC) or installed (run REMOTE_PATH on the ADC)
  SSH_USER         SSH account (default: nsroot)
  SSH_OPTS         Additional SSH options, e.g. "-i ~/.ssh/adc_key -o BatchMode=yes"
  REMOTE_PATH      Collector path on each ADC in installed mode
                   (default: /nsconfig/scripts/ns-inventory.sh)
  MAX_HASH_SIZE    Skip hashing larger files (default: 100 MiB)
  ALLOWLIST_DEFAULT  Suppression list shipped with the tool (default: ./allowlist.default)
  IOC_FILE         Optional known-indicator list (default: ./iocs.conf)

In stream mode, SCAN_ROOTS, EXCLUDE_RE, SUID_ROOTS, MARKER_ROOTS, MARKER_RE,
POSTBOOT_GRACE and LOG_HUNT are passed to the collector when set.

Findings matching a line in ALLOWLIST_DEFAULT, STATE_ROOT/allowlist or
STATE_ROOT/HOST/allowlist are suppressed and counted in the summary.
The baseline remains local and is never updated by check.
USAGE
}

use_colour=0
[[ -t 1 && -z ${NO_COLOR:-} ]] && use_colour=1
args=()
for arg in "$@"; do
    case "$arg" in
        -nocolour|-nocolor|--no-colour|--no-color) use_colour=0 ;;
        -colour|-color|--colour|--color) use_colour=1 ;;
        -noiocs|--no-iocs) use_iocs=0 ;;
        -progress|--progress) show_progress=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown option: $arg" >&2; usage >&2; exit 2 ;;
        *) args+=("$arg") ;;
    esac
done
set -- ${args[@]+"${args[@]}"}
if (( use_colour )); then
    C_HIGH=$'\e[1;31m' C_WARN=$'\e[1;33m' C_INFO=$'\e[1;34m' C_OK=$'\e[1;32m'
    C_HEAD=$'\e[1;36m' C_DIM=$'\e[2m' C_BOLD=$'\e[1m' C_OFF=$'\e[0m'
else
    C_HIGH='' C_WARN='' C_INFO='' C_OK='' C_HEAD='' C_DIM='' C_BOLD='' C_OFF=''
fi

[[ $# -ge 2 ]] || { usage >&2; exit 2; }
ACTION=$1; shift
case "$ACTION" in baseline|check|hunt) ;; *) usage >&2; exit 2 ;; esac
case "$COLLECT_MODE" in installed|stream) ;; *) printf '%s[x]%s ERROR: COLLECT_MODE must be installed or stream\n' "$C_HIGH" "$C_OFF" >&2; exit 2 ;; esac

findings=0
suppressed=0
errors=0
allow=()
ssh_args=()
# SSH_OPTS is intentionally whitespace-split to allow normal ssh option syntax.
if [[ -n "$SSH_OPTS" ]]; then read -r -a ssh_args <<< "$SSH_OPTS"; fi

cleanup_tmpdir() {
    [[ -n ${tmpdir:-} && -d $tmpdir ]] || return 0
    find "$tmpdir" -type f -delete 2>/dev/null || return 1
    rmdir "$tmpdir" 2>/dev/null || return 1
}

section() { printf '\n%s--[ %s ]--%s\n' "$C_HEAD" "$1" "$C_OFF"; }
ok() { printf '%s[+]%s %s\n' "$C_OK" "$C_OFF" "$1"; }
note() { printf '%s[i]%s %s\n' "$C_INFO" "$C_OFF" "$1"; }
err() { printf '%s[x] ERROR:%s %s\n' "$C_HIGH" "$C_OFF" "$1" >&2; errors=$((errors + 1)); }
review() { printf '%s[-]%s %s\n' "$C_DIM" "$C_OFF" "$1"; }
# Print a newline-separated list of review items.
review_block() {
    local line
    while IFS= read -r line; do [[ -n $line ]] && review "${line#  }"; done <<< "$1"
}

load_allowlist() {
    local f line
    allow=()
    for f in "$@"; do
        [[ -f $f ]] || continue
        while IFS= read -r line || [[ -n $line ]]; do
            [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
            allow+=("$line")
        done < "$f"
    done
}

report_finding() {
    local text="[$1] $2" re
    for re in ${allow[@]+"${allow[@]}"}; do
        if [[ $text =~ $re ]]; then suppressed=$((suppressed + 1)); return; fi
    done
    case "$1" in
        HIGH) printf '%s[!] %-7s%s %s\n' "$C_HIGH" "$1" "$C_OFF" "$2" ;;
        WARNING) printf '%s[*] %-7s%s %s\n' "$C_WARN" "$1" "$C_OFF" "$2" ;;
        *) printf '%s[i] %-7s%s %s\n' "$C_INFO" "$1" "$C_OFF" "$2" ;;
    esac
    findings=$((findings + 1))
}

# Known-indicator layer: build matchers from IOC_FILE (see its header).
IOC_PATH_RE='' IOC_NAME_RE='' IOC_IP_RE='' IOC_USER_RE='' IOC_CONTENT_RE='' IOC_LOG_RE=''
declare -A ioc_sha=()
ioc_ports=()
ioc_count=0
load_iocs() {
    local type value rest
    (( use_iocs )) && [[ -f $IOC_FILE ]] || return 0
    while read -r type value rest; do
        [[ -z $type || $type == \#* ]] && continue
        case "$type" in
            path) IOC_PATH_RE+="${IOC_PATH_RE:+|}($value)" ;;
            name) IOC_NAME_RE+="${IOC_NAME_RE:+|}($value)" ;;
            sha256) ioc_sha[${value,,}]=1 ;;
            ip) IOC_IP_RE+="${IOC_IP_RE:+|}${value//./\\.}" ;;
            user) IOC_USER_RE+="${IOC_USER_RE:+|}^($value)\$" ;;
            content) IOC_CONTENT_RE+="${IOC_CONTENT_RE:+|}$value" ;;
            log) IOC_LOG_RE+="${IOC_LOG_RE:+|}$value" ;;
            port) ioc_ports+=("$value") ;;
            *) printf '%s[*]%s ignoring unknown IOC type in %s: %s\n' "$C_WARN" "$C_OFF" "$IOC_FILE" "$type" >&2; continue ;;
        esac
        ioc_count=$((ioc_count + 1))
    done < "$IOC_FILE"
    if [[ -n $IOC_IP_RE ]]; then
        # Addresses are also searched for in logs by the collector.
        IOC_LOG_RE+="${IOC_LOG_RE:+|}(^|[^0-9.])($IOC_IP_RE)([^0-9]|\$)"
        IOC_IP_RE="(^|[^0-9.])($IOC_IP_RE)([^0-9]|\$)"
    fi
}

# True when an octal mode string carries the setuid or setgid bit.
has_suid_bits() { [[ $1 =~ ^[0-7]+$ ]] && (( (8#$1 >> 9) & 6 )); }
fmt_time() { printf '%(%Y-%m-%d %H:%M:%S %z)T' "$1"; }

# Single-quote a value for POSIX sh.
sq() { local s=${1//\'/\'\\\'\'}; printf "'%s'" "$s"; }

# Remote command for stream mode: the collector, prefixed with settings, is
# gzipped and base64-encoded into the command line and decoded by the ADC's
# own openssl/gunzip into sh; nothing is written to the appliance. Each run is
# tagged with a per-host token so the collector can leave its own invocations
# out of the bash.log check.
stream_command() {
    local hostdir=$1 tagfile=$1/run-tag token payload v
    if [[ ! -s $tagfile ]]; then
        (umask 077; od -An -N12 -tx1 /dev/urandom | tr -d ' \n' > "$tagfile") || return 1
    fi
    token=$(<"$tagfile")
    payload=$( {
        for v in "${STREAM_VARS[@]}"; do
            [[ -n ${!v+x} ]] && printf '%s=%s\n' "$v" "$(sq "${!v}")"
        done
        printf 'MAX_HASH_SIZE=%s\nOWN_RUN_RE=%s\n' "$(sq "$MAX_HASH_SIZE")" "$(sq "nsdrifter-$token")"
        printf 'IOC_MARKER_RE=%s\nIOC_LOG_RE=%s\n' "$(sq "$IOC_CONTENT_RE")" "$(sq "$IOC_LOG_RE")"
        cat "$COLLECTOR"
    } | gzip -9n | base64 | tr -d '\n') || return 1
    printf 'shell ": nsdrifter-%s; echo %s | openssl base64 -d -A | gunzip | sh"' "$token" "$payload"
}

collect() {
    local host=$1 out=$2 hostdir=$3 remote qpath
    if [[ $COLLECT_MODE == stream ]]; then
        remote=$(stream_command "$hostdir") || { err "cannot build stream payload from $COLLECTOR"; return 1; }
    else
        # Quote the configured path as one shell argument.
        printf -v qpath '%q' "$REMOTE_PATH"
        remote="shell $qpath"
    fi
    local rc expected=
    if (( show_progress )); then
        # Expected file count for the percentage: this host's previous run.
        for prev in "$hostdir/inventory.latest" "$hostdir/inventory.baseline"; do
            [[ -f $prev ]] && { expected=$(grep -c $'^FILE\t' "$prev"); break; }
        done
        ssh -n "${ssh_args[@]}" "${SSH_USER}@${host}" "$remote" | progress_reader "$out" "$host" "$expected"
        rc=${PIPESTATUS[0]}
    else
        ssh -n "${ssh_args[@]}" "${SSH_USER}@${host}" "$remote" > "$out"
        rc=$?
    fi
    if (( rc != 0 )); then
        err "inventory collection failed for $host"
        return 1
    fi
    if ! grep -q $'^META\tHOST\t' "$out"; then
        err "no valid inventory received from $host (check SSH shell invocation and collector path)"
        return 1
    fi
}

# Collector stages in output order, with rough shares of collection time on
# a 14.1 VPX (the file inventory dominates).
PROGRESS_STAGES=(processes files suid sockets persistence conf scripts markers cores integrity logs)
PROGRESS_WEIGHTS=(2 55 8 1 1 1 6 14 1 5 6)

# Copy collector output to a file while drawing a status line on stderr:
# stage, overall bar, file count (against the previous run's) and elapsed
# time. Without a terminal on stderr, one plain line per stage is printed.
progress_reader() {
    local out=$1 host=$2 expected=${3:-0} line stage=connecting idx=-1 files=0 tty=0 start=$SECONDS
    [[ -t 2 ]] && tty=1
    exec 3> "$out"
    progress_draw
    while IFS= read -r line || [[ -n $line ]]; do
        printf '%s\n' "$line" >&3
        case "$line" in
            STAGE$'\t'*)
                stage=${line#STAGE$'\t'}
                for idx in "${!PROGRESS_STAGES[@]}"; do [[ ${PROGRESS_STAGES[idx]} == "$stage" ]] && break; done
                progress_draw
                ;;
            FILE$'\t'*)
                files=$((files + 1))
                (( files % 200 == 0 )) && progress_draw
                ;;
        esac
    done
    exec 3>&-
    stage='done' idx=${#PROGRESS_STAGES[@]}
    progress_draw
    (( tty )) && printf '\r\e[K' >&2
}

progress_draw() {
    local pct=0 i done_w=0 total_w=0 frac=0 bar width=24 fill detail elapsed=$((SECONDS - start))
    for i in "${!PROGRESS_WEIGHTS[@]}"; do
        total_w=$((total_w + PROGRESS_WEIGHTS[i]))
        (( i < idx )) && done_w=$((done_w + PROGRESS_WEIGHTS[i]))
    done
    # Within the file stage, advance by files seen against the expected count.
    if [[ $stage == files ]] && (( expected > 0 )); then
        frac=$(( files * 100 / expected )); (( frac > 99 )) && frac=99
        done_w=$((done_w * 100 + PROGRESS_WEIGHTS[idx] * frac))
    else
        done_w=$((done_w * 100))
    fi
    (( idx >= 0 )) && pct=$(( done_w / total_w ))
    (( pct > 100 )) && pct=100
    detail=$stage
    [[ $stage == files ]] && detail+=" ${files}${expected:+/$expected}"
    [[ $stage == files && $expected == 0 ]] && detail="files $files"
    if (( tty )); then
        fill=$(( pct * width / 100 ))
        printf -v bar '%*s' "$fill" ''; bar=${bar// /#}
        printf -v bar '%s%*s' "$bar" $((width - fill)) ''; bar=${bar// /-}
        printf '\r\e[K%s%s%s [%s] %3d%%  %-24s %d:%02d' "$C_HEAD" "$host" "$C_OFF" "$bar" "$pct" "$detail" \
            $((elapsed / 60)) $((elapsed % 60)) >&2
    elif [[ $detail != "${last_detail:-}" && ( $stage != files || $files == 0 ) ]]; then
        printf '[%s] %s: %s (%d%%, %ds)\n' "$(date +%T)" "$host" "$stage" "$pct" "$elapsed" >&2
    fi
    last_detail=$detail
}

split_inventory() {
    local inventory=$1 dir=$2
    awk -F '\t' '$1=="PROCESS" {cmd=$5; for(i=6;i<=NF;i++) cmd=cmd "\t" $i; print $2 "|" cmd}' "$inventory" | LC_ALL=C sort > "$dir/processes"
    awk -F '\t' '$1=="FILE" {print $2 "|" $3 "|" $4 "|" $5 "|" $6 "|" $7 "|" $8}' "$inventory" | LC_ALL=C sort -t '|' -k1,1 > "$dir/files"
    awk -F '\t' '$1=="SUID" {print $2 "|" $3 "|" $4 "|" $5 "|" $6}' "$inventory" | LC_ALL=C sort -t '|' -k1,1 > "$dir/suid"
    awk -F '\t' '$1=="CONF" {l=$3; for(i=4;i<=NF;i++) l=l "\t" $i; print $2 "|" l}' "$inventory" | LC_ALL=C sort -u > "$dir/conf"
    awk -F '\t' '$1=="MARKER" {print $2 "|" $3}' "$inventory" | LC_ALL=C sort -u > "$dir/markers"
    # sockstat: USER COMMAND PID FD PROTO LOCAL FOREIGN; keyed without pid/fd
    # so worker processes and restarts do not count as drift.
    awk -F '\t' '$1=="LISTENER" {n=split($2, w, " "); if (n >= 6) print w[1] "|" w[2] "|" w[5] "|" w[6]}' "$inventory" | LC_ALL=C sort -u > "$dir/listeners"
}

compare_processes() {
    local old=$1 cur=$2 inventory=$3 line
    section 'Process drift'
    if cmp -s "$old" "$cur"; then ok 'No process drift detected.'; return; fi
    # Rows are keyed on user|command; pids are not baselined, so list the
    # current pids of each new or changed pair to aid follow-up.
    while IFS= read -r line; do report_finding WARNING "$line"; done < <(awk -F '\t' '
      FILENAME==ARGV[1] { a[$0]++; next }
      FILENAME==ARGV[2] { b[$0]++; next }
      $1=="PROCESS" {
        cmd=$5; for (i=6; i<=NF; i++) cmd=cmd "\t" $i
        k=$2 "|" cmd
        pids[k]=pids[k] (pids[k]=="" ? "" : ", ") $3 " (ppid " $4 ")"
      }
      function show(k,   u, c) { u=k; sub(/\|.*/, "", u); c=k; sub(/^[^|]*\|/, "", c); return "user=" u " command=" c }
      END {
        for (k in a) if (!(k in b)) printf "MISSING PROCESS: %s (baseline instances: %d)\n", show(k), a[k]
        for (k in b) if (!(k in a)) printf "NEW PROCESS: %s pids: %s\n", show(k), pids[k]
        for (k in a) if ((k in b) && a[k]!=b[k]) printf "PROCESS COUNT CHANGED: %s: %d -> %d pids: %s\n", show(k), a[k], b[k], pids[k]
      }' "$old" "$cur" "$inventory" | LC_ALL=C sort)
}

compare_suid() {
    local old=$1 cur=$2 line
    section 'Setuid/setgid drift'
    if cmp -s "$old" "$cur"; then ok 'No setuid/setgid drift detected.'; return; fi
    while IFS= read -r line; do report_finding HIGH "NEW SETUID/SETGID FILE: $line"; done < <(
        awk -F'|' 'FNR==NR {o[$1]=1; next} !($1 in o)' "$old" "$cur")
    while IFS= read -r line; do report_finding HIGH "MODIFIED SETUID/SETGID FILE: $line"; done < <(
        awk -F'|' 'FNR==NR {o[$1]=$0; next} ($1 in o) && o[$1]!=$0 {print $1 " | old={" o[$1] "} new={" $0 "}"}' "$old" "$cur")
    while IFS= read -r line; do report_finding INFO "SETUID/SETGID FILE GONE OR BIT CLEARED: $line"; done < <(
        awk -F'|' 'FNR==NR {n[$1]=1; next} !($1 in n)' "$cur" "$old")
}

# Persistence-relevant configuration lines (cron, startup scripts, SSH keys,
# httpd directives, ns.conf users/policies), compared line by line.
compare_conf() {
    local old=$1 cur=$2 line
    section 'Configuration drift'
    if cmp -s "$old" "$cur"; then ok 'No configuration drift detected.'; return; fi
    while IFS= read -r line; do report_finding HIGH "CONFIG LINE ADDED: ${line%%|*}: ${line#*|}"; done < <(LC_ALL=C comm -13 "$old" "$cur")
    while IFS= read -r line; do report_finding WARNING "CONFIG LINE REMOVED: ${line%%|*}: ${line#*|}"; done < <(LC_ALL=C comm -23 "$old" "$cur")
}

# Listening sockets (TCP listeners and bound UDP sockets). A new one is a
# bind shell, tunnel or webshell side channel until shown otherwise.
compare_listeners() {
    local old=$1 cur=$2 line user cmd proto addr
    section 'Listener drift'
    if cmp -s "$old" "$cur"; then ok 'No listener drift detected.'; return; fi
    while IFS='|' read -r user cmd proto addr; do
        report_finding HIGH "NEW LISTENER: $proto $addr process=$cmd user=$user"
    done < <(LC_ALL=C comm -13 "$old" "$cur")
    while IFS='|' read -r user cmd proto addr; do
        report_finding INFO "LISTENER GONE: $proto $addr process=$cmd user=$user"
    done < <(LC_ALL=C comm -23 "$old" "$cur")
}

compare_markers() {
    local old=$1 cur=$2 line
    section 'Webshell/implant marker drift'
    if cmp -s "$old" "$cur"; then ok 'No marker drift detected.'; return; fi
    while IFS= read -r line; do
        if [[ ${line%%|*} =~ $VENDOR_MARKER_RE ]]; then
            report_finding WARNING "NEW CONTENT MARKER IN VENDOR TREE: ${line%%|*}: ${line#*|}"
        else
            report_finding HIGH "NEW CONTENT MARKER: ${line%%|*}: ${line#*|}"
        fi
    done < <(LC_ALL=C comm -13 "$old" "$cur")
}

# Finding label for an inventory type: FILE, DIRECTORY, SYMLINK, SOCKET, ...
kind_of() {
    case "$1" in
        'Regular File') printf FILE ;;
        Directory) printf DIRECTORY ;;
        'Symbolic Link') printf SYMLINK ;;
        *) printf '%s' "${1^^}" ;;
    esac
}

compare_files() {
    local old=$1 cur=$2 event data path base before after kind
    local otype ouid ogid omodehash ntype nuid ngid nmodehash
    local f0=$findings s0=$suppressed
    section 'Filesystem drift'
    awk -F'|' '
      FNR==NR {old[$1]=$0; next}
      {new[$1]=$0; if (!($1 in old)) print "ADDED|" $0; else if ($0!=old[$1]) print "CHANGED|" old[$1] "\t" $0}
      END {for (p in old) if (!(p in new)) print "REMOVED|" old[p]}
    ' "$old" "$cur" > "${cur}.diff"
    while IFS='|' read -r event data; do
        case "$event" in
          ADDED)
            IFS='|' read -r path ntype _ _ _ _ nmodehash <<< "$data"
            base=${path##*/}; kind=$(kind_of "$ntype")
            if has_suid_bits "${nmodehash%%:*}"; then report_finding HIGH "NEW SETUID/SETGID $kind: $data"
            elif [[ $path =~ $WEBROOT_RE ]]; then report_finding HIGH "NEW $kind IN WEB ROOT: $data"
            elif [[ $path == */.* ]]; then report_finding HIGH "NEW HIDDEN $kind: $data"
            else
                case "$path" in /tmp/*|/var/tmp/*) report_finding HIGH "NEW $kind IN TEMPORARY LOCATION: $data";; *) report_finding WARNING "NEW $kind: $data";; esac
            fi
            ;;
          REMOVED)
            IFS='|' read -r _ otype _ <<< "$data"
            report_finding INFO "REMOVED $(kind_of "$otype"): $data"
            ;;
          CHANGED)
            IFS=$'\t' read -r before after <<< "$data"
            IFS='|' read -r path otype _ _ ouid ogid omodehash <<< "$before"
            IFS='|' read -r path ntype _ _ nuid ngid nmodehash <<< "$after"
            # A directory's size and mtime change whenever entries are created
            # or deleted; lasting entries are reported themselves, so only
            # type, owner and mode changes of a directory are of interest.
            if [[ $otype == Directory && $ntype == Directory && $ouid == "$nuid" && $ogid == "$ngid" && $omodehash == "$nmodehash" ]]; then
                continue
            fi
            if [[ $otype == "$ntype" ]]; then kind=$(kind_of "$ntype"); else kind="ENTRY (type $otype -> $ntype)"; fi
            if has_suid_bits "${nmodehash%%:*}" && ! has_suid_bits "${omodehash%%:*}"; then
                report_finding HIGH "SETUID/SETGID BIT ADDED: $path | old={$before} new={$after}"
            elif has_suid_bits "${nmodehash%%:*}"; then
                report_finding HIGH "MODIFIED SETUID/SETGID $kind: $path | old={$before} new={$after}"
            elif [[ $path =~ $WEBROOT_RE ]]; then
                report_finding HIGH "MODIFIED $kind IN WEB ROOT: $path | old={$before} new={$after}"
            else
                report_finding WARNING "MODIFIED $kind: $path | old={$before} new={$after}"
            fi
            ;;
        esac
    done < "${cur}.diff"
    if (( findings == f0 )); then
        if (( suppressed > s0 )); then note "No filesystem drift beyond $((suppressed - s0)) allowlisted change(s)."
        else ok 'No filesystem drift detected.'; fi
    fi
}

# Compare one optional baseline component; baselines made before it existed
# are skipped with a note rather than reporting everything as new.
compare_optional() {
    local fn=$1 title=$2 name=$3
    if [[ -f $hostdir/$name.baseline ]]; then
        "$fn" "$hostdir/$name.baseline" "$tmpdir/$name"
    else
        section "$title"
        note 'Skipped: baseline predates this inventory. Re-run baseline from a known-good state to enable.'
    fi
}

hunt_processes() {
    local user pid ppid command exe target base w words
    while IFS=$'\t' read -r _ user pid ppid command; do
        IFS=' ' read -r -a words <<< "$command"
        exe=${words[0]:-}; target=$exe
        # For interpreters, judge the script they run rather than the binary.
        if [[ ${exe##*/} =~ $INTERP_RE ]]; then
            for w in "${words[@]:1}"; do [[ $w == -* ]] && continue; target=$w; break; done
        fi
        if [[ $exe =~ ^/(tmp|var/tmp|dev/shm)/ || $target =~ ^/(tmp|var/tmp|dev/shm)/ ]]; then
            report_finding HIGH "PROCESS RUNNING FROM TEMPORARY PATH: user=$user pid=$pid ppid=$ppid command=$command"
        elif [[ $exe == */.* || $target == /*/.* ]]; then
            report_finding HIGH "PROCESS RUNNING FROM HIDDEN PATH: user=$user pid=$pid ppid=$ppid command=$command"
        elif [[ $command =~ $SUSPICIOUS_CMD_RE ]]; then
            report_finding HIGH "SUSPICIOUS PROCESS COMMAND: user=$user pid=$pid ppid=$ppid command=$command"
        fi
    done < <(awk -F '\t' '$1=="PROCESS"' "$inventory")
}

hunt_files() {
    local path type size mtime uid gid modehash mode hash base exec
    while IFS='|' read -r path type size mtime uid gid modehash; do
        [[ -n $path ]] || continue
        mode=${modehash%%:*}; hash=${modehash#*:}; base=${path##*/}
        exec=0
        [[ $type == 'Regular File' && $mode =~ ^[0-7]+$ ]] && (( 8#$mode & 8#111 )) && exec=1
        if [[ $type == 'Regular File' && $path =~ ^/netscaler/portal/templates/[^/]+\.xml$ ]]; then
            report_finding HIGH "XML TEMPLATE IN PORTAL TEMPLATES (CVE-2019-19781 TECHNIQUE): $path size=$size hash=$hash"
            continue
        fi
        if [[ $type == 'Regular File' && $path =~ ^/var/vpn/bookmark/ ]]; then
            report_finding WARNING "FILE IN VPN BOOKMARK STORE (CVE-2019-19781 TECHNIQUE): $path size=$size hash=$hash"
            continue
        fi
        if [[ $path =~ $WEBROOT_RE ]]; then
            if [[ $path == */.* ]]; then
                report_finding HIGH "HIDDEN ENTRY IN WEB ROOT: $path type=$type size=$size mode=$mode hash=$hash"
            elif [[ $type == 'Regular File' && $base == *.sig ]]; then
                report_finding HIGH ".SIG FILE IN WEB ROOT (WEBSHELL TECHNIQUE, NONE IN STOCK): $path size=$size mode=$mode hash=$hash"
            elif [[ $type == 'Regular File' && $path == /var/netscaler/logon/* && $base =~ $SCRIPT_EXT_RE ]]; then
                if [[ $path == */custom/* ]]; then
                    report_finding HIGH "SERVER-SIDE SCRIPT IN LOGON CUSTOMIZATION: $path size=$size mode=$mode hash=$hash"
                else
                    report_finding WARNING "SERVER-SIDE SCRIPT IN LOGON PORTAL: $path size=$size mode=$mode hash=$hash"
                fi
            fi
            continue
        fi
        if [[ $type == Directory ]]; then
            [[ $base == .* ]] && report_finding WARNING "HIDDEN DIRECTORY: $path mode=$mode uid=$uid gid=$gid"
            continue
        fi
        # Links, sockets and pipes live in /tmp or carry x bits routinely.
        [[ $type == 'Regular File' ]] || continue
        case "$path" in
            /tmp/*|/var/tmp/*)
                if (( exec )); then
                    report_finding HIGH "EXECUTABLE FILE IN TEMPORARY LOCATION: $path size=$size mode=$mode hash=$hash"
                elif [[ ${path%/*} == */.* ]]; then
                    report_finding HIGH "FILE IN HIDDEN TEMPORARY DIRECTORY: $path size=$size mode=$mode hash=$hash"
                fi
                continue
                ;;
        esac
        if [[ ${path%/*} == */.* ]] && (( exec )); then
            report_finding HIGH "EXECUTABLE FILE IN HIDDEN DIRECTORY: $path size=$size mode=$mode hash=$hash"
        elif [[ ${path%/*} == */.* ]]; then
            report_finding WARNING "FILE IN HIDDEN DIRECTORY: $path size=$size mode=$mode hash=$hash"
        elif [[ $path =~ ^/var/[^/]+$ && ( $base =~ $SCRIPT_EXT_RE || $base =~ $BINARY_EXT_RE || $exec == 1 ) ]]; then
            report_finding HIGH "SCRIPT OR EXECUTABLE AT TOP OF /var: $path size=$size mode=$mode hash=$hash"
        elif [[ $path == /nsconfig/* || $path == /flash/* ]]; then
            if [[ $base =~ $SCRIPT_EXT_RE || $base =~ $BINARY_EXT_RE ]]; then
                report_finding WARNING "SCRIPT OR BINARY IN CONFIG/FLASH AREA: $path size=$size mode=$mode hash=$hash"
            elif (( exec )); then
                report_finding WARNING "EXECUTABLE IN CONFIG/FLASH AREA: $path size=$size mode=$mode hash=$hash"
            fi
        fi
    done < <(awk -F '\t' '$1=="FILE" {print $2 "|" $3 "|" $4 "|" $5 "|" $6 "|" $7 "|" $8}' "$inventory")
}

hunt_suid() {
    local path mode uid gid hash base suid_listing=
    # Setuid/setgid shells, interpreters and file tools are root shells in
    # waiting; so is any setuid/setgid file in writable or config areas.
    while IFS='|' read -r path mode uid gid hash; do
        [[ -n $path ]] || continue
        base=${path##*/}
        if [[ $base =~ ^(sh|csh|tcsh|bash|ksh|ksh93|mksh|zsh|dash|rbash|perl[0-9.]*|python[0-9.]*|php[0-9.]*|ruby[0-9.]*|lua[0-9.]*|tclsh[0-9.]*|expect|awk|nawk|gawk|find|env|vi|vim|ex|view|nvi|less|more|nc|ncat|socat|dd|cp|mv|tee|tar|busybox|gdb|script|xargs|nice|timeout|stdbuf)$ ]]; then
            report_finding HIGH "SETUID/SETGID SHELL OR INTERPRETER: $path mode=$mode uid=$uid gid=$gid hash=$hash"
        elif [[ $path == /tmp/* || $path == /var/* || $path == /nsconfig/* || $path == /flash/* || $path == /home/* || $path == /root/* || $path == */.* ]]; then
            report_finding HIGH "SETUID/SETGID FILE IN UNEXPECTED LOCATION: $path mode=$mode uid=$uid gid=$gid hash=$hash"
        else
            suid_listing+="  $path mode=$mode uid=$uid gid=$gid hash=$hash"$'\n'
        fi
    done < <(awk -F '\t' '$1=="SUID" {print $2 "|" $3 "|" $4 "|" $5 "|" $6}' "$inventory")
    section 'Other setuid/setgid files (review, not counted)'
    review_block "$suid_listing"
}

# The root filesystem is a memory disk rebuilt from the firmware image at
# boot, so a root-fs file whose inode changed well after boot was modified at
# runtime (content, mode or owner), e.g. 'chmod 6555 /bin/sh'.
hunt_postboot() {
    local path type ctime mtime mode listing=
    while IFS=$'\t' read -r _ path type ctime mtime mode; do
        case "$path" in
            /etc/*|/root/*) listing+="  $path changed=$(fmt_time "$ctime") modified=$(fmt_time "$mtime") mode=$mode"$'\n' ;;
            *) report_finding HIGH "ROOT FS FILE CHANGED AFTER BOOT: $path changed=$(fmt_time "$ctime") modified=$(fmt_time "$mtime") mode=$mode" ;;
        esac
    done < <(awk -F '\t' '$1=="POSTBOOT"' "$inventory")
    section 'Root filesystem files in /etc and /root changed after boot (review, not counted)'
    review_block "$listing"
}

hunt_integrity() {
    local path kind want got
    while IFS=$'\t' read -r _ path kind want got; do
        if [[ $kind == MISMATCH ]]; then
            report_finding HIGH "VENDOR MANIFEST HASH MISMATCH: $path expected=$want actual=$got"
        else
            report_finding WARNING "FILE LISTED IN VENDOR MANIFEST IS MISSING: $path"
        fi
    done < <(awk -F '\t' '$1=="INTEGRITY_FAIL"' "$inventory")
}

# Describe the collector's base64-literal analysis of a marker file.
b64_note() {
    case "$1" in
        -) printf 'embedded base64: <NONE DETECTED>' ;;
        '') printf 'embedded base64: not analysed (older collector)' ;;
        *) printf 'embedded base64: %s' "$1" ;;
    esac
}

hunt_markers() {
    local path match b64 listing=
    while IFS=$'\t' read -r _ path match b64; do
        if [[ $path =~ $VENDOR_MARKER_RE ]]; then
            listing+="  $path: $match -- $(b64_note "$b64")"$'\n'
            [[ -n $b64 && $b64 != - ]] &&
                report_finding WARNING "BASE64 LITERAL DECODED IN VENDOR FILE: $path: $(b64_note "$b64")"
        else
            report_finding HIGH "WEBSHELL/IMPLANT MARKER IN FILE: $path: $match -- $(b64_note "$b64")"
        fi
    done < <(awk -F '\t' '$1=="MARKER"' "$inventory")
    section 'Content markers in vendor trees (review, not counted)'
    review_block "$listing"
}

hunt_conf() {
    local file line cmd users='' keys=''
    while IFS=$'\t' read -r _ file line; do
        case "$file" in
          /etc/httpd*)
            if [[ $line =~ ^php_(admin_)?flag[[:space:]]+engine[[:space:]]+on ]]; then
                report_finding HIGH "PHP ENGINE ENABLED IN HTTPD CONFIG: $file: $line"
            elif [[ $line =~ ^#[[:space:]]*php_(admin_)?flag[[:space:]]+engine[[:space:]]+off ]]; then
                report_finding HIGH "PHP ENGINE RESTRICTION COMMENTED OUT IN HTTPD CONFIG: $file: $line"
            elif [[ $line =~ ^AddType[[:space:]]+application/x-httpd-php[[:space:]] && $line =~ [[:space:]]\.[A-Za-z0-9]+ && ! $line =~ ^AddType[[:space:]]+application/x-httpd-php(-source)?([[:space:]]+\.phps?)+[[:space:]]*$ ]]; then
                report_finding HIGH "HTTPD MAPS NON-STANDARD EXTENSION TO PHP: $file: $line"
            elif [[ $line =~ ^(AddHandler|SetHandler)[[:space:]].*php ]]; then
                report_finding HIGH "HTTPD PHP HANDLER DIRECTIVE (NONE IN STOCK): $file: $line"
            elif [[ $line =~ ^AliasMatch[[:space:]] ]]; then
                if [[ $line =~ (\.sig|\.php|\.deb|scripts/linux|LogonPoint/custom|/tmp/|/\.)|\.(ico|css|png|gif|jpg|js)\$?[[:space:]] ]]; then
                    report_finding HIGH "HTTPD ALIASMATCH ROUTING TO WEBSHELL-LIKE TARGET: $file: $line"
                else
                    report_finding WARNING "HTTPD ALIASMATCH (NONE IN STOCK CONFIG): $file: $line"
                fi
            elif [[ $line =~ $HIDDEN_FILES_RE || $line =~ $HIDDEN_FILESMATCH_RE ]]; then
                report_finding HIGH "HTTPD RULE FOR HIDDEN FILE: $file: $line"
            elif [[ $line =~ ^(Alias|ScriptAlias|ScriptAliasMatch)[[:space:]] && $line =~ (LogonPoint/custom|/tmp/|/var/tmp/|/\.|\.sig|\.php) ]]; then
                report_finding HIGH "HTTPD ALIAS TO SUSPICIOUS LOCATION: $file: $line"
            fi
            ;;
          */rc.netscaler|*/nsbefore.sh|*/nsafter.sh)
            if [[ $line =~ python|perl[[:space:]]+-e|base64|b64decode|curl[[:space:]]|wget[[:space:]]|/var/tmp/|/tmp/|httpd\.conf|apachectl|chmod[[:space:]]+[0-7]*[2467][0-7]{3}|chmod[[:space:]]+[ugoa]*\+[rwx]*s ]]; then
                report_finding HIGH "SUSPICIOUS STARTUP COMMAND: $file: $line"
            fi
            ;;
          *crontab|/var/cron/tabs/*)
            cmd=$line
            # lockf's lock file argument routinely lives in /tmp.
            [[ $cmd =~ lockf([[:space:]]+-[a-z]+([[:space:]]+[0-9]+)?)*[[:space:]]+[^[:space:]]+ ]] && cmd=${cmd/"${BASH_REMATCH[0]}"/lockf}
            if [[ $cmd =~ (/tmp/|/var/tmp/|/dev/shm/|/\.[^/[:space:]]) || $cmd =~ $SUSPICIOUS_CMD_RE ||
                  $cmd =~ ^([^[:space:]]+[[:space:]]+){5}nobody[[:space:]] ||
                  ( $cmd =~ ([0-9]{1,3}\.){3}[0-9]{1,3} && ! $cmd =~ 127\.0\.0\.1 ) ||
                  ( $cmd =~ (curl|wget|fetch)[[:space:]] && ! $cmd =~ (curl|wget|fetch)[^|]*://(localhost|127\.0\.0\.1)([:/[:space:]]|$) ) ]]; then
                report_finding HIGH "SUSPICIOUS CRON ENTRY: $file: $line"
            fi
            ;;
          /nsconfig/ns.conf)
            if [[ $line =~ ^add\ system\ user\ ([^ ]+) ]]; then
                users+=" ${BASH_REMATCH[1]}"
            fi
            ;;
          *authorized_keys*)
            keys+="  $file: ${line:0:60}..."$'\n'
            ;;
        esac
    done < <(awk -F '\t' '$1=="CONF" {l=$3; for(i=4;i<=NF;i++) l=l "\t" $i; print $1 "\t" $2 "\t" l}' "$inventory")
    section 'Accounts and SSH keys (review, not counted)'
    review "ns.conf system users:${users:- none besides nsroot}"
    review_block "$keys"
}

hunt_confmarks() {
    local path match
    while IFS=$'\t' read -r _ path match; do
        report_finding HIGH "TAMPERING STRING IN CONFIG/STARTUP FILE: $path: $match"
    done < <(awk -F '\t' '$1=="CONFMARK"' "$inventory")
}

# Server-side scripts outside the vendor admin GUI (collector sweep).
hunt_scripts() {
    local path size mtime mode hash
    while IFS=$'\t' read -r _ path size mtime mode hash; do
        report_finding HIGH "SERVER-SIDE SCRIPT OUTSIDE VENDOR ADMIN GUI: $path size=$size mode=$mode modified=$(fmt_time "$mtime") hash=$hash"
    done < <(awk -F '\t' '$1=="SCRIPT"' "$inventory")
}

hunt_cores() {
    local path size mtime
    while IFS=$'\t' read -r _ path size mtime; do
        report_finding WARNING "PACKET ENGINE CORE DUMP (possible exploitation crash): $path size=$size time=$(fmt_time "$mtime")"
    done < <(awk -F '\t' '$1=="CORE"' "$inventory")
}

hunt_pcaps() {
    local path size mtime level
    while IFS=$'\t' read -r _ path size mtime; do
        level=WARNING
        [[ $path =~ $WEBROOT_RE || $path =~ ^/(tmp|var/tmp)/ || $path == */.* ]] && level=HIGH
        report_finding "$level" "PACKET CAPTURE FILE: $path size=$size time=$(fmt_time "$mtime")"
    done < <(awk -F '\t' '$1=="PCAP"' "$inventory")
}

hunt_logs() {
    local file check count level
    while IFS=$'\t' read -r _ file check count; do
        [[ $check == KNOWN_IOC ]] && continue
        case "$check" in WEB_BASE64_BLOB|SYSTEM_USER_CHANGE|NSPPE_CRASH|DTLS_EXPLOIT_ATTEMPT) level=WARNING ;; *) level=HIGH ;; esac
        report_finding "$level" "LOG EVIDENCE $check: $file: $count matching line(s)"
        awk -F '\t' -v f="$file" -v c="$check" -v d="$C_DIM" -v o="$C_OFF" '$1=="LOGSAMPLE" && $2==f && $3==c {print d "      sample: " $4 o}' "$inventory"
    done < <(awk -F '\t' '$1=="LOGHIT"' "$inventory")
}

# Known-indicator matches from IOC_FILE, reported in their own section.
hunt_iocs() {
    local path type size mode hash base rest line file count p lo hi name kind local_addr
    section "Known IOC matches (${IOC_FILE##*/}, $ioc_count indicators)"
    (( use_iocs )) || { note 'Skipped (-noiocs).'; return; }
    (( ioc_count )) || { note "No indicators loaded from $IOC_FILE."; return; }
    local f0=$findings s0=$suppressed
    while IFS=$'\t' read -r kind path type size mode hash; do
        base=${path##*/}
        if [[ -n $hash && -n ${ioc_sha[${hash,,}]:-} ]]; then
            report_finding HIGH "KNOWN IOC HASH: $path hash=$hash"
        fi
        if [[ ( -n $IOC_PATH_RE && $path =~ $IOC_PATH_RE ) || ( -n $IOC_NAME_RE && $base =~ $IOC_NAME_RE ) ]]; then
            report_finding HIGH "KNOWN IOC PATH: $path type=$type size=$size mode=$mode hash=$hash"
        fi
    done < <(awk -F '\t' '
        $1=="FILE"   { split($8, mh, ":"); h=substr($8, length(mh[1])+2); print "FILE\t" $2 "\t" $3 "\t" $4 "\t" mh[1] "\t" h }
        $1=="SCRIPT" { print "SCRIPT\t" $2 "\tScript\t" $3 "\t" $5 "\t" $6 }
        $1=="SUID"   { print "SUID\t" $2 "\tSetuid/setgid\t-\t" $3 "\t" $6 }' "$inventory" | LC_ALL=C sort -u -t $'\t' -k2,2)
    if [[ -n $IOC_USER_RE ]]; then
        while IFS=$'\t' read -r _ file line; do
            [[ $line =~ ^add\ system\ user\ ([^ ]+) && ${BASH_REMATCH[1]} =~ $IOC_USER_RE ]] &&
                report_finding HIGH "KNOWN IOC SYSTEM USER: $file: $line"
        done < <(awk -F '\t' '$1=="CONF" && $2 ~ /ns\.conf$/' "$inventory")
    fi
    while IFS=$'\t' read -r kind rest; do
        if [[ -n $IOC_IP_RE && $rest =~ $IOC_IP_RE ]]; then
            report_finding HIGH "KNOWN IOC ADDRESS IN CONNECTION: $rest"
        elif [[ $kind == LISTENER && ${#ioc_ports[@]} -gt 0 ]]; then
            read -r _ _ _ _ _ local_addr _ <<< "$rest"
            p=${local_addr##*:}
            [[ $p =~ ^[0-9]+$ ]] || continue
            for name in "${ioc_ports[@]}"; do
                lo=${name%-*}; hi=${name#*-}
                (( p >= lo && p <= hi )) && { report_finding WARNING "LISTENER ON KNOWN IOC PORT ($name): $rest"; break; }
            done
        fi
    done < <(awk -F '\t' '$1=="LISTENER" || $1=="SOCKET"' "$inventory")
    while IFS=$'\t' read -r _ path line; do
        report_finding HIGH "KNOWN IOC CONTENT: $path: $line"
    done < <(awk -F '\t' '$1=="IOCMARKER"' "$inventory")
    while IFS=$'\t' read -r _ file _ count; do
        report_finding HIGH "KNOWN IOC IN LOG: $file: $count matching line(s)"
        awk -F '\t' -v f="$file" -v d="$C_DIM" -v o="$C_OFF" '$1=="LOGSAMPLE" && $2==f && $3=="KNOWN_IOC" {print d "      sample: " $4 o}' "$inventory"
    done < <(awk -F '\t' '$1=="LOGHIT" && $3=="KNOWN_IOC"' "$inventory")
    if [[ $COLLECT_MODE != stream && ( -n $IOC_CONTENT_RE || -n $IOC_LOG_RE ) ]]; then
        note 'Content and log indicators need COLLECT_MODE=stream; installed collectors run only built-in checks.'
    fi
    (( findings == f0 && suppressed == s0 )) && ok 'No known indicators matched.'
}

hunt_current() {
    local inventory=$1
    section 'Current-state checks'
    hunt_processes
    hunt_files
    hunt_integrity
    hunt_scripts
    hunt_confmarks
    hunt_cores
    hunt_pcaps
    hunt_logs
    # The functions below also print review sections after their findings.
    hunt_suid
    hunt_postboot
    hunt_markers
    hunt_conf
    hunt_iocs

    section 'Vendor manifest verification'
    awk -F '\t' -v g="$C_OK" -v i="$C_INFO" -v o="$C_OFF" '
        $1=="INTEGRITY" {printf "%s %s: %d files checked, %d mismatched, %d missing\n", ($4+$5 ? i "[i]" o : g "[+]" o), $2, $3, $4, $5; n++}
        END {if (!n) print i "[i]" o " No .signedexe.manifest files found or perl Digest::SHA unavailable."}' "$inventory"
    section 'Listeners and active sockets'
    awk -F '\t' '$1=="LISTENER" {print "LISTENER " substr($0,index($0,"\t")+1)} $1=="SOCKET" {print "SOCKET   " substr($0,index($0,"\t")+1)}' "$inventory"
    section 'Persistence files'
    awk -F '\t' '$1=="PERSISTENCE" {print $2 " mtime=" $3 " sha=" $4}' "$inventory"
    awk -F '\t' -v w="$C_WARN" -v o="$C_OFF" '$1=="WARN" {print w "[*]" o " Collector warning: " $2 " " $3}' "$inventory"
}

load_iocs

for host in "$@"; do
    if [[ ! $host =~ ^[A-Za-z0-9_.:@-]+$ ]]; then err "unsafe host name: $host"; continue; fi
    printf '\n%s==[ %s | %s | %s ]==%s\n' "$C_BOLD" "$host" "$ACTION" "$(date '+%Y-%m-%d %H:%M:%S %z')" "$C_OFF"
    hostdir="$STATE_ROOT/$host"
    mkdir -p "$hostdir" || { err "cannot create $hostdir"; continue; }
    chmod 700 "$hostdir" 2>/dev/null
    load_allowlist "$ALLOWLIST_DEFAULT" "$STATE_ROOT/allowlist" "$hostdir/allowlist"
    tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/ns-hunt.XXXXXX") || { err "cannot create temporary directory"; continue; }
    trap cleanup_tmpdir EXIT
    if ! collect "$host" "$tmpdir/inventory" "$hostdir"; then cleanup_tmpdir; continue; fi
    split_inventory "$tmpdir/inventory" "$tmpdir"
    case "$ACTION" in
      baseline)
        for part in processes files suid conf markers listeners; do cp "$tmpdir/$part" "$hostdir/$part.baseline"; done
        cp "$tmpdir/inventory" "$hostdir/inventory.baseline"
        chmod 600 "$hostdir"/*.baseline
        ok "Baseline saved locally: $hostdir (protect and back up this directory)."
        ;;
      check)
        if [[ ! -f $hostdir/processes.baseline || ! -f $hostdir/files.baseline ]]; then
            err "no baseline for $host; run '$0 baseline $host' first."; cleanup_tmpdir; continue
        fi
        compare_processes "$hostdir/processes.baseline" "$tmpdir/processes" "$tmpdir/inventory"
        compare_files "$hostdir/files.baseline" "$tmpdir/files"
        compare_optional compare_suid 'Setuid/setgid drift' suid
        compare_optional compare_conf 'Configuration drift' conf
        compare_optional compare_markers 'Webshell/implant marker drift' markers
        compare_optional compare_listeners 'Listener drift' listeners
        hunt_current "$tmpdir/inventory"
        cp "$tmpdir/inventory" "$hostdir/inventory.latest" && chmod 600 "$hostdir/inventory.latest"
        ;;
      hunt)
        hunt_current "$tmpdir/inventory"
        cp "$tmpdir/inventory" "$hostdir/inventory.latest" && chmod 600 "$hostdir/inventory.latest"
        ;;
    esac
    cleanup_tmpdir
done

section Summary
count_line() { # label value colour-when-nonzero
    local c=$C_OK; (( $2 > 0 )) && c=$3
    printf '%s%-28s %s%s\n' "$c" "$1" "$2" "$C_OFF"
}
count_line 'Potential findings:' "$findings" "$C_HIGH"
count_line 'Suppressed by allowlist:' "$suppressed" "$C_DIM"
count_line 'Collection/baseline errors:' "$errors" "$C_HIGH"
(( errors > 0 )) && exit 2
(( findings > 0 )) && exit 1
exit 0
