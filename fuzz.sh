#!/bin/bash
# ==========================================
#  fuzz.sh — Background Fuzzer v3.0
#  Usage: ./fuzz.sh <url> [options]
#         ./fuzz.sh --status
#         ./fuzz.sh --tail <url>
#         ./fuzz.sh --results <url>
#         ./fuzz.sh --kill <url>
# ==========================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

JOBS_DIR="$HOME/.fuzz_jobs"
mkdir -p "$JOBS_DIR"

# ==========================================
# WORDLIST PRESETS
# ==========================================
declare -A WORDLISTS=(
    ["common"]="/usr/share/seclists/Discovery/Web-Content/common.txt"
    ["raft-small"]="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
    ["raft-medium"]="/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
    ["raft-large"]="/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"
    ["api"]="/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
    ["dirs"]="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    ["big"]="/usr/share/seclists/Discovery/Web-Content/big.txt"
    ["params"]="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    ["lfi"]="/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
    ["backup"]="/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt"
)

# ==========================================
# HELPERS
# ==========================================
log_info()    { echo -e "${BLUE}[*]${RESET} $1"; }
log_success() { echo -e "${GREEN}[+]${RESET} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error()   { echo -e "${RED}[✗]${RESET} $1"; }

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "  ███████╗██╗   ██╗███████╗███████╗"
    echo "  ██╔════╝██║   ██║╚══███╔╝╚══███╔╝"
    echo "  █████╗  ██║   ██║  ███╔╝   ███╔╝ "
    echo "  ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  "
    echo "  ██║     ╚██████╔╝███████╗███████╗ "
    echo "  ╚═╝      ╚═════╝ ╚══════╝╚══════╝  v3.0"
    echo -e "${RESET}"
}

usage() {
    print_banner
    echo -e "${BOLD}Launch (runs in background, terminal is free):${RESET}"
    echo "  $0 <url> [options]"
    echo ""
    echo -e "${BOLD}Manage jobs:${RESET}"
    echo "  $0 --status               Show all running/finished jobs"
    echo "  $0 --tail <url>           Live tail log for a target"
    echo "  $0 --results <url>        Print results for a target"
    echo "  $0 --kill <url>           Kill a running job"
    echo "  $0 --killall              Kill all running jobs"
    echo "  $0 --clean                Remove finished job records"
    echo ""
    echo -e "${BOLD}Wordlist presets (--wl):${RESET}"
    for key in $(echo "${!WORDLISTS[@]}" | tr ' ' '\n' | sort); do
        printf "  %-14s %s\n" "$key" "${WORDLISTS[$key]}"
    done
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo "  -w  <path>         Custom wordlist path"
    echo "  --wl <preset>      Wordlist preset (default: common)"
    echo "  --rate <n>         Requests/sec (default: 2)"
    echo "  --threads <n>      Threads (default: 40)"
    echo "  --depth <n>        Recursion depth (default: 2)"
    echo "  --ext <list>       Extensions to append e.g. php,html,js"
    echo "  --mc <codes>       Match HTTP codes (default: 200,201,204,301,302,307,401,403,405)"
    echo "  --fc <codes>       Filter HTTP codes (default: 404,429)"
    echo "  --H <header>       Add header e.g. 'Authorization: Bearer token'"
    echo "  --follow           Follow redirects"
    echo "  --                 Pass remaining args directly to ffuf"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0 one.com                          # https:// added automatically"
    echo "  $0 one.com --wl raft-medium"
    echo "  $0 one.com --ext php,html --rate 4"
    echo "  $0 one.com --H 'Cookie: session=abc'"
    echo "  $0 --status"
    echo "  $0 --tail one.com"
    echo "  $0 --results one.com"
    exit 0
}

url_to_id() {
    echo "$1" | sed 's|https\?://||;s|[/:.?=]|_|g;s|_*$||'
}

count_lines() {
    [ -f "$1" ] && wc -l < "$1" || echo 0
}

# ==========================================
# JOB MANAGEMENT
# ==========================================
show_status() {
    echo ""
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${CYAN}${BOLD}  FUZZ JOB STATUS${RESET}"
    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    local any=false
    printf "  %-45s %-12s %-10s %s\n" "TARGET" "STATUS" "FINDINGS" "STARTED"
    echo "  $(printf '%.0s─' {1..68})"

    for jobfile in "$JOBS_DIR"/*.job 2>/dev/null; do
        [ -f "$jobfile" ] || continue
        any=true
        unset TARGET PID OUTDIR LOGFILE STARTED
        source "$jobfile"

        if kill -0 "$PID" 2>/dev/null; then
            status_str="${GREEN}running${RESET}"
        else
            if grep -q "\[DONE\]" "$LOGFILE" 2>/dev/null; then
                status_str="${BLUE}done${RESET}"
            else
                status_str="${RED}failed?${RESET}"
            fi
        fi

        local findings=0
        for f in "$OUTDIR"/*.txt; do
            [ -f "$f" ] && findings=$((findings + $(wc -l < "$f" 2>/dev/null || echo 0)))
        done

        printf "  %-45s %-22b %-10s %s\n" \
            "${TARGET:0:44}" "$status_str" "$findings" "$STARTED"
    done

    if [ "$any" = false ]; then
        echo "  No jobs found."
    fi

    echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    echo -e "  ${YELLOW}Tail a job  :${RESET} $0 --tail <url>"
    echo -e "  ${YELLOW}See results :${RESET} $0 --results <url>"
    echo ""
}

tail_job() {
    local url="$1"
    [[ "$url" != http* ]] && url="https://$url"
    local id; id=$(url_to_id "$url")
    local jobfile="$JOBS_DIR/${id}.job"

    if [ ! -f "$jobfile" ]; then
        log_error "No job found for: $url"
        log_info  "Run '$0 --status' to see all jobs"
        exit 1
    fi

    source "$jobfile"
    log_info "Tailing: ${BOLD}$TARGET${RESET}  (Ctrl+C stops tailing, job keeps running)"
    echo ""
    tail -f "$LOGFILE"
}

show_results() {
    local url="$1"
    [[ "$url" != http* ]] && url="https://$url"
    local id; id=$(url_to_id "$url")
    local jobfile="$JOBS_DIR/${id}.job"

    if [ ! -f "$jobfile" ]; then
        log_error "No job found for: $url"
        exit 1
    fi

    source "$jobfile"

    echo ""
    echo -e "${CYAN}${BOLD}Results : $TARGET${RESET}"
    echo -e "${CYAN}${BOLD}Dir     : $OUTDIR${RESET}"
    echo ""

    local found=false
    for f in "$OUTDIR"/*.txt; do
        [ -f "$f" ] && [ -s "$f" ] || continue
        found=true
        echo -e "${BOLD}── $(basename "$f") ($(wc -l < "$f") findings) ──${RESET}"
        cat "$f"
        echo ""
    done

    if [ "$found" = false ]; then
        log_warn "No results yet — job may still be running."
        log_info "Live output: $0 --tail $url"
    fi
}

kill_job() {
    local url="$1"
    [[ "$url" != http* ]] && url="https://$url"
    local id; id=$(url_to_id "$url")
    local jobfile="$JOBS_DIR/${id}.job"

    if [ ! -f "$jobfile" ]; then
        log_error "No job found for: $url"
        exit 1
    fi

    source "$jobfile"

    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null
        pkill -P "$PID" 2>/dev/null
        log_success "Killed: $TARGET (PID $PID)"
    else
        log_warn "Job already finished: $TARGET"
    fi
    rm -f "$jobfile"
}

kill_all() {
    local count=0
    for jobfile in "$JOBS_DIR"/*.job 2>/dev/null; do
        [ -f "$jobfile" ] || continue
        source "$jobfile"
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null
            pkill -P "$PID" 2>/dev/null
            log_success "Killed: $TARGET (PID $PID)"
            ((count++))
        fi
        rm -f "$jobfile"
    done
    log_info "Killed $count job(s)"
}

clean_jobs() {
    local count=0
    for jobfile in "$JOBS_DIR"/*.job 2>/dev/null; do
        [ -f "$jobfile" ] || continue
        source "$jobfile"
        if ! kill -0 "$PID" 2>/dev/null; then
            rm -f "$jobfile"
            ((count++))
        fi
    done
    log_success "Cleaned $count finished job record(s)"
}

# ==========================================
# PARSE FFUF JSON → COLORED TXT
# ==========================================
parse_results() {
    local jsonfile="$1"
    local txtfile="${jsonfile%.json}.txt"

    python3 - "$jsonfile" "$txtfile" <<'PYEOF'
import json, sys

try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except:
    sys.exit(0)

results = data.get("results", [])
results.sort(key=lambda x: (x.get("status", 0), x.get("url", "")))

lines = []
for r in results:
    status = r.get("status", "?")
    length = r.get("length", "?")
    words  = r.get("words", "?")
    url    = r.get("url", "?")
    redir  = f" -> {r['redirectlocation']}" if r.get("redirectlocation") else ""

    if   status in (200, 201):     color = "\033[0;32m"
    elif status in (301,302,307):  color = "\033[0;34m"
    elif status == 403:            color = "\033[1;33m"
    elif status == 401:            color = "\033[0;35m"
    else:                          color = "\033[0;37m"

    lines.append(f"{color}[{status}]\033[0m {url}  (len:{length}, words:{words}){redir}")

with open(sys.argv[2], "w") as f:
    f.write("\n".join(lines) + "\n")
PYEOF
}

# ==========================================
# HTML REPORT
# ==========================================
generate_report() {
    local outdir="$1"
    local target="$2"
    local scan_date; scan_date=$(date '+%Y-%m-%d %H:%M:%S')

    python3 - "$outdir" "$outdir/report.html" "$target" "$scan_date" <<'PYEOF'
import json, os, sys, glob

out_dir, report_path, target, scan_date = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

all_results = []
for jf in sorted(glob.glob(os.path.join(out_dir, "*.json"))):
    try:
        with open(jf) as f:
            data = json.load(f)
        all_results += data.get("results", [])
    except:
        continue

all_results.sort(key=lambda x: (x.get("status", 0), x.get("url", "")))
total = len(all_results)

def cnt(codes): return sum(1 for r in all_results if r.get("status") in codes)

rows = []
for r in all_results:
    s   = r.get("status","?")
    url = r.get("url","?")
    l   = r.get("length","?")
    w   = r.get("words","?")
    rd  = r.get("redirectlocation","")
    sc  = "ok" if s in (200,201) else "redirect" if s in (301,302,307) else "forbidden" if s==403 else "auth" if s==401 else "other"
    rd_html = f' <span class="redir">→ {rd}</span>' if rd else ""
    rows.append(f'<tr class="{sc}"><td>{s}</td><td><a href="{url}" target="_blank">{url}</a>{rd_html}</td><td>{l}</td><td>{w}</td></tr>')

html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Fuzz: {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:2em}}
h1{{color:#58a6ff;margin-bottom:.3em;font-size:1.4em}}
.meta{{color:#8b949e;font-size:.85em;margin-bottom:1.5em}}
.stats{{display:flex;gap:1em;margin-bottom:1.5em;flex-wrap:wrap}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:.8em 1.2em;min-width:100px}}
.stat .num{{font-size:1.8em;font-weight:bold}}
.stat .lbl{{font-size:.75em;color:#8b949e;margin-top:2px}}
#search{{width:100%;padding:.5em 1em;background:#161b22;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;font-family:monospace;font-size:.95em;margin-bottom:1em;outline:none}}
#search:focus{{border-color:#58a6ff}}
table{{width:100%;border-collapse:collapse;font-size:.88em}}
th{{background:#161b22;color:#58a6ff;padding:8px 12px;text-align:left;position:sticky;top:0;border-bottom:2px solid #30363d}}
td{{padding:5px 12px;border-bottom:1px solid #161b22;word-break:break-all}}
tr:hover td{{background:#161b22}}
a{{color:#c9d1d9;text-decoration:none}}
a:hover{{color:#58a6ff}}
.redir{{color:#8b949e;font-size:.85em}}
.ok td:first-child{{color:#3fb950;font-weight:bold}}
.redirect td:first-child{{color:#58a6ff}}
.forbidden td:first-child{{color:#f0a500}}
.auth td:first-child{{color:#bc8cff}}
.other td:first-child{{color:#8b949e}}
.hidden{{display:none!important}}
</style>
</head>
<body>
<h1>🔍 {target}</h1>
<div class="meta">Scanned: {scan_date} · Total findings: {total}</div>
<div class="stats">
  <div class="stat"><div class="num" style="color:#3fb950">{cnt([200,201])}</div><div class="lbl">200 OK</div></div>
  <div class="stat"><div class="num" style="color:#f0a500">{cnt([403])}</div><div class="lbl">403</div></div>
  <div class="stat"><div class="num" style="color:#bc8cff">{cnt([401])}</div><div class="lbl">401</div></div>
  <div class="stat"><div class="num" style="color:#58a6ff">{cnt([301,302,307])}</div><div class="lbl">Redirects</div></div>
  <div class="stat"><div class="num">{total}</div><div class="lbl">Total</div></div>
</div>
<input id="search" type="text" placeholder="Filter... (e.g. 200, /admin, .php)" oninput="filterTable()">
<table id="tbl">
<thead><tr><th>Status</th><th>URL</th><th>Length</th><th>Words</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=4 style="color:#8b949e;padding:1em">No findings</td></tr>'}</tbody>
</table>
<script>
function filterTable(){{
    const q=document.getElementById('search').value.toLowerCase();
    document.querySelectorAll('#tbl tbody tr').forEach(r=>{{
        r.classList.toggle('hidden',!!q&&!r.textContent.toLowerCase().includes(q));
    }});
}}
</script>
</body></html>"""

with open(report_path, "w") as f:
    f.write(html)
print(f"  Report: {report_path} ({total} findings)")
PYEOF
}

# ==========================================
# ACTUAL FUZZ RUNNER — called internally in background
# ==========================================
_run_fuzz() {
    local url="$1"
    local outdir="$2"
    shift 2

    # Defaults
    local wordlist="${WORDLISTS[common]}"
    local rate=2
    local threads=40
    local depth=2
    local extensions=""
    local match_codes="200,201,204,301,302,307,401,403,405"
    local filter_codes="404,429"
    local header=""
    local follow=false
    local extra_args=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -w)        wordlist="$2"; shift 2 ;;
            --wl)      wordlist="${WORDLISTS[$2]:-${WORDLISTS[common]}}"; shift 2 ;;
            --rate)    rate="$2"; shift 2 ;;
            --threads) threads="$2"; shift 2 ;;
            --depth)   depth="$2"; shift 2 ;;
            --ext)     extensions="$2"; shift 2 ;;
            --mc)      match_codes="$2"; shift 2 ;;
            --fc)      filter_codes="$2"; shift 2 ;;
            --H)       header="$2"; shift 2 ;;
            --follow)  follow=true; shift ;;
            --)        shift; extra_args="$*"; break ;;
            *)         shift ;;
        esac
    done

    local safe_name
    safe_name=$(echo "$url" | sed 's|https\?://||;s|[/:.?=]|_|g;s|_*$||')
    local outfile="$outdir/$safe_name"

    # Build fuzz URL
    local fuzz_url="$url"
    [[ "$fuzz_url" != */ ]] && fuzz_url="${fuzz_url}/"
    fuzz_url="${fuzz_url}FUZZ"

    log_info "Target   : $url"
    log_info "Wordlist : $wordlist ($(wc -l < "$wordlist" 2>/dev/null || echo "?") words)"
    log_info "Rate     : $rate req/s | Threads: $threads | Depth: $depth"
    [ -n "$extensions" ] && log_info "Ext      : .$extensions"
    echo ""

    local cmd=(ffuf
        -w "$wordlist"
        -u "$fuzz_url"
        -ac
        -recursion
        -recursion-depth "$depth"
        -rate "$rate"
        -t "$threads"
        -mc "$match_codes"
        -fc "$filter_codes"
        -timeout 10
        -o "${outfile}.json"
        -of json
    )

    [ -n "$extensions" ] && cmd+=(-e "$(echo "$extensions" | sed 's/^/./;s/,/,./g')")
    [ -n "$header" ]     && cmd+=(-H "$header")
    [ "$follow" = true ] && cmd+=(-r)
    [ -n "$extra_args" ] && cmd+=($extra_args)

    "${cmd[@]}"

    if [ -f "${outfile}.json" ]; then
        parse_results "${outfile}.json"
        local findings; findings=$(count_lines "${outfile}.txt")
        log_success "Done — $findings findings → ${outfile}.txt"
    fi

    generate_report "$outdir" "$url"

    echo ""
    echo -e "${GREEN}${BOLD}[DONE] $url${RESET}"
}

# ==========================================
# LAUNCH IN BACKGROUND
# ==========================================
launch() {
    local url="$1"
    shift

    # Auto-add https://
    [[ "$url" != http* ]] && url="https://$url"

    local id; id=$(url_to_id "$url")
    local jobfile="$JOBS_DIR/${id}.job"

    # Already running?
    if [ -f "$jobfile" ]; then
        source "$jobfile"
        if kill -0 "$PID" 2>/dev/null; then
            log_warn "Already running: $url (PID $PID)"
            log_info "Kill first: $0 --kill $url"
            exit 1
        fi
    fi

    local timestamp; timestamp=$(date +%Y%m%d_%H%M%S)
    local safe_name; safe_name=$(echo "$url" | sed 's|https\?://||;s|[/:.?=]|_|g;s|_*$||')
    local outdir="$HOME/bb/fuzzing/${safe_name}_${timestamp}"
    local logfile="$outdir/fuzz.log"
    mkdir -p "$outdir"

    # Re-invoke self with internal --_run flag in background
    nohup bash "$0" --_run "$url" "$outdir" "$@" > "$logfile" 2>&1 &
    local pid=$!
    local started; started=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$jobfile" <<EOF
TARGET="$url"
PID=$pid
OUTDIR="$outdir"
LOGFILE="$logfile"
STARTED="$started"
EOF

    print_banner
    log_success "Started: ${BOLD}$url${RESET}"
    echo ""
    echo -e "  ${BOLD}PID     :${RESET} $pid"
    echo -e "  ${BOLD}Output  :${RESET} $outdir"
    echo -e "  ${BOLD}Log     :${RESET} $logfile"
    echo ""
    echo -e "  ${YELLOW}Track:${RESET}"
    echo -e "    $0 --status"
    echo -e "    $0 --tail $url"
    echo -e "    $0 --results $url"
    echo ""
}

# ==========================================
# MAIN
# ==========================================
[ "$#" -eq 0 ] && usage

case "$1" in
    --status)   show_status ;;
    --tail)     tail_job "$2" ;;
    --results)  show_results "$2" ;;
    --kill)     kill_job "$2" ;;
    --killall)  kill_all ;;
    --clean)    clean_jobs ;;
    -h|--help)  usage ;;
    --_run)     shift; _run_fuzz "$@" ;;
    *)          launch "$@" ;;
esac