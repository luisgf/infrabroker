#!/usr/bin/env bash
# audit-issue — deterministic mechanics for the /audit skill.
#
# Encapsulates the parts of the audit loop that must be identical every run:
# the audit-id fingerprint, the fixed issue-body format, dedupe, the close-out
# comment, and the ledger/report — all derived from GitHub so there is no local
# state to drift. The judgment (what to audit, triage, fix) lives in SKILL.md.
#
# Requires: gh (authenticated), git, sha1sum. Repo is taken from the gh context
# of the current directory (origin), matching how the maintainer runs it.
#
# Usage:
#   audit-issue labels-init
#   audit-issue id <category> <normalized-path> <signature>
#   audit-issue create --category C --severity S --title T --location L \
#                      --description D [--repro R] --fix F [--signature SIG] [--dry-run]
#   audit-issue closeout <issue> --commit SHA --files "a,b" --verified "gofmt/vet/..."
#   audit-issue needs-human <issue> --rationale "why a human must decide"
#   audit-issue ledger
#   audit-issue report

set -euo pipefail

die() { echo "audit-issue: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }
need gh; need git; need sha1sum

CATEGORIES="security logic documentation"
SEVERITIES="critical high medium low"

# audit_id computes the stable dedupe fingerprint: sha1(category|path|signature)
# truncated to 12 hex chars. The path is normalized (leading ./ stripped, any
# :line suffix dropped) so the same finding hashes identically across runs even
# as the code around it drifts.
audit_id() {
    local cat="$1" path="$2" sig="$3"
    path="${path#./}"
    path="${path%%:*}"
    printf '%s|%s|%s' "$cat" "$path" "$sig" | sha1sum | cut -c1-12
}

require_enum() {
    local val="$1" set="$2" name="$3"
    for x in $set; do [[ "$val" == "$x" ]] && return 0; done
    die "invalid $name '$val' (must be one of: $set)"
}

# format_body emits the canonical issue body. Every issue created by this tool
# has the same section order, so a reviewer (and the dedupe search) can rely on
# it. audit-id is first and verbatim — it is the machine-readable dedupe key.
format_body() {
    local aid="$1" cat="$2" sev="$3" justification="$4" location="$5" desc="$6" repro="$7" fix="$8"
    printf 'audit-id: %s\n\n' "$aid"
    printf '**Category:** %s · **Severity:** %s — %s\n\n' "$cat" "$sev" "$justification"
    printf '**Location:** %s\n\n' "$location"
    printf '**Description:** %s\n\n' "$desc"
    if [[ -n "$repro" ]]; then
        printf '**Reproduction / evidence:** %s\n\n' "$repro"
    fi
    printf '**Proposed fix & verification:** %s\n' "$fix"
}

cmd_id() {
    [[ $# -eq 3 ]] || die "usage: audit-issue id <category> <normalized-path> <signature>"
    require_enum "$1" "$CATEGORIES" category
    audit_id "$1" "$2" "$3"
}

# find_by_aid prints the issue number whose body carries the given audit-id, or
# nothing. All states, restricted to the audit-bot label. Deliberately lists and
# filters bodies locally instead of --search: the search index lags behind
# freshly created issues, which would break dedupe between close-together runs.
find_by_aid() {
    local aid="$1"
    gh issue list --state all --label audit-bot --limit 500 \
        --json number,body \
        --jq "map(select(.body | contains(\"audit-id: $aid\"))) | .[0].number // empty"
}

cmd_create() {
    local category="" severity="" title="" location="" description="" repro="" fix="" justification="" signature="" dry=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --category) category="$2"; shift 2 ;;
            --severity) severity="$2"; shift 2 ;;
            --title) title="$2"; shift 2 ;;
            --location) location="$2"; shift 2 ;;
            --description) description="$2"; shift 2 ;;
            --repro) repro="$2"; shift 2 ;;
            --fix) fix="$2"; shift 2 ;;
            --justification) justification="$2"; shift 2 ;;
            --signature) signature="$2"; shift 2 ;;
            --dry-run) dry=1; shift ;;
            *) die "create: unknown flag $1" ;;
        esac
    done
    [[ -n "$category" && -n "$severity" && -n "$title" && -n "$location" && -n "$description" && -n "$fix" ]] \
        || die "create: --category --severity --title --location --description --fix are required"
    require_enum "$category" "$CATEGORIES" category
    require_enum "$severity" "$SEVERITIES" severity
    : "${justification:=see description}"

    # The dedupe signature defaults to the title; pass --signature with a short
    # stable phrase when the title might be reworded on a later run (the
    # audit-id must not move, or dedupe breaks and a duplicate gets filed).
    : "${signature:=$title}"
    local aid; aid="$(audit_id "$category" "$location" "$signature")"
    local body; body="$(format_body "$aid" "$category" "$severity" "$justification" "$location" "$description" "$repro" "$fix")"

    if [[ $dry -eq 1 ]]; then
        echo "# labels: audit-bot,$category,severity:$severity"
        echo "# title:  $title"
        echo "# --- body ---"
        printf '%s\n' "$body"
        return 0
    fi

    # Dedupe: never create a second issue for an existing audit-id.
    local existing; existing="$(find_by_aid "$aid")"
    if [[ -n "$existing" ]]; then
        echo "$existing (existing — audit-id $aid, not creating a duplicate)"
        return 0
    fi

    local url; url="$(gh issue create \
        --label audit-bot --label "$category" --label "severity:$severity" \
        --title "$title" --body "$body")"
    echo "${url##*/}"
}

cmd_closeout() {
    local issue="$1"; shift
    [[ -n "$issue" ]] || die "usage: audit-issue closeout <issue> --commit SHA --files F --verified V"
    local commit="" files="" verified=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --commit) commit="$2"; shift 2 ;;
            --files) files="$2"; shift 2 ;;
            --verified) verified="$2"; shift 2 ;;
            *) die "closeout: unknown flag $1" ;;
        esac
    done
    [[ -n "$commit" && -n "$verified" ]] || die "closeout: --commit and --verified are required"
    local body
    body="$(printf 'Fixed in %s.\n\n**Files touched:** %s\n\n**Verification:** %s' "$commit" "${files:-—}" "$verified")"
    gh issue comment "$issue" --body "$body" >/dev/null
    echo "closeout posted on #$issue"
}

cmd_needs_human() {
    local issue="$1"; shift
    [[ -n "$issue" ]] || die "usage: audit-issue needs-human <issue> --rationale R"
    local rationale=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --rationale) rationale="$2"; shift 2 ;;
            *) die "needs-human: unknown flag $1" ;;
        esac
    done
    [[ -n "$rationale" ]] || die "needs-human: --rationale is required"
    gh issue edit "$issue" --add-label needs-human >/dev/null
    gh issue comment "$issue" --body "$(printf '**Triaged as needs-human (product/security decision).**\n\n%s' "$rationale")" >/dev/null
    echo "labeled needs-human and commented on #$issue"
}

# ledger prints one row per audit-bot issue, derived live from GitHub: the
# audit-id (parsed from the body), issue number, state, severity, and title.
cmd_ledger() {
    gh issue list --state all --label audit-bot --limit 500 \
        --json number,title,state,labels,body \
        --jq '
          sort_by(.number) | .[] |
          ( (.body | capture("audit-id: (?<a>[0-9a-f]+)").a)? // null ) as $aid |
          ( [.labels[].name | select(startswith("severity:"))] | .[0] // "severity:?" ) as $sev |
          "\($aid // "?")\t#\(.number)\t\(.state)\t\($sev | ltrimstr("severity:"))\t\(.title)"
        '
}

# report prints the final summary: counts by category/severity plus the closed
# and needs-human lists. All from GitHub, so it is correct regardless of which
# machine or run produced the issues.
cmd_report() {
    local json; json="$(gh issue list --state all --label audit-bot --limit 500 \
        --json number,title,state,labels)"
    echo "=== Audit report (from GitHub, label=audit-bot) ==="
    echo
    echo "Total findings: $(jq 'length' <<<"$json")"
    echo
    echo "By category:"
    for c in $CATEGORIES; do
        printf '  %-14s %s\n' "$c" "$(jq --arg c "$c" '[.[] | select(.labels[].name==$c)] | length' <<<"$json")"
    done
    echo "By severity:"
    for s in $SEVERITIES; do
        printf '  %-14s %s\n' "$s" "$(jq --arg s "severity:$s" '[.[] | select(.labels[].name==$s)] | length' <<<"$json")"
    done
    echo
    echo "Closed: $(jq '[.[] | select(.state=="CLOSED")] | length' <<<"$json")   Open: $(jq '[.[] | select(.state=="OPEN")] | length' <<<"$json")   needs-human: $(jq '[.[] | select(.labels[].name=="needs-human")] | length' <<<"$json")"
    echo
    echo "Open needs-human (require a decision):"
    jq -r '.[] | select(.labels[].name=="needs-human") | select(.state=="OPEN") | "  #\(.number) \(.title)"' <<<"$json" | { grep . || echo "  (none)"; }
}

cmd_labels_init() {
    # (name, color, description) — created idempotently.
    local specs=(
        "security|b60205|Audit category: security"
        "logic|d93f0b|Audit category: logic"
        "documentation|0075ca|Improvements or additions to documentation"
        "severity:critical|b60205|Severity: critical"
        "severity:high|d93f0b|Severity: high"
        "severity:medium|fbca04|Severity: medium"
        "severity:low|0e8a16|Severity: low"
        "audit-bot|5319e7|Created/managed by the audit loop"
        "needs-human|e99695|Requires a human product/security decision"
    )
    for spec in "${specs[@]}"; do
        IFS='|' read -r name color desc <<<"$spec"
        gh label create "$name" --color "$color" --description "$desc" --force >/dev/null 2>&1 \
            && echo "label ok: $name" || echo "label ok: $name (exists)"
    done
}

case "${1:-}" in
    id)          shift; cmd_id "$@" ;;
    create)      shift; cmd_create "$@" ;;
    closeout)    shift; cmd_closeout "$@" ;;
    needs-human) shift; cmd_needs_human "$@" ;;
    ledger)      shift; cmd_ledger "$@" ;;
    report)      shift; cmd_report "$@" ;;
    labels-init) shift; cmd_labels_init "$@" ;;
    ""|-h|--help)
        # Print the header comment block (stops at the first non-# line), so the
        # help stays correct as the header grows.
        awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
        ;;
    *) die "unknown subcommand '$1' (see --help)" ;;
esac
