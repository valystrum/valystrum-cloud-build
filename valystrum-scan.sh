#!/usr/bin/env bash
# Valystrum security scan for any CI system: leaked secrets, code analysis (SAST) and IaC checks on the files a change
# touches, with a pass or fail verdict for the merge. Licensed under the Apache License 2.0.
#
# Valystrum's GitLab CI/CD, Azure Pipelines, AWS CodeBuild and Google Cloud Build integrations all run this same
# script, unchanged. Set everything through the variables below and leave the script as it is, so an update is a
# plain copy of a newer release.
#
# Needs bash, git, curl, openssl and base64. jq is fetched when the machine has none (pinned and checked, below).
#
# Settings, all environment variables:
#   VALYSTRUM_SCAN_URL          required: https://app.valystrum.io/api/v1/<org>/pipeline/scan
#   VALYSTRUM_SECRET            required: the repository's CI secret (cs_wh_...)
#   VALYSTRUM_REPO              required: the repository exactly as its CI key in Valystrum names it
#   VALYSTRUM_BRANCH            the branch the change is on (a merge or pull request's source branch). Without it the
#                               scan still gates the merge, but closes nothing in Valystrum
#   VALYSTRUM_BASE              the commit or branch to compare with (default: the previous commit)
#   VALYSTRUM_COMMIT            the commit being scanned (default: HEAD)
#   VALYSTRUM_PR_NUMBER         the merge or pull request number, when there is one
#   VALYSTRUM_SEQUENCE          a number that only grows with each new CI run of the repository (the platform's run or
#                               build number); Valystrum orders a branch's scans by it
#   VALYSTRUM_DEFAULT_BRANCH    the repository's default branch (default: what the clone's origin names); a finding is
#                               decided on it once it has read the file
#   VALYSTRUM_PATHS            space-separated pathspecs that narrow the diff, and so the secret scan
#   VALYSTRUM_SEND_FILES        true (default): send the changed files, which code analysis and the IaC checks need
#   VALYSTRUM_FAIL_ON_FINDINGS  true (default): exit 1 when the scan reports a critical or high finding
#   VALYSTRUM_FAIL_ON_ERROR     false (default): exit 1 also when the scan could not run or did not finish
#   VALYSTRUM_ANNOTATIONS       plain (default), or azure for Azure Pipelines log issues and a build summary
#   VALYSTRUM_OUT_DIR           where the outputs go (default: valystrum-reports)
#   VALYSTRUM_CODEQUALITY       also write a GitLab Code Quality report to this path
#   VALYSTRUM_JUNIT             also write a JUnit XML report to this path (AWS CodeBuild report groups)
#
# Writes $VALYSTRUM_OUT_DIR/valystrum-scan.env (VALYSTRUM_PASSED, VALYSTRUM_FINDINGS, VALYSTRUM_SCAN_ID) and
# $VALYSTRUM_OUT_DIR/summary.md on every way out but a setting that is missing.
set -euo pipefail

WEBHOOK_URL="${VALYSTRUM_SCAN_URL:-}"
WEBHOOK_SECRET="${VALYSTRUM_SECRET:-}"
REPO="${VALYSTRUM_REPO:-}"
BRANCH="${VALYSTRUM_BRANCH:-}"
PATHS="${VALYSTRUM_PATHS:-}"
SEND_FILES="${VALYSTRUM_SEND_FILES:-true}"
FAIL_ON_FINDINGS="${VALYSTRUM_FAIL_ON_FINDINGS:-true}"
FAIL_ON_ERROR="${VALYSTRUM_FAIL_ON_ERROR:-false}"
ANNOTATIONS="${VALYSTRUM_ANNOTATIONS:-plain}"
PR_NUMBER="${VALYSTRUM_PR_NUMBER:-}"
case "$PR_NUMBER" in '' | *[!0-9]*) PR_NUMBER="" ;; esac
SEQUENCE="${VALYSTRUM_SEQUENCE:-}"
case "$SEQUENCE" in '' | *[!0-9]*) SEQUENCE="" ;; esac

say_error() { if [ "$ANNOTATIONS" = "azure" ]; then echo "##vso[task.logissue type=error]$1"; else echo "ERROR: $1"; fi; }
say_warning() { if [ "$ANNOTATIONS" = "azure" ]; then echo "##vso[task.logissue type=warning]$1"; else echo "WARNING: $1"; fi; }

[ -n "$WEBHOOK_URL" ] || { say_error "VALYSTRUM_SCAN_URL is empty: set it to https://app.valystrum.io/api/v1/<org>/pipeline/scan."; exit 1; }
[ -n "$WEBHOOK_SECRET" ] || { say_error "VALYSTRUM_SECRET is empty: the pipeline could not read the repository's CI secret (check its name, and that this run may read it)."; exit 1; }
[ -n "$REPO" ] || { say_error "VALYSTRUM_REPO is empty: set it to the repository as its CI key in Valystrum names it."; exit 1; }

OUT_DIR="${VALYSTRUM_OUT_DIR:-valystrum-reports}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
PAYLOAD="$TMP_DIR/valystrum-payload.json"
RESPONSE="$TMP_DIR/valystrum-response.json"
SUMMARY="$OUT_DIR/summary.md"
: > "$SUMMARY"
echo '{"findings":[]}' > "$TMP_DIR/none.json"

# A scan that cannot run never blocks a merge unless VALYSTRUM_FAIL_ON_ERROR is true (the platform's fail-open rule).
setup_failed() {
  say_error "$1"
  printf 'VALYSTRUM_PASSED=true\nVALYSTRUM_FINDINGS=0\nVALYSTRUM_SCAN_ID=\n' > "$OUT_DIR/valystrum-scan.env"
  if [ "$FAIL_ON_ERROR" = "true" ]; then exit 1; fi
  exit 0
}

# ── jq ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
# The one tool most CI images lack: fetched once when there is none, pinned by version and checked by SHA-256.
JQ_VERSION="1.8.2"
if ! command -v jq >/dev/null 2>&1; then
  case "$(uname -m)" in
    x86_64 | amd64) JQ_ASSET="jq-linux-amd64"; JQ_SHA256="b1c22172dd303f3be49e935aa56aa48a8b7a46e0bc838b4997d3bb451495870f" ;;
    aarch64 | arm64) JQ_ASSET="jq-linux-arm64"; JQ_SHA256="8b85c817833814ddca00a144c33705546355afccf0cf39b188f3cdb48b852309" ;;
    *) JQ_ASSET=""; JQ_SHA256="" ;;
  esac
  if [ -z "$JQ_ASSET" ] \
    || ! curl -fsSL --retry 3 -o "$TMP_DIR/jq" "https://github.com/jqlang/jq/releases/download/jq-$JQ_VERSION/$JQ_ASSET" \
    || [ "$(openssl dgst -sha256 -r "$TMP_DIR/jq" | cut -d ' ' -f 1)" != "$JQ_SHA256" ]; then
    setup_failed "jq is not installed, and jq $JQ_VERSION could not be fetched and checked for this machine: install jq in the image."
  fi
  chmod +x "$TMP_DIR/jq"
  PATH="$TMP_DIR:$PATH"
fi

# ── Outputs ────────────────────────────────────────────────────────────────────────────────────────────────────────
# Written on every way out: the verdict as variables, the reports a platform shows natively, and the summary.
# NOT_RUN names why nothing (or not everything) was checked, so a report never shows a scan that did not run as clean.
NOT_RUN=""
write_outputs() { # passed, findings, scan id, the answer to read findings from
  printf 'VALYSTRUM_PASSED=%s\nVALYSTRUM_FINDINGS=%s\nVALYSTRUM_SCAN_ID=%s\n' "$1" "$2" "$3" > "$OUT_DIR/valystrum-scan.env"
  local answer="$4"
  jq -e '(.findings // []) | type == "array"' "$answer" >/dev/null 2>&1 || answer="$TMP_DIR/none.json"
  if [ -n "${VALYSTRUM_CODEQUALITY:-}" ]; then
    mkdir -p "$(dirname "$VALYSTRUM_CODEQUALITY")"
    jq '[(.findings // [])[] | {
          description: "\(.ruleId): \(.message)",
          check_name: .ruleId,
          fingerprint: "\(.ruleId)|\(.file)|\(.line)",
          severity: ({critical: "blocker", high: "critical", medium: "major", low: "minor"}[.severity] // "info"),
          location: {path: .file, lines: {begin: ([(.line // 1), 1] | max)}}
        }]' "$answer" > "$VALYSTRUM_CODEQUALITY"
  fi
  if [ -n "${VALYSTRUM_JUNIT:-}" ]; then
    mkdir -p "$(dirname "$VALYSTRUM_JUNIT")"
    jq -r --arg notRun "$NOT_RUN" '
      def x: tostring | gsub("&"; "&amp;") | gsub("<"; "&lt;") | gsub(">"; "&gt;") | gsub("\""; "&quot;");
      (.findings // []) as $f
      | "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<testsuites><testsuite name=\"Valystrum security scan\" tests=\"\(($f | length) + 1)\" failures=\"\($f | length)\" errors=\"\(if $notRun == "" then 0 else 1 end)\">",
        (if $notRun == "" then "<testcase classname=\"valystrum\" name=\"Scan completed\"/>"
         else "<testcase classname=\"valystrum\" name=\"Scan completed\"><error message=\"\($notRun | x)\"/></testcase>" end),
        ($f[] | "<testcase classname=\"\(.file | x)\" name=\"\(.ruleId | x) at \(.file | x):\(.line | x)\"><failure type=\"\(.severity | x)\" message=\"\(.message | x)\">\(.severity | x): \(.message | x)</failure></testcase>"),
        "</testsuite></testsuites>"' "$answer" > "$VALYSTRUM_JUNIT"
  fi
  if [ "$ANNOTATIONS" = "azure" ]; then
    echo "##vso[task.setvariable variable=VALYSTRUM_PASSED]$1"
    echo "##vso[task.setvariable variable=VALYSTRUM_FINDINGS]$2"
    echo "##vso[task.setvariable variable=VALYSTRUM_SCAN_ID]$3"
    if [ -s "$SUMMARY" ]; then echo "##vso[task.uploadsummary]$SUMMARY"; fi
  fi
  if [ -s "$SUMMARY" ]; then cat "$SUMMARY"; fi
}

# ── The change's diff ──────────────────────────────────────────────────────────────────────────────────────────────
git rev-parse --git-dir >/dev/null 2>&1 || { say_error "This is not a git checkout: run the scan in the repository's working copy."; exit 1; }

# A shallow clone has no base commit to diff against: the scan would see "no changes" on every run and report nothing.
if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
  echo "Shallow clone detected: fetching history so the diff has a base."
  git fetch --unshallow --quiet || git fetch --depth=50 --quiet || true
fi

COMMIT="${VALYSTRUM_COMMIT:-}"
[ -n "$COMMIT" ] || COMMIT="$(git rev-parse HEAD)"
BASE="${VALYSTRUM_BASE:-}"
# A branch's first push has no previous commit.
case "$BASE" in 0000000000000000000000000000000000000000) BASE="" ;; esac
# A branch name, or a commit the clone does not have yet: fetch it from the remote.
if [ -n "$BASE" ] && ! git cat-file -e "$BASE^{commit}" 2>/dev/null; then
  if git fetch --quiet origin "$BASE" 2>/dev/null; then BASE="$(git rev-parse FETCH_HEAD)"; fi
fi
# Last resort: the parent commit. Right for a single-commit push and never empty, which is what matters.
[ -n "$BASE" ] || BASE="$(git rev-parse -q --verify HEAD~1 || git rev-parse HEAD)"
if ! git cat-file -e "$BASE^{commit}" 2>/dev/null; then
  say_warning "Base '$BASE' is not in this clone; falling back to the previous commit (HEAD~1)."
  BASE="$(git rev-parse -q --verify HEAD~1 || git rev-parse HEAD)"
fi

# ── Where the commit stands ────────────────────────────────────────────────────────────────────────────────────────
# Valystrum orders a branch's scans by the run's sequence, else by the commit's time, and lets the default branch
# decide a finding once a scan of it has read the file: send what the clone can tell.
COMMITTED_AT=""
COMMIT_TIME="$(git show -s --format=%ct "$COMMIT" 2>/dev/null || true)"
if [ -n "$COMMIT_TIME" ]; then
  # Capped at now: a commit dated in the future (a skewed clock) would outrank every later scan.
  if [ "$COMMIT_TIME" -gt "$(date +%s)" ]; then
    COMMITTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  else
    COMMITTED_AT="$(git show -s --format=%cI "$COMMIT")"
  fi
fi
DEFAULT_BRANCH="${VALYSTRUM_DEFAULT_BRANCH:-}"
if [ -z "$DEFAULT_BRANCH" ]; then
  DEFAULT_BRANCH="$(git symbolic-ref --short -q refs/remotes/origin/HEAD 2>/dev/null || true)"
  DEFAULT_BRANCH="${DEFAULT_BRANCH#origin/}"
fi
if [ -z "$DEFAULT_BRANCH" ]; then
  DEFAULT_BRANCH="$(GIT_TERMINAL_PROMPT=0 git ls-remote --symref origin HEAD 2>/dev/null | awk '$1 == "ref:" { sub("^refs/heads/", "", $2); print $2; exit }' || true)"
fi
[ -n "$DEFAULT_BRANCH" ] || say_warning "The repository's default branch is unknown (VALYSTRUM_DEFAULT_BRANCH): set it, so Valystrum knows which branch decides a finding."
# ── end of where the commit stands

echo "Diffing $BASE...HEAD"
DIFF="$TMP_DIR/valystrum.diff"
# shellcheck disable=SC2086  # PATHS is an intentional word-split pathspec
if [ -n "$PATHS" ]; then
  git diff --unified=3 "$BASE"...HEAD -- $PATHS > "$DIFF"
else
  git diff --unified=3 "$BASE"...HEAD > "$DIFF"
fi
# shellcheck disable=SC2086  # as above
CHANGED=$(git diff --name-only "$BASE"...HEAD ${PATHS:+-- $PATHS} | wc -l | tr -d ' ')
echo "$CHANGED file(s) changed."
[ -n "$BRANCH" ] || say_warning "No branch named (VALYSTRUM_BRANCH): the scan gates this change, but closes nothing in Valystrum."

if [ ! -s "$DIFF" ]; then
  echo "No changes to scan."
  printf '### Valystrum Security Scan\n\nNo changes to scan.\n' > "$SUMMARY"
  write_outputs true 0 "" "$TMP_DIR/none.json"
  exit 0
fi

# ── Changed file contents ──────────────────────────────────────────────────────────────────────────────────────────
# SAST parses whole files; a unified diff carries only hunks. Without these the platform checks secrets only and says
# so. The caps mirror the server's: 300 files, 512 KB each, 2 MB total body.
FILES_JSON="$TMP_DIR/valystrum-files.json"
echo "[]" > "$FILES_JSON"

if [ "$SEND_FILES" = "true" ]; then
  : > "$TMP_DIR/file-list.txt"
  # Deleted files have no content to scan; skip them (status filter ACMR).
  git diff --name-only --diff-filter=ACMR "$BASE"...HEAD > "$TMP_DIR/file-list.txt" || true

  BUDGET=$((1500 * 1024))   # leave headroom under the 2 MB body cap for the diff
  USED=0
  COUNT=0
  SKIPPED=0
  : > "$TMP_DIR/files.ndjson"

  while IFS= read -r f; do
    [ -z "$f" ] && continue
    [ -f "$f" ] || continue
    [ "$COUNT" -ge 300 ] && { SKIPPED=$((SKIPPED+1)); continue; }

    SIZE=$(wc -c < "$f" | tr -d ' ')
    if [ "$SIZE" -gt $((512 * 1024)) ] || [ $((USED + SIZE)) -gt "$BUDGET" ]; then
      SKIPPED=$((SKIPPED+1)); continue
    fi
    # Binary files break JSON encoding and mean nothing to the scanners.
    if LC_ALL=C grep -qI . "$f" 2>/dev/null; then
      jq -Rn --arg path "$f" --rawfile content "$f" '{path: $path, content: $content}' \
        >> "$TMP_DIR/files.ndjson"
      USED=$((USED + SIZE)); COUNT=$((COUNT+1))
    fi
  done < "$TMP_DIR/file-list.txt"

  if [ -s "$TMP_DIR/files.ndjson" ]; then
    jq -s '.' "$TMP_DIR/files.ndjson" > "$FILES_JSON"
  fi
  echo "Sending $COUNT file(s) for code analysis$([ "$SKIPPED" -gt 0 ] && echo ", $SKIPPED skipped (size/binary/cap)")."
else
  echo "VALYSTRUM_SEND_FILES is false: only secrets will be scanned (code analysis and IaC checks need the files)."
fi

# ── Signed request ─────────────────────────────────────────────────────────────────────────────────────────────────
# base64 via file, not --arg: one argv string is capped at 128 KB on Linux (E2BIG).
base64 -w0 < "$DIFF" > "$DIFF.b64" 2>/dev/null || base64 < "$DIFF" | tr -d '\n' > "$DIFF.b64"

jq -n \
  --arg repo "$REPO" \
  --arg branch "$BRANCH" \
  --arg commitSha "$COMMIT" \
  --rawfile diff "$DIFF.b64" \
  --argjson prNumber "${PR_NUMBER:-null}" \
  --arg committedAt "$COMMITTED_AT" \
  --arg defaultBranch "$DEFAULT_BRANCH" \
  --argjson sequence "${SEQUENCE:-null}" \
  --slurpfile files "$FILES_JSON" \
  '{repo: $repo, commitSha: $commitSha, diff: $diff, files: $files[0]}
   + (if $branch == "" then {} else {branch: $branch} end)
   + (if $prNumber == null then {} else {prNumber: $prNumber} end)
   + (if $committedAt == "" then {} else {committedAt: $committedAt} end)
   + (if $defaultBranch == "" then {} else {defaultBranch: $defaultBranch} end)
   + (if $sequence == null then {} else {sequence: $sequence} end)' \
  > "$PAYLOAD"

BYTES=$(wc -c < "$PAYLOAD" | tr -d ' ')
if [ "$BYTES" -gt $((2 * 1024 * 1024)) ]; then
  say_warning "Payload is ${BYTES} bytes (over the 2 MB cap); sending without file contents, so only secrets will be scanned."
  jq 'del(.files)' "$PAYLOAD" > "$PAYLOAD.tmp" && mv "$PAYLOAD.tmp" "$PAYLOAD"
fi

# Stamped HMAC-SHA256: the digest covers "<unix seconds>.<body>",
# over the exact bytes curl sends (--data-binary is verbatim). The platform
# accepts a stamp within five minutes and once, so every attempt signs
# afresh: a resent signature is refused as already used. The pause between
# attempts is at least a second, so each attempt carries a new stamp.
for ATTEMPT in 1 2 3; do
  : > "$RESPONSE"  # curl leaves -o untouched when nothing answers: no earlier attempt's body in the error
  T=$(date +%s)
  SIGNATURE=$( { printf '%s.' "$T"; cat "$PAYLOAD"; } | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | awk '{print $NF}')
  CODE=$(curl -sS --max-time 120 \
    -o "$RESPONSE" -w '%{http_code}' \
    -X POST "$WEBHOOK_URL" \
    -H 'content-type: application/json' \
    -H "x-cs-signature: t=$T,v1=$SIGNATURE" \
    --data-binary @"$PAYLOAD") || CODE="000"
  # Retried as curl's own retry did: no answer, 408, 429 and 5xx.
  case "$CODE" in 000|408|429|5??) ;; *) break ;; esac
  if [ "$ATTEMPT" -lt 3 ]; then sleep $((1 << (ATTEMPT - 1))); fi
done

if [ "$CODE" != "200" ]; then
  NOT_RUN="the scan endpoint answered HTTP $CODE"
  say_error "Valystrum scan failed (HTTP $CODE): $(head -c 500 "$RESPONSE" 2>/dev/null)"
  printf '### Valystrum Security Scan\n\nThe scan did not run: the endpoint answered HTTP %s. Nothing was checked.\n' "$CODE" > "$SUMMARY"
  write_outputs true 0 "" "$TMP_DIR/none.json"
  # Fail-open by default: a scanner outage must never block a merge.
  [ "$FAIL_ON_ERROR" = "true" ] && exit 1
  exit 0
fi

# ── A scan the platform could not complete ─────────────────────────────────────────────────────────────────────────
# A scanner fault after the request was accepted still answers 200, with `error` in the body: nothing was checked.
# An answer that is not a JSON object (a proxy's page, an empty body) is the same case.
SCAN_ERROR="unreadable answer"
jq -e 'type == "object"' "$RESPONSE" >/dev/null 2>&1 && SCAN_ERROR=$(jq -r '.error // ""' "$RESPONSE")
if [ -n "$SCAN_ERROR" ]; then
  NOT_RUN="the platform could not complete the scan ($SCAN_ERROR)"
  # shellcheck disable=SC2016  # Markdown backticks, not a command
  printf '### Valystrum Security Scan\n\nThe scan could not be completed (`%s`): nothing was checked.\n' "$SCAN_ERROR" > "$SUMMARY"
  write_outputs true 0 "$(jq -r '.scanId // ""' "$RESPONSE" 2>/dev/null || true)" "$TMP_DIR/none.json"
  if [ "$FAIL_ON_ERROR" = "true" ]; then
    say_error "Valystrum could not complete the scan ($SCAN_ERROR); VALYSTRUM_FAIL_ON_ERROR is true, so the job fails."
    exit 1
  fi
  say_warning "Valystrum could not complete the scan ($SCAN_ERROR): nothing was checked. The job passes because VALYSTRUM_FAIL_ON_ERROR is false."
  exit 0
fi

# NOT `.passed // true`: jq's `//` treats `false` as absent, so a failed
# scan would read as a pass and the gate would never block anything.
PASSED=$(jq -r 'if .passed == null then true else .passed end' "$RESPONSE")
COUNT=$(jq  -r '.findings | length // 0' "$RESPONSE")
SCAN_ID=$(jq -r '.scanId // ""'    "$RESPONSE")
SAST_STATUS=$(jq -r '.scanned.sastStatus // "unknown"' "$RESPONSE")
SAST_FILES=$(jq -r '.scanned.sastFilesScanned // 0'    "$RESPONSE")

# ── A code and IaC scanner that did not finish the files sent ──────────────────────────────────────────────────────
# The files went, but the platform's scanner timed out, failed or is not configured, so code analysis, the IaC checks
# or both did not run; `scanned.checks` names what did, and what did still gates the merge.
SENT=$(jq -r '(.files // []) | length' "$PAYLOAD")
CHECKS=$(jq -r '(.scanned.checks // ["secrets"]) | join(", ")' "$RESPONSE")
INCOMPLETE=""
case "$SAST_STATUS" in
  timeout|error|not_configured) if [ "$SENT" -gt 0 ]; then INCOMPLETE="$SAST_STATUS"; fi ;;
esac
if [ -n "$INCOMPLETE" ]; then
  NOT_RUN="the code and IaC scanner did not finish the files sent ($INCOMPLETE); checks that ran: $CHECKS"
  if [ "$FAIL_ON_ERROR" = "true" ]; then
    say_error "Valystrum's code and IaC scanner did not finish the files sent ($INCOMPLETE); only these checks ran: $CHECKS. VALYSTRUM_FAIL_ON_ERROR is true, so the job fails."
  else
    say_warning "Valystrum's code and IaC scanner did not finish the files sent ($INCOMPLETE); only these checks ran: $CHECKS. The job goes on because VALYSTRUM_FAIL_ON_ERROR is false."
  fi
fi

# ── Summary ────────────────────────────────────────────────────────────────────────────────────────────────────────
{
  echo "### Valystrum Security Scan"
  echo ""
  if [ "$SAST_STATUS" = "ok" ]; then
    echo "Analysed **$SAST_FILES** file(s): SAST, secrets and IaC."
  elif [ -n "$INCOMPLETE" ]; then
    echo "The code and IaC scanner did not finish the files sent (\`$INCOMPLETE\`). Checks that ran: $CHECKS."
  else
    echo "Scanned the diff for secrets only. Code analysis and IaC checks: \`$SAST_STATUS\` (they need the changed files)."
  fi
  echo ""
  if [ "$COUNT" = "0" ]; then
    echo "No findings."
  else
    echo "| Severity | Rule | Location |"
    echo "|---|---|---|"
    jq -r '.findings | sort_by(
             if .severity=="critical" then 0 elif .severity=="high" then 1
             elif .severity=="medium" then 2 else 3 end)
           | .[:20][] | "| \(.severity) | `\(.ruleId)` | `\(.file):\(.line)` |"' "$RESPONSE"
    if [ "$COUNT" -gt 20 ]; then echo ""; echo "_...and $((COUNT - 20)) more._"; fi
  fi
  if [ -n "$SCAN_ID" ]; then echo ""; echo "_Scan ID: \`$SCAN_ID\`_"; fi
} > "$SUMMARY"
write_outputs "$PASSED" "$COUNT" "$SCAN_ID" "$RESPONSE"

# Each finding on its own line, in the platform's own form where it has one.
if [ "$ANNOTATIONS" = "azure" ]; then
  jq -r 'def esc: tostring | gsub("%"; "%AZP25") | gsub(";"; "%3B") | gsub("\r"; "%0D") | gsub("\n"; "%0A") | gsub("]"; "%5D");
         .findings[]? | "##vso[task.logissue type=\(if .severity == "critical" or .severity == "high" then "error" else "warning" end);sourcepath=\(.file | esc);linenumber=\(.line | esc);code=\(.ruleId | esc)]\(.severity): \(.message | gsub("[\r\n]+"; " "))"' "$RESPONSE" || true
else
  jq -r '.findings[]? | "\(.severity | ascii_upcase) \(.ruleId) \(.file):\(.line) \(.message | gsub("[\r\n]+"; " "))"' "$RESPONSE" || true
fi

if [ "$PASSED" != "true" ]; then
  say_error "Valystrum: $COUNT finding(s), including critical/high. See the summary above."
  [ "$FAIL_ON_FINDINGS" = "true" ] && exit 1
fi

# The scanner that did not finish the files sent (above), once the summary and the findings are out.
if [ -n "$INCOMPLETE" ] && [ "$FAIL_ON_ERROR" = "true" ]; then
  exit 1
fi

echo "Scan complete: $COUNT finding(s), passed=$PASSED."
