#!/usr/bin/env bash
# Live demo, about 10 minutes. Run from anywhere:
#   bash demo/run_demo.sh          interactive, pauses between steps
#   bash demo/run_demo.sh --auto   no pauses (CI smoke test); exits non-zero if any step misbehaves
set -u
cd "$(dirname "$0")/.."

AUTO=0
[ "${1:-}" = "--auto" ] && AUTO=1
WORK="$(mktemp -d)"
export GUARD_AUDIT_LOG="$WORK/audit.jsonl"
PY="${PYTHON:-python3}"
GUARD="guard/secret_guard.py"
F="demo/fixtures"
PASS=0
FAIL=0

if [ -t 1 ]; then B=$'\033[1m'; GR=$'\033[32m'; RD=$'\033[31m'; DM=$'\033[2m'; CY=$'\033[36m'; N=$'\033[0m'
else B=""; GR=""; RD=""; DM=""; CY=""; N=""; fi

pause() { [ "$AUTO" -eq 1 ] && return 0; echo; read -r -p "  ${DM}[enter] $1${N} " _; echo; }
act()   { echo; echo "${B}${CY}== $1 ==${N}"; }
say()   { echo "${B}$1${N}"; }
show()  { echo "${DM}\$ $*${N}"; }
check() {  # check <expected exit> <actual exit> <label>
  if [ "$2" -eq "$1" ]; then echo "  ${GR}PASS${N} $3 (exit $2)"; PASS=$((PASS + 1))
  else echo "  ${RD}FAIL${N} $3: expected exit $1, got $2"; FAIL=$((FAIL + 1)); fi
}
field() { "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {"d": d}))' "$1" "$2"; }
hook()  {  # hook <prompt|tool> <payload file> <expected exit> <label>
  show "secret_guard hook-$1 < $2"
  "$PY" "$GUARD" "hook-$1" < "$2"
  check "$3" $? "$4"
}

"$PY" demo/make_fixtures.py >/dev/null

act "Act 1. Prompt egress: the developer talks to the AI assistant"
say "1.1 Developer pastes a GitHub token into the assistant while debugging a 401"
echo "    prompt: $(field $F/prompt_payload.json 'd["prompt"]')"
pause "send the prompt"
hook prompt "$F/prompt_payload.json" 2 "prompt blocked before it reached the model"

say "1.2 A normal prompt goes straight through (no friction)"
hook prompt "$F/clean_prompt_payload.json" 0 "clean prompt allowed"

say "1.3 Developer tries to wave it through with the allow marker"
echo "    prompt: $(field $F/prompt_bypass_payload.json 'd["prompt"]')"
pause "try the bypass"
hook prompt "$F/prompt_bypass_payload.json" 2 "allow marker ignored for prompts"

act "Act 2. Agent actions: the coding agent runs tools on the laptop"
say "2.1 Agent calls the GitHub API with a token pasted into the command"
pause "run the agent's Bash call"
hook tool "$F/tool_payload.json" 2 "curl with token blocked"

say "2.2 Agent writes a settings file with hardcoded AWS credentials"
hook tool "$F/tool_write_payload.json" 2 "Write with AWS key pair blocked"

say "2.3 Agent tries to read .env (its contents would land in the model context)"
pause "let the agent read .env"
hook tool "$F/tool_read_env_payload.json" 2 "credential file read blocked"

say "2.4 Agent dumps the environment"
hook tool "$F/tool_env_dump_payload.json" 2 "env dump blocked"

say "2.5 Agent tries to skip the pre-commit hook"
hook tool "$F/tool_no_verify_payload.json" 2 "git commit --no-verify blocked"

say "2.6 A prompt-injected agent tries to switch the guard off"
pause "let the agent edit .claude/settings.json"
hook tool "$F/tool_tamper_payload.json" 2 "guard tamper blocked"

say "2.7 Normal edits are untouched"
hook tool "$F/tool_clean_payload.json" 0 "clean edit allowed"

act "Act 3. Commit: pre-commit, same engine"
say "3.1 Developer commits a config file and a .env with real credentials"
pause "commit"
show "secret_guard scan --stage precommit config_leak.py .env clean_config.py false_positive.py"
"$PY" "$GUARD" scan --stage precommit "$F/config_leak.py" "$F/.env" "$F/clean_config.py" "$F/false_positive.py"
check 1 $? "commit blocked; placeholder, env reference and reviewed allow marker ignored"

act "Act 4. CI: the safety net"
say "4.1 A leak committed on a laptop without hooks reaches the pull request"
pause "run the CI scan"
show "secret_guard scan --stage ci --format sarif --output ci.sarif ci_leak.py"
"$PY" "$GUARD" scan --stage ci --format sarif --output "$WORK/ci.sarif" "$F/ci_leak.py"
check 1 $? "PR check fails"
echo "    SARIF for the GitHub Security tab: $(field "$WORK/ci.sarif" 'str(len(d["runs"][0]["results"])) + " result(s): " + ", ".join(r["ruleId"] + " at " + r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in d["runs"][0]["results"])')"

act "Act 5. Containment: the leaked AWS key from Act 3"
KEY="$(field $F/manifest.json 'd["leaked_aws_key_id"]')"
say "5.1 Dry run first (the default): scope the blast radius, change nothing"
pause "run containment (dry run)"
show "contain_aws_key.py --simulate <key>"
"$PY" remediation/contain_aws_key.py --simulate "$KEY"
check 0 $? "dry run"
say "5.2 Execute: deactivate the key"
pause "execute"
show "contain_aws_key.py --simulate --execute <key>"
"$PY" remediation/contain_aws_key.py --simulate --execute "$KEY" | grep -E '^(\[SIM|Leaked|Mode|Actions|  - )'
check 0 "${PIPESTATUS[0]}" "key deactivated"

act "Act 6. What leadership sees"
pause "show the metrics"
show "metrics/report.py"
"$PY" metrics/report.py "$GUARD_AUDIT_LOG"
check 0 $? "report"
echo
echo "${DM}Audit log stores fingerprints only, never the secret or even a masked preview:${N}"
head -n 1 "$GUARD_AUDIT_LOG"

echo
if [ "$FAIL" -eq 0 ]; then echo "${GR}${B}All $PASS demo checks passed.${N}"; else echo "${RD}${B}$FAIL of $((PASS + FAIL)) demo checks failed.${N}"; fi
[ "$FAIL" -eq 0 ]
