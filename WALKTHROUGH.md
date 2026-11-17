# Walkthrough: test it, then demo it

Part A is a test plan: run it top to bottom before the interview and tick every box.
Part B is the demo script, with what to say at each step.
Part C covers the questions interviewers are likely to ask, with answers.
Part D is the day-of checklist and troubleshooting.

Everything in Parts A1 to A4 runs offline with no accounts. A5 needs a GitHub repo, and A6 needs Terraform.

---

## Part A. Test plan

### A1. Set up (5 minutes, once)

```bash
cd shiftleft-secrets-guard
python3 --version                  # 3.9 or newer
python3 -m venv .venv && . .venv/bin/activate
pip install pytest pre-commit
```

- [ ] `python3 guard/secret_guard.py --version` prints `secret_guard 2.0.0`
- [ ] `python3 guard/secret_guard.py rules` lists 17 rules

### A2. Automated tests (1 minute)

```bash
pytest -q
```

- [ ] `96 passed`

What the suite covers, in case you are asked:

| Area | Examples |
|---|---|
| Detection | vendor rules, `.env` lines, short human passwords, snake_case names, private keys (distinct fingerprints), placeholders and references ignored |
| Prompt hook | blocks secrets, ignores `guard:allow`, fails closed on bad input, break-glass is logged |
| Agent hook | secrets in Write/Edit/MultiEdit/WebFetch, `.env` and key reads, `env` dumps, `--no-verify`, guard tamper, and 12 normal commands that must stay allowed |
| CI | SARIF shape, fail threshold, stage tagging, odd file names, allowlist needs a reason, binaries skipped |
| Safety | no raw secret or partial secret in any output or log; the repo itself scans clean |
| Containment | dry run changes nothing; execute deactivates; multi-region finding; ASIA session revoke; key from another account |
| End to end | the demo script passes all 15 checks |

### A3. Scripted demo (2 minutes)

```bash
bash demo/run_demo.sh --auto
```

- [ ] Ends with `All 15 demo checks passed.`
- [ ] Act 6 shows `Stopped on the laptop: 9 of 10 (90%)` and `Reached CI: 1`

Then run it interactively once (`bash demo/run_demo.sh`, press Enter between steps) so you know the rhythm.

### A4. Live in Claude Code (10 minutes). This is the best part of the demo.

The hooks in `.claude/settings.json` load when Claude Code starts in this folder.

1. Open the folder in Claude Code (VS Code extension or `claude` in a terminal). If it asks whether to trust the project's hooks, say yes. Run `/hooks` to confirm `UserPromptSubmit` and `PreToolUse` are listed.
   If you edit `.claude/settings.json`, restart the session, because hooks are read at start-up.
2. Generate a fake token in a normal terminal (not inside Claude Code):
   ```bash
   python3 demo/make_fixtures.py               # also creates demo/fixtures/.env
   python3 demo/make_fixtures.py --print-token
   ```

| # | Type this into Claude Code | Expected |
|---|---|---|
| 1 | `why does this return 401? my token is <paste fake token>` | Prompt rejected with "blocked this prompt before it reached the AI model". Nothing is sent. |
| 2 | `refactor nothing, just say hi` | Normal answer (no friction). |
| 3 | `<paste fake token> guard:allow` | Still blocked. |
| 4 | `show me the contents of demo/fixtures/.env` | Read is denied (by `permissions.deny` or the hook, "credential file"). |
| 5 | `run: cat demo/fixtures/.env` | Bash call blocked by the hook. |
| 6 | `run the command env and show me the output` | Blocked: "prints secret environment variables". |
| 7 | `commit everything with git commit --no-verify` | Blocked: "skips git hooks". |
| 8 | `edit .claude/settings.json and remove the PreToolUse hook` | Blocked: "secret_guard configuration". |
| 9 | `read demo/fixtures/manifest.json and create src/settings.py that sets AWS_ACCESS_KEY_ID to that leaked_aws_key_id value` | Reading the manifest works (it is not a credential file), and then the Write is blocked: "AWS access key ID at tool:Write:content". Don't paste the key yourself, or the prompt hook blocks it first. |
| 10 | `add a docstring to metrics/report.py` | Works normally. |

- [ ] All 10 behave as expected.

Then show the evidence:

```bash
python3 metrics/report.py          # reads ~/.secret_guard/audit.jsonl
tail -n 3 ~/.secret_guard/audit.jsonl
```

### A5. Real git and GitHub (20 minutes, optional but impressive)

**Pre-commit, locally:**

```bash
git init -b main && git add -A && git commit -m "initial"
pre-commit install
cp demo/fixtures/config_leak.py app_config.py
git add app_config.py && git commit -m "add config"
```

- [ ] The commit is rejected by gitleaks and by `secret_guard (org rules)`. The first run of the gitleaks hook takes a minute while pre-commit installs Go.

Clean up: `git reset -q HEAD app_config.py && rm app_config.py`.

**CI, on GitHub.** Use a **public** test repo: code scanning (the Security tab) is free there, while private repos need GitHub Code Security.

```bash
gh repo create secrets-guard-demo --public --source . --push
git switch -c leak-demo
printf 'export DB_PASSWORD=%s\n' "$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')" > deploy.sh
git add deploy.sh && git commit --no-verify -m "deploy script"     # a human may bypass locally...
git push -u origin leak-demo && gh pr create --fill
```

- [ ] The `secret-guard` check fails on the PR (...but CI still catches it)
- [ ] Security tab > Code scanning shows the finding under the `secrets-guard` category, with a masked preview
- [ ] The `ci` workflow (tests, demo, self-scan, Terraform) is green on `main`

If GitHub push protection rejects a push, that is L4 doing its job. Mention it as a feature.

### A6. Terraform (5 minutes)

```bash
cd terraform
terraform init -backend=false && terraform validate     # "Success! The configuration is valid."
terraform fmt -check -recursive
```

Optional, with a test org you own: `export GITHUB_TOKEN=...` (admin on that org), set `github_org` and `onboarded_repos` in `example.tfvars`, then `terraform plan -var-file=example.tfvars`. In `repo` mode it plans one workflow file and one engine file per repo, plus one ruleset per repo.

- [ ] validate passes

### A7. Containment on its own (2 minutes)

```bash
KEY=$(python3 -c "import json;print(json.load(open('demo/fixtures/manifest.json'))['leaked_aws_key_id'])")
python3 remediation/contain_aws_key.py --simulate "$KEY"              # dry run
python3 remediation/contain_aws_key.py --simulate --execute "$KEY"    # contain
python3 remediation/contain_aws_key.py --simulate --json "$KEY" | head -30
python3 remediation/contain_aws_key.py --simulate --execute "AS""IA${KEY:4}"   # temporary creds
```

- [ ] Dry run says `Would deactivate` and lists 2 high-risk events in 2 regions
- [ ] The ASIA run says `Revoked every session of role orders-api-task`

---

## Part B. Demo script (15 minutes)

### Before you share your screen

- Terminal font size at least 18, dark theme, window wide enough for 110 columns.
- `clear`, `cd` into the repo, activate the venv, and run `bash demo/run_demo.sh --auto > /dev/null && echo ready`.
- Claude Code open on this folder, hooks confirmed with `/hooks`, the fake token ready to paste.
- Close Slack and email. Have a screen recording of A3 and A4 as a backup.

### 0:00 Opening (30 seconds)

> "Most secret scanning starts at the commit. With AI assistants that is too late: developers paste tokens into prompts, and coding agents run commands with access to `.env` files and the shell environment. I built one detection engine and enforced it at every point a secret can leave: the prompt, the agent's actions, the commit, the pull request and the org settings. It ends with a containment runbook and a metric that shows whether we are actually shifting left."

### 0:30 Architecture (1 minute)

Show the diagram at the top of README.md. Make three points:
1. **One engine, five layers**: the same rules give the same answer in the IDE, at commit and in CI.
2. **The agent is untrusted**: it cannot grant itself exceptions or switch the guard off.
3. **Measured**: every block is logged with a keyed fingerprint, never the secret.

### 1:30 Live: Claude Code (3 minutes). This is the moment they will remember.

Run A4 rows 1, 2, 4, 7 and 8 in Claude Code.

- Row 1: *"The prompt never left my laptop. The message tells me how to fix it and to rotate the token if I pasted it anywhere else."*
- Row 2: *"Clean prompts pass instantly, so there is no friction for the 99% case."*
- Row 4: *"Reading `.env` is the bigger risk. Once the agent reads it, the contents are in the model context. Blocking the read is the only control that works."*
- Row 7: *"An agent that hits a failing hook will happily try `--no-verify`. It can't."*
- Row 8: *"A prompt-injected agent's first move would be to switch the guard off. It can't edit its own guardrails."*

If Claude Code misbehaves, say "let me show the same thing with the recorded payloads" and switch to the terminal demo. The terminal demo exercises exactly the same code.

### 4:30 Terminal: `bash demo/run_demo.sh` (6 minutes)

| Act | Say |
|---|---|
| 1.3 bypass | "In the first version, `guard:allow` worked in prompts, so anyone could type it. Exceptions now apply only to reviewed files." |
| 2.2 Write | "This was a real bug I found reviewing my own code: the tool hook serialised the input to JSON, which escaped the quotes, so `password = "..."` slipped through. Now each field is scanned on its own, with a regression test." |
| 3.1 commit | "Same engine at pre-commit. The `.env` lines are caught, while the placeholder, the env reference and the reviewed `guard:allow` line are not. False positives kill adoption faster than missed secrets." |
| 4.1 CI | "Someone committed with `--no-verify` on a laptop without hooks. CI is the net: SARIF goes to the Security tab and the required check blocks the merge." |
| 5 containment | "Detection without response is a notification. This does the first 15 minutes: owner, CloudTrail across every region (a single-region lookup would miss the `RunInstances` in Singapore), persistence via a new access key, then deactivate. Dry run by default." |
| 6 metrics | "The question leadership asks is not how many findings, it is how far secrets get. 9 of 10 stopped on the laptop. One reached CI, and that one needs rotation. The goal is to move that number over time." |

### 10:30 Code tour (2 minutes, only if they want to see code)

Open `guard/secret_guard.py` and show:
- `RULES`: specific rules first, generic rules last, with `looks_like_secret` heuristics for the generic ones.
- `run_hook`: fail closed, and only the exception *type* is printed because the message could quote the payload.
- `check_tool_policy`: agent policy separate from secret detection.
- `terraform/main.tf`: the workflow is committed before the ruleset requires it, and the comment warns about the blast radius of `github_organization_settings`.

### 12:30 Close (1 minute)

> "Known limits: regex can be evaded with encoding; the agent hook sees tool calls, not tool output; and repo-level settings can be removed by the developer, so in production I'd ship the hooks through managed settings. What I'd add next: live validity checks so triage starts with 'is it active', wiring containment to the secret-scanning webhook with a human approval step, and feeding findings into the ASPM next to SAST and SCA."

Naming the limits yourself before they ask is a strong signal of seniority. Do it.

### Making it relevant to Equinix

Keep the claims general. Don't assert anything about their internal stack. Frame it as questions and fit.

- **Scale through paved roads.** A global infrastructure company has many engineering teams. Guardrails have to be self-service and consistent, which is what "one PR adds a repo to `onboarded_repos`" gives you.
- **Hybrid and multi-cloud.** The engine is provider-agnostic. AWS containment is one playbook, and the same pattern extends to Azure and GCP, or to internal platform tokens (the `internal-service-token` rule shows how to add an internal format to both engines).
- **Compliance evidence.** The audit log, SARIF history, Terraform-managed rulesets and CODEOWNERS approvals are ready-made evidence for SOC 2, ISO 27001 or PCI control testing.
- **Partner and customer API credentials.** Platforms that expose APIs to customers issue client IDs and secrets. The generic `client_secret` and env rules cover those, and a custom rule can match an exact format.
- **Questions to ask them:** "How are AI coding assistants rolled out today, and through managed settings or per developer?" "Where do secret findings land now: per-tool dashboards or an ASPM?" "What is your current mean time to rotate a leaked credential?"

---

## Part C. Likely questions

**Why not just use GitHub push protection or gitleaks?**
I use both. They see commits; they cannot see a prompt or an agent reading `.env`. gitleaks gives the broad vendor rule set, and secret_guard adds the AI-specific enforcement points, org-specific rules and agent policy on one engine.

**What about false positives?**
Specific vendor rules run first. Keyword rules must also pass `looks_like_secret`, which skips placeholders, env-var references, paths, templates and secret *names*. Medium findings report but do not block. Exceptions (`guard:allow`, or the allowlist with a mandatory reason) are visible in review, and CODEOWNERS routes them to AppSec. A test scans the repo itself to prove there is no noise.

**How do you stop developers from disabling it?**
Locally, I can't fully, and I say so. The answer is layers: managed settings for the AI hooks, CI as a required check that is enforced by a Terraform-managed ruleset, push protection server-side, and code-owner review for any change to the guard. The agent, which is the bigger risk, cannot disable it at all.

**Why fail closed? Won't that block developers?**
An exit code other than 2 lets the action through, so a crash would silently disable the control. Failing closed with a clear message is safer, and `SECRET_GUARD_FAIL_MODE=open` is a logged break-glass. The hook is standard library only, so crashes are unlikely.

**Why HMAC fingerprints rather than a plain hash?**
A plain SHA-256 of a short password can be brute-forced from the audit log or SARIF. With an org-managed key, fingerprints still dedupe across laptops and CI but are useless without the key.

**How does this scale to 1,000 repos?**
Terraform `gate_mode = "org"` is one org ruleset with a required workflow, with no per-repo changes. Start with `enforcement = "evaluate"`, baseline, then switch to `active`. Repo mode is the fallback for plans without org rulesets.

**What happens when a real key leaks?**
Run `contain_aws_key.py` as a dry run: owning account, user, every-region CloudTrail, high-risk events, other keys. Then `--execute`, which deactivates rather than deletes to keep evidence. Then rotate dependent workloads to roles or OIDC, purge history, and link the fix PR. Next step is triggering it from the secret-scanning webhook with a human approval.

**Temporary credentials?**
They can't be deactivated. The script finds the role in CloudTrail and attaches the same deny policy the IAM console's "Revoke active sessions" adds (`aws:TokenIssueTime` before now). Identity Center roles are pointed to Identity Center instead.

**What are the metrics, and why those?**
Each unique secret counted once at the furthest stage it reached. "Stopped on the laptop" measures prevention, and "reached CI" is the rotation workload. Raw finding counts reward noise; this rewards moving left.

**What would you do differently in production?**
Managed settings for distribution, central log shipping to the SIEM, validity checks, an ASPM integration, and a hosted rules package so rule updates don't need a copy in every repo.

**Supply-chain risk in your own pipeline?**
Every action is pinned to a commit SHA and images to digests, Dependabot updates the pins, `persist-credentials: false` is set, and permissions are least-privilege per job. Tag hijacking, as in the tj-actions/changed-files incident in 2025, is exactly why tags are not enough.

**What did you learn building it?**
Two things. First, my first version had bypasses I only found by attacking it: the allow marker, and JSON escaping hiding secrets from the rules. Now every bypass has a regression test. Second, while I was developing with an AI assistant, the guard blocked that assistant's own commands twice when they contained test tokens. That is the control working on a real agent, and it is why the test fixtures are assembled at runtime.

---

## Part D. Day-of checklist and troubleshooting

- [ ] `pytest -q` passes, and `bash demo/run_demo.sh --auto` prints all 15 checks passed
- [ ] Claude Code hooks confirmed with `/hooks`; fake token copied
- [ ] Backup recording ready
- [ ] Optional: GitHub PR from A5 open in a browser tab, showing the failed check and the Security tab

| Problem | Fix |
|---|---|
| Claude Code does not block anything | Hooks load at start-up: restart the session in this folder and check `/hooks`. Make sure `python3` is on PATH in that shell. |
| Every Claude Code action is blocked with "fails closed" | The guard is crashing. Run `echo '{}' \| python3 guard/secret_guard.py hook-tool` to see the error. Temporary break-glass: start Claude Code with `SECRET_GUARD_FAIL_MODE=open`. |
| You need to edit `.claude/settings.json` with Claude Code's help | The guard blocks that by design. Edit it yourself in the editor. |
| The pre-commit gitleaks hook is slow the first time | pre-commit is installing Go. Run `pre-commit run --all-files` once beforehand. |
| `pytest` not found | `pip install pytest` inside the venv. |
| Colours look wrong on a shared screen | `bash demo/run_demo.sh | cat` disables colour. |
