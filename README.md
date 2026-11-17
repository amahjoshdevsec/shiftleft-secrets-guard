# shiftleft-secrets-guard

Secret scanning that starts **before the developer prompts the AI assistant** and ends with a containment runbook. One detection engine, enforced at every point a secret can escape: the AI prompt, the coding agent's actions, the commit, the pull request, and the org's repository settings.

```
  Developer laptop (IDE)                                   GitHub org / AWS
 ┌────────────────────────────────────────────┐   ┌─────────────────────────────────────────┐
 │ L1  AI prompt hook    block before the LLM │   │ L3  CI gate     gitleaks + secret_guard │
 │ L1b AI agent hook     block tool calls that│──▶│                 + Semgrep + Trivy       │
 │     carry secrets, read .env, dump env,    │   │                 SARIF to Security tab   │
 │     skip git hooks, or disable the guard   │   │ L4  Terraform   ruleset + required check│
 │ L2  pre-commit        gitleaks + guard     │   │                 or org required workflow│
 └────────────────────────────────────────────┘   │ L5  contain_aws_key.py  scope + contain │
          │ audit.jsonl (keyed fingerprints only)  └─────────────────────────────────────────┘
          ▼
   metrics/report.py   "how far did each secret get?"
```

### Reading the diagram

Read it left to right, in the order a secret would travel. Each layer catches what the one before it missed.

**Left box: the developer's laptop.** These layers stop a secret before it leaves the machine.

* **L1, AI prompt hook.** Scans the prompt before the AI assistant sends it to the model. A token pasted in while debugging is blocked, so the model never sees it.
* **L1b, AI agent hook.** Checks each action the coding agent tries to take, before it runs. It blocks a call that:
  * puts a secret into a command or a file;
  * reads credential files such as `.env`;
  * dumps the environment (`env`, `printenv`);
  * skips git hooks (`--no-verify`);
  * edits the guard's own configuration.
* **L2, pre-commit.** Runs gitleaks and the same guard engine on staged files, so a secret in code is stopped before it becomes a commit.

**Arrow to the right box.** Anything that gets past the laptop, for example because someone ran `git commit --no-verify` or never installed the hooks, is pushed to GitHub. The laptop layers make leaks unlikely but can be bypassed. The layers on the right cannot be bypassed by a developer.

**Right box: the GitHub org and AWS.** These layers enforce the policy on the server side and handle leaks that already happened.

* **L3, CI gate.** Every pull request runs gitleaks, secret_guard, Semgrep and Trivy. Findings appear in GitHub's Security tab as SARIF. A critical or high finding fails the `secret-guard` check.
* **L4, Terraform.** Makes that check mandatory. It configures each repo with a ruleset that requires the check, or the org with a required workflow, so a PR cannot merge without passing L3. Onboarding a repo is a Terraform change, not a manual setting.
* **L5, `contain_aws_key.py`.** If an AWS key leaked anyway, this runbook finds who owns the key and what it was used for (CloudTrail in every region), then deactivates it.

**Bottom: measurement.** Every block writes an event to `audit.jsonl`. Events hold only a keyed HMAC fingerprint of the secret, never the secret itself. `metrics/report.py` uses the fingerprints to count each unique secret once, at the furthest stage it reached (prompt, tool, pre-commit or CI). A secret stopped at the prompt or tool stage is a shift-left win. A secret that reached CI was pushed, so it must be rotated.

## Why this design

* **Prompts are a new egress path.** Developers paste tokens into AI assistants while debugging. Commit-time scanning only sees what is committed, which is too late for anything already sent to a model.
* **Coding agents act on the laptop.** An agent can put a credential into a `curl`, write it into a file, `cat .env` into its own context, run `env`, or `git commit --no-verify`. The tool hook checks every call before it runs.
* **The agent is untrusted.** A prompt-injected agent must not be able to grant itself an exception. Inline `guard:allow` markers and the allowlist apply only to reviewed files, never to prompts or agent actions, and the agent cannot edit the guard's configuration.
* **Same engine everywhere.** One rule set in the IDE, at commit and in CI, so developers never get two different answers. The one custom rule shared with gitleaks is kept identical by a test.
* **Fail closed, low friction.** If the guard errors, the prompt or tool call is blocked (with a logged break-glass). Clean prompts pass in milliseconds, placeholders and references are ignored, and every block message says how to fix it.
* **Secrets never get logged.** Findings carry a masked preview (only a fixed vendor prefix such as `ghp_`) and an HMAC fingerprint. The audit log stores neither the secret nor the preview.
* **Measure how far secrets get.** Each unique secret is counted once, at the furthest point it reached. "Stopped on the laptop" is the shift-left number; "reached CI" is the number that needs rotation.

## Quick start

Requires Python 3.9+ (standard library only) and bash. Tested on 3.9.6 (macOS system Python), 3.10, 3.13 and 3.14.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pytest
pytest -q                     # 96 tests, about 4 seconds
bash demo/run_demo.sh         # interactive walkthrough (add --auto for no pauses)
```

[WALKTHROUGH.md](WALKTHROUGH.md) has a step-by-step test plan and a demo script.

## Layers

### L1: AI assistant hooks (Claude Code)

`.claude/settings.json` registers two hooks and a few `permissions.deny` rules. Open the repo in Claude Code and approve the hooks (`/hooks` shows them). Other assistants with pre-prompt or pre-tool hooks can call the same CLI: it reads the hook JSON on stdin and exits `2` to block.

| Hook | Blocks |
|---|---|
| `hook-prompt` (UserPromptSubmit) | a prompt containing a secret, before it is sent |
| `hook-tool` (PreToolUse: Bash, Write, Edit, MultiEdit, NotebookEdit, Read, Grep, WebFetch, WebSearch, MCP) | a secret in any field of the tool call; reading credential files (`.env`, `*.pem`, `~/.aws/credentials`, `~/.ssh/id_*`, `*.tfstate`, ...); printing the environment (`env`, `printenv TOKEN`, `echo $SECRET`); skipping git hooks (`--no-verify`, `SKIP=`, `core.hooksPath`); editing the guard's own config |

Removing a secret is never blocked: the `old_string` of an edit is not scanned.

### L2: pre-commit

```bash
pip install pre-commit && pre-commit install
```

Runs gitleaks (broad community rules) and `secret_guard scan --stage precommit` (org rules) on staged files.

### L3: CI gate

`.github/workflows/secret-guard.yml` is the portable gate that every onboarded repo runs:

* gitleaks over every commit in the PR (not only the final diff) and secret_guard over changed files, both as SARIF in the Security tab
* Semgrep (OWASP Top 10) and Trivy (dependencies and misconfiguration)
* critical/high fails the `secret-guard` check, medium is reported only
* every action pinned to a commit SHA, images pinned to digests, Dependabot keeps them current; changed file names are passed NUL-separated so odd names cannot inject arguments

`.github/workflows/ci.yml` is this repo's own CI: tests on two Python versions, the demo end to end, a self-scan, `terraform validate` and Checkov.

### L4: onboarding as code (Terraform)

```bash
cd terraform
terraform init
terraform plan -var-file=example.tfvars    # needs GITHUB_TOKEN for a real org
```

| `gate_mode` | Plan needed | What it does |
|---|---|---|
| `repo` (default) | any paid plan | commits the gate workflow and the engine into each repo, then a ruleset requiring the `secret-guard` check and code-owner review |
| `org` | Enterprise Cloud | one org ruleset that runs the workflow from this repo as a required workflow; set the org variable `SECRET_GUARD_REPO` so it can fetch the engine |

Optional: `block_sensitive_files_on_push` (org push ruleset that rejects `.env`, `*.pem`, `*.tfstate` and similar files) and `manage_org_defaults` (secret scanning and push protection for new repos; read the warning in `main.tf` first, because that resource owns the whole org profile).

The workflow is committed before the ruleset that requires it, so a newly onboarded repo is never stuck waiting for a check that never reports.

### L5: containment

```bash
python3 remediation/contain_aws_key.py --simulate AKIA...      # demo data, no AWS account needed
python3 remediation/contain_aws_key.py AKIA...                 # real account, dry run
python3 remediation/contain_aws_key.py AKIA... --execute       # deactivate
```

It finds the owning account (`sts:GetAccessKeyInfo`) and IAM user, pulls CloudTrail for the key across **every enabled region** (LookupEvents is regional) and flags persistence and privilege-escalation events. It also lists other keys on the user. Then it contains: AKIA keys are deactivated (not deleted, to keep evidence); ASIA temporary credentials are handled by revoking the role's older sessions. It is a manual tool today; see "What I would add next" for wiring it to alerts.

### Metrics

```bash
python3 metrics/report.py                 # ~/.secret_guard/audit.jsonl
python3 metrics/report.py --json          # for a dashboard
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GUARD_AUDIT_LOG` | `~/.secret_guard/audit.jsonl` | where detections are logged |
| `SECRET_GUARD_FP_KEY` | built-in (unkeyed in effect) | HMAC key for fingerprints. Set the same org-managed value on laptops and in CI (`secrets.SECRET_GUARD_FP_KEY`) |
| `SECRET_GUARD_FAIL_MODE` | `closed` | `open` lets prompts and tool calls through if the guard itself crashes (break-glass, logged) |

False positives in files: add `guard:allow` to the line, or add the fingerprint from the block message to `.secret-guard-allowlist` with an owner and reason. Entries without a reason are ignored. Both changes are visible in review, and CODEOWNERS routes them to AppSec.

## Layout

| Path | Layer | What it does |
|---|---|---|
| `guard/secret_guard.py` | L1, L2, L3 | Detection engine, agent policy and CLI (`hook-prompt`, `hook-tool`, `scan`, `rules`) |
| `.claude/settings.json` | L1 | Claude Code hooks and read-deny rules |
| `.pre-commit-config.yaml`, `.gitleaks.toml` | L2 | Local gate with org-specific rules |
| `.github/workflows/secret-guard.yml` | L3 | Portable PR gate with SARIF upload |
| `.github/workflows/ci.yml` | | This repo's own CI |
| `.github/CODEOWNERS`, `.secret-guard-allowlist` | Governance | AppSec review for guard changes and exceptions |
| `terraform/` | L4 | Rulesets, required check or required workflow, push rules |
| `remediation/contain_aws_key.py` | L5 | First 15 minutes of the leaked-key runbook |
| `metrics/report.py` | Reporting | Furthest stage reached per secret, shift-left percentage |
| `demo/` | | Fixture generator and the self-checking demo script |
| `tests/test_guard.py` | | 96 tests, including a regression test for each bypass found in review |

## Known limitations

These are deliberate scope limits, stated so nobody has to discover them.

* **Pattern matching can be evaded.** A secret that is base64-encoded, split across lines or assembled at runtime is not detected. The hooks raise the cost of an accidental or lazy leak; they do not stop a determined insider. Server-side push protection, CI and rotation are the backstops.
* **The agent hook sees tool calls, not tool output.** If a command the agent runs prints a secret (for example a verbose `curl`), that output reaches the model. Credential-file reads, environment dumps and the most common read commands are blocked; anything else is best effort.
* **Shell analysis is heuristic.** The Bash checks look for common read, write and bypass patterns. An unusual command can get past them, and in rare cases a harmless one is blocked (for example `cp .env.example .env`).
* **Developers control the repo's `.claude/settings.json`.** For enforcement, ship the hooks through managed settings (organization policy) so they cannot be removed locally. The same applies to pre-commit: CI and push protection are the controls that cannot be skipped.
* **Hooks need `python3` on PATH.** If it is missing, the assistant reports a hook error and continues, so hooks fail open in that specific case.
* **The audit log is per machine.** Ship `audit.jsonl` with the existing log forwarder to the SIEM for org-wide metrics.
* **Containment covers AWS keys.** Other providers need their own playbooks, and for temporary credentials the role has to appear in CloudTrail.

## What I would add next

* Live validity checks for found secrets, so triage starts with "is it active?"
* Wire containment to alerts: GitHub secret scanning webhook, then a Lambda that runs the dry run and opens a ticket, then a human approves `--execute`.
* Ownership mapping (CODEOWNERS or the service catalog) to route findings automatically.
* Feed findings into the org's ASPM so secrets sit next to SAST and SCA risk per application.
* Package the hooks through managed settings and an MDM profile so rollout does not depend on each developer.

Demo fixtures are generated at runtime (`demo/make_fixtures.py`) and are git-ignored, so the repo never contains realistic key strings. The test suite proves it by scanning the repo itself.
