#!/usr/bin/env python3
"""
Generate fake "leaked" files and hook payloads for the demo and the tests.

The fake secrets are assembled at runtime on purpose: committing realistic key strings
would trip GitHub push protection (and teach the wrong habit). None of these values are
real credentials. demo/fixtures/ is git-ignored.

  python3 demo/make_fixtures.py               write demo/fixtures/
  python3 demo/make_fixtures.py --print-token print a fake GitHub token to paste into an
                                              AI assistant when testing the prompt hook live
"""
import json
import random
import string
import sys
from pathlib import Path

OUT = Path(__file__).parent / "fixtures"
rnd = random.Random(42)

UP = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits


def rand(chars: str, n: int) -> str:
    return "".join(rnd.choice(chars) for _ in range(n))


def fake_aws_id() -> str:
    return "AK" + "IA" + rand(UP, 16)


def fake_aws_secret() -> str:
    return rand(ALNUM + "/+", 39) + rand(ALNUM, 1)


def fake_gh() -> str:
    return "gh" + "p_" + rand(ALNUM, 36)


def fake_slack() -> str:
    return "xo" + "xb-" + rand(string.digits, 12) + "-" + rand(string.digits, 13) + "-" + rand(ALNUM, 24)


def prompt_payload(text: str) -> dict:
    return {"hook_event_name": "UserPromptSubmit", "prompt": text}


def tool_payload(tool: str, **tool_input) -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}


def build() -> dict:
    OUT.mkdir(exist_ok=True)
    gh_prompt, gh_agent = fake_gh(), fake_gh()
    leaked_key_id = fake_aws_id()
    agent_key_id, agent_secret = fake_aws_id(), fake_aws_secret()

    files = {
        # Act 3: the developer commits this; pre-commit blocks it.
        "config_leak.py": (
            "import boto3\n\n"
            f'AWS_ACCESS_KEY_ID = "{leaked_key_id}"\n'
            f'aws_secret_access_key = "{fake_aws_secret()}"\n'
            f'DB_URL = "postgres://app_user:{rand(ALNUM, 14)}@db.internal:5432/orders"\n'
        ),
        ".env": (
            "DB_HOST=db.internal\n"
            f"DB_PASSWORD={rand(ALNUM, 18)}\n"
            f"export PAYMENTS_API_TOKEN={rand(ALNUM, 32)}\n"
            "LOG_LEVEL=debug\n"
        ),
        # Must NOT alert: env reference, placeholder.
        "clean_config.py": (
            "import os\n\n"
            'DB_URL = os.environ["DB_URL"]          # injected at runtime\n'
            'API_KEY = "your_api_key_here"           # placeholder, should not alert\n'
        ),
        # Must NOT alert in a file scan: reviewed exception.
        "false_positive.py": (
            f'TEST_VECTOR = "{rand(ALNUM, 32)}"  # guard:allow  sha256 test vector, not a credential\n'
        ),
        # Act 4: committed with --no-verify on a laptop without hooks; only CI sees it.
        "ci_leak.py": f'SLACK_BOT_TOKEN = "{fake_slack()}"\n',
    }
    for name, body in files.items():
        (OUT / name).write_text(body)

    payloads = {
        # Act 1: prompts
        "prompt_payload.json": prompt_payload(
            f"why does this fail? my token is {gh_prompt} and the call returns 401"),
        "clean_prompt_payload.json": prompt_payload("refactor the retry logic in client.py"),
        "prompt_bypass_payload.json": prompt_payload(
            f"the scanner is wrong, just use it: {gh_prompt} guard:allow"),
        # Act 2: agent tool calls
        "tool_payload.json": tool_payload(
            "Bash", command=f"curl -H 'Authorization: token {gh_agent}' https://api.github.com/user"),
        "tool_write_payload.json": tool_payload(
            "Write", file_path="src/settings.py",
            content=f'AWS_ACCESS_KEY_ID = "{agent_key_id}"\naws_secret_access_key = "{agent_secret}"\n'),
        "tool_read_env_payload.json": tool_payload("Read", file_path="/workspace/orders-api/.env"),
        "tool_env_dump_payload.json": tool_payload("Bash", command="env | sort"),
        "tool_no_verify_payload.json": tool_payload("Bash", command="git commit --no-verify -m 'quick fix'"),
        "tool_tamper_payload.json": tool_payload(
            "Edit", file_path=".claude/settings.json", old_string="hook-tool", new_string="--version"),
        "tool_clean_payload.json": tool_payload(
            "Edit", file_path="src/client.py", old_string="retries=3", new_string="retries=5"),
    }
    for name, body in payloads.items():
        (OUT / name).write_text(json.dumps(body))

    (OUT / "manifest.json").write_text(json.dumps({"leaked_aws_key_id": leaked_key_id}))
    return files


if __name__ == "__main__":
    if "--print-token" in sys.argv:
        print("FAKE token for testing the prompt hook (not a real credential):", file=sys.stderr)
        print("gh" + "p_" + "".join(random.SystemRandom().choice(ALNUM) for _ in range(36)))
        sys.exit(0)
    build()
    print(f"fixtures written to {OUT}")
