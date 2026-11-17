#!/usr/bin/env python3
"""
Layer 5: containment for a leaked AWS access key.

Detection without response is just a notification. This script does the first 15 minutes
of the leaked-key runbook so the on-call engineer is not doing it by hand:

  1. Which account owns the key (sts:GetAccessKeyInfo works for any key ID).
  2. Which IAM user owns it in this account, and when it was last used.
  3. CloudTrail activity for the key in EVERY enabled region (LookupEvents is regional, so a
     single-region lookup misses an attacker who went elsewhere), with persistence and
     privilege-escalation events flagged.
  4. Other access keys on the same user (CreateAccessKey is a common first attacker move).
  5. Contain:
       AKIA (long-term user key)   deactivate it. Not delete: keeps evidence, allows rollback.
       ASIA (temporary STS creds)  cannot be deactivated. Revoke the role's sessions issued
                                   before now with an explicit-deny inline policy (the same
                                   policy the IAM console's "Revoke active sessions" adds).
  6. Print an incident summary for the ticket and the owning team.

Default is a dry run. --execute makes changes.
--simulate runs against built-in fake AWS clients, so the flow can be demonstrated without an
AWS account. Nothing in simulate mode talks to AWS.

Real mode needs boto3 and: sts:GetAccessKeyInfo, iam:GetAccessKeyLastUsed, iam:ListAccessKeys,
iam:UpdateAccessKey, iam:PutRolePolicy, cloudtrail:LookupEvents, ec2:DescribeRegions.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections import Counter
from typing import Any, Callable

HIGH_RISK_EVENTS = frozenset({
    # persistence / privilege escalation
    "CreateAccessKey", "CreateUser", "CreateLoginProfile", "UpdateLoginProfile", "AttachUserPolicy",
    "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy", "CreateRole", "UpdateAssumeRolePolicy",
    "AddUserToGroup", "CreatePolicyVersion", "SetDefaultPolicyVersion", "CreateVirtualMFADevice",
    "DeactivateMFADevice", "GetFederationToken",
    # defence evasion
    "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteFlowLogs",
    "DeleteDetector",
    # data access / exposure / resource abuse
    "GetSecretValue", "PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy", "PutBucketPublicAccessBlock",
    "ModifySnapshotAttribute", "RunInstances", "CreateKeyPair", "ImportKeyPair",
    "AuthorizeSecurityGroupIngress",
})
REVOKE_POLICY_NAME = "AWSRevokeOlderSessions"
KEY_ID = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")


def error_code(exc: Exception) -> str:
    return (getattr(exc, "response", None) or {}).get("Error", {}).get("Code") or type(exc).__name__


def key_type(key_id: str) -> str:
    return {"AKIA": "long-term", "ASIA": "temporary"}.get(key_id[:4], "unknown")


def mask_key(key_id: str) -> str:
    return f"{key_id[:4]}...{key_id[-4:]}"


def owning_account(sts, key_id: str) -> str | None:
    try:
        return sts.get_access_key_info(AccessKeyId=key_id)["Account"]
    except Exception:  # noqa: BLE001 - informational only
        return None


def find_owner(iam, key_id: str) -> tuple[str | None, dict]:
    try:
        resp = iam.get_access_key_last_used(AccessKeyId=key_id)
    except Exception as exc:
        if error_code(exc) in ("NoSuchEntity", "AccessDenied", "InvalidClientTokenId"):
            return None, {}
        raise
    return resp.get("UserName"), resp.get("AccessKeyLastUsed", {})


def lookup_region(ct, key_id: str, start: dt.datetime, limit: int) -> list[dict]:
    events: list[dict] = []
    token = None
    while len(events) < limit:
        kw: dict[str, Any] = {"LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": key_id}],
                              "StartTime": start, "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        resp = ct.lookup_events(**kw)
        for e in resp.get("Events", []):
            d = json.loads(e.get("CloudTrailEvent") or "{}")
            ident = d.get("userIdentity", {})
            issuer = ident.get("sessionContext", {}).get("sessionIssuer", {})
            events.append({
                "time": str(e.get("EventTime")), "event": e.get("EventName"),
                "region": d.get("awsRegion"), "source_ip": d.get("sourceIPAddress"),
                "user_agent": d.get("userAgent"), "principal": ident.get("arn"),
                "role_name": issuer.get("userName") if issuer.get("type") == "Role" else None,
                "error": d.get("errorCode"), "high_risk": e.get("EventName") in HIGH_RISK_EVENTS,
            })
        token = resp.get("NextToken")
        if not token:
            break
    return events[:limit]


def activity(ct_factory: Callable[[str], Any], regions: list[str], key_id: str, days: int,
             now: dt.datetime, limit_per_region: int = 500) -> tuple[list[dict], dict[str, str]]:
    start = now - dt.timedelta(days=days)
    events: list[dict] = []
    failed: dict[str, str] = {}
    for region in regions:
        try:
            events += lookup_region(ct_factory(region), key_id, start, limit_per_region)
        except Exception as exc:  # noqa: BLE001 - one region failing must not stop the rest
            failed[region] = error_code(exc)
    events.sort(key=lambda e: e["time"])
    return events, failed


def other_keys(iam, user: str, key_id: str, since: dt.datetime) -> list[dict]:
    try:
        meta = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    except Exception as exc:  # noqa: BLE001
        return [{"error": error_code(exc)}]
    return [{"key": mask_key(k["AccessKeyId"]), "status": k["Status"], "created": str(k["CreateDate"]),
             "created_in_window": k["CreateDate"] >= since}
            for k in meta if k["AccessKeyId"] != key_id]


def revoke_policy(now: dt.datetime) -> dict:
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"DateLessThan": {"aws:TokenIssueTime": now.strftime("%Y-%m-%dT%H:%M:%SZ")}}}]}


def contain(*, key_id: str, iam, sts, ct_factory: Callable[[str], Any], regions: list[str],
            days: int = 7, execute: bool = False, now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    kind = key_type(key_id)
    s: dict[str, Any] = {"key": mask_key(key_id), "key_type": kind,
                         "owning_account": owning_account(sts, key_id),
                         "mode": "EXECUTE" if execute else "DRY RUN"}
    events, failed = activity(ct_factory, regions, key_id, days, now)
    s["activity"] = {
        "days": days, "regions_checked": len(regions), "regions_failed": failed, "events": len(events),
        "by_region": dict(Counter(e["region"] for e in events).most_common()),
        "source_ips": sorted({e["source_ip"] for e in events if e["source_ip"]}),
        "high_risk": [e for e in events if e["high_risk"]],
    }
    actions: list[str] = []
    status = None

    if kind == "long-term":
        user, last = find_owner(iam, key_id)
        if not user:
            status = "NOT_IN_THIS_ACCOUNT"
            actions.append(f"Key is not in this account. It belongs to account {s['owning_account'] or 'unknown'}: "
                           "re-run with credentials for that account.")
        else:
            s["owner"] = {"iam_user": user, "last_used": str(last.get("LastUsedDate")),
                          "last_service": last.get("ServiceName"), "last_region": last.get("Region")}
            s["other_keys"] = other_keys(iam, user, key_id, now - dt.timedelta(days=days))
            if execute:
                iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
                actions.append(f"Deactivated {mask_key(key_id)} on IAM user {user}")
            else:
                actions.append(f"Would deactivate {mask_key(key_id)} on IAM user {user} (re-run with --execute)")
    elif kind == "temporary":
        roles = sorted({e["role_name"] for e in events if e["role_name"]})
        s["roles"] = roles
        if not roles:
            actions.append("No CloudTrail event names the role behind these temporary credentials. Find it "
                           "from the leak context, then use 'Revoke active sessions' on that role.")
        for role in roles:
            if role.startswith("AWSReservedSSO_"):
                actions.append(f"{role} is managed by IAM Identity Center: revoke the user's sessions there")
            elif execute:
                iam.put_role_policy(RoleName=role, PolicyName=REVOKE_POLICY_NAME,
                                    PolicyDocument=json.dumps(revoke_policy(now)))
                actions.append(f"Revoked every session of role {role} issued before {now:%Y-%m-%dT%H:%M:%SZ}")
            else:
                actions.append(f"Would revoke every session of role {role} issued before now (re-run with --execute)")
    else:
        status = "UNSUPPORTED_KEY_TYPE"

    s["actions"] = actions
    s["status"] = status or ("CONTAINED" if execute else "DRY_RUN")
    s["next_steps"] = next_steps(s)
    return s


def next_steps(s: dict) -> list[str]:
    steps = []
    hr = s["activity"]["high_risk"]
    if hr:
        names = ", ".join(sorted({e["event"] for e in hr}))
        steps.append(f"ESCALATE to incident response: {len(hr)} high-risk event(s) ({names}). "
                     "Assume the attacker had the same access as the key.")
    new_keys = [k for k in s.get("other_keys", []) if k.get("created_in_window") and k.get("status") == "Active"]
    if new_keys:
        steps.append(f"{len(new_keys)} other active key(s) on this user were created during the leak window. "
                     "Possible attacker persistence: deactivate them unless the owner confirms.")
    if s["key_type"] == "temporary":
        steps.append("Sessions issued after the revocation are not affected. Find and fix how the "
                     "credentials leaked, or the attacker can obtain fresh ones.")
    if s["activity"]["regions_failed"]:
        steps.append(f"CloudTrail lookup failed in {sorted(s['activity']['regions_failed'])}: check those "
                     "regions in the org trail.")
    steps += [
        "Review the source IPs against known CI and office ranges. Unknown IPs mean escalate.",
        "Rotate dependent workloads to an IAM role or OIDC so there is no long-lived key to leak.",
        "Purge the secret from git history and close the finding with the fix PR linked.",
    ]
    return steps


def render(s: dict) -> str:
    a = s["activity"]
    out = []
    if s.get("simulated"):
        out.append("[SIMULATED: built-in fake AWS data, no AWS calls were made]")
    out.append(f"Leaked AWS key {s['key']} ({s['key_type']}), owning account {s['owning_account']}")
    out.append(f"Mode: {s['mode']}{'' if s['mode'] == 'EXECUTE' else ' (no changes made)'}    Status: {s['status']}")
    if "owner" in s:
        o = s["owner"]
        out.append(f"Owner: IAM user {o['iam_user']}, last used {o['last_used']} via {o['last_service']} "
                   f"in {o['last_region']}")
    if s.get("roles"):
        out.append(f"Role(s) using these credentials: {', '.join(s['roles'])}")
    out.append(f"CloudTrail, last {a['days']} days, {a['regions_checked']} regions: {a['events']} events "
               f"from {len(a['source_ips'])} IPs")
    if a["by_region"]:
        out.append("  by region: " + ", ".join(f"{r} {n}" for r, n in a["by_region"].items()))
    for e in a["high_risk"]:
        out.append(f"  HIGH RISK  {e['time']}  {e['event']:<22} {e['region']:<15} from {e['source_ip']}")
    for k in s.get("other_keys", []):
        flag = "  <- created during the leak window" if k.get("created_in_window") else ""
        out.append(f"  other key on user: {k.get('key')} {k.get('status')} created {k.get('created')}{flag}")
    out.append("Actions:")
    out += [f"  - {x}" for x in s["actions"]]
    out.append("Next steps:")
    out += [f"  {i}. {x}" for i, x in enumerate(s["next_steps"], 1)]
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Simulated AWS: deterministic fake clients for demos and tests.
# --------------------------------------------------------------------------- #

class SimulatedError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class SimulatedAWS:
    """A story, not a mock framework: a deploy key leaked, an attacker used it from an unknown IP,
    created a second key for persistence (IAM events land in us-east-1) and launched an instance in
    ap-southeast-1, a region a single-region lookup would never check."""

    ACCOUNT = "111122223333"
    OTHER_ACCOUNT = "444455556666"
    REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
    ATTACKER_IP = "203.0.113.50"   # RFC 5737 documentation range
    CI_IP = "192.0.2.10"

    def __init__(self, key_id: str, now: dt.datetime | None = None, in_account: bool = True):
        self.key_id = key_id
        self.now = now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.in_account = in_account
        self.calls: list[tuple[str, dict]] = []
        self.iam = _SimIAM(self)
        self.sts = _SimSTS(self)

    def cloudtrail(self, region: str) -> "_SimCloudTrail":
        return _SimCloudTrail(self, region)

    def _event(self, hours_ago: float, name: str, region: str, ip: str) -> dict:
        if self.key_id.startswith("ASIA"):
            ident = {"type": "AssumedRole", "arn": f"arn:aws:sts::{self.ACCOUNT}:assumed-role/orders-api-task/i-0abc",
                     "sessionContext": {"sessionIssuer": {"type": "Role", "userName": "orders-api-task"}}}
        else:
            ident = {"type": "IAMUser", "arn": f"arn:aws:iam::{self.ACCOUNT}:user/svc-orders-deploy"}
        detail = {"awsRegion": region, "sourceIPAddress": ip, "userAgent": "aws-cli/2.17", "userIdentity": ident}
        return {"EventTime": self.now - dt.timedelta(hours=hours_ago), "EventName": name,
                "CloudTrailEvent": json.dumps(detail)}


class _SimIAM:
    def __init__(self, sim: SimulatedAWS):
        self.sim = sim

    def get_access_key_last_used(self, AccessKeyId: str) -> dict:
        if not self.sim.in_account or AccessKeyId.startswith("ASIA"):
            raise SimulatedError("AccessDenied")
        return {"UserName": "svc-orders-deploy", "AccessKeyLastUsed": {
            "LastUsedDate": self.sim.now - dt.timedelta(minutes=12), "ServiceName": "ec2", "Region": "ap-southeast-1"}}

    def list_access_keys(self, UserName: str) -> dict:
        new_key = "AKIA" + "SIMULATED0" + "NEWKEY"
        return {"AccessKeyMetadata": [
            {"AccessKeyId": self.sim.key_id, "Status": "Active", "CreateDate": self.sim.now - dt.timedelta(days=400)},
            {"AccessKeyId": new_key, "Status": "Active", "CreateDate": self.sim.now - dt.timedelta(hours=2)},
        ]}

    def update_access_key(self, **kw) -> dict:
        self.sim.calls.append(("update_access_key", kw))
        return {}

    def put_role_policy(self, **kw) -> dict:
        self.sim.calls.append(("put_role_policy", kw))
        return {}


class _SimSTS:
    def __init__(self, sim: SimulatedAWS):
        self.sim = sim

    def get_access_key_info(self, AccessKeyId: str) -> dict:
        return {"Account": self.sim.ACCOUNT if self.sim.in_account else self.sim.OTHER_ACCOUNT}


class _SimCloudTrail:
    def __init__(self, sim: SimulatedAWS, region: str):
        self.sim, self.region = sim, region

    def lookup_events(self, **kw) -> dict:
        s, ip, ci = self.sim, SimulatedAWS.ATTACKER_IP, SimulatedAWS.CI_IP
        pages = {
            "us-east-1": [
                [s._event(30, "GetObject", "us-east-1", ci), s._event(3, "GetCallerIdentity", "us-east-1", ip)],
                [s._event(2.5, "ListBuckets", "us-east-1", ip), s._event(2, "CreateAccessKey", "us-east-1", ip)],
            ],
            "ap-southeast-1": [[s._event(0.5, "RunInstances", "ap-southeast-1", ip)]],
        }.get(self.region, [[]])
        i = int(kw.get("NextToken") or 0)
        resp = {"Events": pages[i]}
        if i + 1 < len(pages):
            resp["NextToken"] = str(i + 1)
        return resp


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Contain a leaked AWS access key (dry run by default).")
    ap.add_argument("access_key_id")
    ap.add_argument("--days", type=int, default=7, help="CloudTrail lookback (max 90)")
    ap.add_argument("--regions", help="comma-separated; default: every region enabled for the account")
    ap.add_argument("--execute", action="store_true", help="actually deactivate / revoke")
    ap.add_argument("--simulate", action="store_true", help="use built-in fake AWS data (no AWS calls)")
    ap.add_argument("--json", action="store_true", help="JSON output for a ticket or SOAR")
    a = ap.parse_args(argv)

    key = a.access_key_id.strip()
    if not KEY_ID.fullmatch(key):
        print("not an AWS access key ID (expected AKIA... or ASIA..., 20 characters)", file=sys.stderr)
        return 2

    if a.simulate:
        sim = SimulatedAWS(key)
        iam, sts, ct_factory = sim.iam, sim.sts, sim.cloudtrail
        regions = a.regions.split(",") if a.regions else SimulatedAWS.REGIONS
    else:
        import boto3  # imported here so --help and --simulate work without boto3
        from botocore.config import Config

        cfg = Config(retries={"mode": "adaptive", "max_attempts": 10})  # LookupEvents is 2 TPS per region
        session = boto3.session.Session()
        iam, sts = session.client("iam", config=cfg), session.client("sts", config=cfg)
        if a.regions:
            regions = a.regions.split(",")
        else:
            ec2 = session.client("ec2", config=cfg, region_name=session.region_name or "us-east-1")
            regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]

        def ct_factory(region: str):
            return session.client("cloudtrail", region_name=region, config=cfg)

    summary = contain(key_id=key, iam=iam, sts=sts, ct_factory=ct_factory, regions=regions,
                      days=min(a.days, 90), execute=a.execute)
    summary["simulated"] = a.simulate
    print(json.dumps(summary, indent=2, default=str) if a.json else render(summary))
    return 0 if summary["status"] in ("CONTAINED", "DRY_RUN") else 1


if __name__ == "__main__":
    sys.exit(main())
