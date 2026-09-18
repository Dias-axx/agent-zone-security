"""Registry and policy consistency validator. Fails closed: any inconsistency,
missing field or malformed value is an error, never a warning that gets ignored.

Run as: python -m control.validate
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

from control.response import ESCALATION_CHAIN
from control.token_issuer import MAX_TTL_SECONDS

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "registry" / "agents.yaml"

REQUIRED_REGISTRY_FIELDS = {
    "id",
    "owner",
    "role",
    "policy",
    "zone",
    "autonomy_level",
    "purpose",
    "review_due",
    "kill_switch",
}


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return dict(data) if data else {}


def _is_valid_egress_entry(entry: str) -> bool:
    return bool(entry) and entry != "." and "*" not in entry


def validate_policy(policy_path: Path) -> list[str]:
    if not policy_path.exists():
        return [f"{policy_path}: file does not exist"]

    policy = load_yaml(policy_path)
    errors: list[str] = []

    if "role" not in policy:
        errors.append(f"{policy_path}: missing 'role'")

    egress = policy.get("egress", {})
    if egress.get("default") != "deny":
        errors.append(f"{policy_path}: egress.default must be 'deny'")
    for entry in egress.get("allowlist", []):
        if not _is_valid_egress_entry(entry):
            errors.append(f"{policy_path}: malformed egress allowlist entry '{entry}'")

    identity = policy.get("identity", {})
    ttl = identity.get("ttl_seconds")
    if ttl is None or not isinstance(ttl, int) or ttl <= 0:
        errors.append(f"{policy_path}: identity.ttl_seconds must be a positive integer")
    elif ttl > MAX_TTL_SECONDS:
        errors.append(f"{policy_path}: identity.ttl_seconds {ttl} exceeds ceiling {MAX_TTL_SECONDS}")

    if identity.get("type") == "delegated" and not identity.get("delegates_scope_from"):
        errors.append(f"{policy_path}: delegated identity missing 'delegates_scope_from'")

    zones = policy.get("zones", {})
    if not zones.get("home"):
        errors.append(f"{policy_path}: zones.home is required")

    on_violation = policy.get("response", {}).get("on_violation")
    if on_violation not in ESCALATION_CHAIN:
        errors.append(
            f"{policy_path}: response.on_violation must be one of {sorted(ESCALATION_CHAIN)}, "
            f"got {on_violation!r}"
        )

    return errors


def validate_entry(entry: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    """Cross-check one registry entry against its loaded policy document."""
    errors: list[str] = []

    home_zone = policy.get("zones", {}).get("home")
    if home_zone != entry.get("zone"):
        errors.append(
            f"registry entry {entry.get('id')}: registry zone '{entry.get('zone')}' "
            f"does not match policy home zone '{home_zone}'"
        )

    identity = policy.get("identity", {})
    if identity.get("type") == "delegated" and not entry.get("delegated_by"):
        errors.append(
            f"registry entry {entry.get('id')}: delegated policy requires 'delegated_by' in registry"
        )

    return errors


def validate_registry() -> list[str]:
    if not REGISTRY_PATH.exists():
        return [f"{REGISTRY_PATH}: registry file does not exist"]

    data = load_yaml(REGISTRY_PATH)
    agents = data.get("agents", [])
    errors: list[str] = []

    if not agents:
        errors.append(f"{REGISTRY_PATH}: no agents defined")

    seen_ids: set[str] = set()
    for entry in agents:
        missing = REQUIRED_REGISTRY_FIELDS - entry.keys()
        if missing:
            errors.append(f"registry entry {entry.get('id', '<unknown>')}: missing fields {sorted(missing)}")
            continue

        if entry["id"] in seen_ids:
            errors.append(f"registry entry {entry['id']}: duplicate id")
        seen_ids.add(entry["id"])

        policy_path = REPO_ROOT / entry["policy"]
        policy_errors = validate_policy(policy_path)
        errors.extend(policy_errors)

        if policy_path.exists() and not policy_errors:
            policy = load_yaml(policy_path)
            errors.extend(validate_entry(entry, policy))

    return errors


def main() -> int:
    errors = validate_registry()
    if errors:
        print(f"VALIDATION FAILED ({len(errors)} error(s)):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("VALIDATION OK: registry and policies are consistent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
