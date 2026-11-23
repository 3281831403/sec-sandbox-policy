"""Fail-closed sandbox policy primitives.

This is the only implementation file. All eight public functions are stubs:
implement them in place, keep the signatures, and do not edit the tests.
Every comparison is deterministic and zero-tolerance: no whitespace
trimming, case folding, type coercion, filesystem lookup, or implicit
permission.
"""

import fnmatch
import re
from collections.abc import Iterable, Mapping, Sequence

_ALLOW = "allow"
_DENY = "deny"
_ACTIONS = (_ALLOW, _DENY)

_ARG_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
_INT_RE = re.compile(r"-?[0-9]+")


def _parse_base10_int(text: str) -> int:
    """Parse a base-10 integer with no tolerance for other spellings."""
    if not isinstance(text, str) or _INT_RE.fullmatch(text) is None:
        raise ValueError("value must be a base-10 integer")
    return int(text)


def _parse_typed_value(raw: str) -> dict:
    """Parse a typed value token into its canonical argument spec."""
    prefix, sep, text = raw.partition(":")
    if not sep:
        raise ValueError("typed value requires a type prefix")
    if prefix in ("path", "str"):
        return {"type": prefix, "value": text}
    if prefix == "int":
        return {"type": "int", "value": _parse_base10_int(text)}
    if prefix == "bool":
        if text == "true":
            return {"type": "bool", "value": True}
        if text == "false":
            return {"type": "bool", "value": False}
        raise ValueError("bool value must be exactly true or false")
    raise ValueError("unknown value type")


def _match_value(spec, value) -> bool:
    """Match one call argument value against one parsed rule argument spec."""
    if not isinstance(spec, Mapping):
        return False
    kind = spec.get("type")
    expected = spec.get("value")
    if kind == "path":
        if type(value) is not str or type(expected) is not str:
            return False
        try:
            return fnmatch.fnmatchcase(
                normalize_path(value), normalize_path(expected)
            )
        except (TypeError, ValueError):
            return False
    if kind == "str":
        return type(value) is str and type(expected) is str and value == expected
    if kind == "int":
        return type(value) is int and type(expected) is int and value == expected
    if kind == "bool":
        return (
            type(value) is bool
            and type(expected) is bool
            and value is expected
        )
    return False


def parse_rule(rule: str) -> dict:
    """Parse one textual rule into a canonical rule mapping.

    Grammar: <action> <syscall> [<arg>=<typed-value> ...] [priority=<int>]

    action must be exactly allow or deny. Any other spelling, including an
    unknown verb, ALLOW, or allow with surrounding whitespace, raises
    ValueError; an unknown action must never be interpreted as allow.
    syscall is a non-empty literal token. arg names are unique and match
    [a-z][a-z0-9_]*. typed-value is one of path:<text>, str:<text>,
    int:<decimal>, or bool:true or bool:false. A path value is stored as text
    and normalized only at match time; a str value is matched exactly; int and
    bool matching uses exact Python types, never equality across types.
    priority is an optional base-10 integer and defaults to 0. Larger numbers
    are more important.

    Return a new dict with exactly the keys action, syscall, args, priority.
    args maps each argument name to {"type": <type>, "value": <value>}.
    Malformed input, duplicate argument names, a second priority token, or a
    non-str rule raises ValueError. Matching tolerance is 0: no case folding,
    whitespace trimming, quoting, or numeric coercion.
    """
    if not isinstance(rule, str):
        raise ValueError("rule must be a str")
    if rule == "":
        raise ValueError("rule must not be empty")

    parts = rule.split(" ")
    if any(part == "" for part in parts):
        raise ValueError("rule contains stray or repeated whitespace")
    if len(parts) < 2:
        raise ValueError("rule requires an action and a syscall")

    action, syscall = parts[0], parts[1]
    if action not in _ACTIONS:
        raise ValueError("action must be exactly allow or deny")
    if syscall == "":
        raise ValueError("syscall must be a non-empty token")

    args = {}
    priority = 0
    seen_priority = False
    for token in parts[2:]:
        name, sep, raw = token.partition("=")
        if not sep or name == "":
            raise ValueError("malformed rule token")
        if name == "priority":
            if seen_priority:
                raise ValueError("duplicate priority token")
            seen_priority = True
            priority = _parse_base10_int(raw)
            continue
        if _ARG_NAME_RE.fullmatch(name) is None:
            raise ValueError("invalid argument name")
        if name in args:
            raise ValueError("duplicate argument name")
        args[name] = _parse_typed_value(raw)

    return {
        "action": action,
        "syscall": syscall,
        "args": args,
        "priority": priority,
    }


def normalize_path(path: str) -> str:
    """Normalize a path lexically so dot segments cannot bypass a rule.

    Both / and backslash are separators and the returned path uses /.
    Collapse repeated separators, remove . segments, and resolve .. by
    removing the preceding normal segment. Unresolved leading .. segments of
    a relative path are preserved; .. above an absolute root is discarded.
    Remove a trailing slash except for a root. An empty path, or one whose
    segments all disappear, becomes . Wildcard characters are ordinary path
    characters here, so the same function can normalize fnmatch patterns.

    The operation is purely lexical: no filesystem access, symlink
    resolution, existence check, case folding, Unicode normalization, or
    environment expansion. A non-str path raises TypeError; an embedded NUL
    raises ValueError. Tolerance is 0: . and .. are never left in place and
    no alternate separator spelling is accepted after normalization.
    """
    if not isinstance(path, str):
        raise TypeError("path must be a str")
    if "\x00" in path:
        raise ValueError("path must not contain a NUL character")

    absolute = path.startswith("/") or path.startswith("\\")
    segments = path.replace("\\", "/").split("/")

    stack = []
    for segment in segments:
        if segment == "" or segment == ".":
            continue
        if segment == "..":
            if stack and stack[-1] != "..":
                stack.pop()
            elif not absolute:
                stack.append("..")
            continue
        stack.append(segment)

    if absolute:
        return "/" + "/".join(stack) if stack else "/"
    if not stack:
        return "."
    return "/".join(stack)


def match_syscall(rule: dict, call: dict) -> bool:
    """Return True only when the call satisfies the complete rule.

    rule is a mapping produced by parse_rule. call has the shape
    {"syscall": <str>, "args": {<name>: <value>, ...}}; a missing args key is
    treated as an empty mapping. The syscall comparison is exact string
    equality, never substring matching, so a write rule cannot match a read
    call merely because the word write appears somewhere in the call.

    Every argument named by the rule must be present in the call and must
    match. Extra call arguments are ignored. path matchers require a str
    value, normalize both the rule pattern and the value with normalize_path,
    and then use fnmatch.fnmatchcase; str matchers are exact and
    case-sensitive. int and bool use exact type identity, so True does not
    match 1, 1 does not match 1.0, and 1 does not match the string 1. A
    missing argument, wrong type, or failed pattern makes the result False.
    Tolerance is 0: no coercion, trimming, case folding, or wildcard
    expansion outside path matchers.
    """
    if not isinstance(rule, Mapping) or not isinstance(call, Mapping):
        return False

    rule_syscall = rule.get("syscall")
    if not isinstance(rule_syscall, str):
        return False
    if call.get("syscall") != rule_syscall:
        return False

    call_args = call.get("args")
    if call_args is None:
        call_args = {}
    if not isinstance(call_args, Mapping):
        return False

    rule_args = rule.get("args")
    if rule_args is None:
        rule_args = {}
    if not isinstance(rule_args, Mapping):
        return False

    for name, spec in rule_args.items():
        if name not in call_args:
            return False
        if not _match_value(spec, call_args[name]):
            return False
    return True


def resolve_rules(rules, call: dict, inherited) -> list:
    """Merge inherited rules with local rules and order the matching ones.

    rules and inherited are iterables of mappings produced by parse_rule;
    None means an empty iterable. Inherited rules are never dropped: a parent
    deny must still constrain a local allow. Keep only rules for which
    match_syscall(rule, call) is True.

    Sort the survivors by numeric priority descending, so a larger priority
    number is considered first. At equal priority deny sorts before allow.
    Remaining ties preserve input order, with local rules before inherited
    rules. Return a new list and do not mutate either input. Tolerance is 0:
    no deduplication, priority coercion, or implicit parent permission.
    """
    local = list(rules) if rules is not None else []
    parent = list(inherited) if inherited is not None else []

    matched = [
        rule for rule in local + parent if match_syscall(rule, call)
    ]
    matched.sort(
        key=lambda rule: (
            -rule["priority"],
            0 if rule["action"] == _DENY else 1,
        )
    )
    return matched


def decide(rules, call: dict) -> dict:
    """Return the final decision for a single call.

    rules is an iterable of parsed local rules. Resolve them with
    match_syscall, descending priority, and the rule that deny precedes allow
    at equal priority. The first surviving rule wins. This means a matching
    allow can win only when it has higher priority than every matching deny;
    a deny wins every equal-priority conflict.

    If no rule matches, return a deny with rule None and reason default:
    omission never means allow. Return exactly
    {"action": "allow" or "deny", "rule": <matched rule> or None,
    "reason": "rule" or "default"}. The input list is not mutated.
    Tolerance is 0: no fallback allow, wildcard syscall matching, coercion,
    or tie randomness.
    """
    resolved = resolve_rules(rules, call, None)
    if not resolved:
        return {"action": _DENY, "rule": None, "reason": "default"}
    chosen = resolved[0]
    return {"action": chosen["action"], "rule": chosen, "reason": "rule"}


def default_action(policy: dict) -> str:
    """Return the policy default action, which must be an explicit deny.

    policy must be a mapping. The key default must exist and its value must
    be the exact string deny. A missing key, allow, DENY, None, an empty
    string, or any other value raises ValueError; there is no implicit
    default and no fallback permission. Return the string deny on success.
    Tolerance is 0: no trimming, case folding, or treating a blank value as
    absent.
    """
    if not isinstance(policy, Mapping):
        raise TypeError("policy must be a mapping")
    if "default" not in policy:
        raise ValueError("policy default is missing")
    value = policy["default"]
    if type(value) is not str or value != _DENY:
        raise ValueError("policy default must be exactly deny")
    return _DENY


def _is_sequence(value) -> bool:
    """Return True for a non-string sequence value."""
    if isinstance(value, (str, bytes, bytearray)):
        return False
    return isinstance(value, Sequence)


def validate_policy(policy: dict) -> list[str]:
    """Return a deterministic list of policy problems.

    policy maps default to an action and optionally maps rules and inherited
    to sequences. Each rule item may be a parsed rule mapping or a rule
    string. The following codes are reported:

    default_not_deny
        default is missing or is not exactly deny.
    invalid_rule:<section>:<index>
        a rule string in that section and zero-based position cannot be
        parsed. section is rules or inherited.
    no_deny_rule
        no successfully parsed local or inherited rule has action deny. The
        default value alone does not count as a deny rule.
    duplicate_priority:<priority>
        one or more parsed local or inherited rules share that priority.

    Report each duplicate priority once. Order the list as default_not_deny,
    invalid_rule entries in input order, no_deny_rule, then duplicate
    priorities ascending. Return an empty list only when none of these
    problems exists. Ordinary policy defects are reported, not raised; a
    non-mapping policy or a non-sequence rules value raises TypeError. The
    function never mutates policy. Tolerance is 0: no implicit deny rule and
    no ignored duplicate priorities.
    """
    if not isinstance(policy, Mapping):
        raise TypeError("policy must be a mapping")

    issues = []

    default = policy.get("default") if "default" in policy else None
    if (
        "default" not in policy
        or type(default) is not str
        or default != _DENY
    ):
        issues.append("default_not_deny")

    parsed = []
    for section in ("rules", "inherited"):
        if section not in policy:
            continue
        value = policy[section]
        if value is None:
            continue
        if not _is_sequence(value):
            raise TypeError(f"policy {section} must be a sequence")
        for index, item in enumerate(value):
            if isinstance(item, str):
                try:
                    parsed.append(parse_rule(item))
                except ValueError:
                    issues.append(f"invalid_rule:{section}:{index}")
            elif isinstance(item, Mapping):
                parsed.append(item)
            else:
                raise TypeError(
                    "rule items must be mappings or strings"
                )

    if not any(rule.get("action") == _DENY for rule in parsed):
        issues.append("no_deny_rule")

    counts = {}
    for rule in parsed:
        priority = rule.get("priority")
        if type(priority) is int:
            counts[priority] = counts.get(priority, 0) + 1
    for priority in sorted(counts):
        if counts[priority] > 1:
            issues.append(f"duplicate_priority:{priority}")

    return issues


def _policy_rule_items(policy: dict, section: str) -> list:
    """Return the raw rule items of one policy section for batch use."""
    if section not in policy:
        return []
    value = policy[section]
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        raise ValueError(f"policy {section} must be a sequence of rules")
    if not isinstance(value, Iterable):
        raise ValueError(f"policy {section} must be a sequence of rules")
    return list(value)


def _coerce_rule(item):
    """Turn a rule mapping or rule string into a validated rule mapping."""
    if isinstance(item, str):
        return parse_rule(item)
    if not isinstance(item, Mapping):
        raise ValueError("rule must be a mapping or a str")

    action = item.get("action")
    if type(action) is not str or action not in _ACTIONS:
        raise ValueError("rule action must be exactly allow or deny")
    syscall = item.get("syscall")
    if type(syscall) is not str or syscall == "":
        raise ValueError("rule syscall must be a non-empty str")
    args = item.get("args")
    if not isinstance(args, Mapping):
        raise ValueError("rule args must be a mapping")
    if type(item.get("priority")) is not int:
        raise ValueError("rule priority must be an int")
    return item


def sandbox_batch(calls, policy: dict) -> dict:
    """Evaluate every call independently under policy.

    policy maps default to an explicit deny and optionally maps rules and
    inherited to sequences of parsed rule mappings or rule strings. Each call
    is a mapping with a unique non-empty str id, a str syscall, and optional
    args mapping. The policy default is checked with default_action first: a
    missing or non-deny default raises ValueError rather than silently
    allowing anything.

    For each call, merge local and inherited rules for that call, then apply
    decide. Results are a new dict mapping each call id to its decision. No
    matched rule list or decision may be reused across calls, even when two
    calls have the same syscall; input order must not change any call's
    result. A policy without any deny rule is still evaluated here, because
    validate_policy is the separate reporting interface. Duplicate call ids,
    malformed calls, malformed rules, or an invalid default raise ValueError.
    Do not mutate policy or calls. Tolerance is 0: no cached match, coercion,
    or implicit allow.
    """
    default_action(policy)

    local = [
        _coerce_rule(item) for item in _policy_rule_items(policy, "rules")
    ]
    inherited = [
        _coerce_rule(item)
        for item in _policy_rule_items(policy, "inherited")
    ]

    if isinstance(calls, (str, bytes, bytearray, Mapping)):
        raise ValueError("calls must be an iterable of call mappings")
    if not isinstance(calls, Iterable):
        raise ValueError("calls must be an iterable of call mappings")

    results = {}
    for item in calls:
        if not isinstance(item, Mapping):
            raise ValueError("call must be a mapping")

        if "id" not in item:
            raise ValueError("call id is missing")
        call_id = item["id"]
        if type(call_id) is not str or call_id == "":
            raise ValueError("call id must be a non-empty str")
        if call_id in results:
            raise ValueError("duplicate call id")

        syscall = item.get("syscall")
        if type(syscall) is not str:
            raise ValueError("call syscall must be a str")

        if "args" in item:
            raw_args = item["args"]
            if not isinstance(raw_args, Mapping):
                raise ValueError("call args must be a mapping")
        else:
            raw_args = {}

        call = {"syscall": syscall, "args": dict(raw_args)}

        # Re-match every call from scratch: no matched list, rule set, or
        # decision may carry over from a previous call.
        resolved = resolve_rules(local, call, inherited)
        results[call_id] = decide(resolved, call)

    return results
