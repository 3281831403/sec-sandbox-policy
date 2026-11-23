"""15 red tests for the sandbox policy contract.

Every test calls at least one of the eight public stubs. The tests are part
of the contract and must not be modified when implementing the module.
"""

import pytest

from sandbox.rules import (
    decide,
    default_action,
    match_syscall,
    normalize_path,
    parse_rule,
    resolve_rules,
    sandbox_batch,
    validate_policy,
)


def test_defect_01_write_rule_does_not_match_read_call():
    """缺陷 1：写文件规则不得靠子串命中读文件调用。"""
    rule = parse_rule("deny write_file target=path:/tmp/write.log priority=10")
    read_call = {
        "syscall": "read_file",
        "args": {"target": "/tmp/write.log"},
    }
    write_call = {
        "syscall": "write_file",
        "args": {"target": "/tmp/write.log"},
    }
    assert match_syscall(rule, read_call) is False
    assert match_syscall(rule, write_call) is True


def test_defect_02_every_argument_and_exact_type_checked():
    """缺陷 2：每个参数都必须比较，并且按精确类型比较。"""
    rule = parse_rule(
        "deny write_file target=path:/tmp/data flags=int:2 priority=10"
    )
    assert (
        match_syscall(
            rule,
            {
                "syscall": "write_file",
                "args": {"target": "/tmp/data", "flags": 2},
            },
        )
        is True
    )
    assert (
        match_syscall(
            rule,
            {
                "syscall": "write_file",
                "args": {"target": "/tmp/data", "flags": 1},
            },
        )
        is False
    )
    assert (
        match_syscall(
            rule,
            {
                "syscall": "write_file",
                "args": {"target": "/tmp/data", "flags": "2"},
            },
        )
        is False
    )
    assert (
        match_syscall(
            rule,
            {"syscall": "write_file", "args": {"target": "/tmp/data"}},
        )
        is False
    )

    bool_rule = parse_rule("deny write_file active=bool:true priority=7")
    assert (
        match_syscall(
            bool_rule,
            {"syscall": "write_file", "args": {"active": True}},
        )
        is True
    )
    assert (
        match_syscall(
            bool_rule,
            {"syscall": "write_file", "args": {"active": 1}},
        )
        is False
    )


def test_defect_03_relative_path_segments_are_collapsed():
    """缺陷 3：相对段必须先折叠，绕道路径不得绕过规则。"""
    assert (
        normalize_path("/data/./tmp/../secret/./passwd")
        == "/data/secret/passwd"
    )
    assert normalize_path("data//sub/../file/") == "data/file"
    assert normalize_path("/../../etc/passwd") == "/etc/passwd"
    assert normalize_path("a/../../b") == "../b"
    assert normalize_path("data\\sub\\..\\file") == "data/file"
    assert normalize_path("") == "."

    rule = parse_rule("deny write_file target=path:/data/secret/* priority=20")
    call = {
        "syscall": "write_file",
        "args": {"target": "/data/./tmp/../secret/./passwd"},
    }
    assert match_syscall(rule, call) is True


def test_defect_04_higher_priority_is_ordered_first():
    """缺陷 4：优先级必须降序，高优先级规则先命中。"""
    deny_rule = parse_rule(
        "deny write_file target=path:/data/* priority=10"
    )
    allow_rule = parse_rule(
        "allow write_file target=path:/data/* priority=90"
    )
    call = {
        "syscall": "write_file",
        "args": {"target": "/data/report.txt"},
    }

    resolved = resolve_rules([deny_rule, allow_rule], call, [])
    assert [rule["priority"] for rule in resolved] == [90, 10]

    decision = decide([deny_rule, allow_rule], call)
    assert decision["action"] == "allow"
    assert decision["rule"] == allow_rule


def test_defect_05_deny_wins_at_equal_priority():
    """缺陷 5：同优先级时拒绝必须压过允许。"""
    allow_rule = parse_rule(
        "allow read_file target=path:/data/* priority=50"
    )
    deny_rule = parse_rule(
        "deny read_file target=path:/data/secret/* priority=50"
    )
    call = {
        "syscall": "read_file",
        "args": {"target": "/data/secret/keyring"},
    }

    resolved = resolve_rules([allow_rule, deny_rule], call, [])
    assert resolved[0] == deny_rule

    decision = decide([allow_rule, deny_rule], call)
    assert decision["action"] == "deny"
    assert decision["rule"] == deny_rule


def test_defect_06_inherited_deny_constrains_local_allow():
    """缺陷 6：父策略的拒绝规则必须继续生效。"""
    local_allow = parse_rule(
        "allow write_file target=path:/data/* priority=10"
    )
    inherited_deny = parse_rule(
        "deny write_file target=path:/data/secret/* priority=100"
    )
    call = {
        "syscall": "write_file",
        "args": {"target": "/data/secret/key"},
    }

    resolved = resolve_rules([local_allow], call, [inherited_deny])
    assert resolved == [inherited_deny, local_allow]
    assert decide(resolved, call)["action"] == "deny"


def test_defect_07_default_allow_is_rejected():
    """缺陷 7：默认允许不能生效，缺省默认也不能被当成允许。"""
    with pytest.raises(ValueError):
        default_action({"default": "allow", "rules": []})
    with pytest.raises(ValueError):
        default_action({"rules": []})
    with pytest.raises(ValueError):
        default_action({"default": " DENY "})

    policy = {"default": "allow", "rules": []}
    calls = [
        {
            "id": "c1",
            "syscall": "write_file",
            "args": {"target": "/etc/passwd"},
        }
    ]
    with pytest.raises(ValueError):
        sandbox_batch(calls, policy)


def test_defect_08_validation_requires_deny_rule():
    """缺陷 8：策略校验必须报告缺少拒绝规则。"""
    allow_rule = parse_rule(
        "allow read_file target=path:/data/* priority=10"
    )
    policy = {"default": "deny", "rules": [allow_rule]}
    issues = validate_policy(policy)
    assert "no_deny_rule" in issues
    assert "default_not_deny" not in issues

    bad_policy = {
        "default": "allow",
        "rules": [
            parse_rule("allow read_file target=path:/data/a/* priority=10"),
            parse_rule("allow read_file target=path:/data/b/* priority=10"),
        ],
    }
    bad_issues = validate_policy(bad_policy)
    assert "default_not_deny" in bad_issues
    assert "duplicate_priority:10" in bad_issues

    inherited_deny = parse_rule(
        "deny write_file target=path:/etc/* priority=50"
    )
    inherited_only = {
        "default": "deny",
        "rules": [],
        "inherited": [inherited_deny],
    }
    assert validate_policy(inherited_only) == []


def test_defect_09_batch_rechecks_each_call():
    """缺陷 9：后一个调用不得复用前一个调用的匹配结果。"""
    policy = {
        "default": "deny",
        "rules": [
            parse_rule("allow read_file target=path:/data/a/* priority=20"),
            parse_rule("deny read_file target=path:/data/b/* priority=20"),
        ],
    }
    calls = [
        {
            "id": "c1",
            "syscall": "read_file",
            "args": {"target": "/data/a/one"},
        },
        {
            "id": "c2",
            "syscall": "read_file",
            "args": {"target": "/data/b/two"},
        },
    ]

    result = sandbox_batch(calls, policy)
    assert result["c1"]["action"] == "allow"
    assert result["c2"]["action"] == "deny"
    assert result["c1"]["rule"] != result["c2"]["rule"]


def test_defect_10_unknown_action_is_rejected():
    """缺陷 10：未知动作必须报错，不能被当成允许。"""
    with pytest.raises(ValueError):
        parse_rule("permit read_file target=path:/data/* priority=10")
    with pytest.raises(ValueError):
        parse_rule("ALLOW read_file priority=10")

    parsed = parse_rule("allow read_file priority=10")
    assert parsed["action"] == "allow"
    assert parsed["priority"] == 10


def test_allow_rule_permits_matching_call():
    """补充 1：允许规则命中时放行。"""
    policy = {
        "default": "deny",
        "rules": [
            parse_rule("allow read_file target=path:/data/* priority=10")
        ],
    }
    calls = [
        {
            "id": "c1",
            "syscall": "read_file",
            "args": {"target": "/data/report.txt"},
        }
    ]

    result = sandbox_batch(calls, policy)
    assert result["c1"]["action"] == "allow"
    assert result["c1"]["reason"] == "rule"


def test_deny_rule_blocks_matching_call():
    """补充 2：拒绝规则命中时拦截。"""
    allow_rule = parse_rule(
        "allow write_file target=path:/etc/* priority=10"
    )
    deny_rule = parse_rule(
        "deny write_file target=path:/etc/* priority=80"
    )
    call = {
        "syscall": "write_file",
        "args": {"target": "/etc/passwd"},
    }

    decision = decide([allow_rule, deny_rule], call)
    assert decision["action"] == "deny"
    assert decision["rule"] == deny_rule
    assert decision["reason"] == "rule"


def test_default_deny_applies_to_unmatched_call():
    """补充 3：默认拒绝对未匹配调用生效。"""
    policy = {
        "default": "deny",
        "rules": [
            parse_rule("allow read_file target=path:/public/* priority=10")
        ],
    }
    calls = [
        {
            "id": "c1",
            "syscall": "write_file",
            "args": {"target": "/etc/passwd"},
        }
    ]

    assert default_action(policy) == "deny"
    result = sandbox_batch(calls, policy)
    assert result["c1"]["action"] == "deny"
    assert result["c1"]["rule"] is None
    assert result["c1"]["reason"] == "default"


def test_inherited_rules_participate_in_decision():
    """补充 4：继承规则参与最终判定。"""
    inherited_deny = parse_rule(
        "deny write_file target=path:/data/secret/* priority=60"
    )
    policy = {
        "default": "deny",
        "rules": [
            parse_rule("allow write_file target=path:/data/* priority=20")
        ],
        "inherited": [inherited_deny],
    }
    calls = [
        {
            "id": "c1",
            "syscall": "write_file",
            "args": {"target": "/data/secret/key"},
        }
    ]

    result = sandbox_batch(calls, policy)
    assert result["c1"]["action"] == "deny"
    assert result["c1"]["rule"] == inherited_deny


def test_two_batches_match_individual_decisions():
    """补充 5：两批独立判定与单独判定完全一致。"""
    policy = {
        "default": "deny",
        "rules": [
            parse_rule(
                "allow read_file target=path:/data/public/* priority=10"
            ),
            parse_rule(
                "deny write_file target=path:/etc/* priority=50"
            ),
        ],
    }
    calls = [
        {
            "id": "read",
            "syscall": "read_file",
            "args": {"target": "/data/public/a.txt"},
        },
        {
            "id": "write",
            "syscall": "write_file",
            "args": {"target": "/etc/passwd"},
        },
        {
            "id": "other",
            "syscall": "read_file",
            "args": {"target": "/data/private/b.txt"},
        },
    ]

    batch_a = sandbox_batch(calls, policy)
    batch_b = sandbox_batch(list(reversed(calls)), policy)
    assert batch_a == batch_b

    for call in calls:
        single = sandbox_batch([call], policy)[call["id"]]
        assert batch_a[call["id"]] == single