插件跑进沙箱之后，本该被拦下的写文件调用还是成功了，日志里一条拦截都没有：一是规则匹配用子串，写文件的规则会命中读文件的调用；二是参数匹配只比较第一个参数，其余参数被忽略；三是路径规范化不折叠相对段，绕道访问可以绕过规则；四是优先级按升序排序，低优先级规则先命中；五是拒绝与允许同优先级时允许胜出；六是继承规则被忽略，父策略的限制失效；七是默认动作取允许，未匹配调用一律放行；八是策略校验不检查是否存在拒绝规则；九是批量判定复用匹配结果，后一个调用命中前一个调用的规则；十是规则解析不校验动作取值，未知动作被当成允许。sandbox/rules.py 是核心，tests/test_rules.py 的 15 个测试全红，要修的是：按上面的顺序把 10 个缺陷逐个修掉。sandbox/rules.py 是核心，tests/test_rules.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

    python -m pytest tests -q

当前基线必须恰好为 15 failed，且没有 error；15 个失败都来自 8 个桩抛出的 NotImplementedError。修复完成后，同一命令应为 15 passed。环境为 Python 3.10 及以上，仅依赖标准库与 pytest，无外部依赖，无联网步骤，无随机因素。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 不可修改项

tests 不可修改：tests/test_rules.py 含且仅含 15 个测试。实现方只实现 src/sandbox/rules.py 中恰好 8 个桩，并保持函数签名与 docstring 中的安全契约。实现只允许使用标准库与 pytest；不得联网、不得引入随机行为，也不得修改测试来换取通过。

## 目录布局

本仓库采用 src 布局：业务实现位于 src/sandbox 包内，而不是仓库根目录。pyproject.toml 在 [tool.pytest.ini_options] 中设置 pythonpath = ["src"]，pytest 因此把 src 加入导入路径，tests/test_rules.py 可以直接从 sandbox 包导入实现。根目录不另放 conftest.py。

    sec-sandbox-policy/
      README.md
      pyproject.toml
      src/
        sandbox/
          __init__.py
          rules.py
      tests/
        test_rules.py