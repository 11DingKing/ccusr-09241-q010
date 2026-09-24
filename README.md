# 融合网络安全策略分波发布系统

编排承载**个人、机器、物联**三类业务区域的访问与隔离策略的分批发布、健康门禁、
角色确认、观测恶化暂停与依赖顺序回退。系统为纯 Python 标准库实现，无外部依赖。

## 能力总览

- **区域拓扑快照**：区域、设备能力/固件、关键业务流的不可变版本，发布单始终绑定快照。
- **策略版本与依赖顺序**：规则带能力条件；`depends_on` 约束下发顺序，拓扑排序检测环。
- **有期限例外**：例外带 `expires_at`，过期是**延迟计算**（不依赖后台任务），
  预演/下发均不再豁免；支持续期（只能延后，须留痕）与撤销；过期/撤销不可复活。
- **预演（Preflight）**：
  - 能力条件校验——规则执行区域内设备缺少所需能力即给出阻断清单并拒绝发布；
  - 可达性模拟——以关键业务流为对象，检查新策略（含例外影响）是否阻断；
  - 批次生成——首批为**金丝雀**（每区按比例抽设备，关键设备优先），
    后续批次按 **机器 → 个人 → 物联** 的区域风险顺序，批内命令按规则依赖排序。
- **分波门禁（严格游标）**：
  `待下发 → 已下发(收回执) → 健康观测 → 等待角色确认 → 已确认`；
  前一批未确认，后续批次不可下发。确认角色按区域类型绑定：
  个人区→安全主管、机器区→网络运维、物联区→业务责任人。
- **双阈值健康证据**：部署比例门禁 + 观测窗口内健康分阈值门禁；
  突破恶化底线或关键业务不可达时**立即**判恶化，无需等窗口；
  证据按来源用单调序号仲裁，迟到旧证据不采纳。
- **乱序回执防护**：每条命令以 `receipt_seq` 水位仲裁，
  **旧回执晚到只记日志，绝不覆盖新状态**；门禁结论一旦通过也不被迟到失败回执逆转。
- **重复命令幂等**：对已下发命令重复下发返回 `duplicate`，设备状态不变，发送全程留痕。
- **观测恶化处置**：冻结所有**尚未开始**的批次为 `paused`，当前批次标记恶化/失败，
  并生成回退计划——**批次按推进逆序、批内按规则依赖逆序（被依赖者最后撤）**，
  从未生效的命令标记 `skipped`（部分回退粒度）。
- **部分回退**：设备回退被拒/超时则步骤 `failed`，发布进入 `partially_rolled_back`，
  可重试失败步骤；已完成回退绝不重复执行。
- **追加式可校验日志**：所有审批、例外创建/续期/撤销、证据采纳、门禁与回退等
  自动动作（标记为 `system`）都进入 SHA-256 哈希链的 JSONL 日志，
  可随时重放校验，篡改/删除/插入条目均能被发现。
- **重启恢复**：发布游标、批次/命令/回退状态、ID 计数器全部落盘，
  重启后通过 `resume_hint` 明确下一步动作，审计日志在同一链上续写。

## 分层结构

```
policy_wave_control/
  domain/        领域模型与状态机（拓扑、策略、例外、发布聚合、审计条目、错误）
  ports/         可替换端口（时钟、ID、仓储、审计、设备网关）
  adapters/      适配器（JSON/JSONL 持久化、模拟设备网关、系统与固定时钟）
  application/   应用服务（预演引擎 PreflightEngine、编排服务 ReleaseService）
  interfaces/    HTTP 接口（标准库 ThreadingHTTPServer）
  bootstrap.py   端口与适配器的组装
  offline_runner.py  离线场景运行器（9 大场景，39 项断言）
  server.py      本地 HTTP 服务入口
scripts/
  acceptance_http.py  基于真实 HTTP 的接口验收
tests/           领域单元测试 + 应用集成/持久化/篡改检测测试
```

时间与 ID 均通过端口注入；离线运行器用 `FixedClock` 精确复现“窗口到期、例外过期、
旧回执晚到”等时序过程。

## 快速开始

### 1. 离线场景验收（无需网络，首选）

```bash
python3 -m policy_wave_control.offline_runner
```

输出按 9 个场景组织，逐条展示对**过期例外、乱序回执、部分回退、重复命令**等的处理：

1. 能力条件不满足 → 预演拒绝（含阻断设备清单）
2. 过期例外不再豁免 / 生效例外继续豁免 / 续期规则
3. 金丝雀下发、乱序回执仲裁、重复命令幂等、证据与角色门禁
4. 机器区批次：门禁通过后迟到失败回执不逆转
5. 个人区观测恶化 → 冻结未开始批次 + 依赖逆序回退计划
6. 部分回退 → 失败步骤重试 → 回退完成
7. 重复回退命令与网关发送留痕
8. 追加式哈希链审计日志校验
9. 服务重启后发布游标恢复（落盘适配器 + 日志续写）

### 2. 本地 HTTP 接口验收

```bash
python3 scripts/acceptance_http.py
```

在真实 HTTP 端口上完成注册→预演→乱序回执→重复命令→证据→角色确认（含 403）
→审计校验→服务重启恢复。

### 3. 启动本地服务

```bash
python3 -m policy_wave_control.server --data-dir ./runtime_data --port 8080
```

数据（状态 JSON、审计 JSONL、ID 计数）全部写入 `--data-dir`（已被 `.gitignore` 排除）。

主要接口（JSON；可用请求头 `X-Actor` / `X-Role` 传递操作者与角色）：

| 方法 & 路径 | 说明 |
| --- | --- |
| `POST /topology/snapshots` | 登记拓扑快照 |
| `POST /policy/versions` | 登记策略版本（含 `depends_on`） |
| `POST /exceptions` / `GET /exceptions` | 创建 / 列出例外（返回时按当前时间标记过期） |
| `POST /exceptions/{id}/renew` `/revoke` | 续期（须晚于当前到期时间）/ 撤销 |
| `POST /releases/plan` | 执行预演并生成金丝雀及后续批次 |
| `GET  /releases/{id}` | 发布视图，含 `resume_hint`（重启恢复游标） |
| `POST /releases/dispatch` `/resend` `/pause` `/resume` `/rollback` | 下发/重复下发/暂停/恢复/回退 |
| `POST /receipts` | 上报设备回执 `{command_id,status,seq}`，旧 seq 拒绝覆盖 |
| `POST /rollback-receipts` | 回退阶段回执 |
| `POST /batches/{id}/evidence` | 提交健康证据（按 source+seq 仲裁） |
| `POST /batches/{id}/confirm` | 对应角色确认（角色不符返回 403） |
| `GET  /audit` `/audit/verify` | 查看 / 校验追加式哈希链日志 |
| `GET  /gateway/records` | 设备网关全部发送留痕（含重复命令） |

回执 `status`：`applied` / `rejected` / `timeout`；重复或乱序上报返回
`{"verdict": "stale"}` 且不改变设备状态。

## 测试与编译检查

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q policy_wave_control tests scripts
```
