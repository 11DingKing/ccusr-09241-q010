# 融合网络安全策略分波发布系统

编排面向个人、机器、物联三类网络区域的访问与隔离策略：管理区域拓扑快照、
策略版本、能力条件、规则依赖顺序与有期限例外，预演变更对可达性和关键
业务的影响，生成金丝雀批次与后续波次；每批只有在健康证据达到阈值并取得
对应角色确认后才能推进，观测恶化时自动暂停尚未开始的批次并生成遵循依赖
逆序的回退计划。

## 分层结构

| 层 | 位置 | 职责 |
| --- | --- | --- |
| 领域层 | `policy_wave_control/domain/` | 拓扑/策略/例外模型、可达性预演、批次与回执状态机、哈希链审计日志 |
| 应用层 | `policy_wave_control/application/` | 发布编排服务、依赖拓扑排序与批次规划、时间/标识端口 |
| 适配层 | `policy_wave_control/adapters/` | JSON 文件持久化（原子写入，服务重启可恢复） |
| 接口层 | `policy_wave_control/interfaces/` | 零依赖本地 HTTP 接口 |
| 离线运行器 | `policy_wave_control/offline/` | 确定性时钟下的端到端验收场景 |

时间与标识生成通过 `Clock`/`IdGenerator` 端口注入，`ScriptedClock` 与
`SequentialIds` 让业务过程可稳定复现。

## 关键规则

- **有期限例外**：例外仅在 `[valid_from, valid_until]` 内生效，续期只能
  延长、可吊销；过期例外在预演中明确列出且不再抑制规则。例外可全局生效，
  也可通过 `scope_device_id` 仅豁免单台设备。
- **能力条件**：设备缺少规则要求的能力则不生成下发命令，预演报告能力缺口；
  关键链路上完全无设备可落地时预演判定为 `blocked`。
- **依赖顺序**：规则按 `depends_on` 拓扑序下发，被依赖者先下发；回退计划
  严格按批次逆序、批内拓扑序逆序生成，依赖方先撤销。
- **批次闸门**：每批需要全部要求角色确认（金丝雀需发布主管 + 安全管理员，
  区域波次需安全管理员 + 对应区域负责人），且命令应用比例与健康指标证据
  全部满足阈值后才能 `advance`。
- **乱序/过期回执**：命令带单调版本号，回执沿 `pending < dispatched <
  acked < failed < applied` 秩推进；旧版本、超前版本、状态回退与完全
  重复的回执一律拒绝，晚到的旧回执不会覆盖新状态，但每条回执（含被拒绝
  的）都留痕。
- **重复命令**：按（批次, 规则, 设备）幂等，重传不产生新版本、不重开
  状态，只计数并审计。
- **恶化处置**：在途批次采纳到越界指标时自动暂停所有未开始批次并生成回退
  计划（不自动执行）；回退逐设备执行，单台失败不阻塞其余步骤，得到
  `partially_rolled_back`，之后可调用补偿重试，全部成功后升级为
  `rolled_back`。
- **追加式审计**：所有审批、例外续期、证据采纳、自动暂停/回退动作均进入
  SHA-256 哈希链日志，`/api/audit/verify` 可重算校验，任何字段被篡改
  都会在断裂点被检出。

## 运行离线验收场景

```bash
python3 -m policy_wave_control.offline.runner
# 机器可读结果：
python3 -m policy_wave_control.offline.runner --json --save result.json
```

场景在确定性时钟下依次演练：建拓扑与策略、长/短例外续期与过期、生成
金丝雀+三区域波次、双角色确认、重复命令、过期与乱序回执、健康闸门、
观测恶化自动暂停、依赖逆序回退计划、单设备撤销失败的部分回退与补偿、
服务重启游标恢复，并在结尾汇总**过期例外、乱序回执、部分回退、重复命令**
四类处理证据与完整审计动作序列。

## 启动本地 HTTP 接口

```bash
python3 -m policy_wave_control.interfaces.http_api --data-dir ./.runtime/data --port 8080
```

主要端点（均为 JSON）：

- `POST /api/snapshots`、`POST /api/policies`、`POST /api/exceptions`
- `GET  /api/policies/{id}/preflight?at=...`
- `POST /api/exceptions/{id}/renew`、`.../revoke`
- `POST /api/rollouts`（创建前强制预演，阻断关键业务则 400）
- `POST /api/rollouts/{id}/approve | dispatch | receipts | evidence |
  advance | pause | resume | rollback-plan | rollback | rollback-retry`
- `GET  /api/rollouts/{id}`、`GET /api/rollouts/{id}/gate?batch_index=0`
- `GET  /api/audit`、`GET /api/audit/verify`、`POST /api/recover`

运行数据写入 `--data-dir`（默认 `./.runtime/data`），不污染源码目录。

## 测试与编译检查

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q policy_wave_control tests
```
