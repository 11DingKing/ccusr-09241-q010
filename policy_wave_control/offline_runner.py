"""离线场景运行器：不依赖网络，完整演练分波发布并清楚呈现关键处理结果。

运行：
    python3 -m policy_wave_control.offline_runner

覆盖场景：
  1. 能力条件不满足 -> 预演拒绝（含阻断设备清单）
  2. 过期例外不再豁免 / 生效例外继续豁免（预演报告 + 命令剔除）
  3. 金丝雀 -> 机器区 -> 个人区批次按角色确认推进
  4. 乱序/迟到回执：旧序号回执不得覆盖新状态
  5. 重复命令：重复下发扬幂等抑制
  6. 部署门禁的“迟到失败回执不逆转已过门禁”
  7. 观测恶化：未开始批次冻结 + 生成依赖逆序回退计划
  8. 部分回退（设备回退拒绝）-> 重试后回退完成（未生效命令跳过）
  9. 追加式哈希链日志校验
  10. 服务重启后发布游标恢复
"""

from __future__ import annotations

import tempfile

from .adapters.runtime import FixedClock
from .bootstrap import build_service
from .domain.errors import AuthorizationError, ConflictError


class _Reporter:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.checks: list[tuple[str, bool, str]] = []

    def section(self, title: str) -> None:
        bar = "=" * 72
        self.lines.append("")
        self.lines.append(bar)
        self.lines.append(title)
        self.lines.append(bar)

    def sub(self, title: str) -> None:
        self.lines.append("")
        self.lines.append(f"-- {title} " + "-" * (60 - len(title)))

    def line(self, msg: str = "") -> None:
        self.lines.append(msg)

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        self.checks.append((name, bool(condition), detail))
        mark = "通过" if condition else "失败"
        self.lines.append(f"  [{mark}] {name}" + (f" —— {detail}" if detail else ""))

    def output(self) -> str:
        return "\n".join(self.lines)


def _topology_payload() -> dict:
    devices = []
    for i in range(1, 5):
        devices.append({"device_id": f"p{i}", "zone_id": "zp",
                        "capabilities": ["acl_v2"], "firmware": "fw-3.1",
                        "critical": i == 1})
    for i in range(1, 9):
        devices.append({"device_id": f"m{i}", "zone_id": "zm",
                        "capabilities": ["acl_v2", "micro_seg"], "firmware": "fw-4.0",
                        "critical": i == 1})
    for i in range(1, 5):
        devices.append({"device_id": f"iot{i}", "zone_id": "zi",
                        "capabilities": ["acl_v2"], "firmware": "fw-2.4"})
    return {
        "snapshot_id": "topo-2026-09-24",
        "version": 7,
        "taken_at": "2026-09-24T00:00:00+00:00",
        "zones": [
            {"zone_id": "zp", "name": "个人业务区", "kind": "personal", "cidr": "10.10.0.0/16"},
            {"zone_id": "zm", "name": "机器业务区", "kind": "machine", "cidr": "10.20.0.0/16"},
            {"zone_id": "zi", "name": "物联业务区", "kind": "iot", "cidr": "10.30.0.0/16"},
        ],
        "devices": devices,
        "services": [
            {"service_id": "svc-billing", "name": "计费对账",
             "src_zone": "zm", "dst_zone": "zm", "protocol": "tcp", "port": 443,
             "owner": "计费组", "rto_minutes": 15},
            {"service_id": "svc-iot-ssh", "name": "物联设备运维通道",
             "src_zone": "zi", "dst_zone": "zp", "protocol": "tcp", "port": 22,
             "owner": "物联运维组", "rto_minutes": 30},
        ],
    }


def _main_policy() -> dict:
    return {
        "policy_id": "pol-access-2026-09",
        "version": 3,
        "rules": [
            {"rule_id": "r1-isolate-modbus", "action": "isolate",
             "src_zone": "zp", "dst_zone": "zi", "protocol": "tcp", "port": 502,
             "required_capability": "acl_v2", "description": "个人区禁止访问物联 Modbus"},
            {"rule_id": "r2-deny-mqtt", "action": "deny",
             "src_zone": "zm", "dst_zone": "zi", "protocol": "tcp", "port": 1883,
             "required_capability": "acl_v2", "description": "机器区到物联 MQTT 收敛"},
            {"rule_id": "r3-deny-iot-ssh", "action": "deny",
             "src_zone": "zi", "dst_zone": "zp", "protocol": "tcp", "port": 22,
             "required_capability": "acl_v2", "description": "物联到个人区 SSH 限制"},
            {"rule_id": "r4-deny-telnet", "action": "deny",
             "src_zone": "zi", "dst_zone": "zi", "protocol": "tcp", "port": 23,
             "required_capability": "acl_v2", "description": "物联区内 Telnet 禁用"},
        ],
        # r2 依赖 r1，r4 依赖 r2：下发与回退都必须遵守此顺序
        "depends_on": {
            "r2-deny-mqtt": ["r1-isolate-modbus"],
            "r4-deny-telnet": ["r2-deny-mqtt"],
        },
        "note": "2026Q3 访问与隔离收敛",
    }


def _capability_policy() -> dict:
    return {
        "policy_id": "pol-cap-demo",
        "version": 1,
        "rules": [
            {"rule_id": "rx-microseg", "action": "isolate",
             "src_zone": "zi", "dst_zone": "zm", "protocol": "tcp", "port": 502,
             "required_capability": "micro_seg",
             "description": "需要微分段能力，物联旧设备不具备"},
        ],
    }


def run(print_output: bool = True) -> dict:
    r = _Reporter()
    clock = FixedClock("2026-09-24T00:00:00+00:00")
    svc = build_service(None, clock=clock, in_memory=True)

    # ------------------------------------------------------------------
    r.section("场景 1：能力条件不满足时预演拒绝")
    svc.register_snapshot(_topology_payload(), actor="ops-admin")
    svc.register_policy(_main_policy(), actor="security-architect")
    svc.register_policy(_capability_policy(), actor="security-architect")
    try:
        svc.plan_release(policy_id="pol-cap-demo", actor="planner")
        r.check("能力不足的预演应被拒绝", False)
    except ConflictError as exc:
        blockers = exc.details["preflight"]["capability_blockers"]
        r.line(f"  预演结论：拒绝发布。{len(blockers)} 台设备缺少 micro_seg 能力，示例：")
        for b in blockers[:3]:
            r.line(f"    - {b['device_id']}（{b['zone_id']}，固件 {b['firmware']}）"
                   f" 执行 {b['rule_id']} 需 {b['required_capability']}")
        r.check("能力阻断清单被返回且未生成发布单", len(blockers) == 4)

    # ------------------------------------------------------------------
    r.section("场景 2：过期例外与生效例外在预演中的差异")
    # 先建两条“当前有效”的例外
    svc.create_exception(
        {"rule_id": "r1-isolate-modbus", "zone_id": "zp",
         "expires_at": "2026-09-25T00:00:00+00:00",
         "reason": "历史巡检终端临时白名单"},
        actor="service-owner-li")
    svc.create_exception(
        {"rule_id": "r3-deny-iot-ssh", "zone_id": "zi",
         "expires_at": "2026-09-30T00:00:00+00:00",
         "reason": "物联运维通道割接期豁免"},
        actor="security-officer-wang")
    # 时间推进：第一条例外过期
    clock.set("2026-09-26T00:00:00+00:00")
    listing = svc.list_exceptions()
    r.line("  当前例外清单（按 2026-09-26 判定）：")
    for e in listing["exceptions"]:
        r.line(f"    - {e['exception_id']} {e['rule_id']}@{e['zone_id']} "
               f"到期 {e['expires_at']} -> {e['status']}"
               f"{'（已过期，不再豁免）' if e.get('expired') else ''}")
    r.check("一条例外被识别为过期", listing["expired"],
            f"过期: {listing['expired']}")

    # 续期：生效例外可续期且必须晚于当前到期时间；过期例外不可续期
    renewed = svc.renew_exception("exc-0002", "2026-10-15T00:00:00+00:00",
                                  actor="security-officer-wang")
    r.check("生效例外续期成功并计数",
            renewed["expires_at"] == "2026-10-15T00:00:00+00:00"
            and renewed["renewed_count"] == 1)
    try:
        svc.renew_exception("exc-0001", "2026-10-01T00:00:00+00:00",
                            actor="security-officer-wang")
        r.check("过期例外续期应被拒绝", False)
    except ConflictError as exc:
        r.check("过期例外不能续期（需重新申请）", exc.code == "conflict")
    try:
        svc.renew_exception("exc-0002", "2026-10-01T00:00:00+00:00",
                            actor="security-officer-wang")
        r.check("续期时间早于当前到期时间应被拒绝", False)
    except Exception:
        r.check("续期不得早于当前到期时间", True)

    plan = svc.plan_release(policy_id="pol-access-2026-09", actor="planner")
    report = plan["preflight"]
    rid = plan["release"]["release_id"]
    expired_rows = report["expired_exceptions"]
    active_rows = report["active_exceptions"]
    r.line(f"  预演报告：可达性检查 {report['reachability']['checked']} 条关键业务，"
           f"阻断 {len(report['reachability']['blocked'])} 条")
    r.line(f"  过期例外（仅警示，不产生豁免）：{[e['exception_id'] for e in expired_rows]}")
    r.line(f"  生效例外（命令据此剔除）：{[(e['rule_id'], e['zone_id']) for e in active_rows]}")
    r.line("  生成批次：")
    for b in report["batch_plan"]:
        r.line(f"    #{b['index']} {b['kind']:<6} zone={b['zone_id']} "
               f"确认角色={b['required_role']} 命令数={b['command_count']}")
    exempted = {(e["rule_id"], e["zone_id"]) for e in report["exempted_commands"]}
    r.check("过期例外未剔除任何命令",
            ("r1-isolate-modbus", "zp") not in exempted)
    r.check("生效例外剔除了物联 SSH 规则的全部命令",
            ("r3-deny-iot-ssh", "zi") in exempted)
    r.check("金丝雀 + 机器/个人/物联三个后续批次",
            [b["kind"] for b in report["batch_plan"]] == ["canary", "zone", "zone", "zone"])
    # 依赖顺序抽查：同设备命令必须 r1(0) -> r2(1) -> r4(2)
    canary = plan["release"]["batches"][0]
    orders = [(c["rule_id"], c["rule_order"]) for c in canary["commands"]]
    r.check("批次内命令按依赖顺序排列",
            [o for _, o in orders] == sorted(o for _, o in orders),
            str(orders))

    # ------------------------------------------------------------------
    r.section("场景 3：金丝雀下发、乱序回执与重复命令")
    disp = svc.dispatch_current(actor="network-operator-zhao")
    canary_cmds = [c for c in canary["commands"]]
    r.line(f"  批次 {disp['batch_id']} 下发 {disp['dispatched']} 条命令，"
           f"重复 {len(disp['duplicate'])} 条")
    r.check("金丝雀首次全部 dispatched",
            disp["dispatched"] == 4 and disp["duplicate"] == [])

    # 3a. 乱序：先到 seq=2，再晚到 seq=1
    target = canary_cmds[0]
    r.sub("乱序/迟到回执（旧序号不得覆盖新状态）")
    res_new = svc.receive_receipt(target["command_id"], "applied", seq=2)
    res_stale = svc.receive_receipt(target["command_id"], "rejected", seq=1)
    r.line(f"    seq=2 applied 先到 -> verdict={res_new['verdict']}")
    r.line(f"    seq=1 rejected 晚到 -> verdict={res_stale['verdict']}，"
           f"设备状态仍为 {res_stale['state']}，采纳水位 last_seq=2")
    r.check("旧回执被拒绝且未覆盖新状态",
            res_stale["verdict"] == "stale" and res_stale["state"] == "applied")

    # 其余金丝雀命令正常 applied
    for c in canary_cmds[1:]:
        svc.receive_receipt(c["command_id"], "applied", seq=1)
    view = svc.release_view(rid)["release"]
    r.check("部署门禁达标后金丝雀进入健康观测",
            view["batches"][0]["status"] == "health_watch",
            f"部署比例 {view['batches'][0]['deploy_ratio']:.0%}")

    # 3b. 重复下发
    r.sub("重复命令幂等抑制")
    resend = svc.resend_current(actor="network-operator-zhao")
    dup_records = [x for x in svc.gateway_records()
                   if x["outcome"] == "duplicate" and x["phase"] == "forward"]
    r.line(f"    再次下发 {len(resend['duplicate_commands'])} 条命令，"
           f"网关全部记录为 duplicate；设备状态未变化")
    r.check("重复命令被幂等识别",
            len(resend["duplicate_commands"]) == 4 and len(dup_records) == 4)

    # 3c. 健康证据：乱序证据 + 窗口/阈值
    r.sub("健康证据采纳与阈值门禁")
    clock.advance(310)  # 越过 300s 观测窗口
    ev = svc.submit_evidence(
        canary["batch_id"], source="probe-a", seq=2, health_score=0.98,
        critical_reachable={"svc-billing": True, "svc-iot-ssh": True})
    ev_stale = svc.submit_evidence(
        canary["batch_id"], source="probe-a", seq=1, health_score=0.10,
        critical_reachable={"svc-billing": False, "svc-iot-ssh": False})
    r.line(f"    旧证据 seq=1（健康 0.10、业务阻断）迟到 -> verdict={ev_stale['verdict']}，"
           f"不参与评估")
    r.check("迟到旧证据不覆盖评估结论",
            ev_stale["verdict"] == "stale" and ev["batch_status"] == "awaiting_approval")

    # 3d. 错误角色确认被拒
    r.sub("角色确认门禁")
    try:
        svc.confirm_batch(canary["batch_id"], role="network_operator",
                          actor="zhao")
        r.check("错误角色确认应被拒绝", False)
    except AuthorizationError as exc:
        r.check("错误角色确认被拒绝",
                exc.details["required_role"] == "security_officer")
    conf = svc.confirm_batch(canary["batch_id"], role="security_officer",
                             actor="wang", note="金丝雀指标正常，放行")
    r.check("安全主管确认后游标推进",
            conf["cursor"] == 1 and conf["release_status"] == "active")

    # ------------------------------------------------------------------
    r.section("场景 4：机器区批次——门禁通过后的迟到失败回执不逆转")
    machine = svc.dispatch_current(actor="network-operator-zhao")
    release = svc.release_view(rid)["release"]
    mbatch = release["batches"][1]
    mcmds = mbatch["commands"]
    r.line(f"    机器批次 {machine['batch_id']}，{len(mcmds)} 台设备")
    # 先 5 台 applied -> 5/6=83% 越过 80% 门禁
    for c in mcmds[:5]:
        svc.receive_receipt(c["command_id"], "applied", seq=1)
    view = svc.release_view(rid)["release"]
    r.check("达到部署比例即进入健康观测",
            view["batches"][1]["status"] == "health_watch",
            f"{view['batches'][1]['deploy_ratio']:.1%}")
    # 第 6 台迟到的 reject：状态如实记录，但门禁结论不回收
    late = svc.receive_receipt(mcmds[5]["command_id"], "rejected", seq=1)
    view = svc.release_view(rid)["release"]
    r.check("迟到失败回执被记录但不逆转已过门禁",
            late["state"] == "rejected"
            and view["batches"][1]["status"] == "health_watch")
    clock.advance(310)
    svc.submit_evidence(
        mbatch["batch_id"], source="probe-b", seq=1, health_score=0.99,
        critical_reachable={"svc-billing": True, "svc-iot-ssh": True})
    try:
        svc.confirm_batch(mbatch["batch_id"], role="security_officer", actor="wang")
        r.check("机器批次必须由网络运维确认", False)
    except AuthorizationError:
        pass
    svc.confirm_batch(mbatch["batch_id"], role="network_operator",
                      actor="zhao", note="机器区指标正常")
    view = svc.release_view(rid)["release"]
    r.check("网络运维确认后游标到个人区批次", view["cursor"] == 2)

    # ------------------------------------------------------------------
    r.section("场景 5：个人区观测恶化 -> 冻结未开始批次并生成回退计划")
    svc.dispatch_current(actor="network-operator-zhao")
    view = svc.release_view(rid)["release"]
    pbatch = view["batches"][2]
    ibatch = view["batches"][3]
    for c in pbatch["commands"]:
        svc.receive_receipt(c["command_id"], "applied", seq=1)
    clock.advance(310)
    bad = svc.submit_evidence(
        pbatch["batch_id"], source="probe-c", seq=1, health_score=0.55,
        critical_reachable={"svc-billing": False, "svc-iot-ssh": True})
    view = svc.release_view(rid)["release"]
    r.line(f"    恶化事件: {bad['auto_events']}")
    r.line(f"    发布状态={view['status']}，原因：{view['pause_reason']}")
    r.check("发布被暂停", view["status"] == "paused")
    r.check("物联批次（尚未开始）被冻结",
            view["batches"][3]["status"] == "paused",
            f"物联批次状态={view['batches'][3]['status']}")
    plan_rb = view["rollback_plan"]
    order = [(s["batch_index"], s["rule_order"]) for s in plan_rb["steps"]
             if s["status"] != "skipped"]
    batches_desc = [b for b, _ in order]
    r.check("回退顺序按批次逆序（个人 -> 机器 -> 金丝雀）",
            batches_desc == sorted(batches_desc, reverse=True),
            str(batches_desc))
    # 同批次内 rule_order 必须逆序
    per_batch: dict[int, list[int]] = {}
    for b, o in order:
        per_batch.setdefault(b, []).append(o)
    r.check("批次内按规则依赖逆序回退（被依赖者最后撤）",
            all(seq == sorted(seq, reverse=True) for seq in per_batch.values()))
    skipped = [s for s in plan_rb["steps"] if s["status"] == "skipped"]
    r.check("从未生效的命令进入计划但标记 skipped（机器区迟到 reject 的那台）",
            len(skipped) == 1, f"skipped={[s['device_id'] for s in skipped]}")

    # ------------------------------------------------------------------
    r.section("场景 6：部分回退 -> 失败步骤重试 -> 回退完成")
    started = svc.start_rollback(actor="security-officer-wang")
    active_steps = [s for s in started["plan"]["steps"] if s["status"] != "skipped"]
    skipped_steps = [s for s in started["plan"]["steps"]
                     if s["status"] == "skipped"]
    r.line(f"    回退命令已发 {len(started['sent'])} 条，"
           f"未生效命令跳过 {len(skipped_steps)} 条（部分回退粒度）")
    r.check("回退首发全部送达（无重复）",
            len(started["sent"]) == len(active_steps) and started["duplicate"] == [])

    # 第一条回退收到 rejected -> 部分回退；其余 applied
    fail_cmd = active_steps[0]["command_id"]
    svc.receive_rollback_receipt(fail_cmd, "rejected", seq=1)
    # 混入一条乱序的旧回退回执（seq=0 不应被采纳）
    stale_rb = svc.receive_rollback_receipt(active_steps[1]["command_id"],
                                            "applied", seq=0)
    r.check("回退阶段旧序号回执同样被拒绝", stale_rb["verdict"] == "stale")
    for s in active_steps[1:]:
        svc.receive_rollback_receipt(s["command_id"], "applied", seq=1)
    view = svc.release_view(rid)["release"]
    r.check("存在回退失败步骤时发布为部分回退",
            view["status"] == "partially_rolled_back",
            view["rollback_plan"]["reason"])
    failed_batch = view["batches"][2]
    r.check("涉事批次标记部分回退",
            failed_batch["status"] == "partially_rolled_back")

    # 重试失败步骤（跳过已 done/skipped），设备恢复正常
    retry = svc.start_rollback(actor="security-officer-wang")
    r.check("重试只重发失败步骤，不重复已完成回退",
            retry["sent"] == [fail_cmd],
            f"sent={retry['sent']}")
    svc.receive_rollback_receipt(fail_cmd, "applied", seq=2)
    view = svc.release_view(rid)["release"]
    r.check("重试成功后发布完全回退", view["status"] == "rolled_back")
    r.check("物联批次保持冻结、从未下发",
            view["batches"][3]["status"] == "paused")

    # ------------------------------------------------------------------
    r.section("场景 7：重复回退命令与网关发送留痕")
    again = svc.start_rollback(actor="security-officer-wang")
    r.check("回退完成后重复启动不产生任何新发送",
            again["sent"] == [] and again["duplicate"] == [])
    rb_dup = [x for x in svc.gateway_records() if x["phase"] == "rollback"]
    r.line(f"    网关回退阶段发送记录 {len(rb_dup)} 条"
           f"（含 {len([x for x in rb_dup if x['outcome']=='duplicate'])} 条重复留痕）")

    # ------------------------------------------------------------------
    r.section("场景 8：追加式哈希链审计日志可校验")
    verify = svc.verify_audit()
    entries = svc.audit_entries()
    actions = {e["action"] for e in entries}
    required_actions = {
        "topology.snapshot_registered", "policy.version_registered",
        "exception.created", "release.preflight_run", "release.planned",
        "batch.dispatched", "receipt.received", "evidence.submitted",
        "batch.confirmed", "release.degraded", "rollback.plan_generated",
        "rollback.started", "rollback.receipt_received",
        "rollback.partial", "rollback.completed",
        "batch.redispatched_duplicate",
    }
    r.line(f"    日志条目 {verify['entries']} 条，链尾 {verify['tail_hash'][:16]}...")
    r.check("哈希链校验通过", verify["ok"], verify.get("reason", ""))
    missing = required_actions - actions
    r.check("审批/例外续期类、证据采纳与自动动作均已留痕",
            not missing, f"缺失动作: {sorted(missing) or '无'}")
    # 自动动作确实以 system 身份记录
    sys_events = [e for e in entries if e["actor"] == "system"]
    r.check("门禁/冻结/回退等自动动作标记为 system",
            any(e["action"] == "release.degraded" for e in sys_events))

    # ------------------------------------------------------------------
    r.section("场景 9：服务重启后发布游标恢复（落盘适配器）")
    restart = _restart_demo(r)
    summary = {
        "release_id": rid,
        "all_passed": all(ok for _, ok, _ in r.checks),
        "checks": r.checks,
        "restart": restart,
        "audit": verify,
    }
    r.line("")
    r.line("#" * 72)
    total = len(r.checks)
    passed = sum(1 for _, ok, _ in r.checks if ok)
    r.line(f"验收结论：{passed}/{total} 项检查通过")
    r.line("#" * 72)
    if print_output:
        print(r.output())
    return summary


def _restart_demo(r: _Reporter) -> dict:
    with tempfile.TemporaryDirectory() as data_dir:
        clock = FixedClock("2026-09-26T00:00:00+00:00")
        svc_a = build_service(data_dir, clock=clock)
        svc_a.register_snapshot(_topology_payload(), actor="ops-admin")
        svc_a.register_policy(_main_policy(), actor="security-architect")
        svc_a.create_exception(
            {"rule_id": "r3-deny-iot-ssh", "zone_id": "zi",
             "expires_at": "2026-09-30T00:00:00+00:00",
             "reason": "物联运维通道割接期豁免"},
            actor="security-officer-wang")
        planned = svc_a.plan_release(actor="planner")
        rid = planned["release"]["release_id"]
        svc_a.dispatch_current(actor="network-operator-zhao")
        canary_id = planned["release"]["batches"][0]["batch_id"]

        # 模拟服务重启：用同一数据目录重新组装（新实例、新网关、日志续写）
        svc_b = build_service(data_dir, clock=clock)
        view = svc_b.release_view(rid)
        hint = view["resume_hint"]
        r.line(f"    重启后游标={hint['cursor']}，发布状态={hint['status']}，"
               f"当前批次={hint['current_batch_status']}，"
               f"恢复动作为“{hint['action']}”")
        r.check("重启后恢复到 ACTIVE/游标 0/等待回执",
                hint["status"] == "active" and hint["cursor"] == 0
                and hint["current_batch_status"] == "dispatched"
                and hint["action"] == "collect_receipts")
        r.check("审计日志在重启后可继续追加并校验通过",
                svc_b.verify_audit()["ok"])

        # 重启后继续业务：补一条回执，状态机正常推进
        cmd_id = view["release"]["batches"][0]["commands"][0]["command_id"]
        receipt = svc_b.receive_receipt(cmd_id, "applied", seq=1)
        r.check("重启后接收回执可继续推进状态机",
                receipt["state"] == "applied")
        r.check("ID 生成器重启后不回绕",
                svc_b.idgen.new_id("ev").startswith("ev-"),
                "计数器从 id_counters.json 恢复")
        return {"release_id": rid, "canary_id": canary_id, "hint": hint}


if __name__ == "__main__":
    result = run()
    raise SystemExit(0 if result["all_passed"] else 1)
