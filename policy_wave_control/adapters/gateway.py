"""设备网关适配器：本地模拟下发，完整记录每次发送（含重复命令痕迹）。"""

from __future__ import annotations

from ..domain.enums import CommandStatus


class SimulatedDeviceGateway:
    """离线可控网关。

    * 首次发送 PLANNED 命令 -> dispatched，命令标记 SENT；
    * 对已 SENT/终结的命令再次发送 -> duplicate，不改变命令状态；
    * 回退命令同理，按 rollback 状态判定。
    所有发送动作写入 sent_records，供离线场景运行器呈现“重复命令”。
    """

    def __init__(self, clock) -> None:
        self._clock = clock
        self._records: list[dict] = []

    def send_commands(self, commands, rollback: bool = False) -> dict[str, str]:
        result: dict[str, str] = {}
        for cmd in commands:
            if rollback:
                first = cmd.mark_rollback_sent(self._clock.now())
                phase = "rollback"
            else:
                first = cmd.mark_sent(self._clock.now())
                phase = "forward"
            outcome = "dispatched" if first else "duplicate"
            result[cmd.command_id] = outcome
            self._records.append({
                "at": self._clock.now(),
                "command_id": cmd.command_id,
                "device_id": cmd.device_id,
                "rule_id": cmd.rule_id,
                "batch_index": cmd.batch_index,
                "phase": phase,
                "outcome": outcome,
                "dispatch_count": cmd.dispatch_count if not rollback else None,
            })
        return result

    def sent_records(self) -> list[dict]:
        return list(self._records)
