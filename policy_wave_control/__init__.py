"""融合网络安全策略分波发布系统的服务端包入口。"""

PROJECT_CODE = "policy_wave_control"


def project_info() -> dict[str, str]:
    """返回稳定的项目标识，供运行检查和诊断使用。"""
    return {"code": PROJECT_CODE, "title": "融合网络安全策略分波发布系统"}
