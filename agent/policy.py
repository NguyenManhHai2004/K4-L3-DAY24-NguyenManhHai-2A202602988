"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"
CLASSIFICATIONS = ("public", "internal", "restricted")


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def _expired(expires_at: str) -> bool | None:
    """True nếu đã hết hạn, False nếu còn hạn, None nếu không đọc được."""
    try:
        deadline = datetime.fromisoformat(expires_at)
    except (TypeError, ValueError):
        return None
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return deadline <= datetime.now(timezone.utc)


def check(context: PolicyContext) -> tuple[bool, str]:
    """Trả (allow, reason); reason luôn có nội dung. Mặc định đóng: thiếu hoặc
    sai bất kỳ điều kiện nào đều deny."""
    # 1. Nhãn dữ liệu phải hợp lệ.
    if context.data_classification not in CLASSIFICATIONS:
        return False, f"deny: data_classification {context.data_classification!r} không hợp lệ"

    # 2. Rule tối thiểu — đặt trước OBO nên không principal nào (kể cả dpo) vượt được.
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return False, "deny: dữ liệu restricted không được đi cùng egress (network) trong cùng một run"

    # 3. OBO: người ra lệnh, tool, phạm vi quyền, mục đích, thời hạn.
    try:
        principals = _load_principals()
    except (OSError, ValueError):
        return False, "deny: không đọc được data/principals.json nên không xác định được principal"
    principal = principals.get(context.principal_id)
    if principal is None:
        return False, f"deny: principal {context.principal_id!r} không có trong data/principals.json"

    if not context.requested_tool:
        return False, "deny: thiếu requested_tool"

    expired = _expired(context.expires_at)
    if expired is None:
        return False, "deny: expires_at thiếu hoặc không phải ISO-8601"
    if expired:
        return False, f"deny: run đã hết hạn lúc {context.expires_at}"

    if context.delegation_depth < 0:
        return False, f"deny: delegation_depth {context.delegation_depth} không hợp lệ"

    effective = set(principal.get("allowed_tools", ())) & set(context.agent_scopes)
    if context.delegation_depth > 0:
        effective &= set(context.parent_scopes)
    if context.requested_tool not in effective:
        return False, (f"deny: {context.requested_tool!r} nằm ngoài quyền hiệu lực của "
                       f"{context.principal_id!r} (principal ∩ agent"
                       f"{' ∩ parent' if context.delegation_depth > 0 else ''} scopes)")

    if context.request_purpose not in principal.get("purposes", ()):
        return False, (f"deny: mục đích {context.request_purpose!r} không nằm trong "
                       f"purposes của {context.principal_id!r}")

    # 4. Mọi điều kiện đều hợp lệ.
    return True, (f"allow: {context.principal_id} được dùng {context.requested_tool} "
                  f"cho {context.request_purpose} (classification={context.data_classification}, "
                  f"egress={context.egress_enabled})")
