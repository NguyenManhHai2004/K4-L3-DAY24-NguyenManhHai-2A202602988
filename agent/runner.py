"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=5)
ALL_SCOPES = ("search_docs", "read_customer", "http_post")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


class _Gate:
    """PEP: mọi tool call đi qua policy.check() và ghi ledger TRƯỚC khi tool chạy."""

    def __init__(self, ledger_path: Path, principal_id: str, run_id: str, agent_id: str,
                 scopes: tuple[str, ...], expires_at: str):
        self.ledger_path = ledger_path
        self.principal_id = principal_id
        self.run_id = run_id
        self.agent_id = agent_id
        self.scopes = scopes
        self.expires_at = expires_at

    def allow(self, tool: str, args: dict, classification: str, purpose: str,
              egress: bool = False) -> bool:
        ctx = policy.PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=self.agent_id,
            delegation_depth=0,
            egress_enabled=egress,
            principal_id=self.principal_id,
            requested_tool=tool,
            agent_scopes=self.scopes,
            expires_at=self.expires_at,
        )
        allowed, reason = policy.check(ctx)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "tool": tool,
            "args_hash": hashlib.sha256(
                json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
            "classification": classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
        }, self.ledger_path)
        return allowed


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) if log_dir else REPORTS_DIR) / "ledger.jsonl"
    run_id = uuid.uuid4().hex
    expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat()
    gate = _Gate(ledger_path, principal_id, run_id, f"{AGENT_ID}/{run_id[:8]}", ALL_SCOPES, expires_at)

    if not gate.allow("search_docs", {"query": message}, "internal", "summarize-tickets"):
        return "Yêu cầu bị từ chối bởi policy (xem ledger)."
    docs = tools.search_docs(message)

    injected = llm.find_injection("\n\n".join(d["text"] for d in docs))
    if injected is not None:
        collected = []
        for customer_id in injected.customer_ids:
            if not gate.allow("read_customer", {"customer_id": customer_id}, "restricted", "support-reply"):
                continue
            try:
                collected.append(tools.read_customer(customer_id))
            except tools.ToolError:
                continue
        if collected and gate.allow("http_post", {"url": injected.target_url}, "restricted",
                                    "support-reply", egress=True):
            tools.http_post(injected.target_url, {"records": collected})

    return llm.summarize(docs)
