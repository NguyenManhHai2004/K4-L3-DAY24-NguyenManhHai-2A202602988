"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re

# Thứ tự = độ ưu tiên khi hai vùng chồng nhau: email và tài khoản có nhãn
# (STK/số tài khoản) thắng CCCD, CCCD thắng số điện thoại. Nhờ vậy STK 12 số
# không bị báo thêm lần nữa thành CCCD.
_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"), 0),
    # Chỉ lấy phần chữ số (group 1); nhãn đi trước để tránh báo nhầm mọi dãy số dài.
    ("VN_BANK_ACCOUNT",
     re.compile(r"(?:STK|số\s+tài\s+khoản|so\s+tai\s+khoan|tài\s+khoản|TK)\s*[:\-]?\s*(\d{8,16})(?!\d)",
                re.IGNORECASE), 1),
    ("VN_CCCD", re.compile(r"(?<![\d.])\d{12}(?![\d.]*\d)"), 0),
    # 0 + 9 chữ số, cho phép dấu cách/chấm/gạch ngang; hoặc +84/84 thay số 0 đầu.
    ("VN_PHONE", re.compile(r"(?<!\d)(?:\+?84|0)(?:[ .-]?\d){9}(?!\d)"), 0),
]


def detect(text: str) -> list[dict]:
    candidates = []
    for priority, (kind, pattern, group) in enumerate(_PATTERNS):
        for m in pattern.finditer(text):
            start, end = m.span(group)
            if kind == "VN_PHONE" and len(re.sub(r"\D", "", m.group())) not in (10, 11):
                continue
            candidates.append((priority, start, end, kind))

    entities: list[dict] = []
    for _, start, end, kind in sorted(candidates):
        if any(start < e["end"] and e["start"] < end for e in entities):
            continue  # vùng đã được loại ưu tiên cao hơn lấy
        entities.append({"type": kind, "start": start, "end": end})
    return sorted(entities, key=lambda e: e["start"])


def redact(text: str) -> str:
    # Thay từ cuối về đầu để offset của các vùng chưa xử lý không bị lệch.
    for e in reversed(detect(text)):
        text = text[: e["start"]] + f"[REDACTED_{e['type']}]" + text[e["end"]:]
    return text
