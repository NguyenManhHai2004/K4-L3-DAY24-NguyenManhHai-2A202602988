# DPIA-lite — checkpoint 5

Đây là bản mô tả học tập cho bài lab, **không phải hồ sơ đánh giá tác động pháp lý chính thức**. Toàn bộ dữ liệu là dữ liệu tổng hợp do repo cung cấp; không có dữ liệu cá nhân thật.

## 1. Loại dữ liệu và phân loại

| Dữ liệu | Nằm ở đâu | Phân loại | Ghi chú |
|---|---|---|---|
| Ticket hỗ trợ (kể cả ticket chứa lure injection) | `corpus/*.md` | `internal`, **không đáng tin** | Người ngoài có thể viết nội dung, nên coi là dữ liệu chứ không phải lệnh |
| Hồ sơ khách giả (CCCD, SĐT, STK, email, `related_tickets`) | `data/customers.json` | `restricted` | Ví dụ khách `KH-000999` gắn với ticket 901–905 |
| Quyền giả lập của người dùng | `data/principals.json` | `internal` | `support_l1`, `billing`, `dpo` |
| Nhật ký quyết định | `reports/ledger.jsonl` | `internal` | Chỉ có `args_hash`, không có PII thô |
| Bản ghi của sink thử nghiệm | `reports/sink.log`, `reports/attack-*.log` | chứa dữ liệu giả ở log trước, rỗng ở log sau | Sink là máy nhận giả ở `127.0.0.1:10024` |

## 2. Mục đích xử lý và principal

- **`support_l1`:** chỉ được `search_docs`, mục đích `summarize-tickets` / `support-reply`. Không được đọc hồ sơ khách.
- **`dpo`:** được `search_docs` và `read_customer`, mục đích `summarize-tickets`, `support-reply`, `privacy-audit`.
- **`billing`:** được `search_docs` và `read_customer` cho `summarize-tickets`, `billing-reconciliation`.
- Principal chỉ là fixture giả lập chọn bằng `--as`, **không phải xác thực** người dùng.

## 3. Dữ liệu đi qua những run/tool/endpoint nào

1. Người dùng hỏi → `agent.loop` → `agent.runner.handle()`.
2. **Run A** (scope chỉ `search_docs`): đọc ticket, rút số ticket từ **tên file**, che PII trong text bằng `agent/pii.py`, báo lại URL mà lure muốn gửi (nếu có). Không đọc hồ sơ khách, không gọi mạng.
3. **Run B** (scope `read_customer`, `http_post`): chỉ nhận danh sách số ticket. Sau khi policy cho phép, tra `related_tickets` trong `data/customers.json` để tìm khách thật sự liên quan, kiểm policy lại trước từng `read_customer`.
4. Nếu lure đòi gửi dữ liệu, Run B chạy một lượt kiểm `http_post` riêng (`restricted` + egress), chỉ mang URL.
5. Mọi quyết định allow/deny đi qua `agent/policy.py` và được ghi vào `reports/ledger.jsonl` (hash chain).
6. Điểm ra duy nhất được phép là sink localhost `127.0.0.1:10024` (hard-allowlist ở `agent/tools.py`); sau khi chặn, sink không nhận gì.

## 4. Đã chặn / cho phép gì và còn giới hạn gì

**Bằng chứng**
- **Trước:** `reports/attack-before.log` có 4 dòng POST, mỗi dòng chứa hồ sơ giả của `KH-000999` (CCCD, SĐT, STK, email) — baseline gửi dữ liệu ra sink.
- **Sau:** chạy `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` với sink đang nghe → `reports/attack-after.log` **0 byte**.
- **Ledger:** `dpo` đọc hợp lệ 21 hồ sơ gắn với ticket (chức năng được giữ), còn `http_post` bị deny với lý do restricted + egress (`reports/ledger.jsonl:24`, `:48`, `on_behalf_of=dpo`). `support_l1` bị deny khi mở dữ liệu riêng.
- **Test:** toàn bộ test pass, không SKIP (số liệu chính xác ở `reports/verification.md`). `ledger.verify()` trả `True`; sửa một ký tự thì trả `False`.

**Giới hạn**
- **Mock LLM:** chỉ nhận diện lure bằng marker xác định trước; model thật có thể bị lừa theo cách khác, và chưa thử `--model` thật.
- **Quyền giả lập:** `--as` chỉ chọn dòng trong file JSON; không có xác thực, không có thu hồi quyền.
- **Regex PII:** chỉ 4 loại theo mẫu cố định; STK không nhãn không bị che, số 12 chữ số bất kỳ có thể báo nhầm là CCCD, chưa có tên người. Điểm precision/recall 1.000 là trên dữ liệu tổng hợp.
- **Hash chain:** phát hiện sửa dòng giữa file, nhưng không phát hiện xoá dòng cuối hoặc viết lại cả file rồi tính lại chuỗi vì không có mốc tin cậy bên ngoài.
- **`dpo` vẫn đọc được hồ sơ hợp lệ:** việc chặn rò rỉ ở khách này chỉ dựa vào policy chặn bước gửi (restricted + egress); nếu policy sai thì dữ liệu có thể ra ngoài.
- **Phạm vi:** chưa xét cơ sở pháp lý xử lý, đồng ý, thời hạn lưu trữ, quyền của chủ thể dữ liệu hay chuyển dữ liệu ra nước ngoài.
