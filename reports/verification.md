# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify:
- Các lỗi còn lại:

## CP3a — PII gate (`agent/pii.py`)

- Lệnh: `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp`
- Kết quả: `gold=118 pred=118 tp=118`, `precision=1.000`, `recall=1.000` (2 test pass). Offset `start`/`end` khớp đúng 120/120 dòng của `tests/vn_pii_testset.jsonl`.
- Cách làm: regex cho 4 loại, mỗi vùng chỉ được tính một lần theo thứ tự ưu tiên EMAIL > VN_BANK_ACCOUNT (có nhãn) > VN_CCCD > VN_PHONE. `redact()` thay từ cuối về đầu.
- Giới hạn của regex:
  - Số tài khoản chỉ nhận khi có nhãn (`STK`, `số tài khoản`, `tài khoản`, `TK`); dãy 8–16 số không nhãn sẽ không bị che, còn dãy đúng 12 số không nhãn bị coi là CCCD.
  - Điện thoại chỉ nhận `0` hoặc `+84`/`84` theo sau đúng 9 chữ số (cho phép cách/chấm/gạch ngang); số bàn hoặc định dạng khác bị bỏ sót.
  - Số 12 chữ số bất kỳ (mã đơn, mã giao dịch) có thể bị báo nhầm là CCCD.
  - Tên người (PERSON) chưa được xử lý; test set không có nhãn này.
  - Test set là dữ liệu tổng hợp theo mẫu cố định nên điểm 1.000 cao hơn mức dự kiến trên dữ liệu thật.

## CP3e — Ledger (`agent/ledger.py`, `reports/ledger.jsonl`)

- Unit test: `python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp` → 3 pass (chuỗi hash, phát hiện sửa dòng, thiếu `reason`).
- Tạo ledger thật: `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` → `reports/ledger.jsonl` 24 dòng (1 `search_docs` allow, 22 `read_customer` allow, 1 `http_post` deny).
- Kiểm: `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"` → `True`.
- Dòng `http_post` deny: `on_behalf_of=dpo`, `classification=restricted`, `reason="deny: dữ liệu restricted không được đi cùng egress (network) trong cùng một run"`.
- Chứng minh phát hiện sửa đổi (làm trên bản sao, không đụng file thật): sửa một ký tự (`allow` → `denx`) ở dòng 13/24 mà không tính lại hash → `verify()` trả `False`; bản sao nguyên vẹn và ledger thật vẫn `True`.
- Không có PII trong ledger: chỉ lưu `args_hash` (sha256 của tham số); không có `KH-`/`cccd` nào trong file.
- Giới hạn: hash chain trong một file không phát hiện được việc xoá dòng cuối hoặc viết lại cả file rồi tính lại chuỗi, vì lab không có mốc tin cậy bên ngoài.
