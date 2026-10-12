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
