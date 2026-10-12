# Verification — điền trước khi nộp

- **OS / Python / Gitleaks:** Windows 10 Pro 10.0.19045 / Python 3.11.9 / Gitleaks 8.30.1 (tải từ release chính thức, SHA256 khớp `checksums.txt`).
- **`python -m pytest tests/ -q --basetemp=.pytest_tmp`:** `33 passed`, 0 skipped, 0 failed (reset sink trước khi chạy).
- **`pre-commit run --all-files`:** `Detect hardcoded secrets...Passed`.
- **Ledger verify:** `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"` → `True`. Sửa một ký tự ở dòng giữa của bản sao → `False` (ledger thật không bị sửa).
- **`reports/attack-before.log`:** 4 dòng POST chứa hồ sơ giả `KH-000999` (1196 byte). **`reports/attack-after.log`:** **0 byte**.
- **Các lỗi còn lại / giới hạn:** không có test fail hay skip. Giới hạn của lab: mock LLM, principal giả lập (không xác thực), regex PII chỉ 4 loại, hash chain không chống cắt đuôi, chưa thử model thật. Điều khoản pháp luật cụ thể trong `compliance-mapping.md` ghi là *chưa xác minh* vì chưa đọc toàn văn.

## Lỗi đã gặp và cách sửa

- `gitleaks` không nhận ra trong terminal đã mở: PATH người dùng chỉ có hiệu lực ở terminal mới; nạp lại PATH hoặc mở lại VS Code.
- `sink.py --reset` báo `UnicodeEncodeError` (cp1252): đặt `PYTHONIOENCODING=utf-8` (log vẫn được reset trước khi in).
- Script replay nằm ngoài repo báo `No module named 'agent'`: đặt `PYTHONPATH` về thư mục repo.
- `attack-before.log` từng có 5 dòng (chạy CLI mà chưa reset): reset và chạy lại đúng 4 lure → 4 dòng.
- Chuỗi `
` bị ghi thành xuống dòng thật khi sinh code (`SyntaxError`): sửa lại literal trong `agent/ledger.py` và `agent/runner.py`.
- `.venv/` gây false positive `generic-api-key` khi quét file hiện tại: thêm allowlist đúng đường dẫn `.venv/`, không đụng rule token giả.
- `attack-before.log`, `attack-after.log`, `ledger.jsonl` bị `.gitignore` chặn: thêm vào commit bằng `git add -f`.

## Lệnh và kết quả theo checkpoint

- **CP1:** đọc `agent/loop.py`, `agent/tools.py` → `reports/baseline.md` (3 câu có `file:dòng`); không có test.
- **CP2:** `python -m agent.check_lure corpus/ticket-90*.md` → `4/4 lure sẵn sàng`; replay baseline bằng `_naive_loop` → `reports/attack-before.log` 4 dòng.
- **CP3b:** `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp` → 4 pass.
- **CP3c:** `python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp` → 5 pass (`support_l1` deny, `dpo` allow).
- **CP3d:** `python -m pytest tests/test_split.py -v ...` → 1 pass; `python -m pytest tests/test_injection.py -v ...` → 8 pass (4 lure x 2 principal, không SKIP).
- **CP5:** reset sink, chạy toàn bộ test (33 pass), reset lại, bật sink thật, chạy `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` → `attack-after.log` 0 byte. Ledger có thêm 24 dòng (tổng 48): 1 `search_docs` allow, 22 `read_customer` allow, 1 `http_post` deny (`on_behalf_of=dpo`, `reason` restricted + egress).

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

## CP4 — Supply chain & secrets

- Phiên bản: Python 3.11.9, Gitleaks 8.30.1 (`gitleaks version`).
- `gitleaks git --config .gitleaks.toml --redact --verbose .` → 11 commit, 1 finding (`lab24-synthetic-token`, `lab-fake-secret.txt:1`, commit `1bdd849`), mã thoát 1 (đúng mong đợi).
- `gitleaks dir --config .gitleaks.toml --redact .`: lần đầu 1 finding false positive `generic-api-key` trong `.venv/Lib/site-packages/setuptools/...`; thêm allowlist đúng đường dẫn `.venv/` vào `.gitleaks.toml`, quét lại → `no leaks found`, mã thoát 0. Chi tiết trong `reports/secrets-incident.md`.
- `python -m piptools compile --generate-hashes -o requirements.lock requirements.txt` → 11 package, mỗi package có `--hash=sha256:` (192 hash). `python -m pip install --require-hashes -r requirements.lock` → thành công.
- `pre-commit install` → ok; `pre-commit run --all-files` → `Detect hardcoded secrets...Passed`.
- `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp` → 3 pass.
