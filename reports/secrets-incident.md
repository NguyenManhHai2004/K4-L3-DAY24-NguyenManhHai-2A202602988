# Secret giả trong lịch sử Git — checkpoint 4

Đây là bài tập với **token giả, vô hiệu** do repo đề bài cố ý đặt; không có credential thật nào bị lộ hoặc được dùng.

- **Scanner và phiên bản:** Gitleaks v8.30.1 (`gitleaks version` → `8.30.1`, tải từ release chính thức, đã đối chiếu SHA256 với `checksums.txt`), cấu hình `.gitleaks.toml` (rule mặc định + rule riêng của lab).
- **Commit chứa token giả:** `1bdd849` (đầy đủ `1bdd849922156c868a5ee9293d68f5b72e242d2c`, ngày 2026-10-09, tác giả "VinUni AI20k Lab").
- **File, rule và kết quả quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` quét 11 commit, mã thoát `1`, đúng **1 finding**: rule `lab24-synthetic-token`, file `lab-fake-secret.txt`, dòng 1, commit `1bdd849`. Giá trị bị che bởi `--redact`. File này đã bị xoá ở commit sau, nhưng token vẫn nằm trong lịch sử. Đây là kết quả mong đợi, không phải lỗi bảo mật thật.
- **Kết quả quét file hiện tại:**
  - Lần quét đầu (`gitleaks dir --config .gitleaks.toml --redact .`) báo 1 finding rule `generic-api-key` tại `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py:45`. Đây là false positive trong thư viện bên thứ ba của môi trường ảo cục bộ (`.venv/` đã nằm trong `.gitignore`), không phải file của bài.
  - Cách xử lý: thêm vào `.gitleaks.toml` một `[[allowlists]]` chỉ cho đường dẫn `(^|/)\.venv/`. Không tắt rule `lab24-synthetic-token`, không bỏ qua cả repo.
  - Sau khi chỉnh: quét file hiện tại → `no leaks found`, mã thoát `0`; quét lịch sử vẫn ra đúng 1 finding ở `1bdd849`, mã thoát `1`. `pre-commit run --all-files` (hook `gitleaks-system`, `rev: v8.30.1`, `pass_filenames: false`) → Passed.
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. Thu hồi/rotate ngay tại dịch vụ đã cấp token (cấp token mới, vô hiệu token cũ).
  2. Kiểm log của dịch vụ đó từ thời điểm commit để tìm việc sử dụng trái phép và đánh giá thiệt hại.
  3. Xử lý mọi bản sao: fork, clone, CI cache, bản mirror. Chỉ khi cần mới viết lại lịch sử (ví dụ `git filter-repo`) và phối hợp để mọi người cập nhật; việc viết lại lịch sử là bước dọn dẹp, không thay cho bước rotate.
  4. Ghi lại sự cố và thêm kiểm tra tự động để lần sau bị chặn trước khi commit.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - Xoá file ở commit mới chỉ làm file biến mất khỏi trạng thái hiện tại; token vẫn còn trong lịch sử Git (như Gitleaks vừa tìm thấy ở `1bdd849`) và trong mọi bản clone/fork đã có. Ai có token đó vẫn dùng được cho đến khi nó bị thu hồi.
  - Pin dependency (`requirements.lock` có hash) bảo vệ chuỗi cung ứng thư viện, và hook pre-commit chỉ chặn secret **trước khi** commit. Hai thứ này không làm một secret đã lộ hết hiệu lực; việc duy nhất làm điều đó là rotate/thu hồi tại nơi cấp.
