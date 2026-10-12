# Baseline — checkpoint 1

Ticket là dữ liệu do người ngoài viết, nhưng baseline (`_naive_loop`) coi chỉ thị nằm trong ticket như lệnh của người dùng: đọc ticket → thấy chỉ thị → đọc hồ sơ → POST ra sink, không có cổng kiểm quyền nào ở giữa.

1. **Agent có identity mỗi run chưa?** 
Chưa. Vì:
 * `_naive_loop(message, llm)` ở `agent/loop.py:27` chỉ nhận câu hỏi và LLM, không có `agent_id`, `run_id` hay principal; không dòng nào trong hàm đề cập đến tạo hoặc truyền identity. 
 * `run_once` có tham số `principal_id` (`agent/loop.py:58`) nhưng chỉ chuyển cho `runner.handle()` (`agent/loop.py:69`)
 * Nhánh baseline `return _naive_loop(message, llm)` (`agent/loop.py:74`) bỏ nó đi nên không có gì để kiểm quyền hay truy vết người đứng sau.

2. **Trước `http_post` có policy kiểm mục đích, quyền, loại dữ liệu không? Ai quyết định gửi?** 
Không có policy nào. 
Vì người quyết định gửi thực chất là nội dung ticket: 
- `llm.find_injection(combined_text)` ở `agent/loop.py:34` trích `customer_ids` và `target_url` từ chỉ thị trong ticket, và chỉ cần `injected is not None` (`agent/loop.py:35`) là vòng lặp tự gọi `read_customer` (`agent/loop.py:39`) rồi `http_post` (`agent/loop.py:44`). 
- Lớp duy nhất ở `agent/tools.py:76-83` chỉ khoá URL về `127.0.0.1:10024`; chính docstring của hàm (`agent/tools.py:71-74`) nói đây chỉ là rào an toàn cho bài lab, không quyết định dữ liệu nào được gửi.

3. **Dòng nào tạo body POST, file nào ghi lại sink đã nhận?** 
- Body được tạo ở `agent/loop.py:44`: `{"records": collected}`, trong đó `collected` là nguyên hồ sơ khách do `read_customer` trả về (`agent/loop.py:39`, `agent/tools.py:55-65`), không lọc PII. 
- Request thực sự gửi ở `agent/tools.py:84` (`requests.post(url, json=body)`).
- Bằng chứng sink đã nhận nằm ở `reports/sink.log`, do handler trong `sink/sink.py:46-47` ghi mỗi request thành một dòng JSON `{"path", "body"}`.
