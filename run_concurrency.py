import threading
import json
from llm.gateway.adapters import GeminiGateway
from run_exhaustive_tests import append_to_report, interceptor

# Remove the old concurrency section and append a new one
with open("test_report_exhaustive.md", "r") as f:
    lines = f.readlines()
with open("test_report_exhaustive.md", "w") as f:
    for line in lines:
        if line.startswith("## 3. Concurrency Test"):
            break
        f.write(line)

append_to_report("\n## 3. Concurrency Test\n")

def worker(gw, results, index):
    try:
        res = gw.summarize_report(f"Test concurrent call {index}")
        results[index] = {"status": "success", "summary": res["summary"]}
    except Exception as e:
        results[index] = {"status": "error", "error": str(e)}

interceptor.force_status = None
interceptor.force_text = None
interceptor.force_error = None
interceptor.force_timeout = False

gw = GeminiGateway()
threads = []
results = {}

for i in range(3):
    t = threading.Thread(target=worker, args=(gw, results, i))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

append_to_report("### 3 Concurrent Requests to GeminiGateway")
append_to_report(f"```json\n{json.dumps(results, indent=2)}\n```")
if all(v["status"] == "success" for v in results.values()):
    append_to_report("**Result:** PASSED - No shared state issues detected; all calls succeeded concurrently.")
else:
    append_to_report("**Result:** FAILED - Concurrency issues or rate limiting occurred.")
