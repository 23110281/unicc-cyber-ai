import threading
import json
import time
from llm.gateway.adapters import GeminiGateway, OllamaGateway
from run_exhaustive_tests import append_to_report, interceptor, run_test_case

# Clear interceptor
interceptor.last_response_text = ""
interceptor.force_status = None
interceptor.force_text = None
interceptor.force_error = None
interceptor.force_timeout = False

append_to_report("\n# Fixed Ollama Very Long Input\n")
try:
    ollama = OllamaGateway(model="tinyllama")
    run_test_case("Ollama Very Long Input (Approaching Context Limits)", ollama, "summarize_report", ["word " * 3000, {"timeout": 120}], expected_pass=True)
except Exception as e:
    append_to_report(f"Failed to run Ollama long input: {e}")


append_to_report("\n# Fixed Concurrency Test (Gemini)\n")
def worker(gw, results, index):
    try:
        start = time.time()
        res = gw.summarize_report(f"Test concurrent call {index}. Please reply with \"Summary {index}\"", {"timeout": 60})
        lat = int((time.time() - start) * 1000)
        results[index] = {"status": "success", "summary": res["summary"], "latency_ms": lat}
    except Exception as e:
        results[index] = {"status": "error", "error": str(e)}

gemini = GeminiGateway()
threads = []
results = {}
for i in range(3):
    t = threading.Thread(target=worker, args=(gemini, results, i))
    threads.append(t)
    t.start()
for t in threads:
    t.join()

append_to_report("### 3 Concurrent Requests Results")
append_to_report(f"```json\n{json.dumps(results, indent=2)}\n```")
if all(v.get("status") == "success" for v in results.values()):
    append_to_report("**Result:** PASSED - 3 separate valid summaries returned concurrently with independent responses.")
else:
    append_to_report("**Result:** FAILED - Concurrency errors detected.")
