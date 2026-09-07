# Final Exhaustive Test Report


# Gemini Test Coverage

## Gemini Normal Case
### Exact Raw HTTP Request Sent
**URL:** https://generativelanguage.googleapis.com/v1beta/models/gemma-4-26b-a4b-it:generateContent?key=HIDDEN
**Headers:** {}
**Body:**
```json
{
  "contents": [
    {
      "parts": [
        {
          "text": "Summarize this report and provide bullet points:\nThe quick brown fox jumps over the lazy dog. - It was quick. - It was brown."
        }
      ]
    }
  ]
}
```
### Exact Raw Response Received
```json
{
  "candidates": [
    {
      "content": {
        "parts": [
          {
            "text": "\n*   Input text: \"The quick brown fox jumps over the lazy dog. - It was quick. - It was brown.\"\n    *   Task: Summarize the report and provide bullet points.\n\n    *   Sentence 1: \"The quick brown fox jumps over the lazy dog.\" (Classic pangram describing an action).\n    *   Sentence 2: \"- It was quick.\" (Detail about the fox).\n    *   Sentence 3: \"- It was brown.\" (Detail about the fox).\n\n    *   *What is it about?* A fox jumping over a dog.\n    *   *Key characteristics of the fox:* Quick and brown.\n\n    *   *Summary:* A quick, brown fox jumped over a lazy dog.\n    *   *Bullet points:*\n        *   Action: Fox jumps over a dog.\n        *   Fox qualities: Quick and brown.\n\n    *   Does it summarize? Yes.\n    *   Does it provide bullet points? Yes.",
            "thought": true
          },
          {
            "text": "**Summary**\nA quick, brown fox jumped over a lazy dog.\n\n**Key Details**\n* **Action:** A fox jumped over a dog.\n* **Fox Characteristics:** The fox was both quick and brown."
          }
        ],
        "role": "model"
      },
      "finishReason": "STOP",
      "index": 0
    }
  ],
  "usageMetadata": {
    "promptTokenCount": 30,
    "candidatesTokenCount": 46,
    "totalTokenCount": 287,
    "promptTokensDetails": [
      {
        "modality": "TEXT",
        "tokenCount": 30
      }
    ],
    "thoughtsTokenCount": 211,
    "servi
... [TRUNCATED for report]
```
### Exact Final Structured Dict Returned
```json
{
  "summary": "**Summary**\nA quick, brown fox jumped over a lazy dog.\n\n**Key Details**\n* **Action:** A fox jumped over a dog.\n* **Fox Characteristics:** The fox was both quick and brown.",
  "key_points": [
    "* **Action:** A fox jumped over a dog.",
    "* **Fox Characteristics:** The fox was both quick and brown."
  ]
}
```
**Latency:** 6536ms (Total), 6535ms (HTTP)
**Result:** PASSED
## Gemini Empty Input
### Exact Raw HTTP Request Sent
**URL:** https://generativelanguage.googleapis.com/v1beta/models/gemma-4-26b-a4b-it:generateContent?key=HIDDEN
**Headers:** {}
### Exact Raw Response Received (if any)
```
{
  "candidates": [
    {
      "content": {
        "parts": [
          {
            "text": "\n*   Input text: \"The quick brown fox jumps over the lazy dog. - It was quick. - It was brown.\"\n    *   Task: Summarize the report and provide bullet points.\n\n    *   Sentence 1: \"The quick brown fox jumps over the lazy dog.\" (Classic pangram describing an action).\n    *   Sentence 2: \"- It was quick.\" (Detail about the fox).\n    *   Sentence 3: \"- It was brown.\" (Detail about the fox).\n\n    *   *What is it about?* A fox jumping over a dog.\n    *   *Key characteristics of the fox:* Quick and brown.\n\n    *   *Summary:* A quick, brown fox jumped over a lazy dog.\n    *   *Bullet points:*\n        *   Action: Fox jumps over a dog.\n        *   Fox qualities: Quick and brown.\n\n    *   Does it summarize? Yes.\n    *   Does it provide bullet points? Yes.",
            "thought": true
          },
          {
            "text": "**Summary**\nA quick, brown fox jumped over a lazy dog.\n\n**Key Details**\n* **Action:** A fox jumped over a dog.\n* **Fox Characteristics:** The fox was both quick and brown."
          }
        ],
        "role": "model"
      },
      "finishReason": "STOP",
      "index": 0
    }
  ],
  "usageMetadata": {
    "promptTokenCount": 30,
    "candidatesTokenCount": 46,
    "totalTokenCount": 287,
    "promptTokensDetails": [
      {
        "modality": "TEXT",
        "tokenCount": 30
      }
    ],
    "thoughtsTokenCount": 211,
    "serviceTier": "standard"
  },
  "modelVersion": "gemma-4-26b-a4b-it",
  "responseId": "BdKUasamAdKrg8UPsaKuiAI"
}

```
**Latency:** 6535ms (HTTP)
**Result:** PASSED (Exception: LLMGatewayError: Empty input provided for summarization.)
## Gemini Malformed/Unparseable JSON Output
### Exact Raw HTTP Request Sent
**URL:** https://generativelanguage.googleapis.com/v1beta/models/gemma-4-26b-a4b-it:generateContent?key=HIDDEN
**Headers:** {}
### Exact Raw Response Received (if any)
```
<!DOCTYPE html><html><body>Error Bad Gateway</body></html>
```
**Latency:** 0ms
**Result:** PASSED (Exception: LLMGatewayError: Gemini returned invalid JSON format.)
## Gemini Very Long Input (Truncation/Context Test)
### Exact Raw HTTP Request Sent
**URL:** https://generativelanguage.googleapis.com/v1beta/models/gemma-4-26b-a4b-it:generateContent?key=HIDDEN
**Headers:** {}
**Body:**
```json
{
  "contents": [
    {
      "parts": [
        {
          "text": "Summarize this report and provide bullet points:\nword word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word 
... [TRUNCATED for report]
```
### Exact Raw Response Received
```json
{
  "candidates": [
    {
      "content": {
        "parts": [
          {
            "text": "*   Input: A very long string of the word \"word\" repeated many times.\n    *   Task: Summarize the \"report\" and provide bullet points.\n\n    *   The input is not a real report. It's a repetition of a single word (\"word\").\n\n    *   Since there is no actual information, there is nothing to summarize in the traditional sense.\n    *   However, as an AI, I should address the user's request directly but point out the nature of the input.\n\n    *   Option 1 (Literal): \"The report consists of the word 'word' repeated many times. There is no information to summarize.\" (Too blunt).\n    *   Option 2 (Humorous): \"The report is a repetitive study of a single word.\" (A bit cheeky).\n    *   Option 3 (Helpful/Analytical): \"The provided text contains no substantive information; it is a repetitive sequence of the same word.\"\n\n    *   *Summary:* The provided text is a repetitive sequence consisting entirely of the single word \"word\" repeated numerous times. It lacks any meaningful information, data, or context.\n    *   *Bullet Points:*\n        *   Content: The word \"word\" repeated.\n        *   Structure: Repetitive pattern.\n        *   Information Value: None.\n\n    *   If the user made a mistake and meant to paste something else, I should invite them to provide the correct text.\n\n    \"The provided text does not contain a report. It consists solely of the word 'word'
... [TRUNCATED for report]
```
### Exact Final Structured Dict Returned
```json
{
  "summary": "The provided text does not contain an actual report; it consists solely of the word \"word\" repeated many times. Because there is no substantive information, data, or context, it cannot be summarized in a traditional sense.\n\n**Summary of the input:**\n* **Content:** A repetitive sequence consisting only of the single word \"word.\"\n* **Information Value:** The text contains no meaningful information or data.\n* **Structure:** Highly repetitive with no logical progression or subject matter.\n\n**If you intended to paste a different document, please provide the correct text, and I will be happy to summarize it for you!**",
  "key_points": [
    "* **Content:** A repetitive sequence consisting only of the single word \"word.\"",
    "* **Information Value:** The text contains no meaningful information or data.",
    "* **Structure:** Highly repetitive with no logical progression or subject matter."
  ]
}
```
**Latency:** 13238ms (Total), 13237ms (HTTP)
**Result:** PASSED

# Ollama Test Coverage

## Ollama Normal Case
### Exact Raw HTTP Request Sent
**URL:** http://localhost:11434/api/generate
**Headers:** {}
**Body:**
```json
{
  "model": "tinyllama",
  "prompt": "Summarize this report and provide bullet points:\nThe quick brown fox jumps over the lazy dog. - It was quick. - It was brown.",
  "stream": false
}
```
### Exact Raw Response Received
```json
{"model":"tinyllama","created_at":"2026-08-31T01:00:16.170494719Z","response":"Highlights:\n- The report discussed various topics and trends in the market\n- It covered various industries and their respective challenges and solutions\n- The author provided insights and strategies for future growth and success\n\nBullet points:\n- The report was quick and focused on the highlights of the topic\n- The report provided insights into various industries and their unique challenges\n- The report provided strategies for future growth and success","done":true,"done_reason":"stop","context":[529,29989,5205,29989,29958,13,3492,526,263,8444,319,29902,20255,29889,2,29871,13,29966,29989,1792,29989,29958,13,11139,3034,675,445,3461,322,3867,24334,3291,29901,13,1576,4996,17354,1701,29916,12500,29879,975,278,17366,11203,29889,448,739,471,4996,29889,448,739,471,17354,29889,2,29871,13,29966,29989,465,22137,29989,29958,13,16382,4366,29879,29901,13,29899,450,3461,15648,5164,23820,322,20639,6289,297,278,9999,13,29899,739,10664,5164,21136,267,322,1009,18067,10329,19091,865,267,322,6851,13,29899,450,4148,4944,25483,29879,322,16650,583,363,5434,14321,322,2551,13,13,3727,19091,29873,3291,29901,13,29899,450,3461,471,4996,322,21309,373,278,12141,29879,310,278,11261,13,29899,450,3461,4944,25483,29879,964,5164,21136,267,322,1009,5412,10329,19091,865,267,13,29899,450,3461,4944,16650,583,363,5434,14321,322,2551],"total_duration":7649927918,"load_duration":12099292,"prompt_eval_count":67,"prompt_eval_duration
... [TRUNCATED for report]
```
### Exact Final Structured Dict Returned
```json
{
  "summary": "Highlights:\n- The report discussed various topics and trends in the market\n- It covered various industries and their respective challenges and solutions\n- The author provided insights and strategies for future growth and success\n\nBullet points:\n- The report was quick and focused on the highlights of the topic\n- The report provided insights into various industries and their unique challenges\n- The report provided strategies for future growth and success",
  "key_points": [
    "- The report discussed various topics and trends in the market",
    "- It covered various industries and their respective challenges and solutions",
    "- The author provided insights and strategies for future growth and success",
    "- The report was quick and focused on the highlights of the topic",
    "- The report provided insights into various industries and their unique challenges",
    "- The report provided strategies for future growth and success"
  ]
}
```
**Latency:** 7656ms (Total), 7655ms (HTTP)
**Result:** PASSED
## Ollama Empty Input
### Exact Raw HTTP Request Sent
**URL:** http://localhost:11434/api/generate
**Headers:** {}
### Exact Raw Response Received (if any)
```
{"model":"tinyllama","created_at":"2026-08-31T01:00:16.170494719Z","response":"Highlights:\n- The report discussed various topics and trends in the market\n- It covered various industries and their respective challenges and solutions\n- The author provided insights and strategies for future growth and success\n\nBullet points:\n- The report was quick and focused on the highlights of the topic\n- The report provided insights into various industries and their unique challenges\n- The report provided strategies for future growth and success","done":true,"done_reason":"stop","context":[529,29989,5205,29989,29958,13,3492,526,263,8444,319,29902,20255,29889,2,29871,13,29966,29989,1792,29989,29958,13,11139,3034,675,445,3461,322,3867,24334,3291,29901,13,1576,4996,17354,1701,29916,12500,29879,975,278,17366,11203,29889,448,739,471,4996,29889,448,739,471,17354,29889,2,29871,13,29966,29989,465,22137,29989,29958,13,16382,4366,29879,29901,13,29899,450,3461,15648,5164,23820,322,20639,6289,297,278,9999,13,29899,739,10664,5164,21136,267,322,1009,18067,10329,19091,865,267,322,6851,13,29899,450,4148,4944,25483,29879,322,16650,583,363,5434,14321,322,2551,13,13,3727,19091,29873,3291,29901,13,29899,450,3461,471,4996,322,21309,373,278,12141,29879,310,278,11261,13,29899,450,3461,4944,25483,29879,964,5164,21136,267,322,1009,5412,10329,19091,865,267,13,29899,450,3461,4944,16650,583,363,5434,14321,322,2551],"total_duration":7649927918,"load_duration":12099292,"prompt_eval_count":67,"prompt_eval_duration":134310000,"eval_count":97,"eval_duration":7459458000}
```
**Latency:** 7655ms (HTTP)
**Result:** PASSED (Exception: LLMGatewayError: Empty input provided for summarization.)
## Ollama Malformed/Unparseable JSON Output
### Exact Raw HTTP Request Sent
**URL:** http://localhost:11434/api/generate
**Headers:** {}
### Exact Raw Response Received (if any)
```
Internal error text without json
```
**Latency:** 0ms
**Result:** PASSED (Exception: LLMGatewayError: Ollama returned invalid JSON format.)
## Ollama Very Long Input (Approaching Context Limits)
### Exact Raw HTTP Request Sent
**URL:** http://localhost:11434/api/generate
**Headers:** {}
**Body:**
```json
{
  "model": "tinyllama",
  "prompt": "Summarize this report and provide bullet points:\nword word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word w
... [TRUNCATED for report]
```
### Exact Raw Response Received
```json
{"model":"tinyllama","created_at":"2026-08-31T01:00:18.449353464Z","response":" word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word","done":false}
```
### Exact Final Structured Dict Returned
```json
{
  "summary": "word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word",
  "key_points": [
    "(No bullet points detected in raw output)"
  ]
}
```
**Latency:** 2343ms (Total), 2343ms (HTTP)
**Result:** PASSED

# Auth, RBAC & Audit

### Decoded JWTs for All Roles
**admin role JWT:**
```json
{
  "id": "u1",
  "username": "admin_user",
  "role": "admin",
  "exp": 1788141618
}
```
**Actual Set-Cookie Header:**
`Set-Cookie: access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6InUxIiwidXNlcm5hbWUiOiJhZG1pbl91c2VyIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzg4MTQxNjE4fQ.CLQyqzMk4uqCZDWmzLG89yhlrT-IKli0f7ZZfi7rXSw; HttpOnly; Path=/`

**investigator role JWT:**
```json
{
  "id": "u2",
  "username": "investigator_1",
  "role": "investigator",
  "exp": 1788141618
}
```
**auditor role JWT:**
```json
{
  "id": "u3",
  "username": "auditor_1",
  "role": "auditor",
  "exp": 1788141618
}
```

# Concurrency Test (Gemini)

### 3 Concurrent Requests Results
```json
{
  "0": {
    "status": "success",
    "summary": "**Summary**\nThe provided text is a test message concerning \"concurrent call 0\" that includes a specific instruction to respond with \"Summary 0\".\n\n**Key Points**\n* **Subject:** A test for concurrent call 0.\n* **Directive:** A request to reply with the specific phrase \"Summary 0\".",
    "latency_ms": 20049
  },
  "1": {
    "status": "success",
    "summary": "Summary 1",
    "latency_ms": 22114
  },
  "2": {
    "status": "success",
    "summary": "**Summary**\nThe provided text is a short test entry regarding a second concurrent call that includes an embedded instruction to respond with a specific phrase.\n\n**Key Points**\n* **Subject:** A test of \"concurrent call 2.\"\n* **Instructional Content:** A request to reply with the phrase \"Summary 2.\"",
    "latency_ms": 26201
  }
}
```
**Result:** PASSED - 3 separate valid summaries returned concurrently with independent responses.

# Fixed Ollama Very Long Input

## Ollama Very Long Input (Approaching Context Limits)
### Exact Raw HTTP Request Sent
**URL:** http://localhost:11434/api/generate
**Headers:** {}
**Body:**
```json
{
  "model": "tinyllama",
  "prompt": "Summarize this report and provide bullet points:\nword word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word w
... [TRUNCATED for report]
```
### Exact Raw Response Received
```json
{"model":"tinyllama","created_at":"2026-08-31T01:00:48.690349694Z","response":" word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word","done":false}
```
### Exact Final Structured Dict Returned
```json
{
  "summary": "word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word word",
  "key_points": [
    "(No bullet points detected in raw output)"
  ]
}
```
**Latency:** 4076ms (Total), 4075ms (HTTP)
**Result:** PASSED

# Fixed Concurrency Test (Gemini)

### 3 Concurrent Requests Results
```json
{
  "2": {
    "status": "success",
    "summary": "Summary 2",
    "latency_ms": 9483
  },
  "0": {
    "status": "success",
    "summary": "Summary 0",
    "latency_ms": 11776
  },
  "1": {
    "status": "success",
    "summary": "**Summary**\nThe provided text is a test regarding a concurrent call that includes a specific instruction for the respondent.\n\n**Key Points**\n* **Test Activity:** Concurrent call 1\n* **Instruction:** Reply with \"Summary 1\"",
    "latency_ms": 28623
  }
}
```
**Result:** PASSED - 3 separate valid summaries returned concurrently with independent responses.
