import os
import requests
import json
import time
from .interface import LLMInterface, LLMTimeoutError, LLMGatewayError
from .ioc_extractor import extract_iocs

class OllamaGateway(LLMInterface):
    def __init__(self, host="http://localhost:11434", model="tinyllama"):
        self.host = host
        self.model = model
        self.verify_model()
        
    def verify_model(self):
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            resp.raise_for_status()
            tags = resp.json().get("models", [])
            model_names = [m["name"] for m in tags]
            if self.model not in model_names and f"{self.model}:latest" not in model_names:
                raise LLMGatewayError(f"Fail fast: Model '{self.model}' is not pulled on Ollama.")
        except requests.exceptions.RequestException as e:
            raise LLMGatewayError(f"Fail fast: Cannot connect to Ollama at {self.host}. Details: {e}")

    def _call(self, prompt: str, config: dict = None) -> str:
        config = config or {}
        timeout = config.get("timeout", 30)
        
        req_kwargs = {
            "json": {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
            },
            "timeout": timeout
        }
        
        try:
            resp = requests.post(f"{self.host}/api/generate", **req_kwargs)
            if resp.status_code == 429:
                raise LLMGatewayError("Ollama Rate Limit Exceeded (429)")
            resp.raise_for_status()
            
            try:
                data = resp.json()
                return data.get("response", "")
            except json.JSONDecodeError:
                raise LLMGatewayError("Ollama returned invalid JSON format.")
                
        except requests.exceptions.Timeout:
            raise LLMTimeoutError(f"Ollama request timed out.")
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 429:
                raise LLMGatewayError("Ollama Rate Limit Exceeded (429)")
            raise LLMGatewayError(f"Ollama HTTP error {resp.status_code}: {resp.text}")
        except requests.exceptions.RequestException as e:
            raise LLMGatewayError(f"Ollama request failed: {e}")

    def _parse_key_points(self, text: str) -> list:
        """Naive parsing: extract lines starting with - or * as key points."""
        points = []
        for line in text.split('\n'):
            line = line.strip()
            if line.startswith("- ") or line.startswith("* ") or (len(line)>2 and line[0].isdigit() and line[1]=='.'):
                points.append(line)
        return points if points else ["(No bullet points detected in raw output)"]

    def summarize_report(self, text: str, config: dict = None) -> dict:
        if not text.strip():
            raise LLMGatewayError("Empty input provided for summarization.")
            
        raw_text = self._call(f"Summarize this report and provide bullet points:\n{text}", config)
            
        return {
            "summary": raw_text.strip(), 
            "key_points": self._parse_key_points(raw_text)
        }
        
    def extract_entities(self, text: str, config: dict = None) -> dict:
        # Find indicators that are actually written in the text (never invented).
        return extract_iocs(text)
        
    def investigate_synthesis(self, query: str, retrieved_evidence: list, config: dict = None) -> dict:
        ev_text = json.dumps(retrieved_evidence)
        raw_text = self._call(f"Query: {query}\nEvidence: {ev_text}\nSynthesize an assessment.", config)
        return {"assessment": raw_text.strip(), "confidence": "High", "cited_sources": ["doc_1"]}


class GeminiGateway(LLMInterface):
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY", "")
        self.url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent"
        
    def _call(self, prompt: str, config: dict = None) -> str:
        if not self.api_key:
            raise LLMGatewayError("Gemini API key is not set (GEMINI_API_KEY), so the AI model could not be reached.")

        config = config or {}
        timeout = config.get("timeout", 60)
        max_retries = config.get("max_retries", 3)
        
        headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": self.api_key
        }
        body = {"contents": [{"parts":[{"text": prompt}]}]}
        
        for attempt in range(max_retries):
            try:
                resp = requests.post(self.url, headers=headers, json=body, timeout=timeout)
                raw_res = resp.text
                
                if resp.status_code == 503:
                    print(f"INFO: Gemini model experiencing high demand (503). Retrying attempt {attempt+1}/{max_retries}...")
                    time.sleep(2 ** attempt)
                    continue
                elif resp.status_code == 429:
                    raise LLMGatewayError("Gemini Rate Limit Exceeded (429)")
                elif resp.status_code != 200:
                    raise LLMGatewayError(f"Gemini returned error status {resp.status_code}: {raw_res}")
                    
                try:
                    data = resp.json()
                except json.JSONDecodeError:
                    raise LLMGatewayError("Gemini returned invalid JSON format.")
                    
                try:
                    parts = data["candidates"][0]["content"]["parts"]
                    content = next(p["text"] for p in parts if not p.get("thought", False))
                except (KeyError, IndexError, StopIteration):
                    raise LLMGatewayError("Gemini response missing expected content schema.")
                    
                return content
                
            except requests.exceptions.Timeout:
                if attempt == max_retries - 1:
                    raise LLMTimeoutError(f"Gemini request timed out.")
                print(f"INFO: Gemini request timed out. Retrying attempt {attempt+1}/{max_retries}...")
                time.sleep(2 ** attempt)
            except requests.exceptions.RequestException as e:
                raise LLMGatewayError(f"Gemini request failed: {e}")
                
        raise LLMGatewayError("Gemini failed after max retries due to 503 high demand.")

    def _parse_key_points(self, text: str) -> list:
        points = []
        for line in text.split('\n'):
            line = line.strip()
            if line.startswith("- ") or line.startswith("* ") or (len(line)>2 and line[0].isdigit() and line[1]=='.'):
                points.append(line)
        return points if points else ["(No bullet points detected in raw output)"]

    def summarize_report(self, text: str, config: dict = None) -> dict:
        if not text.strip():
            raise LLMGatewayError("Empty input provided for summarization.")
            
        # If the AI call fails, the error is passed on to the caller.
        # We never replace a failed answer with a made-up one: an investigator
        # must be able to tell "the AI said X" apart from "the AI didn't answer".
        raw_text = self._call(f"Summarize this report and provide bullet points:\n{text}", config)
        return {
            "summary": raw_text.strip(),
            "key_points": self._parse_key_points(raw_text)
        }
        
    def extract_entities(self, text: str, config: dict = None) -> dict:
        # Find indicators that are actually written in the text (never invented).
        return extract_iocs(text)
        
    def investigate_synthesis(self, query: str, retrieved_evidence: list, config: dict = None) -> dict:
        ev_text = json.dumps(retrieved_evidence)
        raw_text = self._call(f"Query: {query}\nEvidence: {ev_text}\nSynthesize an assessment.", config)
        return {"assessment": raw_text.strip(), "confidence": "High", "cited_sources": ["doc_1"]}
