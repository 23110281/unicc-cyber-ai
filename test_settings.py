"""
Tests for settings (.env / environment variables).
Run with:  pytest -q test_settings.py
"""
import pytest

from backend import config


def test_env_file_is_loaded_but_real_environment_wins(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("UNICC_TEST_A=from-file\nUNICC_TEST_B=from-file\n# a comment\n")
    monkeypatch.setenv("UNICC_TEST_B", "from-environment")
    monkeypatch.setenv("LOAD_DOTENV", "1")
    monkeypatch.delenv("UNICC_TEST_A", raising=False)
    assert config.load_env_file(env_file) is True
    assert config.get_str("UNICC_TEST_A") == "from-file"
    assert config.get_str("UNICC_TEST_B") == "from-environment"
    monkeypatch.delenv("UNICC_TEST_A", raising=False)


def test_missing_env_file_is_fine(tmp_path, monkeypatch):
    monkeypatch.setenv("LOAD_DOTENV", "1")
    assert config.load_env_file(tmp_path / "does-not-exist") is False


def test_number_and_true_false_settings(monkeypatch):
    monkeypatch.setenv("UNICC_TEST_N", "42")
    monkeypatch.setenv("UNICC_TEST_T", "yes")
    assert config.get_int("UNICC_TEST_N", 1) == 42
    assert config.get_int("UNICC_TEST_UNSET", 7) == 7
    assert config.get_bool("UNICC_TEST_T") is True
    monkeypatch.setenv("UNICC_TEST_N", "lots")
    with pytest.raises(RuntimeError):
        config.get_int("UNICC_TEST_N", 1)


def test_ai_model_names_come_from_settings(monkeypatch):
    from llm.gateway.adapters import GeminiGateway, OllamaGateway
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    assert GeminiGateway().url.endswith("/models/gemini-3.8-flash:generateContent")
    monkeypatch.setenv("OLLAMA_HOST", "http://ai-server:11434/")
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.2")
    monkeypatch.setattr(OllamaGateway, "verify_model", lambda self: None)   # no real Ollama needed
    gateway = OllamaGateway()
    assert (gateway.host, gateway.model) == ("http://ai-server:11434", "llama3.2")


def test_unsafe_model_name_is_refused(monkeypatch):
    from llm.gateway.adapters import GeminiGateway
    from llm.gateway.interface import LLMGatewayError
    monkeypatch.setenv("GEMINI_MODEL", "../../other-api?x=1")
    with pytest.raises(LLMGatewayError):
        GeminiGateway()


def test_per_computer_limit_can_be_switched_off():
    from backend.auth.login_limiter import LoginLimiter
    limiter = LoginLimiter(max_failures_per_user=5, max_failures_per_ip=0)
    for i in range(50):                        # many users failing from one shared address
        limiter.record_failure(f"user-{i}", "172.17.0.1")
    assert limiter.seconds_until_allowed("someone-else", "172.17.0.1") == 0
    for _ in range(5):
        limiter.record_failure("alice", "172.17.0.1")
    assert limiter.seconds_until_allowed("alice", "172.17.0.1") > 0   # accounts still protected


def test_example_settings_file_documents_every_setting():
    import pathlib, re
    root = pathlib.Path(__file__).parent
    code = "\n".join(p.read_text() for p in list(root.glob("backend/**/*.py")) + list(root.glob("llm/**/*.py")))
    used = set(re.findall(r'get_(?:str|int|bool)\("([A-Z_]+)"', code)) | set(re.findall(r'environ\.get\("([A-Z_]+)"', code))
    used -= {"LOAD_DOTENV"}
    documented = set(re.findall(r"^([A-Z_]+)=", (root / ".env.example").read_text(), re.M))
    assert used <= documented, f"settings missing from .env.example: {sorted(used - documented)}"
