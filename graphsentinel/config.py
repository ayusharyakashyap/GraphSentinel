"""Environment-backed settings for the local graph database."""

from dataclasses import dataclass
import os
from urllib.parse import urlsplit

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("FALKORDB_HOST", "127.0.0.1")
    port: int = int(os.getenv("FALKORDB_PORT", "6379"))
    graph_name: str = os.getenv("FALKORDB_GRAPH", "graphsentinel")
    password: str | None = os.getenv("FALKORDB_PASSWORD") or None
    llm_api_key: str | None = os.getenv("OPENAI_API_KEY") or None
    llm_base_url: str | None = os.getenv("OPENAI_BASE_URL") or None
    llm_model: str = os.getenv("LLM_MODEL", "gpt-4.1-mini")
    max_tool_calls: int = int(os.getenv("MAX_TOOL_CALLS", "6"))
    max_traversal_depth: int = int(os.getenv("MAX_TRAVERSAL_DEPTH", "5"))
    max_returned_records: int = int(os.getenv("MAX_RETURNED_RECORDS", "100"))
    max_investigation_seconds: int = int(os.getenv("MAX_INVESTIGATION_SECONDS", "30"))
    llm_timeout_seconds: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "15"))
    max_llm_output_tokens: int = int(os.getenv("MAX_LLM_OUTPUT_TOKENS", "1600"))
    max_llm_output_chars: int = int(os.getenv("MAX_LLM_OUTPUT_CHARS", "12000"))
    frontend_origin: str = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")

    def __post_init__(self) -> None:
        bounded = {
            "max_tool_calls": (self.max_tool_calls, 1, 10),
            "max_traversal_depth": (self.max_traversal_depth, 1, 6),
            "max_returned_records": (self.max_returned_records, 1, 200),
            "max_investigation_seconds": (self.max_investigation_seconds, 1, 120),
            "llm_timeout_seconds": (self.llm_timeout_seconds, 1, 60),
            "max_llm_output_tokens": (self.max_llm_output_tokens, 100, 4096),
            "max_llm_output_chars": (self.max_llm_output_chars, 1000, 30000),
        }
        for name, (value, minimum, maximum) in bounded.items():
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")
        origin = urlsplit(self.frontend_origin)
        if (
            origin.scheme not in {"http", "https"}
            or origin.hostname not in {"localhost", "127.0.0.1", "::1"}
            or origin.path
            or origin.query
            or origin.fragment
            or origin.username
            or origin.password
        ):
            raise ValueError("frontend_origin must be an HTTP(S) localhost origin")


settings = Settings()