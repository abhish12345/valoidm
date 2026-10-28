"""
Ollama LLM client for LangGraph agents.
Points at the GPU server (10.199.207.232:11434).
"""
from langchain_ollama import ChatOllama
from app.core.config import settings


def get_llm(temperature: float = 0.1, model: str | None = None) -> ChatOllama:
    """
    Returns a ChatOllama bound to the on-prem GPU server.
    temperature=0.1 keeps responses focused and deterministic — important for IGA.
    """
    return ChatOllama(
        base_url=settings.OLLAMA_BASE_URL,
        model=model or settings.OLLAMA_MODEL,
        temperature=temperature,
    )


def get_reasoning_llm() -> ChatOllama:
    """Higher temperature for exploratory reasoning (role mining, anomaly detection)."""
    return get_llm(temperature=0.3)


def get_structured_llm() -> ChatOllama:
    """Zero temperature for structured output (decisions, risk scores)."""
    return get_llm(temperature=0.0)
