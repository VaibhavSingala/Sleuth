"""Web search tools for local LLMs served by LM Studio."""

from .core import read_url, research, web_search

__all__ = ["web_search", "read_url", "research"]
__version__ = "1.0.0"
