"""Back-compat shim: proxy routing now lives in websearch.intercept.

Kept so existing imports (``from .proxy import proxy_kwargs``) keep working.
The active proxy may be Burp or ZAP; intercept resolves which.
"""

from ..intercept import active_proxy, proxy_enabled, proxy_kwargs

__all__ = ["proxy_kwargs", "proxy_enabled", "active_proxy"]
