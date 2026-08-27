# Security policy

## Authorised use only

Sleuth is a local recon and authorised-testing toolkit. Use it only on systems
you own or have written permission to test. Unauthorised scanning, brute force,
or exploitation can be illegal.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security bugs (especially
anything that bypasses auto-review, the private-address fetch guard, or the
active-skill gate).

Report privately via GitHub Security Advisories:

https://github.com/VaibhavSingala/Sleuth/security/advisories/new

Include:

- What you ran (tool name / skill, not a full exploit chain against third parties)
- Sleuth version or commit
- Whether `SLEUTH_ALLOW_EXEC`, `SLEUTH_ALLOW_SELF_EDIT`, or
  `SLEUTH_ALLOW_ACTIVE_SKILLS` were enabled

We will acknowledge the report and work on a fix before any public disclosure.

## Safe defaults for clones

A fresh checkout without a custom `.env` should:

- Refuse private/loopback fetches (`WEBSEARCH_BLOCK_PRIVATE=true`)
- Keep Burp/ZAP/Wapiti **active** scans off
- Keep `python_exec` / `shell_exec` and `code_write` **off**
- Keep brute-force / XSS-injection / directory-bruteforce skills **unloaded**
- Keep auto-review **on**

Turn those on only in a lab, against authorised targets.
