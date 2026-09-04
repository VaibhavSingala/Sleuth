# Contributing to Sleuth

Thanks for your interest in improving Sleuth. This project is a **local recon and
authorised-testing toolkit** for local LLMs. Contributions are welcome — please
read this first, especially the safety section.

## Ground rules

- **Authorised use only.** Sleuth is for systems you own or have written
  permission to test. Do not contribute features whose only purpose is to attack
  third parties, evade detection, or bypass a target's protections. See
  [`SECURITY.md`](SECURITY.md).
- **Safety gates are load-bearing.** New active/intrusive capability must default
  to **off** behind an explicit environment gate (mirror how `SLEUTH_ALLOW_EXEC`,
  `SLEUTH_ALLOW_ACTIVE_SKILLS`, and the Burp/ZAP/Wapiti active-scan gates work).
- **No secrets, ever.** No API keys, tokens, real target hostnames, or
  machine-specific paths in commits, tests, or fixtures. Configuration lives in
  `.env` (gitignored); document new keys in `.env.example`.

## Development setup

Requires **Python 3.11+**.

```bash
git clone https://github.com/VaibhavSingala/Sleuth.git
cd Sleuth
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"          # add ,js / ,apk / ,scan extras as needed
cp .env.example .env             # everything works with no keys by default
```

Run the MCP server or the chat page:

```bash
python run_server.py             # MCP server (stdio) — what LM Studio launches
python -m websearch.webchat      # chat web page on http://localhost:8765
```

## Before you open a PR

Run the same checks CI runs:

```bash
ruff check .            # lint
ruff format .           # auto-format (use --check in CI)
mypy websearch          # type check (advisory during the src/ migration)
pytest                  # tests
```

- Keep changes focused; one logical change per PR.
- Add or update tests when you change behaviour. Tests live in [`tests/`](tests/).
- Update `README.md` / `.env.example` when you add config or change behaviour.
- Keep source files under ~500 lines where practical; prefer editing existing
  modules over adding new top-level ones.

## Commit & PR style

- Write imperative commit subjects ("Add X", "Fix Y"), not "added"/"fixed".
- Fill in the pull-request template; link issues with `Closes #NN`.
- Small, reviewable PRs merge faster than large ones.

## Adding a tool or skill

- **Built-in tools** are registered in the MCP server; keep recon/read tools
  side-effect-free and route target-facing HTTP through the shared fetch layer so
  the private-address guard and Burp proxying apply.
- **Model-authored skills** live in `skills/` and are loaded dynamically. Active
  ones must be listed in `config.ACTIVE_SKILL_NAMES` so they stay gated behind
  `SLEUTH_ALLOW_ACTIVE_SKILLS`.

## Reporting security issues

Do **not** open a public issue. Use the private advisory flow described in
[`SECURITY.md`](SECURITY.md).

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
