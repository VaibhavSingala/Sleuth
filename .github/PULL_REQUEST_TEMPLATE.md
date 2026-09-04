## What & why

<!-- What does this change do, and what problem does it solve? Link issues: Closes #123 -->

## Type of change

- [ ] Bug fix
- [ ] New tool / skill
- [ ] Refactor / internal
- [ ] Docs
- [ ] Breaking change

## Checklist

- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `pytest` passes locally
- [ ] I added/updated tests where it made sense
- [ ] Docs / `README.md` / `.env.example` updated if behaviour or config changed
- [ ] No secrets, API keys, or machine-specific paths committed

## Security & scope (Sleuth-specific)

- [ ] This change does **not** weaken a safety gate (`WEBSEARCH_BLOCK_PRIVATE`,
      `SLEUTH_ALLOW_EXEC`, `SLEUTH_ALLOW_SELF_EDIT`, `SLEUTH_ALLOW_ACTIVE_SKILLS`,
      auto-review) without a clear, opt-in rationale.
- [ ] Any new active/intrusive capability defaults to **off** and is documented.
