# Contributing to H4ACKBAR

## Ground Rules

1. **No offensive payloads targeting real vendors by name.** Generic
   variants only. Vendor-specific WAF bypasses are out of scope.
2. **No auto-exploit code.** Every network action stays behind a manual click.
3. **Every fix ships with a regression test.** No exceptions.
4. **Zero-warning build.** `ruff check .` and `pytest` must be green.

## Dev Setup

```bash
git clone https://github.com/YOUR_USER/H4ACKBAR.git
cd H4ACKBAR
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Workflow

```bash
git checkout -b feat/short-slug
# ... hack ...
ruff check --fix .
pytest -v
git commit -s -m "feat(chain): add utf-7 encoder"
git push origin feat/short-slug
```

Open a PR. CI must pass.

## Commit Convention

Conventional Commits (loosely):

```
feat(area):  new feature
fix(area):   bug fix
docs(area):  documentation only
test(area):  tests only
refactor(area): non-behavioral change
chore(area): tooling / build
```

Areas: `payloads`, `encoders`, `chain`, `sender`, `ui`, `ci`, `docs`.

## Adding a Payload

1. Pick the correct family in `h4ackbar/payloads.py`.
2. Append a `Payload(...)` with `label`, `payload`, `notes`.
3. Add a test in `tests/test_payloads.py` if the family gains a new pattern
   (e.g. a new DBMS covered).

## Adding an Encoder

1. Add `def enc_xxx(s: str) -> str:` in `h4ackbar/encoders.py`.
2. Register it in the `ENCODERS` dict.
3. Add a test in `tests/test_encoders.py` covering:
   - non-empty output on known seed
   - format invariant (prefix / structure)
   - reversibility if applicable

## Code Style

- Line length: 100 (payload literals may exceed — allowed).
- Type hints on all new public functions.
- Dataclasses over dicts for structured data.
- No `print()` — use `logging` or `QStatusBar`.
