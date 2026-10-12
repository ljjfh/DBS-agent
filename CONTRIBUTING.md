# Working on Star together

## Set up once

```bash
git clone https://github.com/ljjfh/DBS-agent.git && cd DBS-agent
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # works with no keys (offline rule model); add your own keys to use the real model
```

Never commit `.env` (it is in `.gitignore`). Share keys privately, not in the repo, issues or chat logs.

## Change, test, repeat

```bash
uvicorn app.server:app --reload --port 8000        # restarts by itself whenever you save a file
```

Open http://localhost:8000 (not 127.0.0.1 or a LAN IP: passkeys need `localhost` or HTTPS). Edit `web/app.js` or
`web/styles.css` and refresh the page; edit Python files and the server reloads. Before pushing:

```bash
python -m unittest discover tests      # must stay green
python eval/run_eval.py                # hard safety checks: no unsigned execution, every attack blocked
```

## One branch per task

```bash
git switch main && git pull
git switch -c feat/relative-amounts    # short, descriptive
# ... work, commit small steps ...
git push -u origin feat/relative-amounts
```

Open a pull request on GitHub. The tests run automatically on every pull request (GitHub Actions); merge when they
pass and a teammate has had a look. Merging to `main` redeploys the online demo.

- Pull `main` often (`git pull --rebase origin main` on your branch) so conflicts stay small.
- `app/agent/loop.py` and `web/app.js` are large shared files: keep changes there small and merge them quickly.
- New behaviour gets a test in `tests/` and, for conversations, a case in `eval/cases.json`.

## Testing on the online demo

Everyone can test the deployed link at the same time: each browser is its own demo customer, so your payments,
"Reset demo" and passkey never affect a teammate's. Use a private window to start as a fresh customer.
