# AI Code & Security PR Reviewer

AI-powered Pull Request security review for GitHub. The FastAPI service verifies
webhooks, filters code diffs, uses Gemini structured output for AppSec analysis,
stores results in SQLite, and posts Markdown findings to pull requests. Streamlit
provides a live portfolio dashboard for repository and risk filtering.

## Features

- Constant-time HMAC SHA-256 webhook verification.
- Processing for `pull_request` actions `opened` and `synchronize`.
- Diff filtering for lockfiles, binary files, images, and unsupported assets.
- Gemini `gemini-2.5-flash` structured output for consistent findings.
- Detection guidance for secrets, injection, XSS, weak cryptography,
  authentication/authorization bugs, and logic flaws.
- SQLite scan history with pull request metadata and finding details.
- Markdown review comments posted to GitHub.
- Streamlit KPI cards, risk distribution, filters, history, and demo data.

## Architecture

```text
GitHub PR -> FastAPI webhook -> HMAC verification
                              -> GitHub diff fetch/filter
                              -> Gemini structured analysis
                              -> SQLite transaction
                              -> GitHub Markdown comment

Scanner SQLite <- Streamlit dashboard
```

The backend modules are:

- `app/main.py`: webhook endpoints and SQLite persistence.
- `app/config.py`: Pydantic Settings configuration.
- `app/github_client.py`: signature, diff, and GitHub REST integration.
- `app/analyzer.py`: Gemini structured security analysis.
- `app/models.py`: SQLModel and Pydantic schemas.
- `dashboard/app.py`: monitoring and demo experience.

## Local setup

Use Python 3.11 or newer.

```powershell
cd ai-pr-security-reviewer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
```

Fill `.env` with a Gemini API key, GitHub token, and webhook secret:

```text
GEMINI_API_KEY=your-key
GITHUB_TOKEN=github_pat_or_fine_grained_token
GITHUB_WEBHOOK_SECRET=your-random-secret
```

Start FastAPI:

```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Start Streamlit in a second terminal:

```powershell
streamlit run dashboard/app.py
```

Open:

- API documentation: `http://localhost:8000/docs`
- Scan API: `http://localhost:8000/api/scans`
- Dashboard: `http://localhost:8501`

If `scanner.db` is empty, use **Load Sample Audit Data** in the dashboard.

## Run tests

```powershell
pytest -q
```

## Test a GitHub webhook locally with smee.io

1. Create or open a channel at <https://smee.io/>.
2. Install and run the relay:

   ```powershell
   npm install --global smee-client
   smee --url https://smee.io/YOUR_CHANNEL --target http://localhost:8000/webhook/github
   ```

3. In a GitHub repository, open **Settings -> Webhooks -> Add webhook**.
4. Set the payload URL to the smee channel URL.
5. Set content type to `application/json`.
6. Set the secret to the exact value in `GITHUB_WEBHOOK_SECRET`.
7. Select **Let me select individual events**, then choose **Pull requests**.
8. Open or synchronize a pull request to exercise the system.

The webhook receiver rejects mismatched signatures before parsing or processing
the payload.

## Deployment

### Render

Create a Python Web Service from this repository:

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Add `GEMINI_API_KEY`, `GITHUB_TOKEN`, and `GITHUB_WEBHOOK_SECRET` as environment
  variables.
- Run a separate Streamlit service with:
  `streamlit run dashboard/app.py --server.port $PORT --server.address 0.0.0.0`

Use persistent storage or replace SQLite with a managed database for multiple
instances and restarts. The MVP is designed for a single application process.

### Azure App Service

Deploy the FastAPI service as a Linux Python Web App and set startup command:

```text
gunicorn -w 2 -k uvicorn.workers.UvicornWorker app.main:app
```

Configure the same environment variables in App Service settings, attach persistent
storage if SQLite must survive restarts, and expose the Streamlit dashboard as a
separate App Service or Container App.

Configure the public FastAPI URL plus `/webhook/github` as the GitHub webhook
payload URL. Rotate all credentials if an `.env` or deployment log was exposed.

## Security notes

- No credentials are stored in source files or the sample configuration.
- The webhook secret is never logged.
- GitHub and Gemini credentials are loaded only through Pydantic Settings.
- Add the GitHub token with minimum repository pull-read and issue-write permissions.
- Review generated findings before applying security changes.
