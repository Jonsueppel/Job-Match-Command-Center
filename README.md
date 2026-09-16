# Job Match Command Center

A self-hosted job discovery and application-tracking app. Upload a resume, describe the roles you want, collect postings from multiple sources, rank them against your experience and preferences, and receive email alerts for the strongest matches.

## Features

- First-run setup for job titles, skills, location, salary, and exclusions
- PDF, DOCX, TXT, and Markdown resume extraction
- Resume-driven searches and configurable matching
- Editable and individually enabled job sources
- Date, location, salary, title, skill, and dealbreaker scoring
- Duplicate detection and remembered skipped/applied jobs
- Application pipeline, notes, follow-up dates, and CSV export
- Hourly scheduler plus a manual scan button
- Strong-match and digest emails
- Source-quality and operations dashboards
- Authentication, container health checks, verified backups, and SQLite WAL mode

## Quick Start

Requirements: Docker with Docker Compose.

```bash
git clone https://github.com/Jonsueppel/job-match-command-center.git
cd job-match-command-center
cp .env.example .env
```

Edit `.env` and set at least `APP_USERNAME` and a long random `APP_PASSWORD`, then start the app:

```bash
docker compose up -d --build
```

Open `http://localhost:8088`, sign in, complete the setup screen, and upload your resume.

## Email

SMTP credentials belong in `.env`, never in Git. For Gmail, create an app password instead of using the account password.

## Data And Backups

Runtime data is stored in `./data`, imports in `./imports`, and verified daily backups in `./backups`. These directories are intentionally excluded from Git. Backups are retained for 14 days by default.

## Security

The built-in login protects the Web UI, but plain HTTP should only be used on a trusted private network. Use Tailscale, Caddy, or another HTTPS reverse proxy before exposing the app outside your network. See [SECURITY.md](SECURITY.md).

## Tests

```bash
python -m unittest -v
```

## Job Sources

The app includes public feeds and configurable adapters for RSS, Greenhouse, Lever, Adzuna, USAJOBS, local CSV/JSON, and targeted web discovery. Users are responsible for complying with each source's terms and rate limits.

## License

MIT. See [LICENSE](LICENSE).
