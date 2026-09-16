# Security Policy

## Supported Version

Only the latest version on the default branch receives security fixes.

## Deployment

- Set `APP_USERNAME` and a unique, long `APP_PASSWORD` in `.env`.
- Never commit `.env`, `config.json`, databases, resumes, exports, or backups.
- Keep port 8088 private or place the app behind an authenticated HTTPS proxy.
- Use a dedicated SMTP app password with the minimum necessary access.
- Keep Docker, the base image, and host operating system updated.
- Test database restoration periodically.

## Reporting A Vulnerability

Do not open a public issue containing exploit details or personal data. Use the repository's private security-advisory feature to report vulnerabilities.
