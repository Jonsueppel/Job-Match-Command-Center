# Contributing

Contributions are welcome. Keep changes focused, avoid committing personal job-search data, and include tests for scoring or persistence changes.

1. Fork the repository and create a feature branch.
2. Run `python -m unittest -v`.
3. Confirm `git status` contains no `.env`, database, resume, export, or backup files.
4. Open a pull request describing the behavior change and verification performed.

Source adapters should use documented feeds or APIs where possible, include timeouts, respect rate limits and site terms, and fail independently so one unavailable source does not stop a scan.
