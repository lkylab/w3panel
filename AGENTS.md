# Project Agent Guidelines

## Keep UI & Output Minimal
- **Do not add unrequested extra information**: avoid adding extra welcome banners, instructional subtitles, helper cards, badges, tooltips, or explanatory copy in templates/UI unless explicitly requested.
- Keep interfaces clean, direct, and limited to what the user asked for.
- In responses, stay concise and avoid extra commentary or suggestions that were not asked for.

## Never Trigger Local Host Password Prompts or Privileged Tests
- **Never run unmocked tests or commands on the user's local host machine** that invoke `sudo`, `systemctl`, `apt-get`, `crontab`, or other privileged OS commands (which can modify the host or trigger Polkit/sudo password prompts).
- When testing locally on the host, only run isolated/mocked tests (or `manage.py check`) that do not execute host-level system commands; run full system/integration tests inside the test VM (`w3panel-test`) instead.

## Do Deep Research — Never Decide Hypothetically
- **Never guess or make hypothetical design/implementation decisions**: verify exact file formats, system paths, service behavior, CLI flags, and codebase APIs through deep research (reading source files, OS configs, and authoritative documentation) before implementing.
- When something cannot be verified or has real gaps/limitations, report what is verified vs. missing instead of assuming it works.

## Security First
- **Always keep security and performance in focus** across coding, system setup, and updates.
- **Input & command safety**: use list-form `subprocess` calls (or `shlex.quote` for remote SSH commands), never pass secrets in CLI arguments (use environment variables or `0600` temp files), and validate archive/file paths against zip-slip and symlink traversal.
- **Service testability & path overrides**: use `_has_sudo()`, `_write_privileged_file()`, and `W3PANEL_*_DIR` environment overrides (e.g., `W3PANEL_USERS_DIR`, `W3PANEL_VHOST_DIR`, `W3PANEL_SSL_DIR`) in `services/*` so tests run isolated without touching `/etc/` or `/home/`.
- **SQLite-safe streaming**: avoid background threads that write to Django models during `StreamingHttpResponse` views; use synchronous generators on the request thread to prevent `database table is locked`.
- **Pre-commit verification**: run `./venv/bin/python manage.py check` and relevant isolated tests before committing or pushing.
