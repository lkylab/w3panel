# Project Agent Guidelines

## Keep UI & Output Minimal
- **Do not add unrequested extra information**: avoid adding extra welcome banners, instructional subtitles, helper cards, badges, tooltips, or explanatory copy in templates/UI unless explicitly requested.
- Keep interfaces clean, direct, and limited to what the user asked for.
- In responses, stay concise and avoid extra commentary or suggestions that were not asked for.

## Never Trigger Local Host Password Prompts or Privileged Tests
- **Never run unmocked tests or commands on the user's local host machine** that invoke `sudo`, `systemctl`, `apt-get`, `crontab`, or other privileged OS commands (which can modify the host or trigger Polkit/sudo password prompts).
- When testing locally on the host, only run isolated/mocked tests (or `manage.py check`) that do not execute host-level system commands; run full system/integration tests inside the test VM (`w3panel-test`) instead.

