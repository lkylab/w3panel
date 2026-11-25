"""
W3Panel v2 — Cron Jobs Automation Manager
Syncs scheduled tasks to system crontab files in /etc/cron.d/.
"""
import os
import re
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger('w3panel.cron')
CRON_D_DIR = Path('/etc/cron.d')

_CRON_FIELD_RE = re.compile(r'^[0-9*/,-]+$')


def is_valid_cron_schedule(schedule: str) -> bool:
    s = (schedule or '').strip()
    if not s or '\n' in s or '\r' in s:
        return False
    if s in ('@reboot', '@yearly', '@annually', '@monthly', '@weekly', '@daily', '@midnight', '@hourly'):
        return True
    parts = s.split()
    return len(parts) == 5 and all(_CRON_FIELD_RE.match(p) for p in parts)


def is_valid_cron_command(command: str) -> bool:
    c = (command or '').strip()
    return bool(c) and '\n' not in c and '\r' not in c and '\x00' not in c


def sync_cron_jobs(username: str, jobs) -> dict:
    """
    Sync all active cron jobs for a user into /etc/cron.d/w3panel_<username>.
    """
    from services.webserver.manager import _has_sudo, _write_privileged_file

    safe_user = re.sub(r'[^a-zA-Z0-9_-]', '', username or 'user')
    cron_dir = Path(os.environ.get('W3PANEL_CRON_DIR', str(CRON_D_DIR)))
    cron_file = cron_dir / f"w3panel_{safe_user}"
    lines = [
        f"# W3Panel automated cron jobs for {safe_user}",
        "SHELL=/bin/bash",
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
        ""
    ]

    for j in jobs:
        if j.is_active and is_valid_cron_schedule(j.schedule) and is_valid_cron_command(j.command):
            lines.append(f"{j.schedule.strip()} w3panel {j.command.strip()}")

    lines.append("")
    content = "\n".join(lines)

    try:
        if cron_dir.exists() and (_write_privileged_file(cron_file, content)):
            if os.geteuid() == 0:
                os.chmod(cron_file, 0o644)
            elif _has_sudo():
                subprocess.run(['sudo', '-n', 'chmod', '644', str(cron_file)], capture_output=True, timeout=5)
        return {'success': True, 'count': len(jobs)}
    except Exception as e:
        logger.warning(f"Could not write crontab file: {e}")
        return {'success': True, 'note': str(e)}
