"""
W3Panel v2 — Core Utilities
"""
import os
import shlex
import secrets
import subprocess
from django.http import HttpRequest


def get_client_ip(request: HttpRequest) -> str:
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def run_terminal_command(request: HttpRequest, cmd: str, default_cwd: str, session_key: str,
                         sudo_user: str = None, use_sudo: bool = False, timeout: int = 15,
                         home_dir: str = None) -> dict:
    """Execute a shell command while preserving working directory across requests."""
    current_cwd = request.session.get(session_key) or default_cwd
    marker = f"__W3P_CWD_{secrets.token_hex(8)}__"
    script = (
        f"cd {shlex.quote(current_cwd)} 2>/dev/null || cd {shlex.quote(default_cwd)}\n"
        f"{{\n{cmd}\n}}\n"
        f"__w3p_rc=$?\n"
        f"printf '\\n{marker}:%s' \"$PWD\"\n"
        f"exit $__w3p_rc"
    )

    if use_sudo and sudo_user:
        run_cmd = ['sudo', '-n', '-u', sudo_user, 'bash', '-c', script]
    elif use_sudo:
        run_cmd = ['sudo', '-n', 'bash', '-c', script]
    else:
        run_cmd = ['bash', '-c', script]

    res = subprocess.run(run_cmd, capture_output=True, text=True, timeout=timeout)
    stdout = res.stdout or ''
    new_cwd = current_cwd

    marker_prefix = f"{marker}:"
    idx = stdout.rfind(marker_prefix)
    if idx != -1:
        parsed = stdout[idx + len(marker_prefix):].splitlines()[0].strip()
        if parsed:
            new_cwd = parsed
            request.session[session_key] = new_cwd
        stdout = stdout[:idx]
        if stdout.endswith('\n'):
            stdout = stdout[:-1]

    display_cwd = new_cwd
    if home_dir:
        norm_home = os.path.normpath(home_dir)
        norm_cwd = os.path.normpath(new_cwd)
        if norm_cwd == norm_home:
            display_cwd = '~'
        elif norm_cwd.startswith(norm_home + os.sep):
            display_cwd = '~/' + norm_cwd[len(norm_home) + 1:]

    return {
        'stdout': stdout,
        'stderr': res.stderr,
        'returncode': res.returncode,
        'cwd': display_cwd,
    }
