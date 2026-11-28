"""
W3Panel v2 — Mail Stack Automation Manager
Manages Postfix virtual domains/mailboxes/aliases/catch-alls, Dovecot Maildir/quotas/Sieve/master-auth,
OpenDKIM 2048-bit RSA signing, Rspamd/SpamAssassin filtering, mail queue/delivery tracking,
DNS email deliverability (MX/SPF/DKIM/DMARC), and SnappyMail webmail + 1-click SSO.
"""
import hashlib
import http.client
import json
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import urllib.parse
import urllib.request
import warnings
import zipfile
from datetime import datetime
from http.cookies import SimpleCookie
from pathlib import Path

logger = logging.getLogger('w3panel.mail')

VMAIL_BASE = Path('/var/vmail')
POSTFIX_DIR = Path('/etc/postfix')
DOVECOT_DIR = Path('/etc/dovecot')

_SAFE_DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')
_SAFE_LOCAL_RE = re.compile(r'^[a-z0-9._+-]+$')
_W3P_BLOCK_START = '# BEGIN W3PANEL MAIL'
_W3P_BLOCK_END = '# END W3PANEL MAIL'
_SNAPPYMAIL_LATEST_API = 'https://api.github.com/repos/the-djmaze/snappymail/releases/latest'


def _has_sudo() -> bool:
    """Check if passwordless sudo is available."""
    try:
        from services.webserver.manager import _has_sudo as ws_has_sudo
        return ws_has_sudo()
    except Exception:
        return False


def _priv_prefix() -> list[str]:
    return [] if os.geteuid() == 0 else ['sudo', '-n']


def _write_privileged(path: Path, content: str) -> bool:
    """Write text file using privileged helper or direct fallback."""
    from services.webserver.manager import _write_privileged_file
    return _write_privileged_file(path, content)


def _remove_privileged(path: Path) -> bool:
    from services.webserver.manager import _remove_privileged_file
    return _remove_privileged_file(path)


def _read_text_privileged(path: Path) -> str:
    try:
        if path.exists():
            return path.read_text(errors='replace')
    except (PermissionError, OSError):
        if _has_sudo():
            res = subprocess.run(['sudo', '-n', 'cat', str(path)], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return res.stdout
    return ''


def _mkdir_privileged(path: Path) -> bool:
    """Create directory directly or escalate via sudo -n mkdir -p when permitted."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        return True
    except (PermissionError, OSError):
        if not _has_sudo():
            return False
        try:
            res = subprocess.run(_priv_prefix() + ['mkdir', '-p', str(path)], capture_output=True, timeout=5)
            return res.returncode == 0
        except Exception:
            return False


def _path_exists_privileged(path: Path) -> bool:
    try:
        if path.exists():
            return True
    except (PermissionError, OSError):
        pass
    if _has_sudo():
        try:
            return subprocess.run(_priv_prefix() + ['test', '-e', str(path)], capture_output=True, timeout=3).returncode == 0
        except Exception:
            return False
    return False


def _resolve_dir(env_key: str, default_path: Path, fallback_path: Path, create: bool = True) -> Path:
    env_dir = os.environ.get(env_key)
    if env_dir:
        p = Path(env_dir)
        if create:
            p.mkdir(parents=True, exist_ok=True)
        return p
    if default_path.exists() and (os.geteuid() == 0 or os.access(str(default_path), os.W_OK) or _has_sudo()):
        return default_path
    if os.geteuid() == 0 or (default_path.parent.exists() and os.access(str(default_path.parent), os.W_OK)):
        if create:
            default_path.mkdir(parents=True, exist_ok=True)
        return default_path
    if _has_sudo():
        if not create or _mkdir_privileged(default_path):
            return default_path
    if create:
        fallback_path.mkdir(parents=True, exist_ok=True)
    return fallback_path


def _get_vmail_base() -> Path:
    return _resolve_dir('W3PANEL_VMAIL_BASE', VMAIL_BASE, Path('/tmp/w3panel/vmail'))


def _get_postfix_dir() -> Path:
    return _resolve_dir('W3PANEL_POSTFIX_DIR', POSTFIX_DIR, Path('/tmp/w3panel/postfix'))


def _get_dovecot_dir() -> Path:
    return _resolve_dir('W3PANEL_DOVECOT_DIR', DOVECOT_DIR, Path('/tmp/w3panel/dovecot'))


def _get_opendkim_dir() -> Path:
    return _resolve_dir('W3PANEL_OPENDKIM_DIR', Path('/etc/opendkim/keys'), Path('/tmp/w3panel/opendkim/keys'))


def _get_opendkim_conf_dir() -> Path:
    return _resolve_dir('W3PANEL_OPENDKIM_CONF_DIR', Path('/etc/opendkim'), Path('/tmp/w3panel/opendkim'))


def _get_opendkim_conf_file() -> Path:
    env_file = os.environ.get('W3PANEL_OPENDKIM_CONF_FILE')
    if env_file:
        return Path(env_file)
    default_f = Path('/etc/opendkim.conf')
    if default_f.parent.exists() and (os.access(str(default_f.parent), os.W_OK) or _has_sudo()):
        return default_f
    return Path('/tmp/w3panel/opendkim.conf')


def _get_rspamd_dir() -> Path:
    return _resolve_dir('W3PANEL_RSPAMD_DIR', Path('/etc/rspamd/local.d'), Path('/tmp/w3panel/rspamd/local.d'))


def _get_webmail_dir() -> Path:
    env_dir = os.environ.get('W3PANEL_WEBMAIL_DIR')
    if env_dir:
        return Path(env_dir)
    default_dir = Path('/var/lib/w3panel/webmail')
    if (default_dir / 'index.php').exists() or os.geteuid() == 0 or _has_sudo() or os.access('/var/lib/w3panel', os.W_OK):
        return default_dir
    return Path('/tmp/w3panel/webmail')


def _get_etc_w3panel_dir() -> Path:
    return _resolve_dir('W3PANEL_ETC_DIR', Path('/etc/w3panel'), Path('/tmp/w3panel/etc'))


def _get_ssl_dir() -> Path:
    return _resolve_dir('W3PANEL_SSL_DIR', Path('/etc/w3panel/ssl'), Path('/tmp/w3panel/ssl'))


def _get_mail_log_path() -> Path:
    env_log = os.environ.get('W3PANEL_MAIL_LOG')
    if env_log:
        return Path(env_log)
    return Path('/var/log/mail.log')


def _is_valid_email(email: str) -> bool:
    if not email or '@' not in email or any(c in email for c in ('\r', '\n', '\x00', ' ', '\t', ':', ';', '"', "'")):
        return False
    local, dom = email.strip().lower().split('@', 1)
    return bool(_SAFE_LOCAL_RE.match(local) and _SAFE_DOMAIN_RE.match(dom))


def _is_valid_domain(domain: str) -> bool:
    if not domain or any(c in domain for c in ('\r', '\n', '\x00', ' ', '\t')):
        return False
    return bool(_SAFE_DOMAIN_RE.match(domain.strip().lower()))


def _run_postmap(map_file: Path):
    if not map_file.exists():
        return
    if shutil.which('postmap') and (os.geteuid() == 0 or _has_sudo()):
        cmd = _priv_prefix() + ['postmap', str(map_file)]
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception as e:
            logger.warning(f"postmap error for {map_file}: {e}")


def _upsert_managed_block(existing: str, block_body: str) -> str:
    """Replace or append the W3PANEL managed block idempotently."""
    lines = existing.splitlines()
    out = []
    skipping = False
    for line in lines:
        if line.strip() == _W3P_BLOCK_START:
            skipping = True
            continue
        if line.strip() == _W3P_BLOCK_END:
            skipping = False
            continue
        if not skipping:
            out.append(line)
    cleaned = "\n".join(out).rstrip()
    managed = f"{_W3P_BLOCK_START}\n{block_body.rstrip()}\n{_W3P_BLOCK_END}\n"
    if cleaned:
        return cleaned + "\n\n" + managed
    return managed


def _upsert_postfix_main_block(existing: str, block_lines: list[str]) -> str:
    """Comment out duplicate stock assignments outside our managed block to avoid Postfix override warnings."""
    managed_keys = {
        ln.split('=', 1)[0].strip()
        for ln in block_lines
        if '=' in ln
    }
    in_block = False
    filtered_lines = []
    for line in existing.splitlines():
        stripped = line.strip()
        if stripped == _W3P_BLOCK_START:
            in_block = True
        elif stripped == _W3P_BLOCK_END:
            in_block = False
        elif not in_block and line and not line[0].isspace() and not stripped.startswith('#') and '=' in line:
            key = line.split('=', 1)[0].strip()
            if key in managed_keys:
                filtered_lines.append(f"# {line}")
                continue
        filtered_lines.append(line)
    return _upsert_managed_block("\n".join(filtered_lines), "\n".join(block_lines))


def _ensure_vmail_system_user() -> tuple[int, int]:
    """Ensure dedicated virtual mail system user/group (vmail, uid/gid 5000)."""
    import grp
    import pwd
    uid, gid = 5000, 5000
    try:
        gid = grp.getgrnam('vmail').gr_gid
    except KeyError:
        if os.geteuid() == 0 or _has_sudo():
            subprocess.run(_priv_prefix() + ['groupadd', '-g', '5000', 'vmail'], capture_output=True, timeout=5)
            try:
                gid = grp.getgrnam('vmail').gr_gid
            except KeyError:
                pass
    try:
        uid = pwd.getpwnam('vmail').pw_uid
    except KeyError:
        if os.geteuid() == 0 or _has_sudo():
            subprocess.run(
                _priv_prefix() + ['useradd', '-g', str(gid), '-u', '5000', 'vmail', '-d', str(VMAIL_BASE), '-m', '-s', '/usr/sbin/nologin'],
                capture_output=True,
                timeout=5,
            )
            try:
                uid = pwd.getpwnam('vmail').pw_uid
            except KeyError:
                pass
    return uid, gid


def hash_mailbox_password(password: str) -> str:
    """Generate SHA512-CRYPT (or ARGON2ID fallback) password hash suitable for Dovecot."""
    if not password:
        raise ValueError('Password cannot be empty')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            import crypt
        salt = crypt.mksalt(crypt.METHOD_SHA512)
        hashed = crypt.crypt(password, salt)
        if hashed and hashed.startswith('$6$'):
            return f"{{SHA512-CRYPT}}{hashed}"
    except Exception:
        pass

    if shutil.which('openssl'):
        try:
            res = subprocess.run(
                ['openssl', 'passwd', '-6', '-stdin'],
                input=password + '\n',
                capture_output=True,
                text=True,
                timeout=5,
            )
            out = res.stdout.strip()
            if res.returncode == 0 and out.startswith('$6$'):
                return f"{{SHA512-CRYPT}}{out}"
        except Exception:
            pass

    from argon2 import PasswordHasher
    return f"{{ARGON2ID}}{PasswordHasher().hash(password)}"


def _format_dovecot_user_entry(email: str, dovecot_hash: str, home_path: str, quota_mb: int = 1024) -> str:
    quota_val = max(1, int(quota_mb or 1024))
    return f"{email}:{dovecot_hash}:5000:5000::{home_path}::userdb_mail=maildir:{home_path} userdb_quota_rule=*:storage={quota_val}M"


def _get_mailbox_quota_mb(email: str, default: int = 1024) -> int:
    try:
        from packages.core.models import Mailbox
        q = Mailbox.objects.filter(email=email).values_list('quota_mb', flat=True).first()
        if q and int(q) > 0:
            return int(q)
    except Exception:
        pass
    try:
        users_file = _get_dovecot_dir() / 'users'
        for line in _read_text_privileged(users_file).splitlines():
            if line.startswith(f"{email}:"):
                m = re.search(r'userdb_quota_rule=\*:storage=(\d+)M', line)
                if m:
                    return int(m.group(1))
    except Exception:
        pass
    return default


def sync_virtual_domains(extra_domains: list[str] | None = None) -> dict:
    """Sync Postfix vmailbox_domains from Websites, Mailboxes, Forwarders, CatchAlls, and extra_domains."""
    domains: set[str] = set()
    for d in (extra_domains or []):
        if _is_valid_domain(d):
            domains.add(d.strip().lower())

    try:
        from packages.core.models import Website, Mailbox, EmailForwarder, EmailCatchAll
        for d in Website.objects.filter(is_active=True).values_list('domain', flat=True):
            if _is_valid_domain(d):
                domains.add(d.strip().lower())
        for d in Mailbox.objects.filter(is_active=True).values_list('domain', flat=True):
            if _is_valid_domain(d):
                domains.add(d.strip().lower())
        for d in EmailForwarder.objects.filter(is_active=True).values_list('domain', flat=True):
            if _is_valid_domain(d):
                domains.add(d.strip().lower())
        for d in EmailCatchAll.objects.filter(is_active=True).values_list('domain', flat=True):
            if _is_valid_domain(d):
                domains.add(d.strip().lower())
    except Exception:
        pass

    postfix_dir = _get_postfix_dir()
    dom_file = postfix_dir / 'vmailbox_domains'
    existing_lines = _read_text_privileged(dom_file).splitlines()
    for line in existing_lines:
        tok = line.strip().split()
        if tok and not line.strip().startswith('#') and _is_valid_domain(tok[0]):
            domains.add(tok[0].lower())

    content = "".join(f"{dom} OK\n" for dom in sorted(domains))
    _write_privileged(dom_file, content)
    _run_postmap(dom_file)
    return {'success': True, 'domains': sorted(domains), 'path': str(dom_file)}


def set_mailbox_password(email: str, password: str, maildir: str = '', quota_mb: int | None = None) -> dict:
    """Set plain password for a mailbox by hashing and updating Dovecot users."""
    if not password:
        return {'success': False, 'error': 'Password cannot be empty'}
    pw_hash = hash_mailbox_password(password)
    effective_quota = quota_mb if quota_mb is not None else _get_mailbox_quota_mb(email.strip().lower(), 1024)
    return set_mailbox_password_hash(email, pw_hash, maildir=maildir, quota_mb=effective_quota)


def update_mailbox_quota(email: str, quota_mb: int) -> dict:
    """Update per-mailbox Dovecot userdb_quota_rule in users file without disturbing password hash."""
    email = email.strip().lower()
    if not _is_valid_email(email):
        return {'success': False, 'error': 'Invalid email format'}
    quota_val = max(1, int(quota_mb or 1024))
    users_file = _get_dovecot_dir() / 'users'
    existing = _read_text_privileged(users_file).splitlines()
    updated = []
    found = False
    mbox_user, domain = email.split('@', 1)
    default_home = str(_get_vmail_base() / domain / mbox_user)
    for line in existing:
        if line.startswith(f"{email}:"):
            parts = line.split(':')
            pw_hash = parts[1] if len(parts) > 1 else '{CRYPT}!'
            home_path = parts[5] if len(parts) > 5 and parts[5] else default_home
            updated.append(_format_dovecot_user_entry(email, pw_hash, home_path, quota_val))
            found = True
        else:
            updated.append(line)
    if found:
        _write_dovecot_passwd_file(users_file, "\n".join(updated) + "\n")
        _reload_mail_services()
    return {'success': True, 'updated': found, 'quota_mb': quota_val}


def create_mailbox(email: str, password: str = '', quota_mb: int = 1024) -> dict:
    """
    Create virtual mailbox, Maildir structure, Postfix virtual tables, Dovecot credentials/quota, and DKIM keys.
    """
    email = (email or '').strip().lower()
    if not _is_valid_email(email):
        return {'success': False, 'error': 'Invalid email format'}

    mbox_user, domain = email.split('@', 1)
    base_vmail = _get_vmail_base()
    quota_val = max(1, int(quota_mb or 1024))

    # 1. Create Maildir + sieve storage directory
    maildir = base_vmail / domain / mbox_user
    if not all(_mkdir_privileged(maildir / folder) for folder in ('cur', 'new', 'tmp', 'sieve')):
        logger.warning(f"Could not create vmail structure under {maildir}, using /tmp fallback")
        maildir = Path(f"/tmp/w3panel/vmail/{domain}/{mbox_user}")
        for folder in ('cur', 'new', 'tmp', 'sieve'):
            (maildir / folder).mkdir(parents=True, exist_ok=True)

    if os.geteuid() == 0 or _has_sudo():
        _ensure_vmail_system_user()
        subprocess.run(_priv_prefix() + ['chown', '-R', '5000:5000', str(maildir.parent)], capture_output=True, timeout=5)

    # 2. Register virtual domain & configure Postfix Virtual Mailbox
    sync_virtual_domains([domain])
    postfix_dir = _get_postfix_dir()
    try:
        vmailbox_file = postfix_dir / 'vmailbox'
        entry = f"{email} {domain}/{mbox_user}/\n"
        lines = _read_text_privileged(vmailbox_file).splitlines()
        filtered = [l for l in lines if not l.strip().startswith(f"{email} ")]
        filtered.append(entry.rstrip('\n'))
        _write_privileged(vmailbox_file, "\n".join(filtered) + "\n")
        _run_postmap(vmailbox_file)
    except Exception as e:
        logger.warning(f"Postfix vmailbox update error: {e}")

    # 3. Set password + quota in Dovecot users if provided
    if password:
        set_mailbox_password(email, password, maildir=str(maildir), quota_mb=quota_val)

    # 4. Generate OpenDKIM RSA Key & DNS TXT Record
    dkim_txt_record = _setup_dkim(domain)

    # 5. Reload Postfix / Dovecot if active
    _reload_mail_services()

    return {
        'success': True,
        'email': email,
        'maildir': str(maildir),
        'dkim_record': dkim_txt_record,
    }


def delete_mailbox(email: str) -> dict:
    """Delete mailbox from Postfix virtual tables, Dovecot users, and Sieve scripts."""
    email = (email or '').strip().lower()
    if not email or '@' not in email:
        return {'success': False, 'error': 'Invalid email'}

    # 1. Remove from Postfix vmailbox
    try:
        postfix_dir = _get_postfix_dir()
        vmailbox_file = postfix_dir / 'vmailbox'
        if vmailbox_file.exists():
            lines = _read_text_privileged(vmailbox_file).splitlines()
            new_lines = [l for l in lines if not l.strip().startswith(f"{email} ")]
            content = "\n".join(new_lines) + ("\n" if new_lines else "")
            _write_privileged(vmailbox_file, content)
            _run_postmap(vmailbox_file)
    except Exception as e:
        logger.warning(f"Postfix delete error for {email}: {e}")

    # 2. Remove from Dovecot users
    try:
        dovecot_dir = _get_dovecot_dir()
        users_file = dovecot_dir / 'users'
        if users_file.exists():
            lines = _read_text_privileged(users_file).splitlines()
            new_lines = [l for l in lines if not l.strip().startswith(f"{email}:")]
            content = "\n".join(new_lines) + ("\n" if new_lines else "")
            _write_dovecot_passwd_file(users_file, content)
    except Exception as e:
        logger.warning(f"Dovecot user delete error for {email}: {e}")

    # 3. Remove active sieve script
    remove_mailbox_sieve(email)

    _reload_mail_services()
    return {'success': True}


def set_mailbox_password_hash(email: str, pw_hash: str, maildir: str = '', quota_mb: int | None = None) -> dict:
    """Persist an existing crypt/Dovecot password hash and quota for a mailbox."""
    if not _is_valid_email(email) or not pw_hash or '\n' in pw_hash or '\r' in pw_hash:
        return {'success': False, 'error': 'Valid email and hash required'}

    email = email.strip().lower()
    mbox_user, domain = email.split('@', 1)
    dovecot_hash = pw_hash if pw_hash.startswith('{') else f'{{CRYPT}}{pw_hash}'
    home_path = maildir or str(_get_vmail_base() / domain / mbox_user)
    effective_quota = quota_mb if quota_mb is not None else _get_mailbox_quota_mb(email, 1024)
    entry = _format_dovecot_user_entry(email, dovecot_hash, home_path, quota_mb=effective_quota)

    target_dir = _get_dovecot_dir()
    try:
        users_file = target_dir / 'users'
        existing = _read_text_privileged(users_file).splitlines()
        filtered = [l for l in existing if not l.startswith(f"{email}:")]
        filtered.append(entry)
        content = "\n".join(filtered) + "\n"
        _write_dovecot_passwd_file(users_file, content)
        _reload_mail_services()
        return {'success': True, 'path': str(users_file)}
    except Exception as e:
        logger.warning(f"Could not write Dovecot users hash for {email}: {e}")
        return {'success': False, 'error': str(e)}


def create_mail_alias(source_email: str, destinations: list[str]) -> dict:
    """Register Postfix virtual alias/forwarder."""
    source_email = (source_email or '').strip().lower()
    if not _is_valid_email(source_email) or not destinations:
        return {'success': False, 'error': 'Valid source email and destinations required'}

    clean_dests = [d.strip().lower() for d in destinations if _is_valid_email(d.strip().lower())]
    if not clean_dests:
        return {'success': False, 'error': 'No valid destination email addresses'}
    dest_str = ", ".join(clean_dests)
    domain = source_email.split('@', 1)[1]
    sync_virtual_domains([domain])

    target_dir = _get_postfix_dir()
    try:
        virtual_file = target_dir / 'virtual'
        existing = _read_text_privileged(virtual_file).splitlines()
        filtered = [l for l in existing if not l.startswith(f"{source_email} ")]
        filtered.append(f"{source_email} {dest_str}")
        _write_privileged(virtual_file, "\n".join(filtered) + "\n")
        _run_postmap(virtual_file)
        _reload_mail_services()
        return {'success': True, 'path': str(virtual_file)}
    except Exception as e:
        logger.warning(f"Could not write Postfix virtual alias for {source_email}: {e}")
        return {'success': False, 'error': str(e)}


def delete_mail_alias(source_email: str) -> dict:
    """Remove Postfix virtual alias/forwarder."""
    if not source_email:
        return {'success': False, 'error': 'Source email required'}

    source_email = source_email.strip().lower()
    target_dir = _get_postfix_dir()
    try:
        virtual_file = target_dir / 'virtual'
        if virtual_file.exists():
            existing = _read_text_privileged(virtual_file).splitlines()
            filtered = [l for l in existing if not l.startswith(f"{source_email} ")]
            content = "\n".join(filtered) + ("\n" if filtered else "")
            _write_privileged(virtual_file, content)
            _run_postmap(virtual_file)
            _reload_mail_services()
        return {'success': True}
    except Exception as e:
        logger.warning(f"Could not delete Postfix virtual alias for {source_email}: {e}")
        return {'success': False, 'error': str(e)}


def set_domain_catchall(domain: str, action: str, destination: str = '') -> dict:
    """Configure domain catch-all (Default Address) in Postfix virtual alias map."""
    domain = (domain or '').strip().lower()
    if not _is_valid_domain(domain):
        return {'success': False, 'error': 'Invalid domain'}
    if action not in ('forward', 'discard', 'fail'):
        return {'success': False, 'error': 'Invalid catch-all action'}

    dest_clean = (destination or '').strip().lower()
    if action == 'forward' and not _is_valid_email(dest_clean):
        return {'success': False, 'error': 'Valid destination email required for forwarding'}

    sync_virtual_domains([domain])
    virtual_file = _get_postfix_dir() / 'virtual'
    key_prefix = f"@{domain} "
    try:
        existing = _read_text_privileged(virtual_file).splitlines()
        filtered = [l for l in existing if not l.startswith(key_prefix)]
        if action == 'forward':
            filtered.append(f"@{domain} {dest_clean}")
        elif action == 'discard':
            # Ensure local devnull alias routes to /dev/null when privileged
            aliases_path = _get_postfix_dir().parent / 'aliases' if _get_postfix_dir() == POSTFIX_DIR else _get_postfix_dir() / 'aliases'
            aliases_txt = _read_text_privileged(aliases_path)
            if 'devnull:' not in aliases_txt:
                new_aliases = (aliases_txt.rstrip() + '\n' if aliases_txt.strip() else '') + 'devnull: /dev/null\n'
                _write_privileged(aliases_path, new_aliases)
                if shutil.which('newaliases') and (os.geteuid() == 0 or _has_sudo()):
                    subprocess.run(_priv_prefix() + ['newaliases'], capture_output=True, timeout=5)
            filtered.append(f"@{domain} devnull@localhost")
        # For 'fail', omission of @domain lets Postfix reject unknown virtual recipients at RCPT TO (550 5.1.1)
        content = "\n".join(filtered) + ("\n" if filtered else "")
        _write_privileged(virtual_file, content)
        _run_postmap(virtual_file)
        _reload_mail_services()
        return {'success': True, 'path': str(virtual_file)}
    except Exception as e:
        logger.warning(f"Catch-all configuration error for {domain}: {e}")
        return {'success': False, 'error': str(e)}


def delete_domain_catchall(domain: str) -> dict:
    return set_domain_catchall(domain, 'fail')


def _escape_sieve_str(val: str) -> str:
    return (val or '').replace('\\', '\\\\').replace('"', '\\"')


def sync_mailbox_sieve(
    email: str,
    subject: str,
    body: str,
    interval_hours: int = 24,
    start_date=None,
    end_date=None,
    is_active: bool = True,
) -> dict:
    """Write or remove Dovecot Pigeonhole vacation Sieve script for a mailbox."""
    email = (email or '').strip().lower()
    if not _is_valid_email(email):
        return {'success': False, 'error': 'Invalid email address'}

    if not is_active:
        return remove_mailbox_sieve(email)

    mbox_user, domain = email.split('@', 1)
    maildir = _get_vmail_base() / domain / mbox_user
    sieve_file = maildir / '.dovecot.sieve'

    hours = max(1, int(interval_hours or 24))
    seconds = hours * 3600
    safe_subj = _escape_sieve_str(subject.strip())
    safe_body = _escape_sieve_str(body.strip())
    safe_addr = _escape_sieve_str(email)

    reqs = ['"vacation"', '"vacation-seconds"']
    conds = []
    if start_date is not None:
        s_iso = start_date.strftime('%Y-%m-%dT%H:%M:%S+00:00') if isinstance(start_date, datetime) else str(start_date)
        conds.append(f'currentdate :value "ge" "iso8601" "{_escape_sieve_str(s_iso)}"')
    if end_date is not None:
        e_iso = end_date.strftime('%Y-%m-%dT%H:%M:%S+00:00') if isinstance(end_date, datetime) else str(end_date)
        conds.append(f'currentdate :value "le" "iso8601" "{_escape_sieve_str(e_iso)}"')
    if conds:
        reqs.extend(['"date"', '"relational"'])

    vacation_stmt = (
        f'vacation\n'
        f'  :seconds {seconds}\n'
        f'  :addresses ["{safe_addr}"]\n'
        f'  :subject "{safe_subj}"\n'
        f'  "{safe_body}";\n'
    )
    if conds:
        cond_expr = f'allof ({", ".join(conds)})' if len(conds) > 1 else conds[0]
        indented = "\n".join(f"  {ln}" if ln else "" for ln in vacation_stmt.splitlines())
        script = f'require [{", ".join(reqs)}];\nif {cond_expr} {{\n{indented}\n}}\n'
    else:
        script = f'require [{", ".join(reqs)}];\n{vacation_stmt}'

    try:
        _mkdir_privileged(maildir / 'sieve')
        _write_privileged(sieve_file, script)
        if os.geteuid() == 0 or _has_sudo():
            subprocess.run(_priv_prefix() + ['chown', '-R', '5000:5000', str(maildir)], capture_output=True, timeout=5)
        return {'success': True, 'path': str(sieve_file)}
    except Exception as e:
        logger.warning(f"Failed writing sieve script for {email}: {e}")
        return {'success': False, 'error': str(e)}


def remove_mailbox_sieve(email: str) -> dict:
    """Remove Dovecot Sieve vacation script for a mailbox."""
    email = (email or '').strip().lower()
    if '@' not in email:
        return {'success': False, 'error': 'Invalid email'}
    mbox_user, domain = email.split('@', 1)
    sieve_file = _get_vmail_base() / domain / mbox_user / '.dovecot.sieve'
    _remove_privileged(sieve_file)
    return {'success': True}


def get_mail_queue() -> dict:
    """Get Postfix mail queue statistics and messages via postqueue -p."""
    can_exec = _has_sudo() or os.geteuid() == 0
    messages_list = []
    total_count = 0
    is_empty = True

    if can_exec and shutil.which('postqueue'):
        cmd = _priv_prefix() + ['postqueue', '-p']
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            output = res.stdout.strip()
            if "Mail queue is empty" in output or not output:
                is_empty = True
            else:
                is_empty = False
                for line in output.splitlines():
                    line = line.strip()
                    if line and not line.startswith('-') and not line.startswith('Mail queue'):
                        parts = line.split()
                        if len(parts) >= 4 and not line.startswith('('):
                            messages_list.append({
                                'id': parts[0].replace('*', '').replace('!', ''),
                                'size': parts[1] if len(parts) > 1 else '0',
                                'sender': parts[-1] if len(parts) > 3 else 'unknown',
                                'status': 'held' if '!' in parts[0] else ('active' if '*' in parts[0] else 'deferred'),
                            })
                total_count = len(messages_list)
        except Exception as e:
            logger.warning(f"Error checking mail queue: {e}")

    return {
        'empty': is_empty or total_count == 0,
        'count': total_count,
        'messages': messages_list,
    }


def flush_mail_queue() -> dict:
    """Flush pending messages in Postfix queue with postqueue -f."""
    if not (_has_sudo() or os.geteuid() == 0) or not shutil.which('postqueue'):
        return {'success': True, 'flushed': False, 'message': 'Mail queue flush simulated (offline/mock mode)'}
    cmd = _priv_prefix() + ['postqueue', '-f']
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {'success': res.returncode == 0, 'output': res.stdout or res.stderr}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def delete_mail_queue(message_id: str = 'ALL') -> dict:
    """Delete messages from Postfix queue with postsuper -d."""
    if not (_has_sudo() or os.geteuid() == 0) or not shutil.which('postsuper'):
        return {'success': True, 'deleted': False, 'message': 'Mail queue delete simulated'}
    safe_id = 'ALL' if message_id == 'ALL' else ''.join(c for c in message_id if c.isalnum())
    if not safe_id:
        return {'success': False, 'error': 'Invalid queue ID'}
    cmd = _priv_prefix() + ['postsuper', '-d', safe_id]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {'success': res.returncode == 0}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_mail_delivery_log(limit: int = 100, domain_filter: str = '') -> list[dict]:
    """Parse Postfix mail.log / journald lines into Track Delivery events."""
    raw_lines: list[str] = []
    log_path = _get_mail_log_path()
    if log_path.exists():
        txt = _read_text_privileged(log_path)
        raw_lines = txt.splitlines()[-2000:]
    elif (_has_sudo() or os.geteuid() == 0) and shutil.which('journalctl'):
        try:
            res = subprocess.run(
                _priv_prefix() + ['journalctl', '-u', 'postfix', '-n', '500', '--no-pager'],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode == 0:
                raw_lines = res.stdout.splitlines()
        except Exception:
            pass

    senders_by_qid: dict[str, str] = {}
    events: list[dict] = []
    from_re = re.compile(r'postfix/qmgr\[\d+\]:\s+([A-F0-9]+):\s+from=<([^>]*)>')
    to_re = re.compile(r'postfix/(?:smtp|lmtp|local|virtual|pipe)\[\d+\]:\s+([A-F0-9]+):\s+to=<([^>]*)>.*?status=(\w+)\s*\(([^)]*)\)?')
    reject_re = re.compile(r'postfix/smtpd\[\d+\]:\s+NOQUEUE:\s+reject:\s+.*?:([^;]+);\s*(?:from=<([^>]*)>)?\s*(?:to=<([^>]*)>)?')

    for line in raw_lines:
        ts = ' '.join(line.split()[:3]) if len(line.split()) >= 3 else ''
        m_from = from_re.search(line)
        if m_from:
            senders_by_qid[m_from.group(1)] = m_from.group(2) or '<>'
            continue
        m_to = to_re.search(line)
        if m_to:
            qid, rcpt, status, detail = m_to.group(1), m_to.group(2), m_to.group(3).lower(), m_to.group(4)
            sender = senders_by_qid.get(qid, '-')
            if domain_filter and not (rcpt.endswith(f'@{domain_filter}') or sender.endswith(f'@{domain_filter}')):
                continue
            events.append({
                'timestamp': ts,
                'queue_id': qid,
                'sender': sender,
                'recipient': rcpt,
                'status': status,
                'detail': detail[:160],
            })
            continue
        m_rej = reject_re.search(line)
        if m_rej:
            detail, sender, rcpt = m_rej.group(1).strip(), (m_rej.group(2) or '-'), (m_rej.group(3) or '-')
            if domain_filter and not (rcpt.endswith(f'@{domain_filter}') or sender.endswith(f'@{domain_filter}')):
                continue
            events.append({
                'timestamp': ts,
                'queue_id': 'NOQUEUE',
                'sender': sender,
                'recipient': rcpt,
                'status': 'rejected',
                'detail': detail[:160],
            })

    events.reverse()
    return events[:limit]


def get_mail_stats() -> dict:
    """Return delivery, sent, received, queue, and feature counts for reports."""
    from packages.core.models import Mailbox, EmailForwarder, EmailAutoresponder, DNSRecord, SystemSetting
    queue_info = get_mail_queue()
    total_mailboxes = Mailbox.objects.count()
    total_active = Mailbox.objects.filter(is_active=True).count()
    total_forwarders = EmailForwarder.objects.filter(is_active=True).count()
    total_autoresponders = EmailAutoresponder.objects.filter(is_active=True).count()
    dkim_count = DNSRecord.objects.filter(record_type='TXT', name__icontains='_domainkey').count()

    events = get_mail_delivery_log(limit=500)
    if events:
        sent_today = sum(1 for e in events if e['status'] == 'sent')
        bounced_today = sum(1 for e in events if e['status'] in ('bounced', 'rejected'))
        received_today = sum(1 for e in events if e['status'] == 'sent' and e['recipient'] != '-')
        total_attempts = sent_today + bounced_today
        delivery_rate = f"{round((sent_today / total_attempts) * 100)}%" if total_attempts else '100%'
    else:
        def _setting_int(k: str) -> int:
            try:
                return int(SystemSetting.get(k, '0'))
            except (ValueError, TypeError):
                return 0
        sent_today = _setting_int('email_stats_sent_today')
        received_today = _setting_int('email_stats_received_today')
        bounced_today = _setting_int('email_stats_bounced_today')
        total_attempts = sent_today + bounced_today
        delivery_rate = f"{round((sent_today / total_attempts) * 100)}%" if total_attempts else '100%'

    return {
        'total_mailboxes': total_mailboxes,
        'active_mailboxes': total_active,
        'total_forwarders': total_forwarders,
        'total_autoresponders': total_autoresponders,
        'queue_count': queue_info.get('count', 0),
        'sent_today': sent_today,
        'received_today': received_today,
        'bounced_today': bounced_today,
        'delivery_rate': delivery_rate,
        'dkim_configured': dkim_count,
        'recent_deliveries': events[:50],
    }


def get_mailbox_disk_usage(email: str) -> float:
    """Calculate Maildir size in MB."""
    if '@' not in email:
        return 0.0
    mbox_user, domain = email.strip().lower().split('@', 1)
    base = _get_vmail_base()
    maildir = base / domain / mbox_user
    if not maildir.exists():
        fallback = Path(f"/tmp/w3panel/vmail/{domain}/{mbox_user}")
        if fallback.exists():
            maildir = fallback
        else:
            return 0.0
    try:
        total_bytes = sum(f.stat().st_size for f in maildir.glob('**/*') if f.is_file())
        return round(total_bytes / (1024 * 1024), 2)
    except Exception:
        return 0.0


def _generate_dkim_keypair(domain: str) -> tuple[str, str]:
    """Generate a real 2048-bit RSA DKIM keypair via opendkim-genkey or openssl. Returns (priv_path, txt_value)."""
    dkim_base = _get_opendkim_dir()
    domain_dkim_dir = dkim_base / domain
    _mkdir_privileged(domain_dkim_dir)
    priv_key = domain_dkim_dir / 'default.private'
    txt_key = domain_dkim_dir / 'default.txt'
    priv_prefix = _priv_prefix() if (os.geteuid() == 0 or _has_sudo()) else []

    if not _path_exists_privileged(priv_key):
        generated = False
        if shutil.which('opendkim-genkey'):
            try:
                res = subprocess.run(
                    priv_prefix + ['opendkim-genkey', '-b', '2048', '-s', 'default', '-d', domain, '-D', str(domain_dkim_dir)],
                    capture_output=True,
                    timeout=10,
                )
                generated = res.returncode == 0 and _path_exists_privileged(priv_key)
            except Exception:
                pass
        if not generated and shutil.which('openssl'):
            try:
                res = subprocess.run(
                    priv_prefix + ['openssl', 'genrsa', '-out', str(priv_key), '2048'],
                    capture_output=True,
                    timeout=10,
                )
                if res.returncode == 0 and _path_exists_privileged(priv_key):
                    pub = subprocess.run(
                        priv_prefix + ['openssl', 'rsa', '-in', str(priv_key), '-pubout', '-outform', 'PEM'],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if pub.returncode == 0:
                        b64 = ''.join(
                            ln.strip() for ln in pub.stdout.splitlines()
                            if ln.strip() and not ln.startswith('-----')
                        )
                        _write_privileged(txt_key, f'default._domainkey\tIN\tTXT\t( "v=DKIM1; k=rsa; p={b64}" )\n')
            except Exception as e:
                logger.warning(f"OpenSSL DKIM fallback error for {domain}: {e}")

    try:
        if _has_sudo() or os.geteuid() == 0:
            subprocess.run(priv_prefix + ['chmod', '600', str(priv_key)], capture_output=True, timeout=5)
        elif priv_key.exists():
            os.chmod(priv_key, 0o600)
    except Exception:
        pass

    dkim_val = ''
    if _path_exists_privileged(txt_key):
        content = _read_text_privileged(txt_key)
        if 'p=' in content:
            extracted = content.split('p=')[1].split(')')[0].replace('"', '').replace('\n', '').replace('\r', '').replace(' ', '').replace('\t', '')
            if extracted:
                dkim_val = f"v=DKIM1; k=rsa; p={extracted}"
    if not dkim_val and _path_exists_privileged(priv_key) and shutil.which('openssl'):
        try:
            pub = subprocess.run(
                priv_prefix + ['openssl', 'rsa', '-in', str(priv_key), '-pubout', '-outform', 'PEM'],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if pub.returncode == 0:
                b64 = ''.join(ln.strip() for ln in pub.stdout.splitlines() if ln.strip() and not ln.startswith('-----'))
                if b64:
                    dkim_val = f"v=DKIM1; k=rsa; p={b64}"
        except Exception:
            pass

    return str(priv_key), dkim_val


def _sync_opendkim_tables(domains: list[str]) -> None:
    """Update OpenDKIM KeyTable, SigningTable, and TrustedHosts for active domains."""
    conf_dir = _get_opendkim_conf_dir()
    keys_dir = _get_opendkim_dir()

    key_lines = []
    sign_lines = []
    host_lines = ['127.0.0.1', '::1', 'localhost']
    for dom in sorted(set(d.strip().lower() for d in domains if _is_valid_domain(d))):
        priv = keys_dir / dom / 'default.private'
        if _path_exists_privileged(priv):
            key_lines.append(f"default._domainkey.{dom} {dom}:default:{priv}")
            sign_lines.append(f"*@{dom} default._domainkey.{dom}")
        host_lines.append(f"*.{dom}")
        host_lines.append(dom)

    _write_privileged(conf_dir / 'KeyTable', ("\n".join(key_lines) + "\n") if key_lines else "")
    _write_privileged(conf_dir / 'SigningTable', ("\n".join(sign_lines) + "\n") if sign_lines else "")
    _write_privileged(conf_dir / 'TrustedHosts', "\n".join(host_lines) + "\n")

    if os.geteuid() == 0 or _has_sudo():
        subprocess.run(_priv_prefix() + ['chown', '-R', 'opendkim:opendkim', str(conf_dir)], capture_output=True, timeout=5)
        subprocess.run(_priv_prefix() + ['chmod', '755', str(conf_dir), str(keys_dir)], capture_output=True, timeout=5)
        _control_mail_service('opendkim', 'reload')


def _setup_dkim(domain: str) -> str:
    """Generate OpenDKIM 2048-bit keys, register OpenDKIM tables, and save DNS TXT record."""
    domain = (domain or '').strip().lower()
    if not _is_valid_domain(domain):
        return ''

    _, dkim_val = _generate_dkim_keypair(domain)
    all_doms = [domain]
    try:
        from packages.core.models import Website, DNSRecord
        all_doms.extend(Website.objects.filter(is_active=True).values_list('domain', flat=True))
        site = Website.objects.filter(domain=domain).first()
        if site and dkim_val:
            DNSRecord.objects.update_or_create(
                domain=site,
                record_type='TXT',
                name='default._domainkey',
                defaults={'value': dkim_val, 'ttl': 3600},
            )
    except Exception as e:
        logger.warning(f"Could not save DKIM DNS record: {e}")

    _sync_opendkim_tables(all_doms)
    return dkim_val


def get_domain_deliverability(website, server_ip: str = '') -> dict:
    """Inspect MX, SPF, DKIM, and DMARC records for a Website (cPanel Email Deliverability parity)."""
    from packages.core.models import DNSRecord, SystemSetting
    domain = website.domain
    ip = (server_ip or SystemSetting.get('server_ip', '') or '127.0.0.1').strip()
    mail_host = f"mail.{domain}"
    records = list(DNSRecord.objects.filter(domain=website))

    mx_rec = next((r for r in records if r.record_type == 'MX'), None)
    spf_rec = next((r for r in records if r.record_type == 'TXT' and r.name in ('@', domain) and r.value.lower().startswith('v=spf1')), None)
    dkim_rec = next((r for r in records if r.record_type == 'TXT' and '_domainkey' in r.name and 'v=dkim1' in r.value.lower()), None)
    dmarc_rec = next((r for r in records if r.record_type == 'TXT' and r.name.lower() == '_dmarc' and 'v=dmarc1' in r.value.lower()), None)

    suggested_spf = f"v=spf1 a mx ip4:{ip} ~all" if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip) else "v=spf1 a mx ~all"
    suggested_dmarc = f"v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}"

    return {
        'domain': domain,
        'mail_host': mail_host,
        'mx': {'ok': mx_rec is not None, 'value': mx_rec.value if mx_rec else '', 'suggested': mail_host},
        'spf': {'ok': spf_rec is not None, 'value': spf_rec.value if spf_rec else '', 'suggested': suggested_spf},
        'dkim': {'ok': dkim_rec is not None, 'value': dkim_rec.value if dkim_rec else '', 'suggested': '2048-bit RSA key (default._domainkey)'},
        'dmarc': {'ok': dmarc_rec is not None, 'value': dmarc_rec.value if dmarc_rec else '', 'suggested': suggested_dmarc},
        'all_ok': all(x is not None for x in (mx_rec, spf_rec, dkim_rec, dmarc_rec)),
    }


def repair_domain_deliverability(website, server_ip: str = '') -> dict:
    """Create/repair missing MX, mail A, SPF, DKIM (real 2048-bit RSA), and DMARC DNS records."""
    from packages.core.models import DNSRecord, SystemSetting
    from services.dns import export_zone_file

    domain = website.domain
    ip = (server_ip or SystemSetting.get('server_ip', '') or '127.0.0.1').strip()
    status = get_domain_deliverability(website, server_ip=ip)

    if not DNSRecord.objects.filter(domain=website, record_type='A', name='mail').exists():
        DNSRecord.objects.create(domain=website, record_type='A', name='mail', value=ip, ttl=3600)
    if not status['mx']['ok']:
        DNSRecord.objects.create(domain=website, record_type='MX', name='@', value=status['mx']['suggested'], priority=10, ttl=3600)
    if not status['spf']['ok']:
        DNSRecord.objects.create(domain=website, record_type='TXT', name='@', value=status['spf']['suggested'], ttl=3600)
    if not status['dkim']['ok']:
        _setup_dkim(domain)
    if not status['dmarc']['ok']:
        DNSRecord.objects.create(domain=website, record_type='TXT', name='_dmarc', value=status['dmarc']['suggested'], ttl=3600)

    export_zone_file(domain, website.dns_records.all())
    return {'success': True, 'status': get_domain_deliverability(website, server_ip=ip)}


def _get_dovecot_master_credentials() -> tuple[str, str]:
    """Return (master_user, master_password) stored in 0640 key file for SnappyMail 1-click SSO."""
    master_user = 'w3p_master'
    env_pw = os.environ.get('W3PANEL_WEBMAIL_MASTER_PASS', '').strip()
    if env_pw:
        return master_user, env_pw
    key_file = _get_etc_w3panel_dir() / 'webmail_master.key'
    pw = _read_text_privileged(key_file).strip()
    if not pw:
        pw = secrets.token_hex(24)
        _write_privileged(key_file, pw + '\n')
        if os.geteuid() == 0 or _has_sudo():
            subprocess.run(_priv_prefix() + ['chgrp', 'www-data', str(key_file)], capture_output=True, timeout=5)
            subprocess.run(_priv_prefix() + ['chmod', '640', str(key_file)], capture_output=True, timeout=5)
    return master_user, pw


def _detect_mail_tls_cert_key() -> tuple[str, str]:
    ssl_dir = _get_ssl_dir()
    panel_crt = ssl_dir / 'panel.crt'
    panel_key = ssl_dir / 'panel.key'
    if panel_crt.exists() and panel_key.exists():
        return str(panel_crt), str(panel_key)
    if not os.environ.get('W3PANEL_SSL_DIR'):
        try:
            snake_crt = Path('/etc/ssl/certs/ssl-cert-snakeoil.pem')
            snake_key = Path('/etc/ssl/private/ssl-cert-snakeoil.key')
            if snake_crt.exists() and snake_key.exists():
                return str(snake_crt), str(snake_key)
        except (PermissionError, OSError):
            pass
    return str(panel_crt), str(panel_key)


def _write_dovecot_passwd_file(path: Path, content: str) -> bool:
    """Write a Dovecot passwd/users file and ensure group dovecot can read it safely (0640)."""
    ok = _write_privileged(path, content)
    if ok and (os.geteuid() == 0 or _has_sudo()):
        try:
            import grp
            grp.getgrnam('dovecot')
            subprocess.run(_priv_prefix() + ['chgrp', 'dovecot', str(path)], capture_output=True, timeout=5)
        except Exception:
            pass
        subprocess.run(_priv_prefix() + ['chmod', '640', str(path)], capture_output=True, timeout=5)
    return ok


def _sync_dovecot_auth_files(dovecot_dir: Path | None = None) -> tuple[str, str]:
    """Write Dovecot virtual user and SnappyMail master-user SSO authentication configs."""
    target_dir = dovecot_dir or _get_dovecot_dir()
    master_user, master_pass = _get_dovecot_master_credentials()
    master_hash = hash_mailbox_password(master_pass)
    conf_d = target_dir / 'conf.d'
    users_file = target_dir / 'users'
    if not _path_exists_privileged(users_file):
        _write_dovecot_passwd_file(users_file, '')
    elif os.geteuid() == 0 or _has_sudo():
        _write_dovecot_passwd_file(users_file, _read_text_privileged(users_file))
    master_users_file = target_dir / 'passwd.masterusers'

    auth_files = {
        conf_d / '10-auth.conf': (
            "disable_plaintext_auth = yes\n"
            "auth_mechanisms = plain login\n"
            "auth_master_user_separator = *\n"
            "!include auth-passwdfile.conf.ext\n"
            "!include auth-master.conf.ext\n"
        ),
        conf_d / 'auth-passwdfile.conf.ext': (
            f"passdb {{\n  driver = passwd-file\n  args = username_format=%u {users_file}\n}}\n"
            f"userdb {{\n  driver = passwd-file\n  args = username_format=%u {users_file}\n}}\n"
        ),
        conf_d / 'auth-master.conf.ext': (
            f"passdb {{\n  driver = passwd-file\n  master = yes\n  result_success = continue\n  args = {master_users_file}\n}}\n"
        ),
    }
    for path, content in auth_files.items():
        _write_privileged(path, content)
    _write_dovecot_passwd_file(master_users_file, f"{master_user}:{master_hash}\n")
    return master_user, master_pass


def _resolve_mail_unit(service: str) -> str:
    """Resolve Debian/Ubuntu postfix@-.service multi-instance unit when present."""
    if service == 'postfix' and shutil.which('systemctl'):
        try:
            chk = subprocess.run(['systemctl', 'cat', 'postfix@-.service'], capture_output=True, timeout=3)
            if chk.returncode == 0:
                return 'postfix@-'
        except Exception:
            pass
    return service


def _control_mail_service(service: str, action: str = 'reload', allow_inactive_restart: bool = False) -> bool:
    """Restart or reload a mail stack daemon cleanly."""
    if not (os.geteuid() == 0 or _has_sudo()):
        return False
    if service == 'postfix' and action == 'reload' and shutil.which('postfix'):
        try:
            res = subprocess.run(_priv_prefix() + ['postfix', 'reload'], capture_output=True, timeout=5)
            if res.returncode == 0:
                return True
        except Exception:
            pass
    if not shutil.which('systemctl'):
        return False
    unit = _resolve_mail_unit(service)
    try:
        state_res = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True, timeout=2)
        state = state_res.stdout.strip()
        should_act = (state == 'active') or (allow_inactive_restart and state in ('activating', 'failed', 'deactivating'))
        if not should_act and allow_inactive_restart:
            en_res = subprocess.run(['systemctl', 'is-enabled', service], capture_output=True, text=True, timeout=2)
            should_act = en_res.stdout.strip() == 'enabled'
        if should_act:
            act = 'restart' if (action == 'reload' and state != 'active') else action
            run_res = subprocess.run(_priv_prefix() + ['systemctl', act, unit], capture_output=True, timeout=15)
            return run_res.returncode == 0
    except Exception:
        pass
    return False


def configure_mail_stack(
    hostname: str = '',
    smtp_port: str = '',
    spam_filter: str = '',
    dkim_enabled: bool | None = None,
    spam_threshold: float | None = None,
) -> dict:
    """
    Configure Postfix (virtual domains/mailboxes/aliases, LMTP, SASL, submission/smtps),
    Dovecot (passwd-file, quotas, Sieve vacation, master-user SSO), OpenDKIM, and Rspamd/SpamAssassin.
    """
    try:
        from packages.core.models import SystemSetting
        hostname = hostname or SystemSetting.get('server_hostname', '') or socket.getfqdn()
        smtp_port = smtp_port or SystemSetting.get('email_smtp_port', '587')
        spam_filter = spam_filter or SystemSetting.get('email_spam_filter', '') or SystemSetting.get('mail_spam_filter', 'rspamd')
        if dkim_enabled is None:
            dkim_enabled = (SystemSetting.get('email_dkim_enabled', 'true') == 'true')
        if spam_threshold is None:
            try:
                spam_threshold = float(SystemSetting.get('email_spam_threshold', '6.0') or '6.0')
            except ValueError:
                spam_threshold = 6.0
    except Exception:
        hostname = hostname or socket.getfqdn()
        smtp_port = smtp_port or '587'
        spam_filter = spam_filter or 'rspamd'
        dkim_enabled = True if dkim_enabled is None else dkim_enabled
        spam_threshold = 6.0 if spam_threshold is None else spam_threshold

    if not re.match(r'^[A-Za-z0-9.-]+$', hostname):
        hostname = 'localhost.localdomain'
    mydomain = hostname.split('.', 1)[1] if '.' in hostname else hostname

    vmail_base = _get_vmail_base()
    postfix_dir = _get_postfix_dir()
    dovecot_dir = _get_dovecot_dir()
    _ensure_vmail_system_user()
    if os.geteuid() == 0 or _has_sudo():
        subprocess.run(_priv_prefix() + ['chown', '5000:5000', str(vmail_base)], capture_output=True, timeout=5)

    # Ensure Postfix map files exist and sync virtual domains
    for fname in ('vmailbox_domains', 'vmailbox', 'virtual'):
        fpath = postfix_dir / fname
        if not _path_exists_privileged(fpath):
            _write_privileged(fpath, '')
    sync_res = sync_virtual_domains()
    for fname in ('vmailbox_domains', 'vmailbox', 'virtual'):
        _run_postmap(postfix_dir / fname)

    # 1. Configure Dovecot
    cert_path, key_path = _detect_mail_tls_cert_key()
    _sync_dovecot_auth_files(dovecot_dir)
    conf_d = dovecot_dir / 'conf.d'

    dovecot_files = {
        conf_d / '10-mail.conf': (
            f"mail_location = maildir:{vmail_base}/%d/%n\n"
            "namespace inbox {\n"
            "  inbox = yes\n"
            "}\n"
            "mail_privileged_group = vmail\n"
            "first_valid_uid = 5000\n"
            "last_valid_uid = 5000\n"
            "mail_plugins = $mail_plugins quota\n"
        ),
        conf_d / '10-master.conf': (
            "service lmtp {\n"
            "  unix_listener /var/spool/postfix/private/dovecot-lmtp {\n"
            "    mode = 0600\n    user = postfix\n    group = postfix\n  }\n}\n"
            "service auth {\n"
            "  unix_listener /var/spool/postfix/private/auth {\n"
            "    mode = 0660\n    user = postfix\n    group = postfix\n  }\n}\n"
            "service managesieve-login {\n"
            "  inet_listener sieve {\n    port = 4190\n  }\n}\n"
        ),
        conf_d / '10-ssl.conf': (
            f"ssl = yes\nssl_cert = <{cert_path}\nssl_key = <{key_path}\n"
        ),
        conf_d / '20-imap.conf': "protocol imap {\n  mail_plugins = $mail_plugins imap_quota\n}\n",
        conf_d / '20-lmtp.conf': (
            f"protocol lmtp {{\n  postmaster_address = postmaster@{hostname}\n  mail_plugins = $mail_plugins sieve\n}}\n"
        ),
        conf_d / '90-quota.conf': (
            "plugin {\n  quota = maildir:User quota\n  quota_rule = *:storage=1024M\n  quota_rule2 = Trash:storage=+100M\n}\n"
        ),
        conf_d / '90-sieve.conf': (
            "plugin {\n"
            f"  sieve = file:{vmail_base}/%d/%n/sieve;active={vmail_base}/%d/%n/.dovecot.sieve\n"
            "  sieve_extensions = +vacation-seconds\n"
            "  sieve_vacation_min_period = 0s\n"
            "}\n"
        ),
    }
    for path, content in dovecot_files.items():
        _write_privileged(path, content)

    # 2. Configure OpenDKIM & Milter list
    milters: list[str] = []
    if dkim_enabled:
        opendkim_conf_dir = _get_opendkim_conf_dir()
        _sync_opendkim_tables(sync_res.get('domains', []))
        odkim_conf = (
            "Syslog yes\n"
            "UMask 002\n"
            "Mode sv\n"
            "Canonicalization relaxed/relaxed\n"
            "Selector default\n"
            "Background Yes\n"
            "PidFile /run/opendkim/opendkim.pid\n"
            f"KeyTable refile:{opendkim_conf_dir}/KeyTable\n"
            f"SigningTable refile:{opendkim_conf_dir}/SigningTable\n"
            f"ExternalIgnoreList refile:{opendkim_conf_dir}/TrustedHosts\n"
            f"InternalHosts refile:{opendkim_conf_dir}/TrustedHosts\n"
            "Socket local:/var/spool/postfix/opendkim/opendkim.sock\n"
            "UserID opendkim:opendkim\n"
        )
        _write_privileged(_get_opendkim_conf_file(), odkim_conf)
        if os.geteuid() == 0 or _has_sudo():
            subprocess.run(_priv_prefix() + ['mkdir', '-p', '/var/spool/postfix/opendkim', '/run/opendkim'], capture_output=True, timeout=5)
            subprocess.run(_priv_prefix() + ['chown', 'opendkim:postfix', '/var/spool/postfix/opendkim'], capture_output=True, timeout=5)
            subprocess.run(_priv_prefix() + ['chmod', '750', '/var/spool/postfix/opendkim', '/run/opendkim'], capture_output=True, timeout=5)
            subprocess.run(_priv_prefix() + ['chown', 'opendkim:opendkim', '/run/opendkim'], capture_output=True, timeout=5)
            subprocess.run(_priv_prefix() + ['usermod', '-aG', 'opendkim', 'postfix'], capture_output=True, timeout=5)
        milters.append('unix:opendkim/opendkim.sock')

    # 3. Configure Spam Filter (Rspamd / SpamAssassin)
    if spam_filter == 'rspamd':
        rspamd_dir = _get_rspamd_dir()
        _write_privileged(rspamd_dir / 'worker-proxy.inc', 'bind_socket = "127.0.0.1:11332";\nmilter = yes;\n')
        _write_privileged(
            rspamd_dir / 'actions.conf',
            f"reject = {max(8.0, spam_threshold + 6.0):.1f};\n"
            f"add_header = {spam_threshold:.1f};\n"
            f"greylist = {max(2.0, spam_threshold - 2.0):.1f};\n",
        )
        milters.append('inet:127.0.0.1:11332')
    elif spam_filter == 'spamassassin':
        sa_cf = Path(os.environ.get('W3PANEL_SPAMASSASSIN_CF', '/etc/spamassassin/local.cf'))
        if sa_cf.parent.exists() or os.environ.get('W3PANEL_SPAMASSASSIN_CF'):
            sa_body = (
                f"required_score {spam_threshold:.1f}\n"
                "rewrite_header Subject *****SPAM*****\n"
                "report_safe 0\n"
            )
            _write_privileged(sa_cf, sa_body)
        if Path('/var/spool/postfix/spamass/spamass.sock').exists() or shutil.which('spamass-milter'):
            milters.append('unix:/var/spool/postfix/spamass/spamass.sock')

    # 4. Configure Postfix main.cf & master.cf
    milter_line = ", ".join(milters)
    main_cf_path = postfix_dir / 'main.cf'
    main_block_lines = [
        f"myhostname = {hostname}",
        f"mydomain = {mydomain}",
        "myorigin = $mydomain",
        "inet_interfaces = all",
        "mydestination = localhost.$mydomain, localhost",
        f"virtual_mailbox_domains = hash:{postfix_dir}/vmailbox_domains",
        f"virtual_mailbox_maps = hash:{postfix_dir}/vmailbox",
        f"virtual_alias_maps = hash:{postfix_dir}/virtual",
        "virtual_transport = lmtp:unix:private/dovecot-lmtp",
        "smtpd_sasl_type = dovecot",
        "smtpd_sasl_path = private/auth",
        "smtpd_sasl_auth_enable = yes",
        "smtpd_sasl_security_options = noanonymous",
        "broken_sasl_auth_clients = yes",
        f"smtpd_tls_cert_file = {cert_path}",
        f"smtpd_tls_key_file = {key_path}",
        "smtpd_tls_security_level = may",
        "smtp_tls_security_level = may",
        "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination",
        "milter_protocol = 6",
        "milter_default_action = accept",
        f"smtpd_milters = {milter_line}" if milter_line else "smtpd_milters =",
        f"non_smtpd_milters = {milter_line}" if milter_line else "non_smtpd_milters =",
    ]
    existing_main = _read_text_privileged(main_cf_path)
    _write_privileged(main_cf_path, _upsert_postfix_main_block(existing_main, main_block_lines))

    master_cf_path = postfix_dir / 'master.cf'
    master_lines = [
        "submission inet n       -       y       -       -       smtpd",
        "  -o syslog_name=postfix/submission",
        "  -o smtpd_tls_security_level=encrypt",
        "  -o smtpd_sasl_auth_enable=yes",
        "  -o smtpd_tls_auth_only=yes",
        "  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject",
        "  -o milter_macro_daemon_name=ORIGINATING",
        "smtps     inet  n       -       y       -       -       smtpd",
        "  -o syslog_name=postfix/smtps",
        "  -o smtpd_tls_wrappermode=yes",
        "  -o smtpd_sasl_auth_enable=yes",
        "  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject",
        "  -o milter_macro_daemon_name=ORIGINATING",
    ]
    if str(smtp_port).isdigit() and 1 <= int(smtp_port) <= 65535 and str(smtp_port) not in ('25', '465', '587'):
        master_lines.extend([
            f"{smtp_port} inet n       -       y       -       -       smtpd",
            "  -o syslog_name=postfix/submission-custom",
            "  -o smtpd_tls_security_level=encrypt",
            "  -o smtpd_sasl_auth_enable=yes",
            "  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject",
        ])
    existing_master = _read_text_privileged(master_cf_path)
    _write_privileged(master_cf_path, _upsert_managed_block(existing_master, "\n".join(master_lines)))

    # 5. Restart active/enabled mail stack daemons (including multi-instance postfix@- and crashed opendkim)
    for svc in ('opendkim', 'rspamd', 'dovecot', 'postfix'):
        _control_mail_service(svc, 'restart', allow_inactive_restart=True)

    return {'success': True, 'hostname': hostname, 'domains': sync_res.get('domains', []), 'milters': milters}


def _reload_mail_services():
    """Reload Postfix and Dovecot daemons if active and privileged."""
    for service in ('postfix', 'dovecot'):
        _control_mail_service(service, 'reload')


# ---------------------------------------------------------------------------
# SnappyMail Webmail: Installer, Nginx/Same-Origin Proxy, and 1-Click SSO
# ---------------------------------------------------------------------------

def is_snappymail_installed() -> bool:
    env_dir = os.environ.get('W3PANEL_WEBMAIL_DIR')
    if env_dir:
        return (Path(env_dir) / 'index.php').exists()
    return Path('/var/lib/w3panel/webmail/index.php').exists() or Path('/tmp/w3panel/webmail/index.php').exists()


def _get_webmail_signon_secret() -> str:
    try:
        from packages.core.models import SystemSetting
        secret = SystemSetting.get('webmail_signon_secret', '').strip()
        if not secret:
            secret = secrets.token_hex(32)
            SystemSetting.set('webmail_signon_secret', secret)
        return secret
    except Exception:
        return os.environ.get('W3PANEL_WEBMAIL_SIGNON_SECRET', 'w3panel-dev-webmail-secret')


def _safe_extract_zip(zip_path: Path, dest_dir: Path) -> int:
    """Safely extract a zip archive preventing zip-slip and symlink traversal."""
    dest_resolved = dest_dir.resolve()
    extracted = 0
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            norm = info.filename[2:] if info.filename.startswith('./') else info.filename.lstrip('/')
            if not norm or norm.startswith('/') or '..' in Path(norm).parts or '\x00' in norm:
                continue
            # Reject symlinks
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            target = (dest_dir / norm).resolve()
            if dest_resolved not in target.parents and target != dest_resolved:
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, 'r') as src_f, open(target, 'wb') as out_f:
                    shutil.copyfileobj(src_f, out_f)
                extracted += 1
    return extracted


def _fetch_snappymail_release_zip(dest_zip: Path) -> str:
    """Resolve and download the latest official SnappyMail ZIP asset from GitHub."""
    asset_url = ''
    if shutil.which('curl'):
        try:
            api_res = subprocess.run(
                ['curl', '-4', '-fsSL', '-H', 'User-Agent: W3Panel/2.0', '-H', 'Accept: application/vnd.github+json', '--max-time', '25', _SNAPPYMAIL_LATEST_API],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if api_res.returncode == 0 and api_res.stdout:
                release = json.loads(api_res.stdout)
                for asset in release.get('assets', []):
                    name = asset.get('name', '')
                    if re.match(r'^snappymail-[0-9.]+\.zip$', name):
                        asset_url = asset.get('browser_download_url', '')
                        break
                if asset_url:
                    dl_res = subprocess.run(
                        ['curl', '-4', '-fsSL', '-H', 'User-Agent: W3Panel/2.0', '--max-time', '90', '-o', str(dest_zip), asset_url],
                        capture_output=True,
                        text=True,
                        timeout=95,
                    )
                    if dl_res.returncode == 0 and dest_zip.is_file() and dest_zip.stat().st_size > 0:
                        return asset_url
        except Exception:
            pass

    req = urllib.request.Request(
        _SNAPPYMAIL_LATEST_API,
        headers={'User-Agent': 'W3Panel/2.0', 'Accept': 'application/vnd.github+json'},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        release = json.loads(resp.read().decode('utf-8'))
    for asset in release.get('assets', []):
        name = asset.get('name', '')
        if re.match(r'^snappymail-[0-9.]+\.zip$', name):
            asset_url = asset.get('browser_download_url', '')
            break
    if not asset_url:
        raise ValueError('Could not locate snappymail-*.zip asset in latest GitHub release')
    dl_req = urllib.request.Request(asset_url, headers={'User-Agent': 'W3Panel/2.0'})
    with urllib.request.urlopen(dl_req, timeout=60) as resp, open(dest_zip, 'wb') as out_f:
        shutil.copyfileobj(resp, out_f)
    return asset_url


def configure_webmail_webserver() -> dict:
    """Configure Nginx loopback server (127.0.0.1:8091) for /snappymail/ PHP execution."""
    if not is_snappymail_installed():
        return {'success': True, 'configured': False}

    webmail_dir = _get_webmail_dir()
    sites_avail = Path(os.environ.get('W3PANEL_NGINX_SITES_DIR', '/etc/nginx/sites-available'))
    sites_enabled = Path(os.environ.get('W3PANEL_NGINX_ENABLED_DIR', '/etc/nginx/sites-enabled'))
    nginx_conf = sites_avail / 'w3panel-webmail.conf'
    nginx_link = sites_enabled / 'w3panel-webmail.conf'

    from services.database.manager import _detect_php_fpm_socket
    php_sock = _detect_php_fpm_socket()

    conf_body = f"""server {{
    listen 127.0.0.1:8091;
    server_name _;
    client_max_body_size 50M;

    location ^~ /snappymail {{
        alias {webmail_dir};
        index index.php;

        location ~ ^/snappymail/(data|\\.ht) {{
            deny all;
        }}

        location ~ ^/snappymail/(.+\\.php)$ {{
            set $sm_https "";
            if ($http_x_forwarded_proto = "https") {{
                set $sm_https "on";
            }}
            fastcgi_split_path_info ^/snappymail/(.+\\.php)(/.*)$;
            include fastcgi_params;
            fastcgi_index index.php;
            fastcgi_param HTTPS $sm_https;
            fastcgi_param SCRIPT_FILENAME {webmail_dir}/$1;
            fastcgi_param DOCUMENT_ROOT {webmail_dir};
            fastcgi_pass unix:{php_sock};
        }}
    }}
}}
"""
    if sites_avail.exists() or os.environ.get('W3PANEL_NGINX_SITES_DIR'):
        prev = nginx_conf.read_text(errors='ignore') if nginx_conf.exists() else None
        _write_privileged(nginx_conf, conf_body)
        try:
            sites_enabled.mkdir(parents=True, exist_ok=True)
            if not nginx_link.exists() and not nginx_link.is_symlink():
                nginx_link.symlink_to(nginx_conf)
        except (PermissionError, OSError):
            if _has_sudo():
                subprocess.run(_priv_prefix() + ['ln', '-sf', str(nginx_conf), str(nginx_link)], capture_output=True, timeout=5)

        if shutil.which('nginx') and (_has_sudo() or os.geteuid() == 0):
            test_res = subprocess.run(_priv_prefix() + ['nginx', '-t'], capture_output=True, text=True, timeout=5)
            if test_res.returncode == 0:
                subprocess.run(_priv_prefix() + ['systemctl', 'reload', 'nginx'], capture_output=True, timeout=5)
            else:
                if prev is not None:
                    _write_privileged(nginx_conf, prev)
                else:
                    _remove_privileged(nginx_link)
                    _remove_privileged(nginx_conf)
                return {'success': False, 'error': test_res.stderr or test_res.stdout}

    return {'success': True, 'configured': True, 'config_path': str(nginx_conf)}


def ensure_webmail_webserver_configured() -> dict:
    if not is_snappymail_installed():
        return {'success': True, 'configured': False}
    sites_enabled = Path(os.environ.get('W3PANEL_NGINX_ENABLED_DIR', '/etc/nginx/sites-enabled'))
    conf_link = sites_enabled / 'w3panel-webmail.conf'
    if conf_link.exists():
        try:
            if '127.0.0.1:8091' in conf_link.read_text(errors='ignore'):
                return {'success': True, 'configured': True}
        except Exception:
            return {'success': True, 'configured': True}
    if not shutil.which('nginx') and not os.environ.get('W3PANEL_NGINX_SITES_DIR'):
        return {'success': True, 'configured': False}
    return configure_webmail_webserver()


def install_snappymail() -> dict:
    """Download, extract, and configure SnappyMail Webmail + 1-click Dovecot master SSO."""
    target_dir = _get_webmail_dir()
    if not _mkdir_privileged(target_dir):
        target_dir = Path('/tmp/w3panel/webmail')
        target_dir.mkdir(parents=True, exist_ok=True)

    source_zip = os.environ.get('W3PANEL_SNAPPYMAIL_ZIP', '').strip()
    skip_dl = os.environ.get('W3PANEL_WEBMAIL_SKIP_DOWNLOAD', '').strip() == '1'

    if not (target_dir / 'snappymail').exists() and not skip_dl:
        import tempfile
        tmp_zip = None
        tmp_extract = None
        try:
            zip_to_extract = None
            if source_zip and Path(source_zip).is_file():
                zip_to_extract = Path(source_zip)
            else:
                fd, tmp_name = tempfile.mkstemp(prefix='w3p-snappymail-', suffix='.zip')
                os.close(fd)
                tmp_zip = Path(tmp_name)
                _fetch_snappymail_release_zip(tmp_zip)
                zip_to_extract = tmp_zip

            if os.access(str(target_dir), os.W_OK):
                _safe_extract_zip(zip_to_extract, target_dir)
            elif _has_sudo():
                tmp_extract = Path(tempfile.mkdtemp(prefix='w3p-sm-extract-'))
                _safe_extract_zip(zip_to_extract, tmp_extract)
                cp_res = subprocess.run(_priv_prefix() + ['cp', '-a', f'{tmp_extract}/.', str(target_dir)], capture_output=True, text=True, timeout=30)
                if cp_res.returncode != 0:
                    raise RuntimeError(cp_res.stderr or 'Failed copying extracted SnappyMail files')
            else:
                raise PermissionError(f'Directory not writable: {target_dir}')
        except Exception as e:
            logger.error(f"SnappyMail download/extraction failed: {e}")
            return {'success': False, 'error': f"Failed to download/extract SnappyMail: {e}"}
        finally:
            if tmp_zip and tmp_zip.exists():
                tmp_zip.unlink(missing_ok=True)
            if tmp_extract and tmp_extract.exists():
                shutil.rmtree(tmp_extract, ignore_errors=True)

    # Configure SnappyMail default domain + plugins + SSO endpoint
    data_default = target_dir / 'data' / '_data_' / '_default_'
    domains_dir = data_default / 'domains'
    configs_dir = data_default / 'configs'
    plugin_dir = data_default / 'plugins' / 'w3p-master'
    for d in (domains_dir, configs_dir, plugin_dir):
        _mkdir_privileged(d)

    default_domain_cfg = {
        'IMAP': {'host': '127.0.0.1', 'port': 143, 'type': 0, 'shortLogin': False, 'lowerLogin': True},
        'SMTP': {'host': '127.0.0.1', 'port': 587, 'type': 0, 'shortLogin': False, 'lowerLogin': True, 'useAuth': True},
        'Sieve': {'enabled': True, 'host': '127.0.0.1', 'port': 4190, 'type': 0},
        'whiteList': '',
    }
    _write_privileged(domains_dir / 'default.json', json.dumps(default_domain_cfg, indent=2) + '\n')

    app_ini = (
        "[webmail]\n"
        'title = "W3Panel Webmail"\n\n'
        "[security]\n"
        "allow_admin_panel = Off\n"
        'cookie_samesite = "Lax"\n\n'
        "[labs]\n"
        'cookie_default_path = "/snappymail"\n\n'
        "[plugins]\n"
        "enable = On\n"
        'enabled_list = "w3p-master"\n'
    )
    _write_privileged(configs_dir / 'application.ini', app_ini)

    plugin_php = """<?php
class W3pMasterPlugin extends \\RainLoop\\Plugins\\AbstractPlugin
{
    const
        NAME = 'W3Panel Master SSO',
        AUTHOR = 'W3Panel',
        VERSION = '1.0',
        RELEASE = '2026-11-28',
        REQUIRED = '2.0.0',
        CATEGORY = 'Login',
        LICENSE = 'MIT',
        DESCRIPTION = 'Maps internal W3Panel SSO master credentials to Dovecot';

    public function Init() : void
    {
        $this->addHook('login.credentials', 'MapMasterCredentials');
    }

    public function MapMasterCredentials(string &$sEmail, string &$sImapUser, string &$sPassword, string &$sSmtpUser) : void
    {
        if (!empty($GLOBALS['W3P_MASTER_AUTH'])
            && is_array($GLOBALS['W3P_MASTER_AUTH'])
            && ($GLOBALS['W3P_MASTER_AUTH']['email'] ?? '') === $sEmail
        ) {
            $sImapUser = $GLOBALS['W3P_MASTER_AUTH']['imap_user'];
            $sSmtpUser = $GLOBALS['W3P_MASTER_AUTH']['imap_user'];
            $sPassword = $GLOBALS['W3P_MASTER_AUTH']['password'];
        }
    }
}
"""
    _write_privileged(plugin_dir / 'index.php', plugin_php)

    secret = _get_webmail_signon_secret()
    master_user, _ = _get_dovecot_master_credentials()
    key_file = _get_etc_w3panel_dir() / 'webmail_master.key'
    safe_secret = secret.replace("'", "\\'")
    safe_key_file = str(key_file).replace("'", "\\'")
    safe_master_user = master_user.replace("'", "\\'")

    signon_php = f"""<?php
declare(strict_types=1);
$expectedSecret = '{safe_secret}';
$providedSecret = $_SERVER['HTTP_X_W3PANEL_WEBMAIL_SECRET'] ?? '';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST'
    || $expectedSecret === ''
    || !is_string($providedSecret)
    || !hash_equals($expectedSecret, $providedSecret)
) {{
    http_response_code(403);
    exit;
}}
$email = strtolower(trim((string)($_POST['email'] ?? '')));
if ($email === '' || strpos($email, '@') === false) {{
    http_response_code(400);
    exit;
}}
$masterKeyFile = '{safe_key_file}';
$masterPass = is_readable($masterKeyFile) ? trim((string)file_get_contents($masterKeyFile)) : '';
if ($masterPass === '') {{
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => 'Master key unavailable']);
    exit;
}}
$_ENV['SNAPPYMAIL_INCLUDE_AS_API'] = '1';
require __DIR__ . '/index.php';
$GLOBALS['W3P_MASTER_AUTH'] = [
    'email' => $email,
    'imap_user' => $email . '*{safe_master_user}',
    'password' => $masterPass,
];
try {{
    \\RainLoop\\Api::Actions()->LoginProcess($email, new \\SnappyMail\\SensitiveString('__w3p_sso__'));
    header('Content-Type: application/json');
    echo '{{"success":true}}';
}} catch (\\Throwable $e) {{
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}}
"""
    _write_privileged(target_dir / 'w3p-signon.php', signon_php)

    if os.geteuid() == 0 or _has_sudo():
        subprocess.run(_priv_prefix() + ['chown', '-R', 'www-data:www-data', str(target_dir)], capture_output=True, timeout=10)
        subprocess.run(_priv_prefix() + ['chmod', '640', str(target_dir / 'w3p-signon.php')], capture_output=True, timeout=5)
        dovecot_dir = _get_dovecot_dir()
        if (dovecot_dir / 'conf.d').exists():
            _sync_dovecot_auth_files(dovecot_dir)
            _control_mail_service('dovecot', 'reload')

    configure_webmail_webserver()
    return {'success': True, 'path': str(target_dir)}


def uninstall_snappymail() -> dict:
    """Remove SnappyMail installation and Nginx webmail config."""
    webmail_dir = _get_webmail_dir()
    sites_avail = Path(os.environ.get('W3PANEL_NGINX_SITES_DIR', '/etc/nginx/sites-available'))
    sites_enabled = Path(os.environ.get('W3PANEL_NGINX_ENABLED_DIR', '/etc/nginx/sites-enabled'))
    for p in (sites_enabled / 'w3panel-webmail.conf', sites_avail / 'w3panel-webmail.conf'):
        _remove_privileged(p)
    if webmail_dir.exists():
        try:
            shutil.rmtree(webmail_dir)
        except (PermissionError, OSError):
            if _has_sudo():
                subprocess.run(_priv_prefix() + ['rm', '-rf', str(webmail_dir)], capture_output=True, timeout=10)
    if shutil.which('nginx') and (_has_sudo() or os.geteuid() == 0):
        subprocess.run(_priv_prefix() + ['systemctl', 'reload', 'nginx'], capture_output=True, timeout=5)
    return {'success': True}


def proxy_webmail_request(request, subpath: str = ''):
    """Reverse-proxy /snappymail/... on the active panel host, port, and scheme."""
    from django.http import HttpResponse
    if not is_snappymail_installed():
        return HttpResponse('SnappyMail Webmail is not installed.', status=404)

    clean = (subpath or '').lstrip('/')
    if clean.startswith('data/') or clean == 'w3p-signon.php':
        return HttpResponse('Forbidden', status=403)

    ensure_webmail_webserver_configured()
    from services.database.manager import proxy_http_upstream
    return proxy_http_upstream(
        request,
        slug='snappymail',
        subpath=subpath,
        targets=[('127.0.0.1', 8091), ('127.0.0.1', 80)],
    )


def launch_webmail(request, mailbox_email: str = ''):
    """Ensure Nginx webmail route, establish 1-click SnappyMail SSO session if mailbox given, and redirect."""
    from django.shortcuts import redirect

    ensure_webmail_webserver_configured()
    resp = redirect('/snappymail/')
    if not mailbox_email or not _is_valid_email(mailbox_email):
        return resp

    payload = urllib.parse.urlencode({'email': mailbox_email.strip().lower()}).encode()
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': str(len(payload)),
        'X-W3Panel-Webmail-Secret': _get_webmail_signon_secret(),
        'X-Forwarded-Proto': 'https' if (request.is_secure() or request.META.get('HTTP_X_FORWARDED_PROTO') == 'https') else 'http',
        'Host': request.get_host(),
    }

    for host, port in (('127.0.0.1', 8091), ('127.0.0.1', 80)):
        conn = None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.request('POST', '/snappymail/w3p-signon.php', body=payload, headers=headers)
            signon_resp = conn.getresponse()
            signon_resp.read()
            if signon_resp.status == 200:
                for raw_cookie in (signon_resp.headers.get_all('Set-Cookie') or []):
                    parsed = SimpleCookie()
                    parsed.load(raw_cookie)
                    for cname, morsel in parsed.items():
                        resp.cookies[cname] = morsel.value
                        resp.cookies[cname]['path'] = morsel.get('path') or '/snappymail'
                        resp.cookies[cname]['httponly'] = True
                        resp.cookies[cname]['samesite'] = 'Lax'
                        if request.is_secure():
                            resp.cookies[cname]['secure'] = True
                break
        except Exception:
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    return resp
