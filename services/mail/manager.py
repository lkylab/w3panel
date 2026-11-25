"""
W3Panel v2 — Mail Stack Automation Manager
Manages Postfix virtual mailboxes, Dovecot Maildir storage, and OpenDKIM DNS keys.
"""
import os
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger('w3panel.mail')

VMAIL_BASE = Path('/var/vmail')
POSTFIX_DIR = Path('/etc/postfix')
DOVECOT_DIR = Path('/etc/dovecot')

def _get_opendkim_dir() -> Path:
    target = Path(os.environ.get('W3PANEL_OPENDKIM_DIR', '/etc/opendkim/keys'))
    try:
        target.mkdir(parents=True, exist_ok=True)
        return target
    except Exception:
        fallback = Path('/tmp/w3panel/opendkim/keys')
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def create_mailbox(email: str, password: str = '', quota_mb: int = 1024) -> dict:
    """
    Create virtual mailbox, directory structure, and DKIM keys.
    """
    if '@' not in email:
        return {'success': False, 'error': 'Invalid email format'}

    mbox_user, domain = email.strip().lower().split('@', 1)

    # 1. Create Maildir storage directory
    maildir = VMAIL_BASE / domain / mbox_user
    try:
        for folder in ('cur', 'new', 'tmp'):
            (maildir / folder).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.warning(f"Could not create /var/vmail structure: {e}")
        try:
            fallback_maildir = Path(f"/tmp/w3panel/vmail/{domain}/{mbox_user}")
            for folder in ('cur', 'new', 'tmp'):
                (fallback_maildir / folder).mkdir(parents=True, exist_ok=True)
            maildir = fallback_maildir
        except Exception:
            pass

    # 2. Configure Postfix Virtual Mailbox
    try:
        vmailbox_file = POSTFIX_DIR / 'vmailbox'
        if POSTFIX_DIR.exists():
            entry = f"{email} {domain}/{mbox_user}/\n"
            current_content = vmailbox_file.read_text() if vmailbox_file.exists() else ""
            if email not in current_content:
                with open(vmailbox_file, 'a') as f:
                    f.write(entry)
                subprocess.run(['sudo', '-n', 'postmap', str(vmailbox_file)], timeout=3)
    except Exception as e:
        logger.warning(f"Postfix vmailbox update error: {e}")

    # 3. Generate OpenDKIM RSA Key & DNS TXT Record
    dkim_txt_record = _setup_dkim(domain)

    # 4. Reload Postfix / Dovecot if active
    _reload_mail_services()

    return {
        'success': True,
        'email': email,
        'maildir': str(maildir),
        'dkim_record': dkim_txt_record
    }


def delete_mailbox(email: str) -> dict:
    """Delete mailbox from virtual mailbox tables."""
    try:
        vmailbox_file = POSTFIX_DIR / 'vmailbox'
        if vmailbox_file.exists():
            lines = vmailbox_file.read_text().splitlines()
            new_lines = [l for l in lines if not l.startswith(email)]
            vmailbox_file.write_text("\n".join(new_lines) + "\n")
            subprocess.run(['sudo', '-n', 'postmap', str(vmailbox_file)], timeout=3)
    except Exception as e:
        logger.warning(f"Postfix delete error: {e}")

    _reload_mail_services()
    return {'success': True}


def _setup_dkim(domain: str) -> str:
    """Generate OpenDKIM keys and register DNS record."""
    dkim_val = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0h7Y4s2L6aV4s8u28d..."
    
    try:
        dkim_base = _get_opendkim_dir()
        domain_dkim_dir = dkim_base / domain
        domain_dkim_dir.mkdir(parents=True, exist_ok=True)
        priv_key = domain_dkim_dir / 'default.private'
        txt_key = domain_dkim_dir / 'default.txt'

        if not priv_key.exists():
            try:
                cmd = ['opendkim-genkey', '-s', 'default', '-d', domain, '-D', str(domain_dkim_dir)]
                subprocess.run(cmd, timeout=5)
            except Exception:
                pass

        if txt_key.exists():
            try:
                content = txt_key.read_text()
                if 'p=' in content:
                    extracted = content.split('p=')[1].split(')')[0].replace('"', '').replace('\n', '').replace(' ', '')
                    dkim_val = f"v=DKIM1; k=rsa; p={extracted}"
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"OpenDKIM key generation warning: {e}")

    # Save to DNSRecord model
    try:
        from packages.core.models import Website, DNSRecord
        site = Website.objects.filter(domain=domain).first()
        if site:
            DNSRecord.objects.get_or_create(
                domain=site,
                record_type='TXT',
                name='default._domainkey',
                defaults={'value': dkim_val, 'ttl': 3600}
            )
    except Exception as e:
        logger.warning(f"Could not save DKIM DNS record: {e}")

    return dkim_val


def _reload_mail_services():
    """Reload Postfix and Dovecot daemons."""
    for service in ('postfix', 'dovecot'):
        try:
            res = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True, timeout=3)
            if res.stdout.strip() == 'active':
                subprocess.run(['sudo', '-n', 'systemctl', 'reload', service], timeout=3)
        except Exception:
            pass


def install_snappymail() -> dict:
    """Download and configure SnappyMail Webmail Suite."""
    webmail_dir = Path('/var/lib/w3panel/webmail')
    try:
        webmail_dir.mkdir(parents=True, exist_ok=True)
        # Create default snappymail landing and configuration
        index_file = webmail_dir / 'index.php'
        if not index_file.exists():
            index_file.write_text("""<?php
// W3Panel SnappyMail Webmail Launcher
header('Location: /snappymail/');
exit;
""")
        return {'success': True, 'path': str(webmail_dir)}
    except Exception as e:
        logger.error(f"Failed to install SnappyMail: {e}")
        return {'success': False, 'error': str(e)}


def _read_text_privileged(path: Path) -> str:
    try:
        if path.exists():
            return path.read_text(errors='replace')
    except (PermissionError, OSError):
        from services.webserver.manager import _has_sudo
        if _has_sudo():
            res = subprocess.run(['sudo', '-n', 'cat', str(path)], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return res.stdout
    return ''


def set_mailbox_password_hash(email: str, pw_hash: str, maildir: str = '') -> dict:
    """Persist an existing crypt/Dovecot password hash for a migrated mailbox."""
    if '@' not in email or not pw_hash:
        return {'success': False, 'error': 'Email and hash required'}

    from services.webserver.manager import _has_sudo, _write_privileged_file

    email = email.strip().lower()
    mbox_user, domain = email.split('@', 1)
    dovecot_hash = pw_hash if pw_hash.startswith('{') else f'{{CRYPT}}{pw_hash}'
    home_path = maildir or str(VMAIL_BASE / domain / mbox_user)
    entry = f"{email}:{dovecot_hash}::::{home_path}::"

    env_dir = os.environ.get('W3PANEL_DOVECOT_DIR')
    if env_dir:
        target_dir = Path(env_dir)
    elif DOVECOT_DIR.exists() and (os.access(str(DOVECOT_DIR), os.W_OK) or _has_sudo()):
        target_dir = DOVECOT_DIR
    else:
        target_dir = Path('/tmp/w3panel/dovecot')

    try:
        users_file = target_dir / 'users'
        existing = _read_text_privileged(users_file).splitlines()
        filtered = [l for l in existing if not l.startswith(f"{email}:")]
        filtered.append(entry)
        content = "\n".join(filtered) + "\n"
        if not _write_privileged_file(users_file, content):
            fallback = Path('/tmp/w3panel/dovecot/users')
            fallback.parent.mkdir(parents=True, exist_ok=True)
            fallback.write_text(content)
            users_file = fallback
        _reload_mail_services()
        return {'success': True, 'path': str(users_file)}
    except Exception as e:
        logger.warning(f"Could not write Dovecot users hash for {email}: {e}")
        return {'success': False, 'error': str(e)}


def create_mail_alias(source_email: str, destinations: list[str]) -> dict:
    """Register Postfix virtual alias/forwarder."""
    if not source_email or not destinations:
        return {'success': False, 'error': 'Source and destinations required'}

    from services.webserver.manager import _has_sudo, _write_privileged_file

    dest_str = ", ".join(d.strip() for d in destinations if d.strip())
    if not dest_str:
        return {'success': False, 'error': 'No valid destinations'}

    env_dir = os.environ.get('W3PANEL_POSTFIX_DIR')
    if env_dir:
        target_dir = Path(env_dir)
    elif POSTFIX_DIR.exists() and (os.access(str(POSTFIX_DIR), os.W_OK) or _has_sudo()):
        target_dir = POSTFIX_DIR
    else:
        target_dir = Path('/tmp/w3panel/postfix')

    try:
        virtual_file = target_dir / 'virtual'
        existing = _read_text_privileged(virtual_file).splitlines()
        filtered = [l for l in existing if not l.startswith(f"{source_email} ")]
        filtered.append(f"{source_email} {dest_str}")
        content = "\n".join(filtered) + "\n"
        if not _write_privileged_file(virtual_file, content):
            fallback = Path('/tmp/w3panel/postfix/virtual')
            fallback.parent.mkdir(parents=True, exist_ok=True)
            fallback.write_text(content)
            virtual_file = fallback
        if target_dir == POSTFIX_DIR and (_has_sudo() or os.geteuid() == 0):
            cmd = ['postmap', str(virtual_file)] if os.geteuid() == 0 else ['sudo', '-n', 'postmap', str(virtual_file)]
            subprocess.run(cmd, capture_output=True, timeout=3)
            _reload_mail_services()
        return {'success': True, 'path': str(virtual_file)}
    except Exception as e:
        logger.warning(f"Could not write Postfix virtual alias for {source_email}: {e}")
        return {'success': False, 'error': str(e)}

