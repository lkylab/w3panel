"""
W3Panel v2 — Modular Panel Migrator Plugin Registry
Each panel migrator is an independent, on-demand installable plugin so the core panel stays lightweight.
"""
import json
import os
import shutil
import subprocess
import logging
from pathlib import Path
from importlib import import_module

from packages.core.models import SystemSetting

logger = logging.getLogger('w3panel.migrators')

INSTALLED_SETTING_KEY = 'installed_migrators'

MIGRATOR_CATALOG = [
    {
        'id': 'cpanel',
        'name': 'cPanel / WHM',
        'description': 'Migrate via live WHM/SSH server connection or cpmove backup archive (websites, parked/addon/subdomains, .htaccess rules, MySQL/PostgreSQL, mailboxes + shadow hashes + forwarders, DNS, FTP, cron, SSL).',
        'formats': 'Live WHM/SSH, cpmove-*.tar.gz, backup-*.tar.gz, extracted dir',
        'module': 'services.migrators.cpanel',
        'apt_packages': ['sshpass'],
        'supports_remote': True,
        'available': True,
        'version': '2.0.0',
    },
    {
        'id': 'cyberpanel',
        'name': 'CyberPanel (OpenLiteSpeed / LiteSpeed)',
        'description': 'Migrate CyberPanel websites, OpenLiteSpeed/LiteSpeed vhosts, .htaccess rewrites, databases, email, and DNS.',
        'formats': 'Live CyberPanel / SSH, backup-*.tar.gz, meta.xml',
        'module': 'services.migrators.cyberpanel',
        'apt_packages': ['zstd', 'sshpass'],
        'supports_remote': True,
        'available': False,
        'version': 'Planned',
    },
    {
        'id': 'plesk',
        'name': 'Plesk',
        'description': 'Migrate Plesk XML + archive dumps (domains, databases, mailboxes, DNS zones).',
        'formats': 'Plesk dump (.tar / .tgz / .tzst + XML)',
        'module': 'services.migrators.plesk',
        'apt_packages': ['zstd'],
        'supports_remote': False,
        'available': False,
        'version': 'Planned',
    },
    {
        'id': 'directadmin',
        'name': 'DirectAdmin',
        'description': 'Migrate DirectAdmin user backup archives (domains, MySQL, email, DNS, cron).',
        'formats': 'user.admin.*.tar.gz / .tar.zst',
        'module': 'services.migrators.directadmin',
        'apt_packages': ['zstd'],
        'supports_remote': False,
        'available': False,
        'version': 'Planned',
    },
    {
        'id': 'hestiacp',
        'name': 'HestiaCP / VestaCP',
        'description': 'Migrate HestiaCP and VestaCP user backup archives (web, db, mail, dns, cron).',
        'formats': 'user.*.tar / .tar.zst',
        'module': 'services.migrators.hestiacp',
        'apt_packages': ['zstd'],
        'supports_remote': False,
        'available': False,
        'version': 'Planned',
    },
]


def get_staging_dir(migrator_id: str = '') -> Path:
    """Return writable staging directory for migration uploads & temporary extraction."""
    base = Path('/var/lib/w3panel/migrations')
    try:
        base.mkdir(parents=True, exist_ok=True)
        probe = base / '.write_test'
        probe.write_text('ok')
        probe.unlink()
    except Exception:
        base = Path('/tmp/w3panel/migrations')
        base.mkdir(parents=True, exist_ok=True)
    if migrator_id:
        sub = base / migrator_id
        sub.mkdir(parents=True, exist_ok=True)
        return sub
    return base


def get_installed_migrator_ids() -> list[str]:
    """Return list of installed migrator IDs from SystemSetting."""
    raw = SystemSetting.get(INSTALLED_SETTING_KEY, '[]')
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(x) for x in data]
    except (json.JSONDecodeError, TypeError):
        pass
    return []


def _save_installed_migrator_ids(ids: list[str]) -> None:
    unique = list(dict.fromkeys(ids))
    SystemSetting.set(INSTALLED_SETTING_KEY, json.dumps(unique))


def get_migrator_meta(migrator_id: str) -> dict | None:
    for item in MIGRATOR_CATALOG:
        if item['id'] == migrator_id:
            return item
    return None


def is_migrator_installed(migrator_id: str) -> bool:
    meta = get_migrator_meta(migrator_id)
    if not meta or not meta.get('available'):
        return False
    return migrator_id in get_installed_migrator_ids()


def list_migrators() -> list[dict]:
    """Return catalog enriched with installation state."""
    installed = set(get_installed_migrator_ids())
    result = []
    for item in MIGRATOR_CATALOG:
        entry = dict(item)
        entry['installed'] = bool(item['available'] and item['id'] in installed)
        result.append(entry)
    return result


def _ensure_apt_packages(packages: list[str]) -> list[str]:
    """Install missing OS helper packages on demand when running as root or passwordless sudo."""
    missing = [pkg for pkg in packages if not shutil.which(pkg)]
    if not missing:
        return []
    from services.webserver.manager import _has_sudo
    if os.geteuid() != 0 and not _has_sudo():
        return missing

    prefix = [] if os.geteuid() == 0 else ['sudo', '-n']
    try:
        subprocess.run(prefix + ['env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'update', '-qq'], capture_output=True, timeout=60)
        subprocess.run(prefix + ['env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', 'install', '-y', '-qq'] + missing, capture_output=True, timeout=180)
    except Exception as e:
        logger.warning('Optional migrator package install warning (%s): %s', missing, e)
    return [pkg for pkg in missing if not shutil.which(pkg)]


def install_migrator(migrator_id: str) -> dict:
    """Install and enable a specific panel migrator plugin."""
    meta = get_migrator_meta(migrator_id)
    if not meta:
        return {'success': False, 'error': f'Unknown migrator: {migrator_id}'}
    if not meta.get('available'):
        return {'success': False, 'error': f'{meta["name"]} migrator is not yet available.'}

    try:
        mod = import_module(meta['module'])
        if not hasattr(mod, 'inspect') or not hasattr(mod, 'iter_migrate'):
            return {'success': False, 'error': f'Migrator module {meta["module"]} does not implement plugin contract.'}
    except Exception as e:
        logger.exception('Failed to load migrator module %s', meta['module'])
        return {'success': False, 'error': f'Failed to load migrator module: {e}'}

    missing_pkgs = _ensure_apt_packages(meta.get('apt_packages', []))

    installed = get_installed_migrator_ids()
    if migrator_id not in installed:
        installed.append(migrator_id)
        _save_installed_migrator_ids(installed)

    return {'success': True, 'migrator_id': migrator_id, 'missing_optional_packages': missing_pkgs}


def uninstall_migrator(migrator_id: str) -> dict:
    """Uninstall a migrator plugin and remove its temporary staging files."""
    meta = get_migrator_meta(migrator_id)
    if not meta:
        return {'success': False, 'error': f'Unknown migrator: {migrator_id}'}

    installed = [m for m in get_installed_migrator_ids() if m != migrator_id]
    _save_installed_migrator_ids(installed)

    staging = get_staging_dir() / migrator_id
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)

    return {'success': True, 'migrator_id': migrator_id}


def get_migrator(migrator_id: str):
    """Lazily import and return the installed migrator plugin module."""
    if not is_migrator_installed(migrator_id):
        raise ValueError(f'Migrator "{migrator_id}" is not installed.')
    meta = get_migrator_meta(migrator_id)
    return import_module(meta['module'])
