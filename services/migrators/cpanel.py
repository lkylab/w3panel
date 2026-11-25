"""
W3Panel v2 — cPanel / WHM (cpmove) Account Migrator
Parses real cPanel pkgacct/cpmove tarballs or extracted directories and migrates:
- Account user, email, shell access, and hosting package limits
- Primary, addon, and subdomain websites with files, PHP version, and framework detection
- MySQL/MariaDB databases, database users, and SQL dumps
- Email accounts (passwd/quota) and Maildir messages
- BIND RFC 1035 DNS zones (with optional A-record IP remapping)
- ProFTPD sub-FTP accounts
- User cron jobs
- Domain SSL certificates & private keys
"""
import gzip
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from django.db import transaction

from packages.core.models import (
    AuditLog,
    CronJob,
    Database,
    DNSRecord,
    FTPAccount,
    Mailbox,
    Package,
    SystemSetting,
    User,
    Website,
)

logger = logging.getLogger('w3panel.migrators.cpanel')

SKIP_DB_NAMES = {'mysql', 'information_schema', 'performance_schema', 'sys', 'horde', 'roundcube'}
SUPPORTED_PHP_VERSIONS = {'7.4', '8.0', '8.1', '8.2', '8.3', '8.4'}
SUPPORTED_DNS_TYPES = {'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV'}


# ---------------------------------------------------------------------------
# Archive Abstraction (tarfile or extracted directory) with Zip-Slip Safety
# ---------------------------------------------------------------------------

def _is_safe_relpath(rel: str) -> bool:
    """Reject absolute paths, parent traversal, and null bytes."""
    if not rel or '\x00' in rel:
        return False
    p = Path(rel)
    if p.is_absolute():
        return False
    return '..' not in p.parts


class _CpanelSource:
    """Unified reader over a cPanel tar archive or an already-extracted directory."""

    def __init__(self, source_path: str | Path):
        self.source_path = Path(source_path)
        if not self.source_path.exists():
            raise FileNotFoundError(f'Source path does not exist: {self.source_path}')

        self.is_dir = self.source_path.is_dir()
        self.tar: tarfile.TarFile | None = None
        self._members_by_name: dict[str, tarfile.TarInfo] = {}
        self.root_prefix = ''
        self.username = ''

        if not self.is_dir:
            if not tarfile.is_tarfile(self.source_path):
                raise ValueError(f'Unsupported cPanel archive format: {self.source_path.name}')
            self.tar = tarfile.open(self.source_path, 'r:*')
            for member in self.tar.getmembers():
                norm = member.name.lstrip('./')
                if not norm or not _is_safe_relpath(norm):
                    continue
                if member.issym() or member.islnk():
                    link_target = member.linkname
                    if link_target.startswith('/') or '..' in Path(link_target).parts:
                        continue
                self._members_by_name[norm] = member

        self.root_prefix, self.username = self._detect_root_and_user()

    def close(self):
        if self.tar is not None:
            self.tar.close()
            self.tar = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def _detect_root_and_user(self) -> tuple[str, str]:
        """Locate the cpmove root directory prefix and source account username."""
        markers = {'cp', 'userdata', 'homedir', 'mysql', 'dnszones', 'passwd', 'quota'}
        if self.is_dir:
            entries = {p.name for p in self.source_path.iterdir()}
            if entries & markers:
                name = self.source_path.name
                user = name[7:] if name.startswith('cpmove-') else name
                return '', _infer_username_from_dir(self.source_path, user)
            for child in self.source_path.iterdir():
                if child.is_dir():
                    child_entries = {p.name for p in child.iterdir()}
                    if child_entries & markers:
                        name = child.name
                        user = name[7:] if name.startswith('cpmove-') else name
                        return f'{name}/', _infer_username_from_dir(child, user)
            raise ValueError('Could not locate cPanel backup structure (cp/homedir/userdata/mysql).')

        # Tar archive: inspect top 2 path levels
        top_children: dict[str, set[str]] = {}
        root_entries: set[str] = set()
        for name in self._members_by_name:
            parts = name.split('/')
            root_entries.add(parts[0])
            if len(parts) >= 2:
                top_children.setdefault(parts[0], set()).add(parts[1])

        if root_entries & markers:
            return '', self._infer_username_from_tar('')

        for top_dir, sub_entries in top_children.items():
            if sub_entries & markers:
                prefix = f'{top_dir}/'
                guess = top_dir[7:] if top_dir.startswith('cpmove-') else top_dir
                return prefix, self._infer_username_from_tar(prefix, fallback=guess)

        raise ValueError('Could not locate cPanel backup structure inside archive.')

    def _infer_username_from_tar(self, prefix: str, fallback: str = '') -> str:
        cp_prefix = f'{prefix}cp/'
        for name, m in self._members_by_name.items():
            if name.startswith(cp_prefix) and m.isfile():
                fname = name[len(cp_prefix):]
                if '/' not in fname and not fname.endswith('.json') and fname:
                    return fname
        passwd_text = self.read_text_raw(f'{prefix}passwd')
        if passwd_text:
            first = passwd_text.strip().splitlines()[0]
            if ':' in first:
                return first.split(':', 1)[0].strip()
        return fallback

    def _full(self, rel_path: str) -> str:
        rel_path = rel_path.lstrip('/')
        return f'{self.root_prefix}{rel_path}'

    def list_files(self, rel_dir: str) -> list[str]:
        """Return archive paths relative to root_prefix inside rel_dir."""
        target = self._full(rel_dir).rstrip('/')
        prefix = f'{target}/' if target else ''
        out = []
        if self.is_dir:
            base = self.source_path / target if target else self.source_path
            if not base.exists() or not base.is_dir():
                return []
            root_base = self.source_path / self.root_prefix.rstrip('/') if self.root_prefix else self.source_path
            for p in base.rglob('*'):
                if p.is_file():
                    out.append(str(p.relative_to(root_base)).replace('\\', '/'))
            return sorted(out)

        root_len = len(self.root_prefix)
        for name, member in self._members_by_name.items():
            if member.isfile() and name.startswith(prefix):
                out.append(name[root_len:])
        return sorted(out)

    def exists(self, rel_path: str) -> bool:
        full = self._full(rel_path).rstrip('/')
        if self.is_dir:
            return (self.source_path / full).exists()
        return full in self._members_by_name or any(n.startswith(f'{full}/') for n in self._members_by_name)

    def read_bytes(self, rel_path: str) -> bytes | None:
        return self.read_bytes_raw(self._full(rel_path))

    def read_bytes_raw(self, full_path: str) -> bytes | None:
        if self.is_dir:
            p = self.source_path / full_path
            if p.is_file():
                return p.read_bytes()
            return None
        member = self._members_by_name.get(full_path)
        if not member or not member.isfile() or self.tar is None:
            return None
        fh = self.tar.extractfile(member)
        return fh.read() if fh else None

    def read_text(self, rel_path: str) -> str | None:
        return self.read_text_raw(self._full(rel_path))

    def read_text_raw(self, full_path: str) -> str | None:
        raw = self.read_bytes_raw(full_path)
        if raw is None:
            return None
        return raw.decode('utf-8', errors='replace')

    def extract_subtree(self, rel_dir: str, dest_dir: Path) -> int:
        """Safely copy/extract files from rel_dir (relative to root_prefix) into dest_dir."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        rel_dir = rel_dir.strip('/')
        full_prefix = self._full(rel_dir).rstrip('/')
        prefix_slash = f'{full_prefix}/'
        count = 0

        if self.is_dir:
            src = self.source_path / full_prefix
            if not src.exists():
                return 0
            if src.is_file():
                shutil.copy2(src, dest_dir / src.name)
                return 1
            for item in src.rglob('*'):
                rel = item.relative_to(src)
                if not _is_safe_relpath(str(rel)):
                    continue
                target = (dest_dir / rel).resolve()
                if dest_dir.resolve() not in target.parents and target != dest_dir.resolve():
                    continue
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                elif item.is_file() and not item.is_symlink():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, target)
                    count += 1
            return count

        dest_resolved = dest_dir.resolve()
        for name, member in self._members_by_name.items():
            if not (name == full_prefix or name.startswith(prefix_slash)):
                continue
            sub_rel = name[len(prefix_slash):] if name.startswith(prefix_slash) else Path(name).name
            if not sub_rel or not _is_safe_relpath(sub_rel):
                continue
            target = (dest_dir / sub_rel).resolve()
            if dest_resolved not in target.parents and target != dest_resolved:
                continue
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile() and self.tar is not None:
                target.parent.mkdir(parents=True, exist_ok=True)
                fh = self.tar.extractfile(member)
                if fh:
                    with open(target, 'wb') as out_f:
                        shutil.copyfileobj(fh, out_f)
                    count += 1
        return count


def _infer_username_from_dir(root_dir: Path, fallback: str = '') -> str:
    cp_dir = root_dir / 'cp'
    if cp_dir.is_dir():
        for p in cp_dir.iterdir():
            if p.is_file() and not p.name.endswith('.json'):
                return p.name
    passwd_file = root_dir / 'passwd'
    if passwd_file.is_file():
        lines = passwd_file.read_text(errors='replace').strip().splitlines()
        if lines and ':' in lines[0]:
            return lines[0].split(':', 1)[0].strip()
    return fallback


# ---------------------------------------------------------------------------
# Format Parsers (YAML subset, cp key=value, BIND zones, passwd, cron, SQL)
# ---------------------------------------------------------------------------

def _unquote(val: str) -> str:
    val = val.strip()
    if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
        return val[1:-1]
    return val


def _parse_cpanel_yaml(text: str) -> dict:
    """
    Lightweight pure-Python parser for cPanel userdata YAML files
    (handles scalars, lists, nested mappings like addon_domains / customlog).
    """
    result: dict = {}
    if not text:
        return result

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        i += 1
        if not stripped or stripped == '---' or stripped.startswith('#'):
            continue
        indent = len(raw) - len(raw.lstrip(' '))
        if indent != 0 or ':' not in stripped:
            continue

        key, rest = stripped.split(':', 1)
        key = _unquote(key)
        rest = rest.strip()
        if rest and rest not in ('{}', '[]'):
            result[key] = _unquote(rest)
            continue

        if rest == '{}':
            result[key] = {}
            continue
        if rest == '[]':
            result[key] = []
            continue

        # Collect indented block
        block_lines = []
        while i < len(lines):
            nxt = lines[i]
            nxt_stripped = nxt.strip()
            if not nxt_stripped or nxt_stripped.startswith('#'):
                i += 1
                continue
            nxt_indent = len(nxt) - len(nxt.lstrip(' '))
            if nxt_indent <= indent:
                break
            block_lines.append(nxt)
            i += 1

        if not block_lines:
            result[key] = {}
            continue

        first_content = block_lines[0].strip()
        if first_content.startswith('- '):
            items = []
            for bl in block_lines:
                s = bl.strip()
                if s.startswith('- '):
                    item_val = s[2:].strip()
                    if ':' in item_val and not item_val.startswith(('http://', 'https://')):
                        k2, v2 = item_val.split(':', 1)
                        items.append({_unquote(k2): _unquote(v2)})
                    else:
                        items.append(_unquote(item_val))
            result[key] = items
        else:
            mapping = {}
            for bl in block_lines:
                s = bl.strip()
                if ':' in s:
                    k2, v2 = s.split(':', 1)
                    mapping[_unquote(k2)] = _unquote(v2)
            result[key] = mapping

    return result


def _parse_kv_lines(text: str) -> dict[str, str]:
    data = {}
    if not text:
        return data
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        data[k.strip()] = v.strip()
    return data


def _map_cpanel_php_version(raw_php: str, default_php: str = '8.3') -> str:
    if not raw_php or raw_php == 'inherit':
        return default_php
    m = re.search(r'(\d+)\.?(\d+)', raw_php)
    if m:
        ver = f'{m.group(1)}.{m.group(2)}'
        if ver in SUPPORTED_PHP_VERSIONS:
            return ver
    return default_php


def _normalize_doc_root_rel(doc_root: str, old_username: str, homedir_val: str = '') -> str:
    """Convert cPanel absolute doc_root (/home/user/public_html/sub) to homedir-relative path."""
    if not doc_root:
        return 'public_html'
    clean = doc_root.strip().rstrip('/')
    candidates = []
    if homedir_val:
        candidates.append(homedir_val.rstrip('/') + '/')
    if old_username:
        candidates.append(f'/home/{old_username}/')
        candidates.append(f'/home2/{old_username}/')
    for prefix in candidates:
        if clean.startswith(prefix):
            return clean[len(prefix):].lstrip('/') or 'public_html'
    m = re.match(r'^/home\d*/[^/]+/(.+)$', clean)
    if m:
        return m.group(1).lstrip('/')
    return clean.lstrip('/') or 'public_html'


def _detect_framework_in_source(src: _CpanelSource, rel_doc_root: str) -> str:
    base = f'homedir/{rel_doc_root}'.rstrip('/')
    if src.exists(f'{base}/wp-config.php') or src.exists(f'{base}/wp-includes/version.php'):
        return 'wordpress'
    if src.exists(f'{base}/artisan') or (rel_doc_root.endswith('/public') and src.exists(f'homedir/{rel_doc_root[:-7]}/artisan')):
        return 'laravel'
    if src.exists(f'{base}/package.json') and not src.exists(f'{base}/index.php'):
        return 'nodejs'
    return 'none'


def _extract_app_db_credentials(doc_root: Path) -> list[dict]:
    """Scan wp-config.php or Laravel .env in doc_root for DB name/user/password."""
    creds = []
    wp_cfg = doc_root / 'wp-config.php'
    if wp_cfg.is_file():
        text = wp_cfg.read_text(errors='replace')
        def _wp_define(key):
            m = re.search(rf"define\s*\(\s*['\"]{key}['\"]\s*,\s*['\"]([^'\"]*)['\"]", text)
            return m.group(1) if m else ''
        db_name = _wp_define('DB_NAME')
        db_user = _wp_define('DB_USER')
        db_pass = _wp_define('DB_PASSWORD')
        if db_name and db_user:
            creds.append({'db_name': db_name, 'db_user': db_user, 'db_pass': db_pass})

    for env_candidate in (doc_root / '.env', doc_root.parent / '.env'):
        if env_candidate.is_file():
            kv = _parse_kv_lines(env_candidate.read_text(errors='replace'))
            db_name = _unquote(kv.get('DB_DATABASE', ''))
            db_user = _unquote(kv.get('DB_USERNAME', ''))
            db_pass = _unquote(kv.get('DB_PASSWORD', ''))
            if db_name and db_user:
                creds.append({'db_name': db_name, 'db_user': db_user, 'db_pass': db_pass})
    return creds


def _parse_bind_zone(zone_text: str, domain: str) -> list[dict]:
    """Parse a BIND RFC 1035 zone file into W3Panel DNSRecord dicts."""
    if not zone_text:
        return []

    # Strip comments outside quotes and collapse multi-line parentheses
    cleaned_lines = []
    paren_depth = 0
    buf = []
    for raw_line in zone_text.splitlines():
        in_quote = False
        chars = []
        for ch in raw_line:
            if ch == '"':
                in_quote = not in_quote
                chars.append(ch)
            elif ch == ';' and not in_quote:
                break
            else:
                if not in_quote:
                    if ch == '(':
                        paren_depth += 1
                        chars.append(' ')
                        continue
                    elif ch == ')' and paren_depth > 0:
                        paren_depth -= 1
                        chars.append(' ')
                        continue
                chars.append(ch)
        line = ''.join(chars).rstrip()
        if paren_depth > 0:
            buf.append(line)
        else:
            if buf:
                buf.append(line)
                cleaned_lines.append(' '.join(buf))
                buf = []
            else:
                cleaned_lines.append(line)
    if buf:
        cleaned_lines.append(' '.join(buf))

    default_ttl = 3600
    origin = f'{domain}.'
    last_owner = '@'
    records = []

    for line in cleaned_lines:
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()
        if upper.startswith('$TTL'):
            parts = stripped.split()
            if len(parts) >= 2 and parts[1].isdigit():
                default_ttl = int(parts[1])
            continue
        if upper.startswith('$ORIGIN'):
            parts = stripped.split()
            if len(parts) >= 2:
                origin = parts[1]
            continue

        # Tokenize keeping quoted strings intact
        tokens = re.findall(r'"[^"]*"|\S+', stripped)
        if not tokens:
            continue

        starts_with_ws = line[0].isspace()
        idx = 0
        if starts_with_ws:
            owner = last_owner
        else:
            owner = tokens[0]
            idx = 1
            last_owner = owner

        ttl = default_ttl
        while idx < len(tokens):
            tok = tokens[idx]
            if tok.isdigit():
                ttl = int(tok)
                idx += 1
            elif tok.upper() in ('IN', 'CH', 'HS'):
                idx += 1
            else:
                break

        if idx >= len(tokens):
            continue

        rtype = tokens[idx].upper()
        idx += 1
        if rtype not in SUPPORTED_DNS_TYPES:
            continue

        rdata = tokens[idx:]
        if not rdata:
            continue

        # Normalize owner name relative to domain
        norm_owner = owner
        if norm_owner == origin or norm_owner == f'{domain}.' or norm_owner == domain:
            norm_owner = '@'
        elif norm_owner.endswith(f'.{domain}.'):
            norm_owner = norm_owner[:-(len(domain) + 2)] or '@'
        elif norm_owner.endswith('.'):
            norm_owner = norm_owner[:-1] or '@'

        priority = None
        if rtype == 'MX' and len(rdata) >= 2 and rdata[0].isdigit():
            priority = int(rdata[0])
            val = rdata[1].rstrip('.')
        elif rtype == 'TXT':
            # Join multiple quoted TXT strings
            val = ''.join(t[1:-1] if (len(t) >= 2 and t.startswith('"') and t.endswith('"')) else t for t in rdata)
        elif rtype in ('CNAME', 'NS'):
            val = rdata[0].rstrip('.')
        elif rtype == 'SRV' and len(rdata) >= 4 and rdata[0].isdigit():
            priority = int(rdata[0])
            val = ' '.join(rdata[1:]).rstrip('.')
        else:
            val = ' '.join(rdata)

        if val:
            records.append({
                'name': norm_owner[:255],
                'record_type': rtype,
                'value': val[:512],
                'ttl': ttl,
                'priority': priority,
            })

    return records


def _parse_mysql_grants(mysql_sql: str, db_json_text: str | None) -> tuple[dict[str, list[str]], dict[str, str]]:
    """
    Return (db_to_users, user_to_hash) from mysql.sql and optional db.json.
    """
    db_to_users: dict[str, list[str]] = {}
    user_to_hash: dict[str, str] = {}

    if db_json_text:
        try:
            data = json.loads(db_json_text)
            for item in data.get('databases', []):
                dname = item.get('name', '').strip()
                duser = item.get('user', '').strip()
                if dname and duser:
                    db_to_users.setdefault(dname, [])
                    if duser not in db_to_users[dname]:
                        db_to_users[dname].append(duser)
        except json.JSONDecodeError:
            pass

    if mysql_sql:
        # Match GRANT ... ON `db`.* TO 'user'@'host' ... [IDENTIFIED BY PASSWORD '*...']
        grant_re = re.compile(
            r"GRANT\s+.+?\s+ON\s+[`'\"]?([A-Za-z0-9_]+)[`'\"]?\.\*\s+TO\s+['\"]([^'\"]+)['\"]@['\"][^'\"]+['\"]"
            r"(?:.*?IDENTIFIED\s+BY\s+PASSWORD\s+['\"]([^'\"]+)['\"])?",
            re.IGNORECASE,
        )
        for m in grant_re.finditer(mysql_sql):
            dname, duser, phash = m.group(1), m.group(2), m.group(3)
            if dname not in SKIP_DB_NAMES:
                db_to_users.setdefault(dname, [])
                if duser not in db_to_users[dname]:
                    db_to_users[dname].append(duser)
            if phash and duser not in user_to_hash:
                user_to_hash[duser] = phash

        # Match CREATE USER 'user'@'host' IDENTIFIED ... AS '*...'
        user_re = re.compile(
            r"CREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?['\"]([^'\"]+)['\"]@['\"][^'\"]+['\"].*?(?:PASSWORD\s+|AS\s+)['\"]([^'\"]+)['\"]",
            re.IGNORECASE,
        )
        for m in user_re.finditer(mysql_sql):
            duser, phash = m.group(1), m.group(2)
            if phash and duser not in user_to_hash:
                user_to_hash[duser] = phash

    return db_to_users, user_to_hash


# ---------------------------------------------------------------------------
# Public Inspect API
# ---------------------------------------------------------------------------

def inspect_cpanel_archive(source_path: str | Path) -> dict:
    """
    Parse a cPanel cpmove archive or extracted directory without altering the system.
    Returns structured manifest data for preview & selection.
    """
    default_php = SystemSetting.get('default_php', '8.3')
    warnings = []

    with _CpanelSource(source_path) as src:
        username = src.username or 'migrated_user'
        cp_data = _parse_kv_lines(src.read_text(f'cp/{username}') or '')

        contact_json_text = src.read_text('cp/contact_info.json')
        contact_json = {}
        if contact_json_text:
            try:
                contact_json = json.loads(contact_json_text)
            except json.JSONDecodeError:
                pass

        email = cp_data.get('CONTACTEMAIL') or contact_json.get('CONTACTEMAIL') or f'{username}@localhost'
        old_ip = cp_data.get('IP', '').strip()
        plan_name = cp_data.get('PLAN', '').strip()

        # Shell status from passwd or cp file
        shell_enabled = False
        passwd_text = src.read_text('passwd') or ''
        for line in passwd_text.splitlines():
            parts = line.split(':')
            if len(parts) >= 7 and parts[0].strip() == username:
                sh_val = parts[6].strip()
                shell_enabled = sh_val in ('/bin/bash', '/bin/sh', '/bin/zsh')
                break
        if cp_data.get('DEMO') == '1':
            warnings.append('Source cPanel account is marked DEMO=1.')

        # Quota (bytes -> MB)
        quota_mb = -1
        quota_text = (src.read_text('quota') or '').strip()
        if quota_text.isdigit() and int(quota_text) > 0:
            quota_mb = max(1, int(int(quota_text) / (1024 * 1024)))

        bwlimit_gb = -1
        bw_raw = cp_data.get('BWLIMIT', '').strip()
        if bw_raw.isdigit() and int(bw_raw) > 0:
            bwlimit_gb = max(1, int(int(bw_raw) / (1024 * 1024 * 1024)))

        def _parse_limit(key: str) -> int:
            val = cp_data.get(key, '').strip().lower()
            if val.isdigit():
                return int(val)
            return -1

        # Domains: parse userdata/main or userdata/{username}/main, plus cp DNS keys, sds2, addons
        userdata_prefix = f'userdata/{username}' if src.exists(f'userdata/{username}/main') else 'userdata'
        main_yaml = _parse_cpanel_yaml(src.read_text(f'{userdata_prefix}/main') or '')

        main_domain = (main_yaml.get('main_domain') or cp_data.get('DNS') or '').strip().lower()
        addon_map: dict[str, str] = {}
        raw_addons = main_yaml.get('addon_domains')
        if isinstance(raw_addons, dict):
            for k, v in raw_addons.items():
                addon_map[k.strip().lower()] = v.strip().lower()
        elif isinstance(raw_addons, list):
            for entry in raw_addons:
                if isinstance(entry, dict):
                    for k, v in entry.items():
                        addon_map[k.strip().lower()] = v.strip().lower()

        parked_domains = [
            d.strip().lower()
            for d in (main_yaml.get('parked_domains') or [])
            if isinstance(d, str) and d.strip()
        ]
        internal_addon_subs = set(addon_map.values())
        sub_domains = [
            d.strip().lower()
            for d in (main_yaml.get('sub_domains') or [])
            if isinstance(d, str) and d.strip() and d.strip().lower() not in internal_addon_subs
        ]

        # Fallback to cp/{user} DNS1..DNSn and addons / sds2 if userdata/main is absent
        if not main_domain and cp_data.get('DNS'):
            main_domain = cp_data['DNS'].strip().lower()
        for k, v in cp_data.items():
            if re.match(r'^DNS\d+$', k) and v.strip():
                dom = v.strip().lower()
                if dom != main_domain and dom not in addon_map and dom not in sub_domains and dom not in parked_domains:
                    addon_map[dom] = dom

        sds2_map = {}
        for sds_file in ('sds2', 'sds'):
            sds_text = src.read_text(sds_file) or ''
            for line in sds_text.splitlines():
                if ':' in line:
                    sd, path_rel = line.split(':', 1)
                    sds2_map[sd.strip().lower()] = path_rel.strip().lstrip('/')

        ordered_domains: list[tuple[str, str]] = []
        seen_doms = set()
        if main_domain:
            ordered_domains.append((main_domain, 'primary'))
            seen_doms.add(main_domain)
        for ad in addon_map:
            if ad not in seen_doms:
                ordered_domains.append((ad, 'addon'))
                seen_doms.add(ad)
        for sd in sub_domains:
            if sd not in seen_doms:
                ordered_domains.append((sd, 'subdomain'))
                seen_doms.add(sd)

        # Fallback if still empty: inspect dnszones/
        if not ordered_domains:
            for zf in src.list_files('dnszones'):
                if zf.endswith('.db'):
                    dom = Path(zf).name[:-3].lower()
                    if dom not in seen_doms:
                        ordered_domains.append((dom, 'primary' if not ordered_domains else 'addon'))
                        seen_doms.add(dom)

        domains_info = []
        ssl_certs = []
        for dom, kind in ordered_domains:
            dom_yaml = _parse_cpanel_yaml(src.read_text(f'{userdata_prefix}/{dom}') or '')
            if not dom_yaml and kind == 'addon' and addon_map.get(dom):
                dom_yaml = _parse_cpanel_yaml(src.read_text(f'{userdata_prefix}/{addon_map[dom]}') or '')

            if not old_ip and dom_yaml.get('ip'):
                old_ip = dom_yaml['ip']

            raw_doc_root = dom_yaml.get('documentroot', '')
            if raw_doc_root:
                rel_doc_root = _normalize_doc_root_rel(raw_doc_root, username, dom_yaml.get('homedir', ''))
            elif dom in sds2_map:
                rel_doc_root = sds2_map[dom]
            elif kind == 'primary':
                rel_doc_root = 'public_html'
            else:
                rel_doc_root = f'public_html/{dom}'

            php_ver = _map_cpanel_php_version(dom_yaml.get('phpversion', ''), default_php)
            framework = _detect_framework_in_source(src, rel_doc_root)

            has_htaccess = src.exists(f'homedir/{rel_doc_root}/.htaccess')
            has_ssl = _find_ssl_pair(src, dom) is not None
            if has_ssl:
                ssl_certs.append(dom)

            domains_info.append({
                'domain': dom,
                'kind': kind,
                'source_doc_root': rel_doc_root,
                'php_version': php_ver,
                'framework': framework,
                'has_htaccess': has_htaccess,
                'has_ssl': has_ssl,
            })

        # Databases
        mysql_sql = src.read_text('mysql.sql') or ''
        db_json_text = src.read_text('mysql/db.json') or src.read_text('db.json')
        db_to_users, _ = _parse_mysql_grants(mysql_sql, db_json_text)

        databases = []
        for mf in src.list_files('mysql'):
            fname = Path(mf).name
            if fname.endswith('.sql'):
                db_name = fname[:-4]
            elif fname.endswith('.sql.gz'):
                db_name = fname[:-7]
            else:
                continue
            if db_name.lower() in SKIP_DB_NAMES:
                continue
            users = db_to_users.get(db_name, [])
            databases.append({
                'name': db_name,
                'archive_path': mf,
                'db_user': users[0] if users else db_name[:64],
                'all_users': users,
            })

        # Mailboxes (homedir/etc/{domain}/passwd + quota)
        mailboxes = []
        etc_files = src.list_files('homedir/etc')
        seen_emails = set()
        for ef in etc_files:
            parts = ef.split('/')
            # homedir/etc/{domain}/passwd
            if len(parts) == 4 and parts[3] == 'passwd':
                mail_domain = parts[2].lower()
                quota_map = {}
                q_text = src.read_text(f'homedir/etc/{mail_domain}/quota') or ''
                for ql in q_text.splitlines():
                    if ':' in ql:
                        qu, qbytes = ql.split(':', 1)
                        qbytes = qbytes.strip()
                        if qbytes.isdigit() and int(qbytes) > 0:
                            quota_map[qu.strip()] = max(1, int(int(qbytes) / (1024 * 1024)))
                p_text = src.read_text(ef) or ''
                for pl in p_text.splitlines():
                    if ':' not in pl:
                        continue
                    localpart = pl.split(':', 1)[0].strip()
                    if not localpart:
                        continue
                    email_addr = f'{localpart}@{mail_domain}'
                    if email_addr in seen_emails:
                        continue
                    seen_emails.add(email_addr)
                    mailboxes.append({
                        'email': email_addr,
                        'domain': mail_domain,
                        'localpart': localpart,
                        'quota_mb': quota_map.get(localpart, 1024),
                        'has_maildir': src.exists(f'homedir/mail/{mail_domain}/{localpart}'),
                    })

        # DNS zones
        dns_zones = []
        for zf in src.list_files('dnszones'):
            if zf.endswith('.db'):
                zdom = Path(zf).name[:-3].lower()
                recs = _parse_bind_zone(src.read_text(zf) or '', zdom)
                dns_zones.append({
                    'domain': zdom,
                    'archive_path': zf,
                    'records_count': len(recs),
                })

        # FTP accounts
        ftp_accounts = []
        ftp_text = src.read_text('proftpdpasswd') or ''
        for line in ftp_text.splitlines():
            parts = line.split(':')
            if len(parts) >= 6 and parts[0].strip():
                ftp_user = parts[0].strip()
                if ftp_user == username:
                    continue
                ftp_accounts.append({
                    'username': ftp_user,
                    'source_directory': parts[5].strip(),
                })

        # Cron jobs
        cron_jobs = _parse_cpanel_cron(src.read_text(f'cron/{username}') or '', username)

        return {
            'panel': 'cpanel',
            'username': username,
            'email': email,
            'shell_enabled': shell_enabled,
            'old_ip': old_ip,
            'plan_name': plan_name,
            'quota_mb': quota_mb,
            'bwlimit_gb': bwlimit_gb,
            'limits': {
                'databases': _parse_limit('MAXSQL'),
                'email': _parse_limit('MAXPOP'),
                'ftp': _parse_limit('MAXFTP'),
            },
            'domains': domains_info,
            'parked_domains': parked_domains,
            'databases': databases,
            'mailboxes': mailboxes,
            'dns_zones': dns_zones,
            'ftp_accounts': ftp_accounts,
            'cron_jobs': cron_jobs,
            'ssl_certs': ssl_certs,
            'warnings': warnings,
        }


def _find_ssl_pair(src: _CpanelSource, domain: str) -> tuple[str, str] | None:
    """Find matching SSL cert and private key paths inside the cPanel archive."""
    cert_candidates = []
    key_candidates = []
    for folder in ('sslcerts', 'ssl', 'homedir/ssl/certs'):
        for f in src.list_files(folder):
            name = Path(f).name.lower()
            if name.startswith(domain) and (name.endswith('.crt') or name.endswith('.pem')):
                cert_candidates.append(f)
    for folder in ('sslkeys', 'ssl', 'homedir/ssl/keys'):
        for f in src.list_files(folder):
            name = Path(f).name.lower()
            if name.startswith(domain) and name.endswith('.key'):
                key_candidates.append(f)

    if cert_candidates and key_candidates:
        return cert_candidates[0], key_candidates[0]
    return None


def _parse_cpanel_cron(cron_text: str, username: str) -> list[dict]:
    jobs = []
    if not cron_text:
        return jobs
    for line in cron_text.splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', s):
            continue
        if s.startswith('@'):
            parts = s.split(None, 1)
            if len(parts) == 2:
                jobs.append({'schedule': parts[0], 'command': parts[1]})
            continue
        parts = s.split(None, 5)
        if len(parts) == 6:
            jobs.append({'schedule': ' '.join(parts[:5]), 'command': parts[5]})
    return jobs


# ---------------------------------------------------------------------------
# Migration Execution
# ---------------------------------------------------------------------------

def iter_migrate_cpanel_archive(source_path: str | Path, options: dict | None = None):
    """
    Generator executing migration from a cPanel cpmove archive or extracted directory into W3Panel.
    Yields progress dicts: {'percent': int, 'step': str, 'line': str}
    and finishes by yielding {'percent': 100, 'step': 'Migration completed', 'complete': True, 'summary': dict}.
    """
    from services.webserver import (
        create_user_php_pool,
        create_vhost,
        get_doc_root,
        sync_system_user_password,
        sync_system_user_shell,
    )
    from services.webserver.manager import _get_users_base_dir, _has_sudo, _write_privileged_file
    from services.database import create_database, generate_secure_password
    from services.mail import create_mailbox
    from services.mail.manager import VMAIL_BASE
    from services.dns import export_zone_file
    from services.ftp import create_ftp_user
    from services.cron import sync_cron_jobs
    from services.ssl.manager import _get_ssl_dir

    opts = options or {}

    def _evt(percent, step, line):
        return {'percent': percent, 'step': step, 'line': line}

    yield _evt(5, 'Inspecting cPanel archive...', f'>> Inspecting source: {source_path}')
    manifest = inspect_cpanel_archive(source_path)

    old_user = manifest['username']
    target_username = (opts.get('target_username') or old_user).strip()
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$', target_username):
        raise ValueError(f'Invalid target username: "{target_username}"')

    target_email = (opts.get('email') or manifest['email']).strip()
    skip_existing = bool(opts.get('skip_existing', False))

    import_websites = opts.get('import_websites', True)
    import_databases = opts.get('import_databases', True)
    import_mailboxes = opts.get('import_mailboxes', True)
    import_dns = opts.get('import_dns', True)
    update_dns_ip = opts.get('update_dns_ip', True)
    import_ftp = opts.get('import_ftp', True)
    import_cron = opts.get('import_cron', True)
    import_ssl = opts.get('import_ssl', True)

    summary = {
        'username': target_username,
        'account_password': '',
        'websites': [],
        'databases': [],
        'mailboxes': [],
        'dns_zones': [],
        'ftp_accounts': [],
        'cron_jobs': [],
        'ssl_certs': [],
        'warnings': list(manifest.get('warnings', [])),
    }

    with _CpanelSource(source_path) as src:
        # 1. Create or validate W3Panel user & package
        yield _evt(12, 'Provisioning user account...', f'>> Provisioning W3Panel user "{target_username}"')
        user = User.objects.filter(username=target_username).first()
        if user:
            if not skip_existing:
                raise ValueError(f'User "{target_username}" already exists. Enable "Skip existing" or choose a different username.')
            yield _evt(15, 'Using existing user account', f'>> Existing user "{target_username}" reused.')
        else:
            pkg = None
            if manifest['plan_name']:
                pkg, _ = Package.objects.get_or_create(
                    name=manifest['plan_name'][:64],
                    defaults={
                        'disk_limit_mb': manifest['quota_mb'],
                        'bandwidth_limit_gb': manifest['bwlimit_gb'],
                        'databases_limit': manifest['limits']['databases'],
                        'email_limit': manifest['limits']['email'],
                        'ftp_limit': manifest['limits']['ftp'],
                    },
                )
            account_pass = generate_secure_password(16)
            user = User.objects.create_user(
                username=target_username,
                email=target_email,
                password=account_pass,
                role='user',
                package=pkg,
                shell_enabled=manifest['shell_enabled'],
            )
            summary['account_password'] = account_pass
            sync_system_user_shell(target_username, manifest['shell_enabled'])
            sync_system_user_password(target_username, account_pass)
            yield _evt(18, 'Created user account', f'>> Created user "{target_username}" (email: {target_email})')

        # Ensure PHP pool exists even if no websites are migrated
        default_php = SystemSetting.get('default_php', '8.3')
        create_user_php_pool(username=target_username, php_version=default_php)

        # 2. Migrate websites, files, and SSL certificates
        app_db_creds: list[dict] = []
        created_websites: dict[str, Website] = {}
        users_base = _get_users_base_dir()

        if import_websites and manifest['domains']:
            total_doms = len(manifest['domains'])
            for idx, dinfo in enumerate(manifest['domains'], start=1):
                dom = dinfo['domain']
                pct = 20 + int((idx / max(total_doms, 1)) * 25)
                yield _evt(pct, f'Migrating website {dom}...', f'>> [{idx}/{total_doms}] Migrating {dom} ({dinfo["kind"]})')

                existing_site = Website.objects.filter(domain=dom).first()
                if existing_site:
                    if skip_existing:
                        created_websites[dom] = existing_site
                        summary['warnings'].append(f'Skipped existing website {dom}.')
                        continue
                    raise ValueError(f'Domain "{dom}" already exists in W3Panel.')

                framework = dinfo['framework']
                php_ver = dinfo['php_version']
                doc_root = get_doc_root(target_username, dom, framework)

                # Copy files from homedir/<rel_doc_root> into W3Panel doc_root
                src_rel = dinfo['source_doc_root']
                if framework == 'laravel' and src_rel.endswith('/public'):
                    copied = src.extract_subtree(f'homedir/{src_rel[:-7]}', doc_root.parent)
                elif framework == 'laravel' and src.exists(f'homedir/{src_rel}/public'):
                    copied = src.extract_subtree(f'homedir/{src_rel}', doc_root.parent)
                else:
                    copied = src.extract_subtree(f'homedir/{src_rel}', doc_root)

                yield _evt(pct, f'Copied files for {dom}', f'   Copied {copied} file(s) to {doc_root}')

                if doc_root.exists():
                    app_db_creds.extend(_extract_app_db_credentials(doc_root))

                if dinfo['has_htaccess']:
                    summary['warnings'].append(
                        f'{dom}: .htaccess detected; W3Panel uses Nginx (rewrite rules for WordPress/Laravel are handled automatically, review custom Apache rules).'
                    )

                # SSL certificates
                ssl_cert_path = ''
                ssl_key_path = ''
                ssl_enabled = False
                if import_ssl:
                    pair = _find_ssl_pair(src, dom)
                    if pair:
                        cert_bytes = src.read_bytes(pair[0])
                        key_bytes = src.read_bytes(pair[1])
                        if cert_bytes and key_bytes:
                            ssl_dir = _get_ssl_dir()
                            cfile = ssl_dir / f'{dom}.crt'
                            kfile = ssl_dir / f'{dom}.key'
                            cert_text = cert_bytes.decode('utf-8', errors='replace')
                            key_text = key_bytes.decode('utf-8', errors='replace')
                            if not (_write_privileged_file(cfile, cert_text) and _write_privileged_file(kfile, key_text)):
                                fallback_ssl = Path('/tmp/w3panel/ssl')
                                fallback_ssl.mkdir(parents=True, exist_ok=True)
                                cfile = fallback_ssl / f'{dom}.crt'
                                kfile = fallback_ssl / f'{dom}.key'
                                cfile.write_text(cert_text)
                                kfile.write_text(key_text)
                            try:
                                os.chmod(kfile, 0o600)
                                os.chmod(cfile, 0o644)
                            except Exception:
                                pass
                            ssl_cert_path = str(cfile)
                            ssl_key_path = str(kfile)
                            ssl_enabled = True
                            summary['ssl_certs'].append(dom)

                site = Website.objects.create(
                    owner=user,
                    domain=dom,
                    doc_root=str(doc_root),
                    php_version=php_ver,
                    framework=framework,
                    ssl_enabled=ssl_enabled,
                )
                create_vhost(site, ssl_cert=ssl_cert_path, ssl_key=ssl_key_path)

                if _has_sudo():
                    subprocess.run(['sudo', '-n', 'chown', '-R', f'{target_username}:{target_username}', str(users_base / target_username / dom)], capture_output=True, timeout=30)

                created_websites[dom] = site
                summary['websites'].append({'domain': dom, 'framework': framework, 'php_version': php_ver, 'files': copied})

            if manifest['parked_domains']:
                summary['warnings'].append(
                    f'Parked domains detected ({", ".join(manifest["parked_domains"])}): add as server_name aliases in vhost editor if needed.'
                )

        # 3. Migrate databases & SQL dumps
        if import_databases and manifest['databases']:
            cred_by_user = {c['db_user']: c['db_pass'] for c in app_db_creds if c.get('db_user') and c.get('db_pass')}
            total_dbs = len(manifest['databases'])
            for idx, db_info in enumerate(manifest['databases'], start=1):
                db_name = db_info['name'][:64]
                db_user = db_info['db_user'][:64]
                pct = 48 + int((idx / max(total_dbs, 1)) * 18)
                yield _evt(pct, f'Migrating database {db_name}...', f'>> [{idx}/{total_dbs}] Importing database {db_name}')

                if Database.objects.filter(owner=user, name=db_name).exists():
                    if skip_existing:
                        summary['warnings'].append(f'Skipped existing database {db_name}.')
                        continue
                    raise ValueError(f'Database "{db_name}" already exists for user "{target_username}".')

                db_pass = cred_by_user.get(db_user) or generate_secure_password(16)
                create_database(db_name, db_user, db_pass, db_type='mariadb')

                sql_bytes = src.read_bytes(db_info['archive_path']) or b''
                if db_info['archive_path'].endswith('.gz') and sql_bytes:
                    sql_bytes = gzip.decompress(sql_bytes)

                imported_sql = False
                if sql_bytes and (_has_sudo() or os.geteuid() == 0) and shutil.which('mysql'):
                    with tempfile.NamedTemporaryFile(suffix='.sql', delete=False) as tmp_sql:
                        tmp_sql.write(sql_bytes)
                        tmp_sql_path = Path(tmp_sql.name)
                    try:
                        cmd = ['mysql', db_name] if os.geteuid() == 0 else ['sudo', '-n', 'mysql', db_name]
                        with open(tmp_sql_path, 'rb') as sql_in:
                            res = subprocess.run(cmd, stdin=sql_in, capture_output=True, timeout=120)
                        imported_sql = (res.returncode == 0)
                        if not imported_sql:
                            summary['warnings'].append(f'SQL import warning for {db_name}: {res.stderr.decode(errors="replace")[:200]}')
                    finally:
                        tmp_sql_path.unlink(missing_ok=True)

                size_mb = round(len(sql_bytes) / (1024 * 1024), 2)
                Database.objects.create(
                    owner=user,
                    name=db_name,
                    db_type='mariadb',
                    db_user=db_user,
                    size_mb=size_mb,
                )
                summary['databases'].append({
                    'name': db_name,
                    'db_user': db_user,
                    'db_pass': '' if db_user in cred_by_user else db_pass,
                    'matched_app_config': db_user in cred_by_user,
                    'sql_imported': imported_sql,
                })

        # 4. Migrate mailboxes & Maildir
        if import_mailboxes and manifest['mailboxes']:
            total_mb = len(manifest['mailboxes'])
            for idx, mbox in enumerate(manifest['mailboxes'], start=1):
                email_addr = mbox['email']
                pct = 68 + int((idx / max(total_mb, 1)) * 12)
                yield _evt(pct, f'Migrating mailbox {email_addr}...', f'>> [{idx}/{total_mb}] Migrating mailbox {email_addr}')

                if Mailbox.objects.filter(email=email_addr).exists():
                    if skip_existing:
                        summary['warnings'].append(f'Skipped existing mailbox {email_addr}.')
                        continue
                    raise ValueError(f'Mailbox "{email_addr}" already exists.')

                mbox_pass = generate_secure_password(16)
                mbox_res = create_mailbox(email_addr, password=mbox_pass, quota_mb=mbox['quota_mb'])
                maildir_dest = Path(mbox_res.get('maildir') or (VMAIL_BASE / mbox['domain'] / mbox['localpart']))

                copied_mail = 0
                if mbox['has_maildir']:
                    copied_mail = src.extract_subtree(f'homedir/mail/{mbox["domain"]}/{mbox["localpart"]}', maildir_dest)

                Mailbox.objects.create(
                    owner=user,
                    email=email_addr,
                    domain=mbox['domain'],
                    quota_mb=mbox['quota_mb'],
                )
                summary['mailboxes'].append({
                    'email': email_addr,
                    'password': mbox_pass,
                    'messages_copied': copied_mail,
                })

        # 5. Migrate DNS zones
        if import_dns and manifest['dns_zones']:
            target_ip = SystemSetting.get('server_ip', '').strip()
            old_ip = manifest.get('old_ip', '').strip()
            for zinfo in manifest['dns_zones']:
                zdom = zinfo['domain']
                site = created_websites.get(zdom) or Website.objects.filter(owner=user, domain=zdom).first()
                if not site:
                    continue
                yield _evt(84, f'Migrating DNS zone {zdom}...', f'>> Importing DNS zone for {zdom}')
                parsed_recs = _parse_bind_zone(src.read_text(zinfo['archive_path']) or '', zdom)
                DNSRecord.objects.filter(domain=site).delete()
                created_recs = []
                for rec in parsed_recs:
                    val = rec['value']
                    if update_dns_ip and target_ip and rec['record_type'] == 'A':
                        if not old_ip or val == old_ip:
                            val = target_ip
                    created_recs.append(DNSRecord.objects.create(
                        domain=site,
                        record_type=rec['record_type'],
                        name=rec['name'],
                        value=val,
                        ttl=rec['ttl'],
                        priority=rec['priority'],
                    ))
                export_zone_file(zdom, created_recs)
                summary['dns_zones'].append({'domain': zdom, 'records': len(created_recs)})

        # 6. Migrate FTP accounts
        if import_ftp and manifest['ftp_accounts']:
            yield _evt(90, 'Migrating FTP accounts...', '>> Importing FTP accounts')
            for ftp in manifest['ftp_accounts']:
                fuser = ftp['username'][:64]
                if FTPAccount.objects.filter(username=fuser).exists():
                    continue
                rel = _normalize_doc_root_rel(ftp['source_directory'], old_user)
                fdir = str(users_base / target_username / rel)
                fpass = generate_secure_password(16)
                create_ftp_user(fuser, fpass, fdir)
                FTPAccount.objects.create(owner=user, username=fuser, directory=fdir)
                summary['ftp_accounts'].append({'username': fuser, 'directory': fdir, 'password': fpass})

        # 7. Migrate cron jobs
        if import_cron and manifest['cron_jobs']:
            yield _evt(95, 'Migrating cron jobs...', '>> Importing scheduled cron jobs')
            for cj in manifest['cron_jobs']:
                cmd = cj['command']
                if old_user and old_user != target_username:
                    cmd = cmd.replace(f'/home/{old_user}/', f'{users_base}/{target_username}/')
                CronJob.objects.create(
                    owner=user,
                    schedule=cj['schedule'][:64],
                    command=cmd[:512],
                    description='Migrated from cPanel',
                    is_active=True,
                )
                summary['cron_jobs'].append({'schedule': cj['schedule'], 'command': cmd})
            sync_cron_jobs(target_username, CronJob.objects.filter(owner=user, is_active=True))

        AuditLog.objects.create(user=user, action='cpanel_migration', target=target_username)
        yield {'percent': 100, 'step': 'cPanel migration completed', 'line': f'>> Migration completed for "{target_username}"', 'complete': True, 'summary': summary}


def migrate_cpanel_archive(source_path: str | Path, options: dict | None = None, progress_cb=None) -> dict:
    """Synchronous wrapper returning migration summary."""
    summary = {}
    for evt in iter_migrate_cpanel_archive(source_path, options=options):
        if evt.get('complete'):
            summary = evt['summary']
        if progress_cb and 'line' in evt:
            progress_cb(evt['percent'], evt['step'], evt['line'])
    return summary
