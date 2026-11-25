"""
W3Panel v2 — Full cPanel / WHM Migration Plugin
Supports:
- Live Remote cPanel/WHM Server Migration (WHM JSON API + SSH/SCP pkgacct, single & bulk)
- Local/Uploaded cpmove & full backup tarballs (.tar.gz, .tgz, .tar, .tar.bz2, .tar.xz) or extracted dirs
- Account user, reseller owner mapping, email, shell access, and hosting package limits
- Primary, addon, subdomain, and parked-domain (Nginx server_name alias) websites
- .htaccess -> Nginx redirects & .user.ini PHP directives + hardcoded path rewriting
- MariaDB/MySQL dumps + wp-config.php/.env credential matching + mysql.sql password hash preservation
- PostgreSQL dumps (psql/ / pgsql/)
- Mailboxes + Dovecot shadow password hashes + Maildir messages + Postfix virtual forwarders (va/ / valiases/)
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
import shlex
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

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
# Format Parsers
# ---------------------------------------------------------------------------

def _unquote(val: str) -> str:
    val = val.strip()
    if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
        return val[1:-1]
    return val


def _parse_cpanel_yaml(text: str) -> dict:
    """Lightweight parser for cPanel userdata YAML files."""
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
    if not doc_root:
        return 'public_html'
    clean = doc_root.strip().rstrip('/')
    candidates = []
    if homedir_val:
        candidates.append(homedir_val.rstrip('/') + '/')
    if old_username:
        candidates.append(f'/home/{old_user_safe(old_username)}/')
        candidates.append(f'/home2/{old_user_safe(old_username)}/')
    for prefix in candidates:
        if clean.startswith(prefix):
            return clean[len(prefix):].lstrip('/') or 'public_html'
    m = re.match(r'^/home\d*/[^/]+/(.+)$', clean)
    if m:
        return m.group(1).lstrip('/')
    return clean.lstrip('/') or 'public_html'


def old_user_safe(u: str) -> str:
    return u.strip('/')


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


def _translate_htaccess(htaccess_text: str, ssl_enabled: bool = False) -> tuple[str, list[str], list[str]]:
    """
    Convert common safe Apache .htaccess directives to Nginx location/redirect rules and .user.ini lines.
    Returns (nginx_rules_str, user_ini_lines, warnings).
    """
    nginx_blocks: list[str] = []
    user_ini_lines: list[str] = []
    warnings: list[str] = []

    if not htaccess_text:
        return '', [], []

    # Force HTTPS rewrite detection
    if ssl_enabled and re.search(r'RewriteCond\s+%\{HTTPS\}\s+(off|!=on)', htaccess_text, re.IGNORECASE):
        nginx_blocks.append(
            '    if ($scheme != "https") {\n'
            '        return 301 https://$host$request_uri;\n'
            '    }'
        )

    custom_rewrites = 0
    for raw_line in htaccess_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue

        # Redirect [301|302|permanent|temp] /source /target
        m_redir = re.match(r'^Redirect\s+(?:(301|302|permanent|temp)\s+)?(/\S*)\s+(\S+)$', line, re.IGNORECASE)
        if m_redir:
            code_raw = (m_redir.group(1) or '302').lower()
            code = '301' if code_raw in ('301', 'permanent') else '302'
            src_path = m_redir.group(2)
            dst_url = m_redir.group(3)
            # Sanitize against Nginx block injection
            if re.match(r'^/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+$', src_path) and not any(c in dst_url for c in ('{', '}', ';', '\n', '\r')):
                nginx_blocks.append(
                    f'    location = {src_path} {{\n'
                    f'        return {code} {dst_url};\n'
                    f'    }}'
                )
            continue

        # php_value / php_flag -> .user.ini
        m_php = re.match(r'^php_(?:value|flag)\s+([A-Za-z0-9_.]+)\s+(.+)$', line, re.IGNORECASE)
        if m_php:
            pkey = m_php.group(1)
            pval = _unquote(m_php.group(2))
            if re.match(r'^[A-Za-z0-9_.]+$', pkey) and '\n' not in pval and ';' not in pval:
                user_ini_lines.append(f'{pkey} = {pval}')
            continue

        if re.match(r'^RewriteRule\s+', line, re.IGNORECASE):
            # Ignore standard WordPress / Laravel front controller rules handled natively by W3Panel
            if 'index.php' not in line and 'https://' not in line.lower():
                custom_rewrites += 1

    if custom_rewrites > 0:
        warnings.append(f'Detected {custom_rewrites} custom Apache RewriteRule directive(s) in .htaccess; review Nginx vhost if custom rewrites are needed.')

    return '\n'.join(nginx_blocks), user_ini_lines, warnings


def _rewrite_hardcoded_paths(doc_root: Path, old_paths: list[str], new_path: str) -> int:
    """Update hardcoded old home/doc_root paths in common PHP config files."""
    if not doc_root.is_dir():
        return 0
    updated = 0
    targets = [doc_root / '.user.ini', doc_root / 'php.ini', doc_root / 'wp-config.php', doc_root / 'configuration.php']
    for cfg in targets:
        if not cfg.is_file():
            continue
        try:
            content = cfg.read_text(errors='replace')
            new_content = content
            for old_p in old_paths:
                if old_p and old_p != new_path and old_p in new_content:
                    new_content = new_content.replace(old_p, new_path)
            if new_content != content:
                cfg.write_text(new_content)
                updated += 1
        except Exception:
            pass
    return updated


def _parse_bind_zone(zone_text: str, domain: str) -> list[dict]:
    """Parse a BIND RFC 1035 zone file into W3Panel DNSRecord dicts."""
    if not zone_text:
        return []

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
    """Return (db_to_users, user_to_hash) from mysql.sql and optional db.json."""
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

        user_re = re.compile(
            r"CREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?['\"]([^'\"]+)['\"]@['\"][^'\"]+['\"].*?(?:PASSWORD\s+|AS\s+)['\"]([^'\"]+)['\"]",
            re.IGNORECASE,
        )
        for m in user_re.finditer(mysql_sql):
            duser, phash = m.group(1), m.group(2)
            if phash and duser not in user_to_hash:
                user_to_hash[duser] = phash

    return db_to_users, user_to_hash


def _apply_mariadb_password_hash(db_user: str, phash: str) -> bool:
    """Apply an existing MySQL password hash (*40HEX...) to MariaDB."""
    if not phash or not re.match(r'^\*[A-Fa-f0-9]{40}$', phash):
        return False
    from services.database.manager import _has_sudo
    if os.geteuid() != 0 and not _has_sudo():
        return False
    prefix = [] if os.geteuid() == 0 else ['sudo', '-n']
    for sql in (
        f"ALTER USER '{db_user}'@'localhost' IDENTIFIED VIA mysql_native_password USING '{phash}'; FLUSH PRIVILEGES;",
        f"SET PASSWORD FOR '{db_user}'@'localhost' = '{phash}'; FLUSH PRIVILEGES;",
    ):
        try:
            res = subprocess.run(prefix + ['mysql', '-e', sql], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return True
        except Exception:
            pass
    return False


# ---------------------------------------------------------------------------
# Public Inspect API
# ---------------------------------------------------------------------------

def inspect_cpanel_archive(source_path: str | Path) -> dict:
    """Parse a cPanel cpmove archive or extracted directory without altering the system."""
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
        owner_reseller = cp_data.get('OWNER', '').strip()

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
                'raw_source_doc_root': raw_doc_root or f'/home/{username}/{rel_doc_root}',
                'php_version': php_ver,
                'framework': framework,
                'has_htaccess': has_htaccess,
                'has_ssl': has_ssl,
            })

        # MariaDB / MySQL databases
        mysql_sql = src.read_text('mysql.sql') or ''
        db_json_text = src.read_text('mysql/db.json') or src.read_text('db.json')
        db_to_users, user_to_hash = _parse_mysql_grants(mysql_sql, db_json_text)

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
            primary_u = users[0] if users else db_name[:64]
            databases.append({
                'name': db_name,
                'db_type': 'mariadb',
                'archive_path': mf,
                'db_user': primary_u,
                'all_users': users,
                'has_password_hash': primary_u in user_to_hash,
            })

        # PostgreSQL databases (psql/ or pgsql/)
        for pg_dir in ('psql', 'pgsql'):
            for pf in src.list_files(pg_dir):
                fname = Path(pf).name
                if fname.endswith('.sql'):
                    db_name = fname[:-4]
                elif fname.endswith('.sql.gz'):
                    db_name = fname[:-7]
                else:
                    continue
                if db_name.lower() in ('postgres', 'template0', 'template1'):
                    continue
                databases.append({
                    'name': db_name,
                    'db_type': 'postgresql',
                    'archive_path': pf,
                    'db_user': username[:64],
                    'all_users': [username[:64]],
                    'has_password_hash': False,
                })

        # Mailboxes (homedir/etc/{domain}/passwd + shadow + quota)
        mailboxes = []
        etc_files = src.list_files('homedir/etc')
        seen_emails = set()
        for ef in etc_files:
            parts = ef.split('/')
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

                shadow_map = {}
                s_text = src.read_text(f'homedir/etc/{mail_domain}/shadow') or ''
                for sl in s_text.splitlines():
                    if ':' in sl:
                        su, shash = sl.split(':', 2)[:2]
                        if su.strip() and shash.strip() and shash.strip() not in ('*', '!', '!!', 'x'):
                            shadow_map[su.strip()] = shash.strip()

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
                        'has_shadow_hash': localpart in shadow_map,
                    })

        # Email forwarders / virtual aliases (va/{domain} or valiases/{domain} or homedir/etc/{domain}/valiases)
        mail_forwarders = _parse_mail_forwarders(src)

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
            'owner_reseller': owner_reseller,
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
            'mail_forwarders': mail_forwarders,
            'dns_zones': dns_zones,
            'ftp_accounts': ftp_accounts,
            'cron_jobs': cron_jobs,
            'ssl_certs': ssl_certs,
            'warnings': warnings,
        }


def _parse_mail_forwarders(src: _CpanelSource) -> list[dict]:
    forwarders = []
    seen = set()
    candidate_files = []
    for folder in ('va', 'valiases'):
        candidate_files.extend(src.list_files(folder))
    for ef in src.list_files('homedir/etc'):
        if ef.endswith('/valiases'):
            candidate_files.append(ef)

    for cf in candidate_files:
        parts = cf.split('/')
        domain = parts[2].lower() if cf.startswith('homedir/etc/') and len(parts) >= 4 else Path(cf).name.lower()
        text = src.read_text(cf) or ''
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith('#') or ':' not in line:
                continue
            src_part, dst_part = line.split(':', 1)
            src_part = src_part.strip().lower()
            source_email = src_part if '@' in src_part else f'{src_part}@{domain}'
            targets = [t.strip() for t in dst_part.split(',') if t.strip() and not t.strip().startswith(':blackhole:') and not t.strip().startswith(':fail:')]
            if not targets or source_email in seen:
                continue
            seen.add(source_email)
            forwarders.append({'source': source_email, 'targets': targets})
    return forwarders


def _find_ssl_pair(src: _CpanelSource, domain: str) -> tuple[str, str] | None:
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
# Live Remote cPanel / WHM Server Operations (WHM API + SSH / SCP)
# ---------------------------------------------------------------------------

def _ssh_base_cmd(conn: dict) -> tuple[list[str], dict, str | None]:
    """Build safe ssh/scp command prefix, env (for SSHPASS), and optional temp keyfile path."""
    ssh_port = str(int(conn.get('ssh_port') or 22))
    auth_mode = conn.get('ssh_auth_mode', 'password')
    env = os.environ.copy()
    key_file = None

    common_opts = [
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ConnectTimeout=15',
        '-o', 'BatchMode=no' if auth_mode == 'password' else 'BatchMode=yes',
    ]

    if auth_mode == 'key' and conn.get('ssh_key'):
        tf = tempfile.NamedTemporaryFile('w', suffix='.key', delete=False)
        tf.write(conn['ssh_key'].strip() + '\n')
        tf.close()
        os.chmod(tf.name, 0o600)
        key_file = tf.name
        prefix = ['ssh', '-p', ssh_port, '-i', key_file] + common_opts
        scp_prefix = ['scp', '-P', ssh_port, '-i', key_file] + common_opts
        return (prefix, scp_prefix), env, key_file

    password = conn.get('ssh_password', '')
    if password:
        if not shutil.which('sshpass'):
            raise ValueError('sshpass is required for SSH password authentication. Install sshpass or use an SSH private key.')
        env['SSHPASS'] = password
        prefix = ['sshpass', '-e', 'ssh', '-p', ssh_port] + common_opts
        scp_prefix = ['sshpass', '-e', 'scp', '-P', ssh_port] + common_opts
        return (prefix, scp_prefix), env, None

    prefix = ['ssh', '-p', ssh_port] + common_opts
    scp_prefix = ['scp', '-P', ssh_port] + common_opts
    return (prefix, scp_prefix), env, None


def list_remote_accounts(conn: dict) -> list[dict]:
    """
    Fetch live cPanel accounts from a remote cPanel/WHM server.
    Supports WHM JSON API (port 2087 + API token) or SSH (/var/cpanel/users/*).
    """
    host = (conn.get('host') or '').strip()
    if not host or not re.match(r'^[A-Za-z0-9._:-]+$', host):
        raise ValueError('Valid remote host/IP is required.')

    whm_token = (conn.get('whm_token') or '').strip()
    if whm_token:
        import requests
        whm_user = (conn.get('whm_user') or 'root').strip()
        whm_port = int(conn.get('whm_port') or 2087)
        verify_ssl = bool(conn.get('verify_ssl', False))
        url = f'https://{host}:{whm_port}/json-api/listaccts?api.version=1'
        resp = requests.get(
            url,
            headers={'Authorization': f'whm {whm_user}:{whm_token}'},
            timeout=20,
            verify=verify_ssl,
        )
        resp.raise_for_status()
        payload = resp.json()
        meta = payload.get('metadata', {})
        if meta.get('result') != 1:
            raise ValueError(meta.get('reason') or 'WHM API rejected request.')
        accounts = []
        for acct in payload.get('data', {}).get('acct', []):
            accounts.append({
                'user': acct.get('user', ''),
                'domain': acct.get('domain', ''),
                'email': acct.get('email', ''),
                'plan': acct.get('plan', ''),
                'ip': acct.get('ip', ''),
                'diskused': acct.get('diskused', ''),
                'disklimit': acct.get('disklimit', ''),
                'suspended': bool(int(acct.get('suspended', 0) or 0)),
            })
        return accounts

    # SSH fallback: inspect /var/cpanel/users/* on remote cPanel host
    ssh_user = (conn.get('ssh_user') or 'root').strip()
    (ssh_cmd, _), env, key_file = _ssh_base_cmd(conn)
    remote_py = (
        "for f in /var/cpanel/users/*; do "
        "[ -f \"$f\" ] || continue; "
        "u=$(basename \"$f\"); "
        "[ \"$u\" = \"system\" ] && continue; "
        "dom=$(grep -m1 '^DNS=' \"$f\" | cut -d= -f2-); "
        "eml=$(grep -m1 '^CONTACTEMAIL=' \"$f\" | cut -d= -f2-); "
        "pln=$(grep -m1 '^PLAN=' \"$f\" | cut -d= -f2-); "
        "susp=$(grep -m1 '^SUSPENDED=' \"$f\" | cut -d= -f2-); "
        "printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$u\" \"$dom\" \"$eml\" \"$pln\" \"${susp:-0}\"; "
        "done"
    )
    try:
        res = subprocess.run(
            ssh_cmd + [f'{ssh_user}@{host}', remote_py],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if res.returncode != 0:
            raise ValueError(res.stderr.strip() or 'Failed to connect via SSH.')
        accounts = []
        for line in res.stdout.splitlines():
            parts = line.split('\t')
            if parts and parts[0].strip():
                accounts.append({
                    'user': parts[0].strip(),
                    'domain': parts[1].strip() if len(parts) > 1 else '',
                    'email': parts[2].strip() if len(parts) > 2 else '',
                    'plan': parts[3].strip() if len(parts) > 3 else '',
                    'ip': host,
                    'diskused': '',
                    'disklimit': '',
                    'suspended': (parts[4].strip() == '1') if len(parts) > 4 else False,
                })
        return accounts
    finally:
        if key_file:
            Path(key_file).unlink(missing_ok=True)


def iter_migrate_remote(conn: dict, usernames: list[str], options: dict | None = None):
    """
    Package and transfer cPanel account(s) via SSH pkgacct + SCP, then migrate each into W3Panel.
    """
    from services.migrators import get_staging_dir

    host = (conn.get('host') or '').strip()
    if not host or not re.match(r'^[A-Za-z0-9._:-]+$', host):
        raise ValueError('Valid remote host/IP is required.')
    if not usernames:
        raise ValueError('Select at least one cPanel account to migrate.')

    ssh_user = (conn.get('ssh_user') or 'root').strip()
    (ssh_cmd, scp_cmd), env, key_file = _ssh_base_cmd(conn)
    staging = get_staging_dir('cpanel')
    summaries = []

    try:
        total = len(usernames)
        for idx, acct_user in enumerate(usernames, start=1):
            acct_user = acct_user.strip()
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$', acct_user):
                raise ValueError(f'Invalid remote cPanel username: {acct_user}')

            base_pct = int(((idx - 1) / total) * 100)
            span = 100 / total

            yield {
                'percent': min(99, base_pct + 2),
                'step': f'[{idx}/{total}] Packaging {acct_user} on {host}...',
                'line': f'>> [{idx}/{total}] Running pkgacct on {host} for "{acct_user}"...',
            }

            q_user = shlex.quote(acct_user)
            pkg_cmd = (
                f"if [ -x /usr/local/cpanel/scripts/pkgacct ]; then "
                f"/usr/local/cpanel/scripts/pkgacct --allow-override {q_user} /tmp; "
                f"else /scripts/pkgacct {q_user} /tmp; fi"
            )
            pkg_res = subprocess.run(
                ssh_cmd + [f'{ssh_user}@{host}', pkg_cmd],
                env=env,
                capture_output=True,
                text=True,
                timeout=1800,
            )
            if pkg_res.returncode != 0:
                raise RuntimeError(f'pkgacct failed for {acct_user}: {(pkg_res.stderr or pkg_res.stdout)[-400:]}')

            remote_tar = f'/tmp/cpmove-{acct_user}.tar.gz'
            local_tar = staging / f'remote_cpmove-{acct_user}.tar.gz'

            yield {
                'percent': min(99, base_pct + int(span * 0.2)),
                'step': f'[{idx}/{total}] Transferring {acct_user} archive...',
                'line': f'>> Transferring {remote_tar} from {host} via SCP...',
            }

            try:
                scp_res = subprocess.run(
                    scp_cmd + [f'{ssh_user}@{host}:{remote_tar}', str(local_tar)],
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=1800,
                )
                if scp_res.returncode != 0:
                    raise RuntimeError(f'SCP transfer failed for {acct_user}: {scp_res.stderr[-300:]}')
            finally:
                subprocess.run(
                    ssh_cmd + [f'{ssh_user}@{host}', f'rm -f {shlex.quote(remote_tar)}'],
                    env=env,
                    capture_output=True,
                    timeout=30,
                )

            try:
                acct_opts = dict(options or {})
                acct_opts['target_username'] = acct_user if total > 1 else (acct_opts.get('target_username') or acct_user)
                for evt in iter_migrate_cpanel_archive(local_tar, options=acct_opts):
                    if evt.get('complete'):
                        summaries.append(evt['summary'])
                    else:
                        scaled = base_pct + int(span * (0.25 + 0.75 * (evt['percent'] / 100.0)))
                        yield {
                            'percent': min(99, scaled),
                            'step': f'[{idx}/{total}] {evt["step"]}',
                            'line': evt['line'],
                        }
            finally:
                local_tar.unlink(missing_ok=True)

        merged = summaries[0] if len(summaries) == 1 else {
            'accounts_migrated': len(summaries),
            'accounts': summaries,
            'websites': [w for s in summaries for w in s.get('websites', [])],
            'databases': [d for s in summaries for d in s.get('databases', [])],
            'mailboxes': [m for s in summaries for m in s.get('mailboxes', [])],
            'dns_zones': [z for s in summaries for z in s.get('dns_zones', [])],
            'warnings': [w for s in summaries for w in s.get('warnings', [])],
        }
        yield {
            'percent': 100,
            'step': 'Remote cPanel migration completed',
            'line': f'>> Completed migration of {len(summaries)} account(s) from {host}.',
            'complete': True,
            'summary': merged,
        }
    finally:
        if key_file:
            Path(key_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Migration Execution (Archive / Directory)
# ---------------------------------------------------------------------------

def iter_migrate_cpanel_archive(source_path: str | Path, options: dict | None = None):
    """
    Generator executing migration from a cPanel cpmove archive or extracted directory into W3Panel.
    """
    from services.webserver import (
        create_user_php_pool,
        create_vhost,
        get_doc_root,
        sync_system_user_password,
        sync_system_user_shell,
    )
    from services.webserver.manager import _get_users_base_dir, _has_sudo, _write_privileged_file
    from services.database import create_database, create_database_user, grant_user_privileges, generate_secure_password
    from services.mail import create_mailbox, set_mailbox_password_hash, create_mail_alias
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
        'mail_forwarders': [],
        'dns_zones': [],
        'ftp_accounts': [],
        'cron_jobs': [],
        'ssl_certs': [],
        'warnings': list(manifest.get('warnings', [])),
    }

    with _CpanelSource(source_path) as src:
        # 1. User & Package + Reseller owner mapping
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
            parent_reseller = None
            owner_res = manifest.get('owner_reseller', '')
            if owner_res and owner_res != 'root':
                parent_reseller = User.objects.filter(username=owner_res, role='reseller').first()
                if not parent_reseller:
                    summary['warnings'].append(f'Source reseller "{owner_res}" not found in W3Panel; assigned directly under root admin.')

            account_pass = generate_secure_password(16)
            user = User.objects.create_user(
                username=target_username,
                email=target_email,
                password=account_pass,
                role='user',
                package=pkg,
                parent_reseller=parent_reseller,
                shell_enabled=manifest['shell_enabled'],
            )
            summary['account_password'] = account_pass
            sync_system_user_shell(target_username, manifest['shell_enabled'])
            sync_system_user_password(target_username, account_pass)
            yield _evt(18, 'Created user account', f'>> Created user "{target_username}" (email: {target_email})')

        default_php = SystemSetting.get('default_php', '8.3')
        create_user_php_pool(username=target_username, php_version=default_php)

        # 2. Websites, Parked Domain Aliases, .htaccess translation, Path Rewrites, SSL
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
                    old_candidates = [
                        dinfo.get('raw_source_doc_root', ''),
                        f'/home/{old_user}/{src_rel}',
                        f'/home/{old_user}/public_html',
                    ]
                    _rewrite_hardcoded_paths(doc_root, old_candidates, str(doc_root))

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

                # .htaccess -> Nginx rules & .user.ini
                extra_nginx_rules = ''
                if dinfo['has_htaccess']:
                    ht_text = src.read_text(f'homedir/{src_rel}/.htaccess') or ''
                    nginx_rules, ini_lines, ht_warnings = _translate_htaccess(ht_text, ssl_enabled=ssl_enabled)
                    extra_nginx_rules = nginx_rules
                    summary['warnings'].extend(f'{dom}: {w}' for w in ht_warnings)
                    if ini_lines and doc_root.is_dir():
                        ini_file = doc_root / '.user.ini'
                        existing_ini = ini_file.read_text(errors='replace') if ini_file.is_file() else ''
                        added = [ln for ln in ini_lines if ln not in existing_ini]
                        if added:
                            ini_file.write_text((existing_ini.rstrip() + '\n' if existing_ini else '') + '\n'.join(added) + '\n')

                aliases = manifest['parked_domains'] if dinfo['kind'] == 'primary' else None

                site = Website.objects.create(
                    owner=user,
                    domain=dom,
                    doc_root=str(doc_root),
                    php_version=php_ver,
                    framework=framework,
                    ssl_enabled=ssl_enabled,
                )
                create_vhost(site, ssl_cert=ssl_cert_path, ssl_key=ssl_key_path, aliases=aliases, extra_nginx_rules=extra_nginx_rules)

                if _has_sudo():
                    subprocess.run(['sudo', '-n', 'chown', '-R', f'{target_username}:{target_username}', str(users_base / target_username / dom)], capture_output=True, timeout=30)

                created_websites[dom] = site
                summary['websites'].append({'domain': dom, 'framework': framework, 'php_version': php_ver, 'files': copied})

        # 3. Databases (MariaDB + PostgreSQL) & SQL dumps + password hash preservation
        if import_databases and manifest['databases']:
            mysql_sql = src.read_text('mysql.sql') or ''
            db_json_text = src.read_text('mysql/db.json') or src.read_text('db.json')
            _, user_to_hash = _parse_mysql_grants(mysql_sql, db_json_text)

            cred_by_user = {c['db_user']: c['db_pass'] for c in app_db_creds if c.get('db_user') and c.get('db_pass')}
            total_dbs = len(manifest['databases'])
            for idx, db_info in enumerate(manifest['databases'], start=1):
                db_name = db_info['name'][:64]
                db_user = db_info['db_user'][:64]
                db_type = db_info.get('db_type', 'mariadb')
                pct = 48 + int((idx / max(total_dbs, 1)) * 18)
                yield _evt(pct, f'Migrating {db_type} database {db_name}...', f'>> [{idx}/{total_dbs}] Importing {db_type} database {db_name}')

                if Database.objects.filter(owner=user, name=db_name).exists():
                    if skip_existing:
                        summary['warnings'].append(f'Skipped existing database {db_name}.')
                        continue
                    raise ValueError(f'Database "{db_name}" already exists for user "{target_username}".')

                db_pass = cred_by_user.get(db_user) or generate_secure_password(16)
                create_database(db_name, db_user, db_pass, db_type=db_type)

                hash_preserved = False
                if db_type == 'mariadb' and db_user not in cred_by_user and db_user in user_to_hash:
                    hash_preserved = _apply_mariadb_password_hash(db_user, user_to_hash[db_user])

                # Grant any additional database users defined in mysql.sql / db.json
                for extra_user in db_info.get('all_users', [])[1:]:
                    extra_user = extra_user[:64]
                    if not extra_user or extra_user == db_user:
                        continue
                    extra_pass = cred_by_user.get(extra_user) or generate_secure_password(16)
                    create_database_user(extra_user, extra_pass, db_type=db_type)
                    grant_user_privileges(db_name, extra_user, db_type=db_type)
                    if db_type == 'mariadb' and extra_user not in cred_by_user and extra_user in user_to_hash:
                        _apply_mariadb_password_hash(extra_user, user_to_hash[extra_user])

                sql_bytes = src.read_bytes(db_info['archive_path']) or b''
                if db_info['archive_path'].endswith('.gz') and sql_bytes:
                    sql_bytes = gzip.decompress(sql_bytes)

                imported_sql = False
                if sql_bytes and (_has_sudo() or os.geteuid() == 0):
                    with tempfile.NamedTemporaryFile(suffix='.sql', delete=False) as tmp_sql:
                        tmp_sql.write(sql_bytes)
                        tmp_sql_path = Path(tmp_sql.name)
                    try:
                        if db_type == 'mariadb' and shutil.which('mysql'):
                            cmd = ['mysql', db_name] if os.geteuid() == 0 else ['sudo', '-n', 'mysql', db_name]
                            with open(tmp_sql_path, 'rb') as sql_in:
                                res = subprocess.run(cmd, stdin=sql_in, capture_output=True, timeout=180)
                            imported_sql = (res.returncode == 0)
                            if not imported_sql:
                                summary['warnings'].append(f'SQL import warning for {db_name}: {res.stderr.decode(errors="replace")[:200]}')
                        elif db_type == 'postgresql' and shutil.which('psql'):
                            cmd = ['sudo', '-n', '-u', 'postgres', 'psql', '-d', db_name, '-f', str(tmp_sql_path)]
                            res = subprocess.run(cmd, capture_output=True, timeout=180)
                            imported_sql = (res.returncode == 0)
                            if not imported_sql:
                                summary['warnings'].append(f'PostgreSQL import warning for {db_name}: {res.stderr.decode(errors="replace")[:200]}')
                    finally:
                        tmp_sql_path.unlink(missing_ok=True)

                size_mb = round(len(sql_bytes) / (1024 * 1024), 2)
                Database.objects.create(
                    owner=user,
                    name=db_name,
                    db_type=db_type,
                    db_user=db_user,
                    size_mb=size_mb,
                )
                summary['databases'].append({
                    'name': db_name,
                    'db_type': db_type,
                    'db_user': db_user,
                    'db_pass': '' if (db_user in cred_by_user or hash_preserved) else db_pass,
                    'matched_app_config': db_user in cred_by_user,
                    'hash_preserved': hash_preserved,
                    'sql_imported': imported_sql,
                })

        # 4. Mailboxes + Dovecot Shadow Hashes + Maildir + Forwarders
        if import_mailboxes:
            shadow_by_email: dict[str, str] = {}
            for ef in src.list_files('homedir/etc'):
                parts = ef.split('/')
                if len(parts) == 4 and parts[3] == 'shadow':
                    mdom = parts[2].lower()
                    for sl in (src.read_text(ef) or '').splitlines():
                        if ':' in sl:
                            su, shash = sl.split(':', 2)[:2]
                            if su.strip() and shash.strip() and shash.strip() not in ('*', '!', '!!', 'x'):
                                shadow_by_email[f'{su.strip()}@{mdom}'] = shash.strip()

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

                hash_saved = False
                if email_addr in shadow_by_email:
                    h_res = set_mailbox_password_hash(email_addr, shadow_by_email[email_addr], str(maildir_dest))
                    hash_saved = bool(h_res.get('success'))

                Mailbox.objects.create(
                    owner=user,
                    email=email_addr,
                    domain=mbox['domain'],
                    quota_mb=mbox['quota_mb'],
                )
                summary['mailboxes'].append({
                    'email': email_addr,
                    'password': '' if hash_saved else mbox_pass,
                    'hash_preserved': hash_saved,
                    'messages_copied': copied_mail,
                })

            for fwd in manifest.get('mail_forwarders', []):
                create_mail_alias(fwd['source'], fwd['targets'])
                summary['mail_forwarders'].append(fwd)

        # 5. DNS Zones
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

        # 6. FTP Accounts
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

        # 7. Cron Jobs
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


# Standardized Migrator Plugin Interface
inspect = inspect_cpanel_archive
iter_migrate = iter_migrate_cpanel_archive
