"""
W3Panel v2 — Database Provisioning & Performance Manager
Executes database/user creation on local MariaDB / MySQL / PostgreSQL engines,
and enforces low-memory, high-throughput database engine optimization.
"""
import http.client
from http.cookies import SimpleCookie
import os
import re
import shlex
import shutil
import subprocess
import logging
import secrets
import string
import tempfile
import urllib.parse
from pathlib import Path

logger = logging.getLogger('w3panel.database')

_DB_IDENT_RE = re.compile(r'^[a-zA-Z0-9_]{1,64}$')


def _validate_db_identifier(val: str, label: str = 'identifier') -> str:
    val = (val or '').strip()
    if not _DB_IDENT_RE.match(val):
        raise ValueError(f'Invalid SQL {label}: "{val}"')
    return val


def _escape_sql_str(val: str) -> str:
    if '\x00' in val or '\n' in val or '\r' in val:
        raise ValueError('Invalid characters in SQL string.')
    return val.replace('\\', '\\\\').replace("'", "\\'")


_SBIN_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def _find_bin(*names: str) -> str | None:
    """Locate binary checking both active PATH and standard sbin/bin locations."""
    env_path = os.environ.get('PATH', '')
    full_path = f"{env_path}:{_SBIN_PATH}" if env_path else _SBIN_PATH
    for name in names:
        hit = shutil.which(name) or shutil.which(name, path=full_path)
        if hit:
            return hit
    return None


def is_mariadb_installed() -> bool:
    """Check if MariaDB / MySQL server is installed on host."""
    return bool(_find_bin('mariadbd', 'mysqld', 'mariadb', 'mysql'))


def is_postgresql_installed() -> bool:
    """Check if PostgreSQL server is installed on host."""
    if _find_bin('psql', 'postgres'):
        return True
    pg_lib = Path('/usr/lib/postgresql')
    return pg_lib.exists() and any(pg_lib.glob('*/bin/postgres'))


def _has_sudo() -> bool:
    try:
        res = subprocess.run(['sudo', '-n', 'true'], capture_output=True, timeout=2)
        return res.returncode == 0
    except Exception:
        return False


def _write_privileged_file(target_path: Path, content: str) -> bool:
    """Write file directly or escalate with sudo -n tee if permission denied."""
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(content)
        return True
    except (PermissionError, OSError):
        if not _has_sudo():
            return False
        try:
            subprocess.run(['sudo', '-n', 'mkdir', '-p', str(target_path.parent)], capture_output=True, timeout=3)
            proc = subprocess.run(
                ['sudo', '-n', 'tee', str(target_path)],
                input=content,
                text=True,
                capture_output=True,
                timeout=3
            )
            return proc.returncode == 0
        except Exception as e:
            logger.error(f"Failed to write privileged database config {target_path}: {e}")
            return False


def generate_secure_password(length: int = 16) -> str:
    """Generate a random alphanumeric password."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def create_database(db_name: str, db_user: str, db_pass: str = '', db_type: str = 'mariadb') -> dict:
    """
    Create a database and associated database user with full privileges.
    """
    try:
        db_name = _validate_db_identifier(db_name, 'database name')
        db_user = _validate_db_identifier(db_user, 'username')
    except ValueError as e:
        return {'success': False, 'error': str(e)}

    if not db_pass:
        db_pass = generate_secure_password()

    if db_type == 'mariadb':
        return _create_mariadb(db_name, db_user, db_pass)
    elif db_type == 'postgresql':
        return _create_postgresql(db_name, db_user, db_pass)
    else:
        return {'success': False, 'error': f'Unsupported database type: {db_type}'}


def delete_database(db_name: str, db_user: str = '', db_type: str = 'mariadb') -> dict:
    """
    Drop database and user.
    """
    try:
        db_name = _validate_db_identifier(db_name, 'database name')
        if db_user:
            db_user = _validate_db_identifier(db_user, 'username')
    except ValueError as e:
        return {'success': False, 'error': str(e)}

    if db_type == 'mariadb':
        return _delete_mariadb(db_name, db_user)
    elif db_type == 'postgresql':
        return _delete_postgresql(db_name, db_user)
    return {'success': True}


def create_database_user(db_user: str, db_pass: str = '', db_type: str = 'mariadb') -> dict:
    """Create a database user on MariaDB or PostgreSQL."""
    try:
        db_user = _validate_db_identifier(db_user, 'username')
    except ValueError as e:
        return {'success': False, 'error': str(e)}

    if not db_pass:
        db_pass = generate_secure_password()

    safe_pass = _escape_sql_str(db_pass)
    if db_type == 'mariadb':
        sql = f"CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{safe_pass}'; FLUSH PRIVILEGES;"
        try:
            cmd = ['sudo', '-n', 'mysql', '-e', sql]
            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return {'success': True, 'db_user': db_user, 'db_pass': db_pass}
        except Exception as e:
            logger.warning(f"MariaDB create user warning: {e}")
            return {'success': True, 'db_user': db_user, 'db_pass': db_pass, 'note': str(e)}
    elif db_type == 'postgresql':
        try:
            check_user = subprocess.run(
                ['sudo', '-n', '-u', 'postgres', 'psql', '-tAc', f"SELECT 1 FROM pg_roles WHERE rolname='{db_user}'"],
                capture_output=True, text=True, timeout=5
            )
            if '1' not in check_user.stdout:
                pg_pass = db_pass.replace("'", "''")
                cmd_user = ['sudo', '-n', '-u', 'postgres', 'psql', '-c', f"CREATE USER \"{db_user}\" WITH PASSWORD '{pg_pass}';"]
                subprocess.run(cmd_user, capture_output=True, text=True, timeout=5)
            return {'success': True, 'db_user': db_user, 'db_pass': db_pass}
        except Exception as e:
            logger.warning(f"PostgreSQL create user warning: {e}")
            return {'success': True, 'db_user': db_user, 'db_pass': db_pass, 'note': str(e)}
    return {'success': False, 'error': f'Unsupported database type: {db_type}'}


def grant_user_privileges(db_name: str, db_user: str, db_type: str = 'mariadb') -> dict:
    """Grant all privileges on database to user."""
    try:
        db_name = _validate_db_identifier(db_name, 'database name')
        db_user = _validate_db_identifier(db_user, 'username')
    except ValueError as e:
        return {'success': False, 'error': str(e)}

    if db_type == 'mariadb':
        sql = f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost'; FLUSH PRIVILEGES;"
        try:
            cmd = ['sudo', '-n', 'mysql', '-e', sql]
            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    elif db_type == 'postgresql':
        try:
            cmd = ['sudo', '-n', '-u', 'postgres', 'psql', '-c', f"GRANT ALL PRIVILEGES ON DATABASE \"{db_name}\" TO \"{db_user}\";"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    return {'success': False, 'error': f'Unsupported database type: {db_type}'}


def change_user_password(db_user: str, new_password: str, db_type: str = 'mariadb') -> dict:
    """Update database user password."""
    try:
        db_user = _validate_db_identifier(db_user, 'username')
        safe_pass = _escape_sql_str(new_password)
    except ValueError as e:
        return {'success': False, 'error': str(e)}

    if db_type == 'mariadb':
        sql = f"ALTER USER '{db_user}'@'localhost' IDENTIFIED BY '{safe_pass}'; FLUSH PRIVILEGES;"
        try:
            cmd = ['sudo', '-n', 'mysql', '-e', sql]
            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    elif db_type == 'postgresql':
        try:
            pg_pass = new_password.replace("'", "''")
            cmd = ['sudo', '-n', '-u', 'postgres', 'psql', '-c', f"ALTER USER \"{db_user}\" WITH PASSWORD '{pg_pass}';"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    return {'success': False, 'error': f'Unsupported database type: {db_type}'}


def delete_database_user(db_user: str, db_type: str = 'mariadb') -> dict:
    """Drop database user."""
    try:
        db_user = _validate_db_identifier(db_user, 'username')
    except ValueError as e:
        return {'success': False, 'error': str(e)}
    if db_type == 'mariadb':
        sql = f"DROP USER IF EXISTS '{db_user}'@'localhost'; FLUSH PRIVILEGES;"
        try:
            cmd = ['sudo', '-n', 'mysql', '-e', sql]
            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except Exception as e:
            logger.warning(f"MariaDB drop user error: {e}")
        return {'success': True}
    elif db_type == 'postgresql':
        try:
            cmd = ['sudo', '-n', '-u', 'postgres', 'psql', '-c', f"DROP USER IF EXISTS \"{db_user}\";"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except Exception as e:
            logger.warning(f"PostgreSQL drop user error: {e}")
        return {'success': True}
    return {'success': True}


def _create_mariadb(db_name: str, db_user: str, db_pass: str) -> dict:
    """Run SQL commands against local MariaDB/MySQL."""
    safe_pass = _escape_sql_str(db_pass)
    sql = f"""
CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '{db_user}'@'localhost' IDENTIFIED BY '{safe_pass}';
GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'localhost';
FLUSH PRIVILEGES;
"""
    try:
        cmd = ['sudo', '-n', 'mysql', '-e', sql]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            return {'success': True, 'db_name': db_name, 'db_user': db_user, 'db_pass': db_pass}
        else:
            logger.warning(f"MariaDB SQL execution warning: {res.stderr}")
            return {'success': True, 'db_name': db_name, 'db_user': db_user, 'db_pass': db_pass, 'note': res.stderr}
    except Exception as e:
        logger.warning(f"MariaDB not reachable or not yet installed: {e}")
        return {'success': True, 'db_name': db_name, 'db_user': db_user, 'db_pass': db_pass, 'note': str(e)}


def _delete_mariadb(db_name: str, db_user: str = '') -> dict:
    """Drop MariaDB database."""
    sql = f"DROP DATABASE IF EXISTS `{db_name}`;"
    try:
        cmd = ['sudo', '-n', 'mysql', '-e', sql]
        subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except Exception as e:
        logger.warning(f"MariaDB drop error: {e}")
    if db_user:
        delete_database_user(db_user, db_type='mariadb')
    return {'success': True}


def _create_postgresql(db_name: str, db_user: str, db_pass: str) -> dict:
    """Run SQL commands against local PostgreSQL."""
    try:
        # Check if user exists, create if not
        check_user = subprocess.run(
            ['sudo', '-n', '-u', 'postgres', 'psql', '-tAc', f"SELECT 1 FROM pg_roles WHERE rolname='{db_user}'"],
            capture_output=True, text=True, timeout=5
        )
        if '1' not in check_user.stdout:
            pg_pass = db_pass.replace("'", "''")
            cmd_user = ['sudo', '-n', '-u', 'postgres', 'psql', '-c', f"CREATE USER \"{db_user}\" WITH PASSWORD '{pg_pass}';"]
            subprocess.run(cmd_user, capture_output=True, text=True, timeout=5)
        else:
            # User exists, update password
            pg_pass = db_pass.replace("'", "''")
            cmd_pwd = ['sudo', '-n', '-u', 'postgres', 'psql', '-c', f"ALTER USER \"{db_user}\" WITH PASSWORD '{pg_pass}';"]
            subprocess.run(cmd_pwd, capture_output=True, text=True, timeout=5)

        cmd_db = ['sudo', '-n', '-u', 'postgres', 'psql', '-c', f"CREATE DATABASE \"{db_name}\" OWNER \"{db_user}\";"]
        subprocess.run(cmd_db, capture_output=True, text=True, timeout=5)

        cmd_grant = ['sudo', '-n', '-u', 'postgres', 'psql', '-c', f"GRANT ALL PRIVILEGES ON DATABASE \"{db_name}\" TO \"{db_user}\";"]
        subprocess.run(cmd_grant, capture_output=True, text=True, timeout=5)

        return {'success': True, 'db_name': db_name, 'db_user': db_user, 'db_pass': db_pass}
    except Exception as e:
        logger.warning(f"PostgreSQL not reachable: {e}")
        return {'success': True, 'db_name': db_name, 'db_user': db_user, 'db_pass': db_pass, 'note': str(e)}


def _delete_postgresql(db_name: str, db_user: str = '') -> dict:
    """Drop PostgreSQL database."""
    try:
        cmd = ['sudo', '-n', '-u', 'postgres', 'psql', '-c', f"DROP DATABASE IF EXISTS \"{db_name}\";"]
        subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except Exception as e:
        logger.warning(f"PostgreSQL drop error: {e}")
    if db_user:
        delete_database_user(db_user, db_type='postgresql')
    return {'success': True}


def apply_database_tuning() -> dict:
    """
    Apply high-performance, low-resource MariaDB optimization:
    - skip-name-resolve: Disables slow DNS lookups on incoming socket/TCP connections
    - performance_schema = OFF: Frees 100MB+ of server RAM
    - innodb_buffer_pool_size = 128M: Efficient buffer cache for small to medium nodes
    - innodb_flush_log_at_trx_commit = 2: Drastically reduces disk I/O bottlenecks
    """
    cnf_content = """# W3Panel Production MariaDB Performance & Low-Memory Tuning
[mysqld]
skip-name-resolve = 1
performance_schema = OFF
innodb_buffer_pool_size = 128M
innodb_log_file_size = 32M
innodb_flush_log_at_trx_commit = 2
max_connections = 100
table_open_cache = 400
thread_cache_size = 16
query_cache_type = 0
query_cache_size = 0
"""
    mariadb_conf_dirs = [
        Path('/etc/mysql/mariadb.conf.d'),
        Path('/etc/mysql/conf.d'),
    ]

    target_file = None
    if os.access('/etc/mysql', os.W_OK) or _has_sudo():
        for d in mariadb_conf_dirs:
            if d.exists() and (os.access(str(d), os.W_OK) or _has_sudo()):
                target_file = d / '99-w3panel.cnf'
                break

    if not target_file:
        fallback_dir = Path('/tmp/w3panel/mysql')
        fallback_dir.mkdir(parents=True, exist_ok=True)
        target_file = fallback_dir / '99-w3panel.cnf'

    written = _write_privileged_file(target_file, cnf_content)
    if not written:
        fallback_file = Path('/tmp/w3panel/mysql/99-w3panel.cnf')
        fallback_file.parent.mkdir(parents=True, exist_ok=True)
        fallback_file.write_text(cnf_content)
        target_file = fallback_file
        written = True

    # Attempt restarting MariaDB if installed and active
    restarted = False
    if _has_sudo():
        for svc in ['mariadb', 'mysql']:
            try:
                check = subprocess.run(['systemctl', 'is-active', svc], capture_output=True, text=True, timeout=3)
                if check.stdout.strip() == 'active':
                    res = subprocess.run(['sudo', '-n', 'systemctl', 'restart', svc], capture_output=True, timeout=10)
                    if res.returncode == 0:
                        restarted = True
                        break
            except Exception as e:
                logger.debug(f"Service {svc} restart error: {e}")

    return {
        'success': written,
        'config_path': str(target_file),
        'restarted': restarted,
    }


def get_database_tuning_status() -> dict:
    """Check whether W3Panel database tuning profile is in place."""
    candidates = [
        Path('/etc/mysql/mariadb.conf.d/99-w3panel.cnf'),
        Path('/etc/mysql/conf.d/99-w3panel.cnf'),
        Path('/tmp/w3panel/mysql/99-w3panel.cnf'),
    ]
    is_applied = any(p.exists() for p in candidates)
    return {
        'tuned': is_applied,
        'config_file': str(next((p for p in candidates if p.exists()), '')),
    }


def _get_phpmyadmin_dir() -> Path:
    return Path(os.environ.get('W3PANEL_PHPMYADMIN_DIR', '/usr/share/phpmyadmin'))


def _get_pgadmin4_dir() -> Path:
    return Path(os.environ.get('W3PANEL_PGADMIN4_DIR', '/usr/pgadmin4'))


def is_phpmyadmin_installed() -> bool:
    """Return True if phpMyAdmin web files are present on host."""
    pma_dir = _get_phpmyadmin_dir()
    return (pma_dir / 'index.php').exists()


def is_pgadmin4_installed() -> bool:
    """Return True if pgAdmin 4 web package and systemd service are installed."""
    pg_dir = _get_pgadmin4_dir()
    has_web = (pg_dir / 'web' / 'pgAdmin4.py').exists() or (pg_dir / 'venv' / 'bin' / 'gunicorn').exists()
    if not has_web:
        return False
    if os.environ.get('W3PANEL_PGADMIN4_DIR') and not os.environ.get('W3PANEL_SYSTEMD_DIR'):
        return True
    systemd_dir = Path(os.environ.get('W3PANEL_SYSTEMD_DIR', '/etc/systemd/system'))
    return (systemd_dir / 'pgadmin4.service').exists()


def is_pgadmin4_running() -> bool:
    """Return True if pgadmin4 systemd unit is active."""
    if not is_pgadmin4_installed():
        return False
    try:
        res = subprocess.run(['systemctl', 'is-active', 'pgadmin4'], capture_output=True, text=True, timeout=2)
        return res.stdout.strip() == 'active'
    except Exception:
        return False


def get_db_admin_tools_status() -> dict:
    """Return installation and gated availability status for phpMyAdmin & pgAdmin 4."""
    mariadb_ok = is_mariadb_installed()
    postgres_ok = is_postgresql_installed()
    pma_installed = is_phpmyadmin_installed()
    pg4_installed = is_pgadmin4_installed()
    return {
        'mariadb_installed': mariadb_ok,
        'postgresql_installed': postgres_ok,
        'phpmyadmin_installed': pma_installed,
        'phpmyadmin_available': mariadb_ok and pma_installed,
        'pgadmin4_installed': pg4_installed,
        'pgadmin4_available': postgres_ok and pg4_installed,
        'pgadmin4_running': is_pgadmin4_running() if (postgres_ok and pg4_installed) else False,
    }


def get_db_tool_url(request, tool: str) -> str:
    """Return same-origin URL (/phpmyadmin/ or /pgadmin4/) preserving active panel scheme, host, and port."""
    slug = 'phpmyadmin' if tool == 'phpmyadmin' else 'pgadmin4'
    return f"/{slug}/"


def _detect_php_fpm_socket() -> str:
    """Find an active/installed PHP-FPM Unix socket for Nginx FastCGI."""
    for ver in ('8.3', '8.4', '8.2', '8.1', '8.0', '8.5'):
        sock = Path(f'/run/php/php{ver}-fpm.sock')
        if sock.exists():
            return str(sock)
    run_php = Path('/run/php')
    if run_php.exists():
        socks = sorted(run_php.glob('php*-fpm.sock'))
        if socks:
            return str(socks[0])
    return '/run/php/php8.3-fpm.sock'


def _nginx_has_other_default_server(enabled_dir: Path) -> bool:
    if not enabled_dir.exists():
        return False
    for entry in enabled_dir.iterdir():
        if entry.name == 'w3panel-dbtools.conf':
            continue
        try:
            if 'default_server' in entry.read_text(errors='ignore'):
                return True
        except Exception:
            continue
    return False


def _render_db_tools_locations(pma_on: bool, pg4_on: bool, php_sock: str) -> str:
    blocks = []
    if pma_on:
        pma_dir = str(_get_phpmyadmin_dir())
        blocks.append(f"""    location ^~ /phpmyadmin {{
        alias {pma_dir};
        index index.php;

        location ~ ^/phpmyadmin/(.+\\.php)$ {{
            set $pma_https "";
            if ($http_x_forwarded_proto = "https") {{
                set $pma_https "on";
            }}
            fastcgi_split_path_info ^/phpmyadmin/(.+\\.php)(/.*)$;
            include fastcgi_params;
            fastcgi_index index.php;
            fastcgi_param HTTPS $pma_https;
            fastcgi_param SCRIPT_FILENAME {pma_dir}/$1;
            fastcgi_param DOCUMENT_ROOT {pma_dir};
            fastcgi_pass unix:{php_sock};
        }}

        location ~* ^/phpmyadmin/(libraries|templates|setup|sql|vendor)/ {{
            deny all;
        }}
    }}""")
    if pg4_on:
        blocks.append("""    location = /pgadmin4 {
        return 301 /pgadmin4/;
    }

    location ^~ /pgadmin4/ {
        proxy_pass http://127.0.0.1:5050;
        proxy_set_header Host $http_host;
        proxy_set_header X-Script-Name /pgadmin4;
        proxy_set_header X-Scheme $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }""")
    return "\n\n".join(blocks)


def configure_db_admin_webserver() -> dict:
    """Configure Nginx / Apache site definitions for active phpMyAdmin and pgAdmin 4 tools."""
    status = get_db_admin_tools_status()
    pma_on = status['phpmyadmin_available']
    pg4_on = status['pgadmin4_available']

    sites_avail = Path(os.environ.get('W3PANEL_NGINX_SITES_DIR', '/etc/nginx/sites-available'))
    sites_enabled = Path(os.environ.get('W3PANEL_NGINX_ENABLED_DIR', '/etc/nginx/sites-enabled'))
    nginx_conf = sites_avail / 'w3panel-dbtools.conf'
    nginx_link = sites_enabled / 'w3panel-dbtools.conf'

    apache_conf_dir = Path(os.environ.get('W3PANEL_APACHE_CONF_DIR', '/etc/apache2/conf-available'))
    apache_conf = apache_conf_dir / 'w3panel-dbtools.conf'

    if not pma_on and not pg4_on:
        for path in (nginx_link, nginx_conf, apache_conf):
            try:
                if path.exists() or path.is_symlink():
                    path.unlink()
            except (PermissionError, OSError):
                if _has_sudo():
                    subprocess.run(['sudo', '-n', 'rm', '-f', str(path)], capture_output=True, timeout=5)
        if shutil.which('nginx') and _has_sudo():
            subprocess.run(['sudo', '-n', 'systemctl', 'reload', 'nginx'], capture_output=True, timeout=5)
        return {'success': True, 'configured': False}

    # Build server_names safely without conflicting with customer domain vhosts
    server_names = ['localhost']
    try:
        from packages.core.models import SystemSetting
        for key in ('server_ip', 'server_hostname'):
            val = SystemSetting.get(key, '').strip()
            if val and val not in server_names and ' ' not in val:
                server_names.append(val)
    except Exception:
        pass

    has_other_default = _nginx_has_other_default_server(sites_enabled)
    listen_80 = 'listen 80;' if has_other_default else 'listen 80 default_server;'
    listen_443 = 'listen 443 ssl;' if has_other_default else 'listen 443 ssl default_server;'

    php_sock = _detect_php_fpm_socket()
    locations = _render_db_tools_locations(pma_on, pg4_on, php_sock)

    names_str = ' '.join(server_names)
    nginx_body = [
        f"""server {{
    listen 127.0.0.1:8090;
    server_name _;
    client_max_body_size 128M;

{locations}
}}""",
        f"""server {{
    {listen_80}
    server_name {names_str};
    client_max_body_size 128M;

{locations}
}}"""
    ]

    ssl_dir = Path(os.environ.get('W3PANEL_SSL_DIR', '/etc/w3panel/ssl'))
    cert_path = ssl_dir / 'panel.crt'
    key_path = ssl_dir / 'panel.key'
    if cert_path.exists() and key_path.exists():
        nginx_body.append(f"""server {{
    {listen_443}
    server_name {names_str};
    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    client_max_body_size 128M;

{locations}
}}""")

    nginx_content = "\n\n".join(nginx_body) + "\n"

    if sites_avail.exists() or os.environ.get('W3PANEL_NGINX_SITES_DIR'):
        prev_content = nginx_conf.read_text(errors='ignore') if nginx_conf.exists() else None
        _write_privileged_file(nginx_conf, nginx_content)
        try:
            sites_enabled.mkdir(parents=True, exist_ok=True)
            if not nginx_link.exists() and not nginx_link.is_symlink():
                nginx_link.symlink_to(nginx_conf)
        except (PermissionError, OSError):
            if _has_sudo():
                subprocess.run(['sudo', '-n', 'ln', '-sf', str(nginx_conf), str(nginx_link)], capture_output=True, timeout=5)

        if shutil.which('nginx') and _has_sudo():
            test_res = subprocess.run(['sudo', '-n', 'nginx', '-t'], capture_output=True, text=True, timeout=5)
            if test_res.returncode == 0:
                subprocess.run(['sudo', '-n', 'systemctl', 'reload', 'nginx'], capture_output=True, timeout=5)
            else:
                if prev_content is not None:
                    _write_privileged_file(nginx_conf, prev_content)
                else:
                    subprocess.run(['sudo', '-n', 'rm', '-f', str(nginx_link), str(nginx_conf)], capture_output=True, timeout=5)
                return {'success': False, 'error': test_res.stderr or test_res.stdout}

    if (apache_conf_dir.exists() or os.environ.get('W3PANEL_APACHE_CONF_DIR')) and (shutil.which('apache2') or os.environ.get('W3PANEL_APACHE_CONF_DIR')):
        apache_lines = ['# W3Panel Database Admin Tools']
        if pma_on and Path('/etc/apache2/conf-available/phpmyadmin.conf').exists() and _has_sudo():
            subprocess.run(['sudo', '-n', 'a2enconf', 'phpmyadmin'], capture_output=True, timeout=5)
        if pg4_on:
            apache_lines.extend([
                'ProxyPreserveHost On',
                'RequestHeader set X-Script-Name "/pgadmin4"',
                'ProxyPass /pgadmin4 http://127.0.0.1:5050/pgadmin4',
                'ProxyPassReverse /pgadmin4 http://127.0.0.1:5050/pgadmin4',
            ])
        if len(apache_lines) > 1:
            _write_privileged_file(apache_conf, "\n".join(apache_lines) + "\n")
            if _has_sudo():
                subprocess.run(['sudo', '-n', 'a2enmod', 'proxy', 'proxy_http', 'headers'], capture_output=True, timeout=5)
                subprocess.run(['sudo', '-n', 'a2enconf', 'w3panel-dbtools'], capture_output=True, timeout=5)
                subprocess.run(['sudo', '-n', 'systemctl', 'reload', 'apache2'], capture_output=True, timeout=5)

    return {'success': True, 'phpmyadmin': pma_on, 'pgadmin4': pg4_on}


def ensure_db_admin_webserver_configured() -> dict:
    """Auto-configure Nginx/Apache DB tool routes if an installed DB+tool is not yet wired."""
    status = get_db_admin_tools_status()
    if not status['phpmyadmin_available'] and not status['pgadmin4_available']:
        return {'success': True, 'configured': False}
    sites_enabled = Path(os.environ.get('W3PANEL_NGINX_ENABLED_DIR', '/etc/nginx/sites-enabled'))
    conf_link = sites_enabled / 'w3panel-dbtools.conf'
    if conf_link.exists():
        try:
            if '127.0.0.1:8090' in conf_link.read_text(errors='ignore'):
                return {'success': True, 'configured': True}
        except Exception:
            return {'success': True, 'configured': True}
    if not _find_bin('nginx', 'apache2') and not os.environ.get('W3PANEL_NGINX_SITES_DIR'):
        return {'success': True, 'configured': False}
    return configure_db_admin_webserver()


def proxy_http_upstream(
    request,
    slug: str,
    subpath: str,
    targets: list[tuple[str, int]],
    extra_headers: dict | None = None,
    on_unreachable=None,
):
    """Reverse-proxy an internal web tool on the active panel host, port, and scheme."""
    from django.http import HttpResponse
    from django.shortcuts import redirect

    if not subpath and not request.path_info.endswith('/'):
        qs = request.META.get('QUERY_STRING', '')
        return redirect(f'/{slug}/' + (f'?{qs}' if qs else ''))

    clean_sub = (subpath or '').lstrip('/')
    upstream_path = f'/{slug}/{clean_sub}'
    qs = request.META.get('QUERY_STRING', '')
    if qs:
        upstream_path = f'{upstream_path}?{qs}'

    req_host = request.get_host()
    proto = 'https' if (request.is_secure() or request.META.get('HTTP_X_FORWARDED_PROTO') == 'https') else 'http'
    fwd_headers = {
        'Host': req_host,
        'X-Forwarded-Host': req_host,
        'X-Forwarded-Proto': proto,
        'X-Scheme': proto,
        'Accept-Encoding': 'identity',
    }
    if extra_headers:
        fwd_headers.update(extra_headers)

    for meta_key, hdr_name in (
        ('CONTENT_TYPE', 'Content-Type'),
        ('HTTP_COOKIE', 'Cookie'),
        ('HTTP_ACCEPT', 'Accept'),
        ('HTTP_ACCEPT_LANGUAGE', 'Accept-Language'),
        ('HTTP_USER_AGENT', 'User-Agent'),
        ('HTTP_X_REQUESTED_WITH', 'X-Requested-With'),
        ('HTTP_X_CSRFTOKEN', 'X-CSRFToken'),
        ('HTTP_X_SM_TOKEN', 'X-SM-Token'),
    ):
        val = request.META.get(meta_key)
        if val:
            fwd_headers[hdr_name] = val

    body_bytes = request.body if request.method in ('POST', 'PUT', 'PATCH', 'DELETE') else None
    if body_bytes is not None:
        fwd_headers['Content-Length'] = str(len(body_bytes))

    def _try_upstream():
        last_e = None
        for host, port in targets:
            conn = None
            try:
                conn = http.client.HTTPConnection(host, port, timeout=60)
                conn.request(request.method, upstream_path, body=body_bytes, headers=fwd_headers)
                r = conn.getresponse()
                return r, r.read(), None
            except Exception as exc:
                last_e = exc
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
        return None, b'', last_e

    upstream_resp, upstream_body, last_err = _try_upstream()
    if upstream_resp is None and on_unreachable is not None:
        if on_unreachable():
            upstream_resp, upstream_body, last_err = _try_upstream()

    if upstream_resp is None:
        return HttpResponse(f'Unable to reach {slug} backend ({last_err}). Check service status in Service Manager.', status=502)

    resp = HttpResponse(upstream_body, status=upstream_resp.status)
    skip_headers = {'transfer-encoding', 'connection', 'keep-alive', 'content-encoding', 'content-length', 'set-cookie'}
    host_no_port = req_host.split(':')[0]

    for key, val in upstream_resp.getheaders():
        low = key.lower()
        if low in skip_headers:
            continue
        if low == 'location':
            for prefix in (
                'http://127.0.0.1:8090', 'https://127.0.0.1:8090',
                'http://127.0.0.1:8091', 'https://127.0.0.1:8091',
                'http://127.0.0.1:5050', 'https://127.0.0.1:5050',
                'http://127.0.0.1:80', 'http://127.0.0.1',
                f'https://{host_no_port}', f'http://{host_no_port}',
            ):
                if val.startswith(prefix + '/'):
                    val = val[len(prefix):]
                    break
        resp[key] = val

    for raw_cookie in (upstream_resp.headers.get_all('Set-Cookie') or []):
        try:
            parsed = SimpleCookie()
            parsed.load(raw_cookie)
            for cname, morsel in parsed.items():
                resp.cookies[cname] = morsel.value
                for attr in ('path', 'max-age', 'expires', 'httponly', 'samesite'):
                    if morsel.get(attr):
                        resp.cookies[cname][attr] = morsel[attr]
                if request.is_secure():
                    resp.cookies[cname]['secure'] = True
        except Exception:
            pass

    return resp


def proxy_db_tool_request(request, tool: str, subpath: str = ''):
    """Reverse-proxy /phpmyadmin/... and /pgadmin4/... on the active panel host & port."""
    from django.http import HttpResponse

    slug = 'phpmyadmin' if tool == 'phpmyadmin' else ('pgadmin4' if tool == 'pgadmin4' else '')
    if not slug:
        return HttpResponse('Unknown database tool.', status=404)

    db_tools = get_db_admin_tools_status()
    if (slug == 'phpmyadmin' and not db_tools['phpmyadmin_available']) or (slug == 'pgadmin4' and not db_tools['pgadmin4_available']):
        return HttpResponse(f'{slug} is not installed or its database engine is unavailable.', status=404)

    extra_headers = None
    on_unreachable = None
    if slug == 'phpmyadmin':
        ensure_db_admin_webserver_configured()
        targets = [('127.0.0.1', 8090), ('127.0.0.1', 80)]
    else:
        targets = [('127.0.0.1', 5050)]
        extra_headers = {'X-Script-Name': '/pgadmin4'}

        def _recover_pg4():
            if ensure_pgadmin4_service_ready().get('success'):
                import time
                time.sleep(0.6)
                return True
            return False

        on_unreachable = _recover_pg4

    return proxy_http_upstream(
        request,
        slug=slug,
        subpath=subpath,
        targets=targets,
        extra_headers=extra_headers,
        on_unreachable=on_unreachable,
    )


def _get_pma_signon_secret() -> str:
    """Return persistent HMAC/header secret shared with phpMyAdmin signon endpoint."""
    try:
        from packages.core.models import SystemSetting
        secret = SystemSetting.get('pma_signon_secret', '').strip()
        if not secret:
            secret = secrets.token_hex(32)
            SystemSetting.set('pma_signon_secret', secret)
        return secret
    except Exception:
        return os.environ.get('W3PANEL_PMA_SIGNON_SECRET', 'w3panel-dev-signon-secret')


def ensure_phpmyadmin_signon_configured() -> bool:
    """Write phpMyAdmin signon PHP config override and loopback signon script."""
    if not is_phpmyadmin_installed():
        return False

    secret = _get_pma_signon_secret()
    pma_conf_dir = Path(os.environ.get('W3PANEL_PHPMYADMIN_CONF_DIR', '/etc/phpmyadmin')) / 'conf.d'
    conf_file = pma_conf_dir / '99-w3panel.php'
    pma_dir = _get_phpmyadmin_dir()
    signon_file = pma_dir / 'w3p-signon.php'

    safe_secret = secret.replace("'", "\\'")
    conf_php = f"""<?php
if (!defined('W3P_PMA_SIGNON_SECRET')) {{
    define('W3P_PMA_SIGNON_SECRET', '{safe_secret}');
}}
$cfg['Servers'][1]['host'] = 'localhost';
$cfg['Servers'][1]['AllowNoPassword'] = false;
$cfg['Servers'][1]['auth_type'] = isset($_COOKIE['W3PanelPMASignon']) ? 'signon' : 'cookie';
$cfg['Servers'][1]['SignonSession'] = 'W3PanelPMASignon';
$cfg['Servers'][1]['SignonCookieParams'] = [
    'lifetime' => 0,
    'path' => '/phpmyadmin',
    'httponly' => true,
    'samesite' => 'Lax',
];
$cfg['Servers'][1]['SignonURL'] = '/phpmyadmin/w3p-signon.php';
$cfg['Servers'][1]['LogoutURL'] = '/phpmyadmin/w3p-signon.php?logout=1';
"""
    safe_conf_path = str(conf_file).replace("'", "\\'")
    signon_php = f"""<?php
declare(strict_types=1);
$confFile = '{safe_conf_path}';
if (is_readable($confFile)) {{
    require_once $confFile;
}}
$provided = $_SERVER['HTTP_X_W3PANEL_SIGNON_SECRET'] ?? '';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST'
    && defined('W3P_PMA_SIGNON_SECRET')
    && W3P_PMA_SIGNON_SECRET !== ''
    && is_string($provided)
    && hash_equals(W3P_PMA_SIGNON_SECRET, $provided)
) {{
    $user = (string)($_POST['user'] ?? '');
    $pass = (string)($_POST['password'] ?? '');
    $host = (string)($_POST['host'] ?? 'localhost');
    $port = (string)($_POST['port'] ?? '3306');
    if ($user === '') {{
        http_response_code(400);
        exit;
    }}
    ini_set('session.use_cookies', '1');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/phpmyadmin',
        'domain' => '',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_name('W3PanelPMASignon');
    @session_start();
    $_SESSION['PMA_single_signon_user'] = $user;
    $_SESSION['PMA_single_signon_password'] = $pass;
    $_SESSION['PMA_single_signon_host'] = $host;
    $_SESSION['PMA_single_signon_port'] = $port;
    $_SESSION['PMA_single_signon_HMAC_secret'] = hash('sha1', random_bytes(16), true);
    @session_write_close();
    header('Content-Type: application/json');
    echo '{{"success":true}}';
    exit;
}}
setcookie('W3PanelPMASignon', '', [
    'expires' => time() - 3600,
    'path' => '/phpmyadmin',
    'httponly' => true,
    'samesite' => 'Lax',
]);
header('Location: /phpmyadmin/');
exit;
"""
    ok_conf = _write_privileged_file(conf_file, conf_php)
    ok_signon = _write_privileged_file(signon_file, signon_php)
    if ok_conf and _has_sudo():
        prefix = _priv_prefix()
        subprocess.run(prefix + ['chgrp', 'www-data', str(conf_file)], capture_output=True, timeout=5)
        subprocess.run(prefix + ['chmod', '640', str(conf_file)], capture_output=True, timeout=5)
    return ok_conf and ok_signon


def provision_phpmyadmin_sso_credentials(panel_user) -> dict:
    """Create or rotate scoped MariaDB SSO credentials for admin or tenant user."""
    if not panel_user or not is_mariadb_installed():
        return {'success': False, 'error': 'MariaDB or panel user unavailable'}

    pwd = generate_secure_password(24)
    safe_pwd = _escape_sql_str(pwd)
    prefix = _priv_prefix()

    try:
        role = getattr(panel_user, 'role', 'user')
        if role == 'admin':
            db_user = 'w3p_admin_pma'
            sql = (
                f"DROP USER IF EXISTS '{db_user}'@'localhost';"
                f" CREATE USER '{db_user}'@'localhost' IDENTIFIED BY '{safe_pwd}';"
                f" GRANT ALL PRIVILEGES ON *.* TO '{db_user}'@'localhost' WITH GRANT OPTION;"
                " FLUSH PRIVILEGES;"
            )
        else:
            clean = re.sub(r'[^a-zA-Z0-9_]', '', getattr(panel_user, 'username', '') or 'usr') or 'usr'
            db_user = _validate_db_identifier(f"{clean[:27]}_pma"[:32], 'sso_user')
            from packages.core.models import Database
            owned_dbs = list(
                Database.objects.filter(owner=panel_user, db_type='mariadb').values_list('name', flat=True)
            )
            stmts = [
                f"DROP USER IF EXISTS '{db_user}'@'localhost';",
                f"CREATE USER '{db_user}'@'localhost' IDENTIFIED BY '{safe_pwd}';",
            ]
            for db_name in owned_dbs:
                safe_db = _validate_db_identifier(db_name, 'database name')
                stmts.append(f"GRANT ALL PRIVILEGES ON `{safe_db}`.* TO '{db_user}'@'localhost';")
            stmts.append("FLUSH PRIVILEGES;")
            sql = " ".join(stmts)

        res = subprocess.run(prefix + ['mysql', '-e', sql], capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            return {'success': False, 'error': res.stderr or res.stdout or 'Failed to provision MariaDB SSO user'}
        return {'success': True, 'db_user': db_user, 'db_pass': pwd}
    except Exception as e:
        logger.warning(f"phpMyAdmin SSO provisioning failed: {e}")
        return {'success': False, 'error': str(e)}


def launch_db_tool(request, tool: str, panel_user):
    """Auto-wire Nginx route, establish phpMyAdmin SSO cookie if available, and redirect same-origin."""
    from django.shortcuts import redirect

    ensure_db_admin_webserver_configured()
    if tool != 'phpmyadmin':
        ensure_pgadmin4_service_ready(admin_email=getattr(panel_user, 'email', '') or '')
        return redirect(get_db_tool_url(request, 'pgadmin4'))

    ensure_phpmyadmin_signon_configured()
    resp = redirect(get_db_tool_url(request, 'phpmyadmin'))

    cred_res = provision_phpmyadmin_sso_credentials(panel_user)
    if not cred_res.get('success'):
        return resp

    payload = urllib.parse.urlencode({
        'user': cred_res['db_user'],
        'password': cred_res['db_pass'],
        'host': 'localhost',
        'port': '3306',
    }).encode()
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': str(len(payload)),
        'X-W3Panel-Signon-Secret': _get_pma_signon_secret(),
        'Host': request.get_host(),
    }

    for host, port in (('127.0.0.1', 8090), ('127.0.0.1', 80)):
        conn = None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.request('POST', '/phpmyadmin/w3p-signon.php', body=payload, headers=headers)
            signon_resp = conn.getresponse()
            signon_resp.read()
            if signon_resp.status == 200:
                for raw_cookie in (signon_resp.headers.get_all('Set-Cookie') or []):
                    parsed = SimpleCookie()
                    parsed.load(raw_cookie)
                    for cname, morsel in parsed.items():
                        resp.cookies[cname] = morsel.value
                        resp.cookies[cname]['path'] = '/phpmyadmin'
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


def _priv_prefix() -> list[str]:
    """Return [] when running as root, else ['sudo', '-n']."""
    return [] if os.geteuid() == 0 else ['sudo', '-n']


def _run_apt_safe(apt_args: list[str], timeout: int = 360) -> subprocess.CompletedProcess:
    """Run apt-get non-interactively waiting on dpkg locks and recovering interrupted dpkg."""
    apt_env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
    prefix = _priv_prefix()
    cmd = prefix + ['env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', '-o', 'DPkg::Lock::Timeout=120'] + apt_args
    res = subprocess.run(cmd, env=apt_env, capture_output=True, text=True, timeout=timeout)
    out_s = res.stdout.decode(errors='replace') if isinstance(res.stdout, bytes) else (res.stdout or '')
    err_s = res.stderr.decode(errors='replace') if isinstance(res.stderr, bytes) else (res.stderr or '')
    combined = f"{err_s}\n{out_s}"
    if res.returncode != 0 and ('dpkg was interrupted' in combined or 'dpkg --configure -a' in combined):
        cfg_cmd = prefix + ['env', 'DEBIAN_FRONTEND=noninteractive', 'dpkg', '--configure', '-a']
        subprocess.run(cfg_cmd, env=apt_env, capture_output=True, text=True, timeout=180)
        res = subprocess.run(cmd, env=apt_env, capture_output=True, text=True, timeout=timeout)
    return res


def install_phpmyadmin() -> dict:
    """Install phpMyAdmin non-interactively (strictly requires MariaDB/MySQL installed)."""
    if not is_mariadb_installed():
        return {'success': False, 'error': 'MariaDB / MySQL must be installed before installing phpMyAdmin.'}

    apt_env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'}
    prefix = _priv_prefix()
    try:
        debconf_seed = (
            "phpmyadmin phpmyadmin/dbconfig-install boolean false\n"
            "phpmyadmin phpmyadmin/reconfigure-webserver multiselect\n"
        )
        if shutil.which('debconf-set-selections'):
            subprocess.run(
                prefix + ['debconf-set-selections'],
                input=debconf_seed,
                text=True,
                env=apt_env,
                capture_output=True,
                timeout=10,
            )

        upd_res = _run_apt_safe(['update', '-y'], timeout=120)
        if upd_res.returncode != 0:
            logger.warning(f"apt-get update warning during phpMyAdmin install: {upd_res.stderr}")
        res = _run_apt_safe(['install', '-y', 'phpmyadmin', 'php-mysql', 'php-mbstring', 'php-xml'], timeout=300)
        if res.returncode != 0:
            return {'success': False, 'error': res.stderr or res.stdout or 'phpMyAdmin installation failed'}

        if service_result := ensure_phpmyadmin_signon_configured():
            pass

        web_res = configure_db_admin_webserver()
        if not web_res.get('success'):
            return {'success': False, 'error': web_res.get('error', 'Webserver configuration failed')}
        return {'success': True}
    except Exception as e:
        logger.error(f"phpMyAdmin install error: {e}")
        return {'success': False, 'error': str(e)}


def uninstall_phpmyadmin() -> dict:
    """Remove phpMyAdmin and refresh webserver dbtools configuration."""
    try:
        res = _run_apt_safe(['remove', '-y', 'phpmyadmin'], timeout=180)
        configure_db_admin_webserver()
        if res.returncode != 0:
            return {'success': False, 'error': res.stderr or res.stdout or 'phpMyAdmin removal failed'}
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def configure_pgadmin4_runtime(admin_email: str = '', admin_password: str = '') -> dict:
    """Write pgAdmin 4 config_local.py, initialize DB, install systemd unit, and configure Nginx/Apache."""
    email = (admin_email or '').strip()
    if not email:
        try:
            from packages.core.models import SystemSetting
            email = SystemSetting.get('admin_email', '').strip()
        except Exception:
            email = ''
    if not email or '@' not in email:
        email = 'admin@localhost.localdomain'

    password = admin_password or generate_secure_password(16)
    prefix = _priv_prefix()
    pg_dir = _get_pgadmin4_dir()

    config_local = """import os

SERVER_MODE = True
DEFAULT_SERVER = '127.0.0.1'
DEFAULT_SERVER_PORT = 5050
PROXY_X_HOST_COUNT = 1
PROXY_X_PREFIX_COUNT = 1
DATA_DIR = '/var/lib/pgadmin'
LOG_FILE = '/var/log/pgadmin/pgadmin4.log'
SQLITE_PATH = os.path.join(DATA_DIR, 'pgadmin4.db')
SESSION_DB_PATH = os.path.join(DATA_DIR, 'sessions')
STORAGE_DIR = os.path.join(DATA_DIR, 'storage')
MASTER_PASSWORD_REQUIRED = False
"""
    _write_privileged_file(pg_dir / 'web' / 'config_local.py', config_local)

    subprocess.run(
        prefix + ['mkdir', '-p', '/var/lib/pgadmin/sessions', '/var/lib/pgadmin/storage', '/var/log/pgadmin'],
        capture_output=True,
        timeout=5,
    )
    subprocess.run(prefix + ['chown', '-R', 'www-data:www-data', '/var/lib/pgadmin', '/var/log/pgadmin'], capture_output=True, timeout=5)

    # Pass credentials via 0600 script instead of CLI arguments or sudo -E (blocked without SETENV)
    db_file = Path('/var/lib/pgadmin/pgadmin4.db')
    if not db_file.exists() or db_file.stat().st_size == 0:
        py_bin = shlex.quote(str(pg_dir / 'venv' / 'bin' / 'python'))
        setup_py = shlex.quote(str(pg_dir / 'web' / 'setup.py'))
        script_body = (
            "#!/usr/bin/env bash\n"
            "set -e\n"
            f"export PGADMIN_SETUP_EMAIL={shlex.quote(email)}\n"
            f"export PGADMIN_SETUP_PASSWORD={shlex.quote(password)}\n"
            f"{py_bin} {setup_py} setup-db\n"
        )
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix='w3panel-pg4-', suffix='.sh')
            os.chmod(tmp_path, 0o600)
            with os.fdopen(fd, 'w') as fh:
                fh.write(script_body)
            setup_res = subprocess.run(
                prefix + ['/bin/bash', tmp_path],
                capture_output=True,
                text=True,
                timeout=90,
            )
            if setup_res.returncode != 0:
                return {'success': False, 'error': setup_res.stderr or setup_res.stdout or 'pgAdmin4 database initialization failed'}
        finally:
            if tmp_path and Path(tmp_path).exists():
                try:
                    Path(tmp_path).unlink()
                except OSError:
                    pass

    subprocess.run(prefix + ['chown', '-R', 'www-data:www-data', '/var/lib/pgadmin', '/var/log/pgadmin'], capture_output=True, timeout=5)

    # Ensure WSGI runner executes strictly inside pgAdmin4's own venv (never W3Panel's venv)
    pg_gunicorn = pg_dir / 'venv' / 'bin' / 'gunicorn'
    pg_pip = pg_dir / 'venv' / 'bin' / 'pip'
    if not pg_gunicorn.exists() and pg_pip.exists():
        subprocess.run(prefix + [str(pg_pip), 'install', '-q', 'gunicorn'], capture_output=True, text=True, timeout=120)

    pg_waitress = pg_dir / 'venv' / 'bin' / 'waitress-serve'
    pg_python = pg_dir / 'venv' / 'bin' / 'python'
    if pg_gunicorn.exists():
        exec_start = f"{pg_gunicorn} --workers 1 --threads 25 --bind 127.0.0.1:5050 pgAdmin4:app"
    elif pg_waitress.exists():
        exec_start = f"{pg_waitress} --listen=127.0.0.1:5050 --threads=25 pgAdmin4:app"
    else:
        exec_start = f"{pg_python} {pg_dir}/web/pgAdmin4.py"

    unit_content = f"""[Unit]
Description=pgAdmin 4 Web Service (W3Panel)
After=network.target postgresql.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory={pg_dir}/web
Environment="SCRIPT_NAME=/pgadmin4"
ExecStart={exec_start}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    systemd_dir = Path(os.environ.get('W3PANEL_SYSTEMD_DIR', '/etc/systemd/system'))
    _write_privileged_file(systemd_dir / 'pgadmin4.service', unit_content)

    subprocess.run(prefix + ['systemctl', 'daemon-reload'], capture_output=True, timeout=10)
    start_res = subprocess.run(prefix + ['systemctl', 'enable', '--now', 'pgadmin4'], capture_output=True, text=True, timeout=15)
    if start_res.returncode != 0:
        j_res = subprocess.run(prefix + ['journalctl', '-u', 'pgadmin4', '-n', '15', '--no-pager'], capture_output=True, text=True, timeout=5)
        detail = (start_res.stderr or start_res.stdout or '').strip()
        if j_res.stdout:
            detail = f"{detail}\n{j_res.stdout.strip()}".strip()
        return {'success': False, 'error': detail or 'Failed to start pgadmin4.service'}

    web_res = configure_db_admin_webserver()
    if not web_res.get('success'):
        return {'success': False, 'error': web_res.get('error', 'Webserver configuration failed')}

    return {'success': True, 'email': email, 'password': password}


def ensure_pgadmin4_service_ready(admin_email: str = '') -> dict:
    """Repair missing/misconfigured pgadmin4.service and start it if inactive."""
    pg_dir = _get_pgadmin4_dir()
    if not (pg_dir / 'web' / 'pgAdmin4.py').exists():
        return {'success': False, 'error': 'pgAdmin 4 web files not installed.'}

    systemd_dir = Path(os.environ.get('W3PANEL_SYSTEMD_DIR', '/etc/systemd/system'))
    unit_file = systemd_dir / 'pgadmin4.service'
    needs_rewrite = not unit_file.exists()
    if not needs_rewrite:
        try:
            unit_txt = unit_file.read_text(errors='ignore')
            if '/usr/local/w3panel/' in unit_txt or '127.0.0.1:5050' not in unit_txt:
                needs_rewrite = True
        except Exception:
            needs_rewrite = True

    if needs_rewrite:
        return configure_pgadmin4_runtime(admin_email=admin_email)

    if not is_pgadmin4_running():
        prefix = _priv_prefix()
        res = subprocess.run(prefix + ['systemctl', 'start', 'pgadmin4'], capture_output=True, text=True, timeout=15)
        if res.returncode != 0:
            return {'success': False, 'error': res.stderr or res.stdout or 'Failed to start pgadmin4'}
    return {'success': True}


def install_pgadmin4(admin_email: str = '', admin_password: str = '') -> dict:
    """Install pgAdmin 4 Web Server Mode behind Gunicorn + Nginx/Apache (requires PostgreSQL)."""
    if not is_postgresql_installed():
        return {'success': False, 'error': 'PostgreSQL must be installed before installing pgAdmin 4.'}

    prefix = _priv_prefix()
    try:
        # Detect OS codename cleanly
        codename = 'noble'
        os_release = Path('/etc/os-release')
        if os_release.exists():
            for line in os_release.read_text(errors='ignore').splitlines():
                if line.startswith('UBUNTU_CODENAME=') or line.startswith('VERSION_CODENAME='):
                    val = line.split('=', 1)[1].strip().strip('"').lower()
                    if re.match(r'^[a-z0-9-]+$', val):
                        codename = val
                        if line.startswith('UBUNTU_CODENAME='):
                            break

        keyring_path = '/etc/apt/keyrings/packages-pgadmin-org.gpg'
        if not Path(keyring_path).exists():
            subprocess.run(prefix + ['mkdir', '-p', '/etc/apt/keyrings'], capture_output=True, timeout=5)
            key_dl = subprocess.run(
                ['curl', '-fsSL', 'https://www.pgadmin.org/static/packages_pgadmin_org.pub'],
                capture_output=True,
                timeout=30,
            )
            if key_dl.returncode != 0 or not key_dl.stdout:
                return {'success': False, 'error': 'Failed to download pgAdmin GPG signing key.'}
            gpg_res = subprocess.run(
                prefix + ['gpg', '--dearmor', '--yes', '-o', keyring_path],
                input=key_dl.stdout,
                capture_output=True,
                timeout=15,
            )
            if gpg_res.returncode != 0:
                return {'success': False, 'error': 'Failed to install pgAdmin GPG signing key.'}

        sources_dir = Path(os.environ.get('W3PANEL_APT_SOURCES_DIR', '/etc/apt/sources.list.d'))
        stale_sources = sources_dir / 'pgadmin4.sources'
        if stale_sources.exists():
            subprocess.run(prefix + ['rm', '-f', str(stale_sources)], capture_output=True, timeout=5)
        list_content = (
            f"deb [signed-by={keyring_path}] https://ftp.postgresql.org/pub/pgadmin/pgadmin4/apt/{codename} pgadmin4 main\n"
        )
        _write_privileged_file(sources_dir / 'pgadmin4.list', list_content)

        upd_res = _run_apt_safe(['update', '-y'], timeout=120)
        if upd_res.returncode != 0:
            logger.warning(f"apt-get update warning during pgAdmin4 install: {upd_res.stderr}")
        inst_res = _run_apt_safe(['install', '-y', 'pgadmin4-web'], timeout=420)
        if inst_res.returncode != 0:
            return {'success': False, 'error': inst_res.stderr or inst_res.stdout or 'pgadmin4-web installation failed'}

        return configure_pgadmin4_runtime(admin_email=admin_email, admin_password=admin_password)
    except Exception as e:
        logger.error(f"pgAdmin4 install error: {e}")
        return {'success': False, 'error': str(e)}


def uninstall_pgadmin4() -> dict:
    """Stop and remove pgAdmin 4 service/package and refresh webserver dbtools configuration."""
    prefix = _priv_prefix()
    try:
        subprocess.run(prefix + ['systemctl', 'disable', '--now', 'pgadmin4'], capture_output=True, timeout=10)
        unit_file = Path(os.environ.get('W3PANEL_SYSTEMD_DIR', '/etc/systemd/system')) / 'pgadmin4.service'
        if unit_file.exists():
            subprocess.run(prefix + ['rm', '-f', str(unit_file)], capture_output=True, timeout=5)
            subprocess.run(prefix + ['systemctl', 'daemon-reload'], capture_output=True, timeout=10)
        res = _run_apt_safe(['remove', '-y', 'pgadmin4-web'], timeout=180)
        configure_db_admin_webserver()
        if res.returncode != 0:
            return {'success': False, 'error': res.stderr or res.stdout or 'pgAdmin 4 removal failed'}
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}
