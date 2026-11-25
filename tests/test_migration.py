"""
W3Panel v2 — Modular Panel Migrators & cPanel Migration Tests
"""
import io
import json
import os
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase

from packages.core.models import (
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


def _add_tar_bytes(tar: tarfile.TarFile, arcname: str, data: bytes):
    info = tarfile.TarInfo(name=arcname)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def _build_cpanel_tarball(dest_path: Path, username: str = 'testacct') -> Path:
    root = f'cpmove-{username}'
    with tarfile.open(dest_path, 'w:gz') as tar:
        _add_tar_bytes(
            tar,
            f'{root}/cp/{username}',
            (
                f'USER={username}\n'
                f'CONTACTEMAIL=owner@example.com\n'
                f'DNS=example.com\n'
                f'IP=198.51.100.5\n'
                f'PLAN=AgencyPlan\n'
                f'BWLIMIT=53687091200\n'
                f'MAXSQL=10\n'
                f'MAXPOP=25\n'
                f'MAXFTP=5\n'
            ).encode(),
        )
        _add_tar_bytes(tar, f'{root}/quota', b'2147483648\n')
        _add_tar_bytes(tar, f'{root}/passwd', f'{username}:x:1001:1001::/home/{username}:/bin/bash\n'.encode())
        _add_tar_bytes(
            tar,
            f'{root}/userdata/main',
            (
                '---\n'
                'main_domain: example.com\n'
                'addon_domains:\n'
                '  addon.net: addon.example.com\n'
                'parked_domains:\n'
                '  - alias.example.org\n'
                'sub_domains:\n'
                '  - blog.example.com\n'
                '  - addon.example.com\n'
            ).encode(),
        )
        _add_tar_bytes(
            tar,
            f'{root}/userdata/example.com',
            (
                '---\n'
                f'documentroot: /home/{username}/public_html\n'
                f'homedir: /home/{username}\n'
                'ip: 198.51.100.5\n'
                'phpversion: ea-php82\n'
            ).encode(),
        )
        _add_tar_bytes(
            tar,
            f'{root}/userdata/addon.net',
            (
                '---\n'
                f'documentroot: /home/{username}/public_html/addon.net\n'
                f'homedir: /home/{username}\n'
                'phpversion: ea-php83\n'
            ).encode(),
        )
        _add_tar_bytes(
            tar,
            f'{root}/userdata/blog.example.com',
            (
                '---\n'
                f'documentroot: /home/{username}/public_html/blog\n'
                f'homedir: /home/{username}\n'
                'phpversion: ea-php81\n'
            ).encode(),
        )
        _add_tar_bytes(
            tar,
            f'{root}/homedir/public_html/wp-config.php',
            (
                "<?php\n"
                f"define('DB_NAME', '{username}_wp');\n"
                f"define('DB_USER', '{username}_wpuser');\n"
                "define('DB_PASSWORD', 'WpSecretPass99!');\n"
                "define('DB_HOST', 'localhost');\n"
            ).encode(),
        )
        _add_tar_bytes(tar, f'{root}/homedir/public_html/.htaccess', b'RewriteEngine On\n')
        _add_tar_bytes(tar, f'{root}/homedir/public_html/addon.net/index.php', b'<?php echo "addon"; ?>')
        _add_tar_bytes(tar, f'{root}/homedir/public_html/blog/index.html', b'<h1>Blog</h1>')

        # Unsafe traversal entry that must be ignored
        _add_tar_bytes(tar, '../../../etc/evil_pwned', b'bad')

        # MySQL dump + grants
        _add_tar_bytes(tar, f'{root}/mysql/{username}_wp.sql', b'CREATE TABLE wp_options (id INT);\n')
        _add_tar_bytes(
            tar,
            f'{root}/mysql.sql',
            f"GRANT ALL PRIVILEGES ON `{username}_wp`.* TO '{username}_wpuser'@'localhost' IDENTIFIED BY PASSWORD '*123456';\n".encode(),
        )

        # Mailboxes + Maildir
        _add_tar_bytes(
            tar,
            f'{root}/homedir/etc/example.com/passwd',
            f'info:x:500:500::/home/{username}/mail/example.com/info:/bin/false\n'.encode(),
        )
        _add_tar_bytes(tar, f'{root}/homedir/etc/example.com/quota', b'info:262144000\n')
        _add_tar_bytes(tar, f'{root}/homedir/mail/example.com/info/cur/msg1', b'Subject: Hello\n\nTest email')

        # BIND DNS zone
        _add_tar_bytes(
            tar,
            f'{root}/dnszones/example.com.db',
            (
                '; cPanel zone file\n'
                '$TTL 14400\n'
                'example.com. 86400 IN SOA ns1.example.com. admin.example.com. (\n'
                '    2026010101 ; serial\n'
                '    3600 ; refresh\n'
                '    1800 ; retry\n'
                '    1209600 ; expire\n'
                '    86400 ) ; minimum\n'
                'example.com. 14400 IN A 198.51.100.5\n'
                'www 14400 IN CNAME example.com.\n'
                'example.com. 14400 IN MX 10 mail.example.com.\n'
                'example.com. 14400 IN TXT "v=spf1 +a +mx " "~all"\n'
            ).encode(),
        )

        # FTP + Cron + SSL
        _add_tar_bytes(
            tar,
            f'{root}/proftpdpasswd',
            f'deploy@example.com:$1$hash:500:500::/home/{username}/public_html/addon.net:/bin/ftpsh\n'.encode(),
        )
        _add_tar_bytes(
            tar,
            f'{root}/cron/{username}',
            f'MAILTO=""\n*/5 * * * * /usr/bin/php /home/{username}/public_html/wp-cron.php\n'.encode(),
        )
        _add_tar_bytes(tar, f'{root}/sslcerts/example.com.crt', b'-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----\n')
        _add_tar_bytes(tar, f'{root}/sslkeys/example.com.key', b'-----BEGIN PRIVATE KEY-----\nFAKEKEY\n-----END PRIVATE KEY-----\n')

    return dest_path


class CpanelMigrationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user('mig_admin', 'mig@local.test', 'Pass123!', role='admin')
        self.reseller = User.objects.create_user('mig_reseller', 'res@local.test', 'Pass123!', role='reseller')
        SystemSetting.set('initial_setup_completed', 'true')
        SystemSetting.set('server_ip', '203.0.113.10')
        SystemSetting.set('default_php', '8.3')
        self.client.post('/login/', {'username': 'mig_admin', 'password': 'Pass123!'})

    def test_migrator_catalog_install_uninstall_and_role_check(self):
        # Catalog page shows cPanel available and CyberPanel/others planned
        resp = self.client.get('/migration/')
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'cPanel / WHM')
        self.assertContains(resp, 'CyberPanel (OpenLiteSpeed / LiteSpeed)')
        self.assertContains(resp, 'Install Migrator')

        # Cannot open uninstalled migrator
        resp_uninstalled = self.client.get('/migration/cpanel/')
        self.assertRedirects(resp_uninstalled, '/migration/', fetch_redirect_response=False)

        # Cannot install planned migrator yet
        resp_planned = self.client.post('/migration/', {'action': 'install', 'migrator_id': 'cyberpanel'})
        self.assertEqual(resp_planned.status_code, 302)
        from services.migrators import is_migrator_installed
        self.assertFalse(is_migrator_installed('cyberpanel'))

        # Install cpanel migrator
        resp_inst = self.client.post('/migration/', {'action': 'install', 'migrator_id': 'cpanel'})
        self.assertEqual(resp_inst.status_code, 302)
        self.assertTrue(is_migrator_installed('cpanel'))

        resp_panel = self.client.get('/migration/cpanel/')
        self.assertEqual(resp_panel.status_code, 200)
        self.assertContains(resp_panel, 'cPanel / WHM Migration')

        # Uninstall cpanel migrator
        resp_uninst = self.client.post('/migration/', {'action': 'uninstall', 'migrator_id': 'cpanel'})
        self.assertEqual(resp_uninst.status_code, 302)
        self.assertFalse(is_migrator_installed('cpanel'))

        # Reseller cannot access /migration/
        r_client = Client()
        r_client.post('/login/', {'username': 'mig_reseller', 'password': 'Pass123!'})
        r_resp = r_client.get('/migration/')
        self.assertRedirects(r_resp, '/dashboard/', fetch_redirect_response=False)

    def test_cpanel_inspect_and_full_migration(self):
        self.client.post('/migration/', {'action': 'install', 'migrator_id': 'cpanel'})

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive_path = _build_cpanel_tarball(tmp / 'cpmove-testacct.tar.gz', username='testacct')

            users_dir = tmp / 'users'
            vhosts_dir = tmp / 'vhosts'
            pools_dir = tmp / 'pools'
            ssl_dir = tmp / 'ssl'
            dns_dir = tmp / 'dns'
            dkim_dir = tmp / 'opendkim'
            vmail_dir = tmp / 'vmail'
            staging_dir = tmp / 'staging'
            staging_dir.mkdir(parents=True, exist_ok=True)

            env_patch = {
                'W3PANEL_USERS_DIR': str(users_dir),
                'W3PANEL_VHOST_DIR': str(vhosts_dir),
                'W3PANEL_PHP_POOL_DIR': str(pools_dir),
                'W3PANEL_SSL_DIR': str(ssl_dir),
                'W3PANEL_DNS_DIR': str(dns_dir),
                'W3PANEL_OPENDKIM_DIR': str(dkim_dir),
            }

            with patch.dict(os.environ, env_patch), \
                 patch('services.migrators.get_staging_dir', return_value=staging_dir), \
                 patch('services.mail.manager.VMAIL_BASE', vmail_dir), \
                 patch('services.webserver.manager._has_sudo', return_value=False), \
                 patch('services.database.manager._has_sudo', return_value=False), \
                 patch('services.webserver.manager.subprocess.run') as mock_web_sub, \
                 patch('services.database.manager.subprocess.run') as mock_db_sub, \
                 patch('services.mail.manager.subprocess.run'), \
                 patch('services.ftp.manager.subprocess.Popen') as mock_ftp_popen, \
                 patch('services.ftp.manager.subprocess.run'), \
                 patch('services.cron.manager.subprocess.run'), \
                 patch('services.migrators.cpanel.subprocess.run'):
                mock_web_sub.return_value.returncode = 1
                mock_web_sub.return_value.stdout = ''
                mock_db_sub.return_value.returncode = 0
                mock_db_sub.return_value.stderr = ''
                mock_ftp_popen.return_value.communicate.return_value = ('', '')

                # 1. Inspect via upload
                uploaded = SimpleUploadedFile('cpmove-testacct.tar.gz', archive_path.read_bytes(), content_type='application/gzip')
                inspect_resp = self.client.post('/migration/cpanel/inspect/', {'archive_file': uploaded})
                self.assertEqual(inspect_resp.status_code, 200)
                inspect_data = inspect_resp.json()
                self.assertTrue(inspect_data['success'])
                self.assertTrue(inspect_data['source_token'])

                manifest = inspect_data['manifest']
                self.assertEqual(manifest['username'], 'testacct')
                self.assertEqual(manifest['email'], 'owner@example.com')
                self.assertTrue(manifest['shell_enabled'])
                self.assertEqual(manifest['plan_name'], 'AgencyPlan')
                self.assertEqual(manifest['quota_mb'], 2048)

                dom_map = {d['domain']: d for d in manifest['domains']}
                self.assertEqual(set(dom_map.keys()), {'example.com', 'addon.net', 'blog.example.com'})
                self.assertEqual(dom_map['example.com']['framework'], 'wordpress')
                self.assertEqual(dom_map['example.com']['php_version'], '8.2')
                self.assertTrue(dom_map['example.com']['has_ssl'])
                self.assertEqual(manifest['parked_domains'], ['alias.example.org'])
                self.assertEqual(len(manifest['databases']), 1)
                self.assertEqual(manifest['databases'][0]['db_user'], 'testacct_wpuser')
                self.assertEqual(len(manifest['mailboxes']), 1)
                self.assertEqual(manifest['mailboxes'][0]['quota_mb'], 250)
                self.assertEqual(len(manifest['dns_zones']), 1)
                self.assertEqual(manifest['dns_zones'][0]['records_count'], 4)
                self.assertEqual(len(manifest['ftp_accounts']), 1)
                self.assertEqual(len(manifest['cron_jobs']), 1)

                # Ensure traversal entry did not escape staging/tmp
                self.assertFalse((tmp / 'evil_pwned').exists())

                # 2. Execute migration via SSE endpoint
                exec_resp = self.client.post('/migration/cpanel/execute/', {
                    'source_token': inspect_data['source_token'],
                    'target_username': 'testacct',
                    'email': 'owner@example.com',
                    'import_websites': '1',
                    'import_databases': '1',
                    'import_mailboxes': '1',
                    'import_dns': '1',
                    'update_dns_ip': '1',
                    'import_ftp': '1',
                    'import_cron': '1',
                    'import_ssl': '1',
                })
                self.assertEqual(exec_resp.status_code, 200)
                self.assertIn('text/event-stream', exec_resp['Content-Type'])
                body = b''.join(exec_resp.streaming_content).decode()
                self.assertIn('"status": "complete"', body)

                # Verify staged file was cleaned up
                self.assertFalse((staging_dir / inspect_data['source_token']).exists())

            # 3. Verify W3Panel database models & extracted files
            user = User.objects.get(username='testacct')
            self.assertEqual(user.email, 'owner@example.com')
            self.assertTrue(user.shell_enabled)
            pkg = Package.objects.get(name='AgencyPlan')
            self.assertEqual(user.package_id, pkg.id)
            self.assertEqual(pkg.disk_limit_mb, 2048)

            wp_site = Website.objects.get(domain='example.com')
            self.assertEqual(wp_site.framework, 'wordpress')
            self.assertEqual(wp_site.php_version, '8.2')
            self.assertTrue(wp_site.ssl_enabled)
            self.assertTrue((Path(wp_site.doc_root) / 'wp-config.php').is_file())
            self.assertTrue((ssl_dir / 'example.com.crt').is_file())
            self.assertTrue((ssl_dir / 'example.com.key').is_file())

            addon_site = Website.objects.get(domain='addon.net')
            self.assertTrue((Path(addon_site.doc_root) / 'index.php').is_file())
            blog_site = Website.objects.get(domain='blog.example.com')
            self.assertTrue((Path(blog_site.doc_root) / 'index.html').is_file())

            db_obj = Database.objects.get(owner=user, name='testacct_wp')
            self.assertEqual(db_obj.db_user, 'testacct_wpuser')

            mbox = Mailbox.objects.get(owner=user, email='info@example.com')
            self.assertEqual(mbox.quota_mb, 250)
            self.assertTrue((vmail_dir / 'example.com' / 'info' / 'cur' / 'msg1').is_file())

            a_rec = DNSRecord.objects.get(domain=wp_site, record_type='A', name='@')
            self.assertEqual(a_rec.value, '203.0.113.10')
            txt_rec = DNSRecord.objects.get(domain=wp_site, record_type='TXT', name='@')
            self.assertEqual(txt_rec.value, 'v=spf1 +a +mx ~all')
            mx_rec = DNSRecord.objects.get(domain=wp_site, record_type='MX', name='@')
            self.assertEqual(mx_rec.priority, 10)
            self.assertEqual(mx_rec.value, 'mail.example.com')

            ftp = FTPAccount.objects.get(owner=user, username='deploy@example.com')
            self.assertIn('/testacct/public_html/addon.net', ftp.directory)

            cj = CronJob.objects.get(owner=user)
            self.assertIn('/testacct/public_html/wp-cron.php', cj.command)
