"""Isolated security & panel hardening tests for Host Panel, User Panel, Services, and Middleware."""

import os
import re
import tempfile
from pathlib import Path
from unittest.mock import patch

import pyotp
from django.test import TestCase, Client

from packages.core.models import (
    CronJob,
    DNSRecord,
    Database,
    FTPAccount,
    Package,
    SystemSetting,
    User,
    Website,
)
from services.cron.manager import is_valid_cron_command, is_valid_cron_schedule, sync_cron_jobs
from services.database.manager import _validate_db_identifier, create_database, delete_database_user


class HostAndUserPanelHardeningTests(TestCase):
    def setUp(self):
        self.pkg = Package.objects.create(
            name='Limited Plan',
            disk_limit_mb=5000,
            bandwidth_limit_gb=50,
            websites_limit=1,
            databases_limit=1,
            ftp_limit=1,
        )
        self.admin = User.objects.create_user('secadmin', 'secadmin@local.test', 'Pass123!', role='admin')
        self.reseller = User.objects.create_user('secreseller', 'secreseller@local.test', 'Pass123!', role='reseller')
        self.tenant = User.objects.create_user(
            'sectenant',
            'sectenant@local.test',
            'Pass123!',
            role='user',
            package=self.pkg,
            parent_reseller=self.reseller,
        )
        self.other_tenant = User.objects.create_user(
            'otheruser',
            'other@local.test',
            'Pass123!',
            role='user',
            package=self.pkg,
        )
        SystemSetting.set('initial_setup_completed', 'true')
        self.client = Client()

    def _login(self, username, password='Pass123!', url='/login/', port='2087'):
        client = Client()
        resp = client.post(url, {'username': username, 'password': password}, SERVER_PORT=port)
        self.assertEqual(resp.status_code, 302)
        return client, {'SERVER_PORT': port}

    # ------------------------------------------------------------------
    # 1. Middleware Authentication & Role Isolation
    # ------------------------------------------------------------------

    def test_unauthenticated_redirect_on_default_port(self):
        """Non-2087/2083 proxy/HTTP ports still enforce login on protected panel routes."""
        resp_admin = self.client.get('/dashboard/', SERVER_PORT='80')
        self.assertEqual(resp_admin.status_code, 302)
        self.assertIn('/login/', resp_admin.url)

        resp_user = self.client.get('/user/websites/', SERVER_PORT='80')
        self.assertEqual(resp_user.status_code, 302)
        self.assertIn('/user/login/', resp_user.url)

    def test_tenant_blocked_from_host_panel_routes(self):
        """role='user' cannot reach Host Panel routes regardless of SERVER_PORT."""
        c, extra = self._login('sectenant', url='/user/login/', port='80')
        for path in ('/dashboard/', '/users/', '/settings/', '/terminal/'):
            resp = c.get(path, **extra)
            self.assertEqual(resp.status_code, 302)
            self.assertIn('/user/', resp.url)

    def test_reseller_blocked_from_server_admin_routes_and_unowned_users(self):
        """Resellers are blocked from server-admin routes and cannot mutate unowned users."""
        c, extra = self._login('secreseller', url='/login/', port='2087')

        for restricted in ('/administrators/', '/settings/', '/security/firewall/', '/migration/', '/terminal/'):
            resp = c.get(restricted, **extra)
            self.assertEqual(resp.status_code, 302, f'{restricted} should redirect reseller')
            self.assertIn('/dashboard/', resp.url)

        term_exec = c.post('/terminal/exec/', {'cmd': 'id'}, **extra)
        self.assertEqual(term_exec.status_code, 403)

        # Cannot edit, toggle, or delete admin or other_tenant
        for forbidden_target in (self.admin.id, self.other_tenant.id):
            resp = c.post(f'/users/{forbidden_target}/edit/', {'email': 'pwn@evil.test'}, **extra)
            self.assertEqual(resp.status_code, 403)
            resp_toggle = c.post(f'/users/{forbidden_target}/toggle-status/', **extra)
            self.assertEqual(resp_toggle.status_code, 403)
            resp_del = c.post(f'/users/{forbidden_target}/delete/', **extra)
            self.assertEqual(resp_del.status_code, 403)

        # Reseller cannot escalate owned tenant role to admin
        resp_owned = c.post(
            f'/users/{self.tenant.id}/edit/',
            {'email': 'updated@local.test', 'role': 'admin'},
            **extra,
        )
        self.assertEqual(resp_owned.status_code, 302)
        self.tenant.refresh_from_db()
        self.assertEqual(self.tenant.email, 'updated@local.test')
        self.assertEqual(self.tenant.role, 'user')

    # ------------------------------------------------------------------
    # 2. 2FA Setup & Login Enforcement (Host Panel + User Panel)
    # ------------------------------------------------------------------

    def test_admin_2fa_setup_and_login_enforcement(self):
        """Host Panel 2FA init -> confirm -> enforced TOTP check on login."""
        c, extra = self._login('secadmin', url='/login/', port='2087')

        c.post('/security/2fa/', {'action': 'init_setup'}, **extra)
        self.admin.refresh_from_db()
        self.assertTrue(bool(self.admin.otp_secret))
        self.assertFalse(self.admin.is_2fa_enabled)

        # Wrong OTP fails
        c.post('/security/2fa/', {'action': 'confirm_enable', 'otp_code': '000000'}, **extra)
        self.admin.refresh_from_db()
        self.assertFalse(self.admin.is_2fa_enabled)

        # Valid OTP enables 2FA
        valid_code = pyotp.TOTP(self.admin.otp_secret).now()
        c.post('/security/2fa/', {'action': 'confirm_enable', 'otp_code': valid_code}, **extra)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_2fa_enabled)

        # Fresh client verifies login requires 2FA step
        c2 = Client()
        resp_step1 = c2.post('/login/', {'username': 'secadmin', 'password': 'Pass123!'}, SERVER_PORT='2087')
        self.assertEqual(resp_step1.status_code, 200)
        self.assertContains(resp_step1, 'name="otp_code"')

        # Wrong OTP fails step 2
        resp_bad = c2.post('/login/', {'otp_code': '000000'}, SERVER_PORT='2087')
        self.assertEqual(resp_bad.status_code, 200)
        self.assertEqual(c2.get('/dashboard/', SERVER_PORT='2087').status_code, 302)

        # Valid OTP completes login
        valid_code2 = pyotp.TOTP(self.admin.otp_secret).now()
        resp_ok = c2.post('/login/', {'otp_code': valid_code2}, SERVER_PORT='2087')
        self.assertEqual(resp_ok.status_code, 302)
        self.assertIn('/dashboard/', resp_ok.url)
        self.assertEqual(c2.get('/dashboard/', SERVER_PORT='2087').status_code, 200)

    def test_user_2fa_setup_and_login_enforcement(self):
        """User Panel 2FA init -> confirm -> enforced TOTP check on login."""
        c, extra = self._login('sectenant', url='/user/login/', port='2083')

        c.post('/user/profile/', {'action': 'init_2fa'}, **extra)
        self.tenant.refresh_from_db()
        self.assertTrue(bool(self.tenant.otp_secret))

        valid_code = pyotp.TOTP(self.tenant.otp_secret).now()
        c.post('/user/profile/', {'action': 'confirm_2fa', 'otp_code': valid_code}, **extra)
        self.tenant.refresh_from_db()
        self.assertTrue(self.tenant.is_2fa_enabled)

        c2 = Client()
        resp_step1 = c2.post('/user/login/', {'username': 'sectenant', 'password': 'Pass123!'}, SERVER_PORT='2083')
        self.assertEqual(resp_step1.status_code, 200)
        self.assertContains(resp_step1, 'name="otp_code"')

        valid_code2 = pyotp.TOTP(self.tenant.otp_secret).now()
        resp_ok = c2.post('/user/login/', {'otp_code': valid_code2}, SERVER_PORT='2083')
        self.assertEqual(resp_ok.status_code, 302)
        self.assertIn('/dashboard/', resp_ok.url)
        self.assertEqual(c2.get('/dashboard/', SERVER_PORT='2083').status_code, 200)

    # ------------------------------------------------------------------
    # 3. Database Manager & User Panel Database Isolation
    # ------------------------------------------------------------------

    def test_database_identifier_validation_blocks_sqli(self):
        self.assertEqual(_validate_db_identifier('app_db_1'), 'app_db_1')
        with self.assertRaises(ValueError):
            _validate_db_identifier('bad; DROP TABLE users;--')
        with self.assertRaises(ValueError):
            _validate_db_identifier("bad`name")

        res_create = create_database('bad;drop', 'user1', 'pass')
        self.assertFalse(res_create['success'])
        res_del = delete_database_user("root' OR '1'='1")
        self.assertFalse(res_del['success'])

    def test_user_databases_ownership_and_limit_enforcement(self):
        """Tenants cannot reset root/other user passwords or exceed databases_limit."""
        c, extra = self._login('sectenant', url='/user/login/', port='2083')
        Database.objects.create(owner=self.tenant, name='sectenant_one', db_type='mariadb', db_user='sectenant_user')
        Database.objects.create(owner=self.other_tenant, name='otheruser_db', db_type='mariadb', db_user='otheruser_u')

        # Limit = 1 already reached
        with patch('services.database.create_database') as mock_create_db:
            c.post('/user/databases/', {'action': 'create_database', 'name': 'seconddb'}, **extra)
            mock_create_db.assert_not_called()
            self.assertEqual(Database.objects.filter(owner=self.tenant).count(), 1)

        # Cross-tenant / root DB user password reset blocked
        with patch('services.database.change_user_password') as mock_chg_pw:
            c.post(
                '/user/databases/',
                {'action': 'change_password', 'db_user': 'root', 'new_password': 'Hacked123!'},
                **extra,
            )
            c.post(
                '/user/databases/',
                {'action': 'change_password', 'db_user': 'otheruser_u', 'new_password': 'Hacked123!'},
                **extra,
            )
            mock_chg_pw.assert_not_called()

        # Grant privileges on unowned DB user blocked
        owned_db = Database.objects.get(owner=self.tenant)
        with patch('services.database.grant_user_privileges') as mock_grant:
            c.post(
                '/user/databases/',
                {'action': 'grant_privileges', 'database_id': owned_db.id, 'db_user': 'otheruser_u'},
                **extra,
            )
            mock_grant.assert_not_called()

    # ------------------------------------------------------------------
    # 4. Website Creation Limit, Domain Validation & VHost Tenant Validation
    # ------------------------------------------------------------------

    def test_user_website_create_limit_and_domain_validation(self):
        c, extra = self._login('sectenant', url='/user/login/', port='2083')

        # Invalid domain rejected
        with patch('services.webserver.create_vhost') as mock_vhost:
            c.post('/user/websites/create/', {'domain': '../../etc/passwd'}, **extra)
            mock_vhost.assert_not_called()
            self.assertEqual(Website.objects.filter(owner=self.tenant).count(), 0)

        # First valid site succeeds (limit = 1)
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch.dict(os.environ, {'W3PANEL_USERS_DIR': tmpdir}), \
             patch('services.webserver.create_vhost') as mock_vhost:
            c.post('/user/websites/create/', {'domain': 'tenant-one.example.com'}, **extra)
            self.assertEqual(Website.objects.filter(owner=self.tenant).count(), 1)
            self.assertEqual(mock_vhost.call_count, 1)

            # Second valid site blocked by websites_limit=1
            c.post('/user/websites/create/', {'domain': 'tenant-two.example.com'}, **extra)
            self.assertEqual(Website.objects.filter(owner=self.tenant).count(), 1)

    def test_user_website_vhost_sandbox(self):
        c, extra = self._login('sectenant', url='/user/login/', port='2083')
        site = Website.objects.create(
            owner=self.tenant,
            domain='sandbox.example.com',
            doc_root='/home/sectenant/public_html/sandbox.example.com',
        )

        dangerous_configs = [
            'server { server_name sandbox.example.com; root /etc; }',
            'server { server_name sandbox.example.com; include /etc/passwd; }',
            'server { server_name *; root /home/sectenant/public_html; }',
            'server { server_name sandbox.example.com; location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.3-fpm-otheruser.sock; } }',
            'server { server_name sandbox.example.com; lua_need_request_body on; }',
        ]
        for bad_cfg in dangerous_configs:
            with patch('services.webserver.save_custom_vhost') as mock_write:
                c.post(
                    f'/user/websites/{site.id}/vhost/',
                    {'action': 'save_vhost', 'vhost_content': bad_cfg},
                    **extra,
                )
                mock_write.assert_not_called()

        valid_cfg = (
            'server {\n'
            '    listen 80;\n'
            '    server_name sandbox.example.com;\n'
            '    root /home/sectenant/public_html/sandbox.example.com;\n'
            '    location / { try_files $uri $uri/ =404; }\n'
            '}\n'
        )
        with patch('services.webserver.save_custom_vhost', return_value={'success': True}) as mock_write:
            c.post(
                f'/user/websites/{site.id}/vhost/',
                {'action': 'save_vhost', 'vhost_content': valid_cfg},
                **extra,
            )
            mock_write.assert_called_once()

    # ------------------------------------------------------------------
    # 5. FTP Traversal + Limits & Cron Injection Validation
    # ------------------------------------------------------------------

    def test_user_ftp_traversal_and_limit_enforcement(self):
        c, extra = self._login('sectenant', url='/user/login/', port='2083')

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch.dict(os.environ, {'W3PANEL_USERS_DIR': tmpdir}), \
             patch('services.ftp.create_ftp_user') as mock_ftp:
            # Traversal outside home directory must be rejected
            c.post('/user/ftp/', {'username': 'evilftp', 'directory': '../../etc'}, **extra)
            mock_ftp.assert_not_called()
            self.assertEqual(FTPAccount.objects.filter(owner=self.tenant).count(), 0)

            # Valid FTP account created inside home (limit=1)
            c.post('/user/ftp/', {'username': 'deploy', 'directory': 'public_html'}, **extra)
            mock_ftp.assert_called_once()
            self.assertEqual(FTPAccount.objects.filter(owner=self.tenant).count(), 1)

            # Second FTP account blocked by ftp_limit=1
            c.post('/user/ftp/', {'username': 'second', 'directory': 'public_html'}, **extra)
            self.assertEqual(mock_ftp.call_count, 1)

    def test_cron_injection_rejected_and_sync_isolated(self):
        self.assertTrue(is_valid_cron_schedule('*/5 * * * *'))
        self.assertFalse(is_valid_cron_schedule('*/5 * * * *\n* * * * *'))
        self.assertTrue(is_valid_cron_command('/usr/bin/php /home/sectenant/cron.php'))
        self.assertFalse(is_valid_cron_command('/usr/bin/id\n* * * * * root /bin/sh'))

        c, extra = self._login('sectenant', url='/user/login/', port='2083')
        with patch('services.cron.manager.sync_cron_jobs') as mock_sync:
            c.post(
                '/user/cron/',
                {'schedule': '0 * * * *', 'command': 'echo ok\n* * * * * id'},
                **extra,
            )
            mock_sync.assert_not_called()
            self.assertEqual(CronJob.objects.filter(owner=self.tenant).count(), 0)

        with tempfile.TemporaryDirectory() as crondir, \
             patch.dict(os.environ, {'W3PANEL_CRON_DIR': crondir}), \
             patch('services.webserver.manager._has_sudo', return_value=False), \
             patch('services.cron.manager.subprocess.run'):
            CronJob.objects.create(owner=self.tenant, schedule='0 * * * *', command='/usr/bin/php ~/job.php')
            res = sync_cron_jobs(self.tenant.username, CronJob.objects.filter(owner=self.tenant))
            self.assertTrue(res['success'])
            cron_file = Path(crondir) / f'w3panel_{self.tenant.username}'
            self.assertTrue(cron_file.exists())
            content = cron_file.read_text()
            self.assertIn('/usr/bin/php ~/job.php', content)

    # ------------------------------------------------------------------
    # 6. DNS Input Validation
    # ------------------------------------------------------------------

    def test_dns_rejects_newline_and_invalid_type(self):
        c, extra = self._login('sectenant', url='/user/login/', port='2083')
        site = Website.objects.create(owner=self.tenant, domain='dns.example.com', doc_root='/home/sectenant/dns')

        c.post(
            f'/user/dns/?domain_id={site.id}',
            {'action': 'add_record', 'record_type': 'BOGUS', 'name': 'www', 'value': '1.2.3.4'},
            **extra,
        )
        c.post(
            f'/user/dns/?domain_id={site.id}',
            {'action': 'add_record', 'record_type': 'TXT', 'name': 'txt', 'value': 'ok\n* IN A 6.6.6.6'},
            **extra,
        )
        self.assertEqual(DNSRecord.objects.filter(domain=site).count(), 0)

    def test_admin_user_create_primary_domain_stack_selection(self):
        c, extra = self._login('secadmin', url='/login/', port='2087')
        SystemSetting.set('server_ip', '198.51.100.42')

        get_resp = c.get('/users/create/', **extra)
        self.assertEqual(get_resp.status_code, 200)
        self.assertContains(get_resp, 'Application Stack / Framework')
        self.assertContains(get_resp, 'name="framework"')
        self.assertContains(get_resp, 'name="php_version"')
        self.assertContains(get_resp, 'name="port"')

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch.dict(os.environ, {
                 'W3PANEL_USERS_DIR': f'{tmpdir}/users',
                 'W3PANEL_VHOST_DIR': f'{tmpdir}/vhosts',
                 'W3PANEL_PHP_POOL_DIR': f'{tmpdir}/pools',
             }), \
             patch('services.webserver.manager._has_sudo', return_value=False), \
             patch('services.webserver.sync_system_user_shell', return_value=True), \
             patch('services.webserver.sync_system_user_password', return_value=True):
            # Laravel primary domain uses /public doc_root, selected PHP version, and server_ip A record
            r1 = c.post('/users/create/', {
                'username': 'laraclient',
                'email': 'lara@example.com',
                'password': 'StrongPassword123!',
                'domain': 'lara.example.com',
                'framework': 'laravel',
                'php_version': '8.4',
            }, **extra)
            self.assertEqual(r1.status_code, 302)
            site1 = Website.objects.get(domain='lara.example.com')
            self.assertEqual(site1.framework, 'laravel')
            self.assertEqual(site1.php_version, '8.4')
            self.assertTrue(site1.doc_root.endswith('/laraclient/lara.example.com/public_html/public'))
            self.assertEqual(DNSRecord.objects.get(domain=site1, record_type='A', name='@').value, '198.51.100.42')
            vhost1 = (Path(tmpdir) / 'vhosts' / 'lara.example.com.conf').read_text()
            self.assertIn('Mode: laravel', vhost1)
            self.assertIn('php8.4-fpm-laraclient.sock', vhost1)

            # Node.js primary domain preserves validated port and generates reverse proxy config
            r2 = c.post('/users/create/', {
                'username': 'nodeclient',
                'email': 'node@example.com',
                'password': 'StrongPassword123!',
                'domain': 'nodeapp.example.com',
                'framework': 'nodejs',
                'port': '4500',
            }, **extra)
            self.assertEqual(r2.status_code, 302)
            site2 = Website.objects.get(domain='nodeapp.example.com')
            self.assertEqual(site2.framework, 'nodejs')
            self.assertEqual(site2.port, 4500)
            vhost2 = (Path(tmpdir) / 'vhosts' / 'nodeapp.example.com.conf').read_text()
            self.assertIn('proxy_pass http://127.0.0.1:4500;', vhost2)

            # Invalid framework/port safely fall back to defaults
            r3 = c.post('/users/create/', {
                'username': 'badstack',
                'email': 'bad@example.com',
                'password': 'StrongPassword123!',
                'domain': 'badstack.example.com',
                'framework': 'invalid_stack',
                'php_version': '9.9',
                'port': '80',
            }, **extra)
            self.assertEqual(r3.status_code, 302)
            site3 = Website.objects.get(domain='badstack.example.com')
            self.assertEqual(site3.framework, 'none')
            self.assertEqual(site3.php_version, '8.3')
            self.assertEqual(site3.port, 3000)

    def test_user_website_alias_domain_sharing_and_ownership(self):
        # Allow multiple websites under tenant's package for alias creation test
        self.pkg.websites_limit = 3
        self.pkg.save()
        c, extra = self._login('sectenant', url='/user/login/', port='2083')

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch.dict(os.environ, {
                 'W3PANEL_USERS_DIR': f'{tmpdir}/users',
                 'W3PANEL_VHOST_DIR': f'{tmpdir}/vhosts',
                 'W3PANEL_PHP_POOL_DIR': f'{tmpdir}/pools',
             }), \
             patch('services.webserver.manager._has_sudo', return_value=False):
            main_doc = f'{tmpdir}/users/sectenant/main.example.com/public_html/public'
            Path(main_doc).mkdir(parents=True, exist_ok=True)
            main_site = Website.objects.create(
                owner=self.tenant,
                domain='main.example.com',
                doc_root=main_doc,
                framework='laravel',
                php_version='8.4',
            )
            foreign_site = Website.objects.create(
                owner=self.other_tenant,
                domain='foreign.example.com',
                doc_root=f'{tmpdir}/users/otheruser/foreign.example.com/public_html',
                framework='none',
                php_version='8.3',
            )

            # GET create page lists owned domain for aliasing (and not foreign domain)
            form_resp = c.get('/websites/create/', **extra)
            self.assertEqual(form_resp.status_code, 200)
            self.assertContains(form_resp, 'Alias Domain (Share Existing Doc Root)')
            self.assertContains(form_resp, 'main.example.com')
            self.assertNotContains(form_resp, 'foreign.example.com')

            # Creating alias referencing another tenant's site must be rejected
            c.post('/websites/create/', {
                'domain': 'hijack.example.com',
                'domain_mode': 'alias',
                'alias_target_id': str(foreign_site.id),
            }, **extra)
            self.assertFalse(Website.objects.filter(domain='hijack.example.com').exists())

            # Creating alias referencing own domain shares doc_root, stack, PHP version, and skips unused dir
            ok_resp = c.post('/websites/create/', {
                'domain': 'parked.example.com',
                'domain_mode': 'alias',
                'alias_target_id': str(main_site.id),
                'proxy_real_ip': '1',
            }, **extra)
            self.assertEqual(ok_resp.status_code, 302)

            alias_site = Website.objects.get(domain='parked.example.com')
            self.assertEqual(alias_site.doc_root, main_doc)
            self.assertEqual(alias_site.framework, 'laravel')
            self.assertEqual(alias_site.php_version, '8.4')
            self.assertTrue(alias_site.proxy_real_ip)
            self.assertFalse((Path(tmpdir) / 'users' / 'sectenant' / 'parked.example.com').exists())

            alias_vhost = (Path(tmpdir) / 'vhosts' / 'parked.example.com.conf').read_text()
            self.assertIn(f'root {main_doc};', alias_vhost)
            self.assertIn('php8.4-fpm-sectenant.sock', alias_vhost)

            # Domains list indicates alias target and links Files to shared doc_root path
            list_resp = c.get('/websites/', **extra)
            self.assertEqual(list_resp.status_code, 200)
            self.assertContains(list_resp, 'Alias &rarr; main.example.com')
            self.assertContains(list_resp, '/filemanager/?path=main.example.com/public_html/public')
            fm_resp = c.get('/filemanager/?path=main.example.com/public_html/public', **extra)
            self.assertEqual(fm_resp.status_code, 200)

    def test_user_webmail_and_filemanager_links_open_in_new_tab(self):
        c, extra = self._login('sectenant', url='/user/login/', port='2083')

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch.dict(os.environ, {'W3PANEL_USERS_DIR': f'{tmpdir}/users'}), \
             patch('services.mail.is_snappymail_installed', return_value=True), \
             patch('services.process_manager.get_app_status', return_value={'status': 'inactive', 'is_running': False, 'port': 3000}):
            site = Website.objects.create(
                owner=self.tenant,
                domain='tabcheck.example.com',
                doc_root=f'{tmpdir}/users/sectenant/tabcheck.example.com/public_html/public',
                framework='laravel',
                php_version='8.3',
            )

            anchor_re = re.compile(r'<a\b[^>]*href="/(?:filemanager|webmail|snappymail)[^"]*"[^>]*>')
            for path, expected_hrefs in [
                ('/', ['/filemanager/', '/webmail/']),
                ('/websites/', ['/filemanager/?path=tabcheck.example.com/public_html/public']),
                (f'/websites/{site.id}/manage/', ['/filemanager/?path=tabcheck.example.com/public_html/public']),
                ('/emails/', ['/webmail/']),
                ('/webmail/', ['/snappymail/']),
            ]:
                resp = c.get(path, **extra)
                self.assertEqual(resp.status_code, 200)
                html = resp.content.decode()
                for href in expected_hrefs:
                    self.assertIn(f'href="{href}"', html)
                tags = anchor_re.findall(html)
                self.assertTrue(tags, f'Expected target links on {path}')
                for tag in tags:
                    self.assertIn('target="_blank"', tag, f'Missing target="_blank" in {tag} on {path}')
                    self.assertIn('rel="noopener noreferrer"', tag, f'Missing rel="noopener noreferrer" in {tag} on {path}')
