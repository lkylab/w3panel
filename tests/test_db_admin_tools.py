"""Isolated tests for gated phpMyAdmin & pgAdmin 4 integration across Host & User panels."""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.test import Client, TestCase

from apps.admin.views import _prepare_wizard_setup, get_server_stack_status
from packages.core.models import SystemSetting, User
from services.database.manager import (
    configure_db_admin_webserver,
    get_db_admin_tools_status,
    install_pgadmin4,
    install_phpmyadmin,
)


class DbAdminToolsIntegrationTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user('dbadmin', 'dbadmin@local.test', 'Pass123!', role='admin')
        self.user = User.objects.create_user('dbuser', 'dbuser@local.test', 'Pass123!', role='user')
        SystemSetting.set('initial_setup_completed', 'true')

    def _login(self, username, url='/login/', port='2087'):
        client = Client()
        resp = client.post(url, {'username': username, 'password': 'Pass123!'}, SERVER_PORT=port)
        self.assertEqual(resp.status_code, 302)
        return client, {'SERVER_PORT': port}

    def test_tools_strictly_gated_on_db_engine_presence(self):
        """phpMyAdmin/pgAdmin4 are hidden/unavailable unless their DB engine is installed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pma_dir = Path(tmpdir) / 'phpmyadmin'
            pg4_dir = Path(tmpdir) / 'pgadmin4'
            pma_dir.mkdir()
            (pma_dir / 'index.php').write_text('<?php echo 1;')
            (pg4_dir / 'web').mkdir(parents=True)
            (pg4_dir / 'web' / 'pgAdmin4.py').write_text('# stub')

            with patch.dict(os.environ, {'W3PANEL_PHPMYADMIN_DIR': str(pma_dir), 'W3PANEL_PGADMIN4_DIR': str(pg4_dir)}), \
                 patch('services.database.manager.is_mariadb_installed', return_value=False), \
                 patch('services.database.manager.is_postgresql_installed', return_value=False):
                st = get_db_admin_tools_status()
                self.assertTrue(st['phpmyadmin_installed'])
                self.assertTrue(st['pgadmin4_installed'])
                self.assertFalse(st['phpmyadmin_available'])
                self.assertFalse(st['pgadmin4_available'])

                # Verify views hide both tools when DB engines are absent
                c_adm, adm_extra = self._login('dbadmin', '/login/', '2087')
                c_usr, usr_extra = self._login('dbuser', '/user/login/', '2083')

                with patch('apps.admin.views.shutil.which', return_value=None):
                    svc_resp = c_adm.get('/services/', **adm_extra)
                    dash_resp = c_adm.get('/dashboard/', **adm_extra)
                    self.assertNotContains(svc_resp, 'phpMyAdmin')
                    self.assertNotContains(svc_resp, 'pgAdmin 4')
                    self.assertNotContains(dash_resp, '/phpmyadmin/')
                    self.assertNotContains(dash_resp, '/pgadmin4/')

                u_dash = c_usr.get('/dashboard/', **usr_extra)
                u_db = c_usr.get('/databases/', **usr_extra)
                self.assertNotContains(u_dash, '/phpmyadmin/')
                self.assertNotContains(u_dash, '/pgadmin4/')
                self.assertNotContains(u_db, '/phpmyadmin/')
                self.assertNotContains(u_db, '/pgadmin4/')

    def test_only_matching_db_tool_rendered_when_engine_installed(self):
        """Show phpMyAdmin only when MariaDB is installed and pgAdmin 4 only when PostgreSQL is installed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pma_dir = Path(tmpdir) / 'phpmyadmin'
            pg4_dir = Path(tmpdir) / 'pgadmin4'
            pma_dir.mkdir()
            (pma_dir / 'index.php').write_text('<?php echo 1;')
            (pg4_dir / 'web').mkdir(parents=True)
            (pg4_dir / 'web' / 'pgAdmin4.py').write_text('# stub')

            c_adm, adm_extra = self._login('dbadmin', '/login/', '2087')
            c_usr, usr_extra = self._login('dbuser', '/user/login/', '2083')

            with patch.dict(os.environ, {'W3PANEL_PHPMYADMIN_DIR': str(pma_dir), 'W3PANEL_PGADMIN4_DIR': str(pg4_dir)}), \
                 patch('services.database.manager.is_mariadb_installed', return_value=True), \
                 patch('services.database.manager.is_postgresql_installed', return_value=False):
                svc_resp = c_adm.get('/services/', **adm_extra)
                self.assertContains(svc_resp, 'phpMyAdmin')
                self.assertContains(svc_resp, '/services/db-tool/phpmyadmin/')
                self.assertNotContains(svc_resp, 'pgAdmin 4')
                self.assertContains(svc_resp, 'Restart')

                launch_adm = c_adm.get('/services/db-tool/phpmyadmin/', **adm_extra)
                self.assertEqual(launch_adm.status_code, 302)
                self.assertEqual(launch_adm.url, '/phpmyadmin/')

                u_db = c_usr.get('/databases/', **usr_extra)
                self.assertContains(u_db, '/databases/launch/phpmyadmin/')
                self.assertNotContains(u_db, '/databases/launch/pgadmin4/')

                launch_usr = c_usr.get('/databases/launch/phpmyadmin/', **usr_extra)
                self.assertEqual(launch_usr.status_code, 302)
                self.assertEqual(launch_usr.url, '/phpmyadmin/')

            with patch.dict(os.environ, {'W3PANEL_PHPMYADMIN_DIR': str(pma_dir), 'W3PANEL_PGADMIN4_DIR': str(pg4_dir)}), \
                 patch('services.database.manager.is_mariadb_installed', return_value=False), \
                 patch('services.database.manager.is_postgresql_installed', return_value=True), \
                 patch('services.database.manager.is_pgadmin4_running', return_value=True):
                svc_resp = c_adm.get('/services/', **adm_extra)
                self.assertNotContains(svc_resp, 'phpMyAdmin')
                self.assertContains(svc_resp, 'pgAdmin 4')
                self.assertContains(svc_resp, '/services/db-tool/pgadmin4/')

                u_dash = c_usr.get('/dashboard/', **usr_extra)
                self.assertContains(u_dash, '/databases/launch/pgadmin4/')
                self.assertNotContains(u_dash, '/databases/launch/phpmyadmin/')

    def test_mariadb_restart_and_minimal_path_detection(self):
        """MariaDB is detected even when PATH lacks /usr/sbin and Restart invokes systemctl cleanly."""
        c_adm, adm_extra = self._login('dbadmin', '/login/', '2087')
        with patch('services.database.manager.is_mariadb_installed', return_value=True), \
             patch('services.database.manager.is_postgresql_installed', return_value=False), \
             patch('apps.admin.views._run_privileged', return_value=MagicMock(returncode=0, stdout='', stderr='')) as mock_priv:
            resp = c_adm.post('/services/', {'service': 'mariadb', 'action': 'restart'}, **adm_extra)
            self.assertEqual(resp.status_code, 302)
            mock_priv.assert_called_once_with(['systemctl', 'restart', 'mariadb'], timeout=15)

        with patch('apps.admin.views.shutil.which', side_effect=lambda name, path=None: '/usr/sbin/mariadbd' if (name == 'mariadbd' and path) else None), \
             patch('services.database.manager.is_mariadb_installed', return_value=True), \
             patch('services.database.manager.is_postgresql_installed', return_value=False), \
             patch('apps.admin.views.subprocess.run', return_value=MagicMock(stdout='active\n')):
            svc_resp = c_adm.get('/services/', **adm_extra)
            self.assertContains(svc_resp, 'MariaDB Database Server')
            self.assertContains(svc_resp, 'value="restart"')

    def test_install_guards_and_no_cli_secret_for_pgadmin4(self):
        """Installers refuse without their engine and never pass passwords on CLI args."""
        with patch('services.database.manager.is_mariadb_installed', return_value=False):
            res_pma = install_phpmyadmin()
            self.assertFalse(res_pma['success'])

        with patch('services.database.manager.is_postgresql_installed', return_value=False):
            res_pg4 = install_pgadmin4()
            self.assertFalse(res_pg4['success'])

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch.dict(os.environ, {
                 'W3PANEL_PGADMIN4_DIR': str(Path(tmpdir) / 'pgadmin4'),
                 'W3PANEL_APT_SOURCES_DIR': str(Path(tmpdir) / 'sources'),
                 'W3PANEL_SYSTEMD_DIR': str(Path(tmpdir) / 'systemd'),
                 'W3PANEL_NGINX_SITES_DIR': str(Path(tmpdir) / 'sites-avail'),
                 'W3PANEL_NGINX_ENABLED_DIR': str(Path(tmpdir) / 'sites-enabled'),
             }), \
             patch('services.database.manager.is_postgresql_installed', return_value=True), \
             patch('services.database.manager.is_mariadb_installed', return_value=False), \
             patch('services.database.manager._has_sudo', return_value=False), \
             patch('services.database.manager.shutil.which', return_value=None), \
             patch('services.database.manager.subprocess.run') as mock_run:
            mock_run.side_effect = lambda cmd, **kw: MagicMock(returncode=0, stdout=(b'FAKE-GPG' if not kw.get('text') else ''), stderr=(b'' if not kw.get('text') else ''))
            res = install_pgadmin4(admin_email='pg@example.com', admin_password='SuperSecretValue99!')
            self.assertTrue(res['success'])

            for call_obj in mock_run.call_args_list:
                cmd_args = call_obj.args[0] if call_obj.args else []
                self.assertNotIn('SuperSecretValue99!', ' '.join(str(x) for x in cmd_args))
                self.assertNotIn('-E', cmd_args)

            bash_calls = [c for c in mock_run.call_args_list if '/bin/bash' in (c.args[0] if c.args else [])]
            self.assertEqual(len(bash_calls), 1)
            apt_calls = [c for c in mock_run.call_args_list if 'apt-get' in (c.args[0] if c.args else [])]
            self.assertTrue(any('DPkg::Lock::Timeout=120' in ' '.join(c.args[0]) for c in apt_calls))

    def test_pgadmin4_requires_service_unit_self_heals_and_recovers_dpkg(self):
        """Partial pgadmin4 install without service unit stays not_installed until configured or self-healed on start."""
        from services.database.manager import _run_apt_safe, is_pgadmin4_installed

        with tempfile.TemporaryDirectory() as tmpdir:
            pg4_dir = Path(tmpdir) / 'pgadmin4'
            sysd_dir = Path(tmpdir) / 'systemd'
            (pg4_dir / 'web').mkdir(parents=True)
            (pg4_dir / 'web' / 'pgAdmin4.py').write_text('# stub')
            sysd_dir.mkdir()

            with patch.dict(os.environ, {'W3PANEL_PGADMIN4_DIR': str(pg4_dir), 'W3PANEL_SYSTEMD_DIR': str(sysd_dir)}):
                self.assertFalse(is_pgadmin4_installed())

                c_adm, adm_extra = self._login('dbadmin', '/login/', '2087')
                with patch('services.database.configure_pgadmin4_runtime', return_value={'success': True}) as mock_cfg, \
                     patch('services.database.manager.is_pgadmin4_running', return_value=False):
                    resp = c_adm.post('/services/', {'service': 'pgadmin4', 'action': 'start'}, **adm_extra)
                    self.assertEqual(resp.status_code, 302)
                    mock_cfg.assert_called_once()

                # Broken unit referencing /usr/local/w3panel/ must be rewritten automatically
                unit_file = sysd_dir / 'pgadmin4.service'
                unit_file.write_text('ExecStart=/usr/local/w3panel/venv/bin/gunicorn pgAdmin4:app\n')
                with patch('services.database.manager._has_sudo', return_value=False), \
                     patch('services.database.manager.is_mariadb_installed', return_value=False), \
                     patch('services.database.manager.is_postgresql_installed', return_value=False), \
                     patch('services.database.manager.subprocess.run', return_value=MagicMock(returncode=0, stdout='', stderr='')):
                    from services.database import ensure_pgadmin4_service_ready
                    rep = ensure_pgadmin4_service_ready()
                    self.assertTrue(rep['success'])
                    unit_txt = unit_file.read_text()
                    self.assertNotIn('/usr/local/w3panel/venv/bin/gunicorn', unit_txt)
                    self.assertIn('pgAdmin4.py', unit_txt)

                self.assertTrue(is_pgadmin4_installed())

                # Verify streaming install endpoint handles pgadmin4 cleanly
                with patch('services.database.is_postgresql_installed', return_value=True), \
                     patch('services.database.manager._priv_prefix', return_value=[]), \
                     patch('apps.admin.views.subprocess.run', return_value=MagicMock(returncode=0, stdout=b'FAKE', stderr='')), \
                     patch('apps.admin.views._stream_cmd', return_value=iter(['>> ok'])), \
                     patch('services.webserver.manager._write_privileged_file', return_value=True), \
                     patch('services.database.configure_pgadmin4_runtime', return_value={'success': True, 'email': 'dbadmin@local.test', 'password': 'pw'}):
                    stream_resp = c_adm.post('/services/install-stream/', {'service': 'pgadmin4'}, **adm_extra)
                    self.assertEqual(stream_resp.status_code, 200)
                    body = b''.join(stream_resp.streaming_content).decode()
                    self.assertIn('"status": "complete"', body)

        # Verify _run_apt_safe runs dpkg --configure -a on interrupted dpkg
        with patch('services.database.manager.subprocess.run') as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=100, stdout='', stderr='E: dpkg was interrupted, you must manually run dpkg --configure -a'),
                MagicMock(returncode=0, stdout='', stderr=''),
                MagicMock(returncode=0, stdout='ok', stderr=''),
            ]
            res = _run_apt_safe(['install', '-y', 'pgadmin4-web'])
            self.assertEqual(res.returncode, 0)
            self.assertEqual(mock_run.call_count, 3)
            self.assertIn('dpkg', mock_run.call_args_list[1].args[0])

    def test_configure_db_admin_webserver_nginx_config_and_cleanup(self):
        """configure_db_admin_webserver writes gated locations, avoids default_server conflicts, and cleans up."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pma_dir = Path(tmpdir) / 'phpmyadmin'
            pg4_dir = Path(tmpdir) / 'pgadmin4'
            sites_avail = Path(tmpdir) / 'sites-avail'
            sites_en = Path(tmpdir) / 'sites-enabled'
            ssl_dir = Path(tmpdir) / 'ssl'
            pma_dir.mkdir()
            (pma_dir / 'index.php').write_text('<?php echo 1;')
            (pg4_dir / 'web').mkdir(parents=True)
            (pg4_dir / 'web' / 'pgAdmin4.py').write_text('# stub')
            sites_avail.mkdir()
            sites_en.mkdir()
            ssl_dir.mkdir()
            (ssl_dir / 'panel.crt').write_text('CERT')
            (ssl_dir / 'panel.key').write_text('KEY')
            (sites_en / 'default').write_text('server { listen 80 default_server; }')

            env = {
                'W3PANEL_PHPMYADMIN_DIR': str(pma_dir),
                'W3PANEL_PGADMIN4_DIR': str(pg4_dir),
                'W3PANEL_NGINX_SITES_DIR': str(sites_avail),
                'W3PANEL_NGINX_ENABLED_DIR': str(sites_en),
                'W3PANEL_SSL_DIR': str(ssl_dir),
            }
            with patch.dict(os.environ, env), \
                 patch('services.database.manager.is_mariadb_installed', return_value=True), \
                 patch('services.database.manager.is_postgresql_installed', return_value=True), \
                 patch('services.database.manager.shutil.which', return_value=None):
                res = configure_db_admin_webserver()
                self.assertTrue(res['success'])
                conf_file = sites_avail / 'w3panel-dbtools.conf'
                self.assertTrue(conf_file.exists())
                content = conf_file.read_text()
                self.assertIn('listen 127.0.0.1:8090;', content)
                self.assertIn('location ^~ /phpmyadmin', content)
                self.assertIn('location ^~ /pgadmin4/', content)
                self.assertIn('X-Script-Name /pgadmin4', content)
                self.assertIn('proxy_pass http://127.0.0.1:5050;', content)
                self.assertNotIn('default_server', content)

                # Cleanup when engines uninstalled
                with patch('services.database.manager.is_mariadb_installed', return_value=False), \
                     patch('services.database.manager.is_postgresql_installed', return_value=False):
                    res2 = configure_db_admin_webserver()
                    self.assertFalse(res2['configured'])
                    self.assertFalse(conf_file.exists())

    def test_wizard_db_tools_respect_selected_engine(self):
        """Wizard only enables phpMyAdmin/pgAdmin 4 if their database engine is enabled."""
        from django.http import QueryDict
        stack = {
            'webserver_nginx': {'installed': True, 'active': True},
            'webserver_apache': {'installed': False, 'active': False},
            'db_mariadb': {'installed': True, 'active': True},
            'db_postgresql': {'installed': True, 'active': True},
            'mail_postfix': {'installed': True, 'active': True},
            'ftp_pureftpd': {'installed': True, 'active': True},
            'container_podman': {'installed': False, 'active': False},
        }
        q_off = QueryDict('webserver_choice=nginx&default_php=8.3&enable_phpmyadmin=1&enable_pgadmin4=1')
        _, _, opts_off = _prepare_wizard_setup(q_off, stack, mark_completed=False)
        self.assertFalse(opts_off['enable_phpmyadmin'])
        self.assertFalse(opts_off['enable_pgadmin4'])

        q_on = QueryDict('webserver_choice=nginx&default_php=8.3&enable_mariadb=1&enable_postgresql=1&enable_phpmyadmin=1&enable_pgadmin4=1')
        _, _, opts_on = _prepare_wizard_setup(q_on, stack, mark_completed=False)
        self.assertTrue(opts_on['enable_phpmyadmin'])
        self.assertTrue(opts_on['enable_pgadmin4'])

    def test_same_origin_db_tool_proxy_requires_auth_and_preserves_port_and_cookies(self):
        """Proxy requires panel auth, preserves panel origin/port in Location, and forwards Set-Cookie."""
        unauth = Client().get('/phpmyadmin/', SERVER_PORT='12087')
        self.assertEqual(unauth.status_code, 302)

        with tempfile.TemporaryDirectory() as tmpdir:
            pma_dir = Path(tmpdir) / 'phpmyadmin'
            pma_dir.mkdir()
            (pma_dir / 'index.php').write_text('<?php echo 1;')

            c_adm, adm_extra = self._login('dbadmin', '/login/', '12087')

            class _FakeHeaders(list):
                def get_all(self, name):
                    return [v for k, v in self if k.lower() == name.lower()]

            fake_hdrs = _FakeHeaders([
                ('Content-Type', 'text/html; charset=utf-8'),
                ('Location', 'http://127.0.0.1:8090/phpmyadmin/index.php?route=/'),
                ('Set-Cookie', 'phpMyAdmin=sess123; path=/phpmyadmin/; HttpOnly'),
                ('Set-Cookie', 'pma_lang=en; path=/phpmyadmin/'),
            ])
            fake_resp = MagicMock()
            fake_resp.status = 302
            fake_resp.read.return_value = b''
            fake_resp.getheaders.return_value = fake_hdrs
            fake_resp.headers = fake_hdrs

            fake_conn = MagicMock()
            fake_conn.getresponse.return_value = fake_resp

            with patch.dict(os.environ, {'W3PANEL_PHPMYADMIN_DIR': str(pma_dir)}), \
                 patch('services.database.manager.is_mariadb_installed', return_value=True), \
                 patch('services.database.manager.ensure_db_admin_webserver_configured', return_value={'success': True}), \
                 patch('services.database.manager.http.client.HTTPConnection', return_value=fake_conn):
                resp = c_adm.get('/phpmyadmin/', **adm_extra)
                self.assertEqual(resp.status_code, 302)
                self.assertEqual(resp['Location'], '/phpmyadmin/index.php?route=/')
                self.assertEqual(resp.cookies['phpMyAdmin'].value, 'sess123')
                self.assertEqual(resp.cookies['pma_lang'].value, 'en')

    def test_phpmyadmin_signon_provisioning_scoping_and_php_syntax(self):
        """phpMyAdmin SSO provisions admin vs tenant-scoped SQL grants, writes valid PHP, and sets W3PanelPMASignon."""
        import shutil
        import subprocess as real_subproc
        from packages.core.models import Database
        from services.database.manager import ensure_phpmyadmin_signon_configured, provision_phpmyadmin_sso_credentials

        other = User.objects.create_user('otherpma', 'otherpma@local.test', 'Pass123!', role='user')
        Database.objects.create(owner=self.user, name='dbuser_app', db_type='mariadb', db_user='dbuser_u')
        Database.objects.create(owner=other, name='otherpma_secret', db_type='mariadb', db_user='otherpma_u')

        with tempfile.TemporaryDirectory() as tmpdir:
            pma_dir = Path(tmpdir) / 'phpmyadmin'
            conf_dir = Path(tmpdir) / 'conf'
            pma_dir.mkdir()
            (conf_dir / 'conf.d').mkdir(parents=True)
            (pma_dir / 'index.php').write_text('<?php echo 1;')

            env = {
                'W3PANEL_PHPMYADMIN_DIR': str(pma_dir),
                'W3PANEL_PHPMYADMIN_CONF_DIR': str(conf_dir),
            }
            with patch.dict(os.environ, env), \
                 patch('services.database.manager._has_sudo', return_value=False), \
                 patch('services.database.manager.is_mariadb_installed', return_value=True):
                self.assertTrue(ensure_phpmyadmin_signon_configured())
                conf_php = conf_dir / 'conf.d' / '99-w3panel.php'
                signon_php = pma_dir / 'w3p-signon.php'
                self.assertTrue(conf_php.exists())
                self.assertTrue(signon_php.exists())
                self.assertIn('W3PanelPMASignon', conf_php.read_text())
                self.assertIn('PMA_single_signon_user', signon_php.read_text())

                if shutil.which('php'):
                    for pf in (conf_php, signon_php):
                        lint = real_subproc.run(['php', '-l', str(pf)], capture_output=True, text=True)
                        self.assertEqual(lint.returncode, 0, lint.stderr)

                with patch('services.database.manager.subprocess.run', return_value=MagicMock(returncode=0, stdout='', stderr='')) as mock_sql:
                    adm_cred = provision_phpmyadmin_sso_credentials(self.admin)
                    self.assertTrue(adm_cred['success'])
                    self.assertEqual(adm_cred['db_user'], 'w3p_admin_pma')
                    adm_sql = mock_sql.call_args.args[0][-1]
                    self.assertIn('ON *.* TO', adm_sql)

                with patch('services.database.manager.subprocess.run', return_value=MagicMock(returncode=0, stdout='', stderr='')) as mock_sql:
                    usr_cred = provision_phpmyadmin_sso_credentials(self.user)
                    self.assertTrue(usr_cred['success'])
                    self.assertEqual(usr_cred['db_user'], 'dbuser_pma')
                    usr_sql = mock_sql.call_args.args[0][-1]
                    self.assertIn('ON `dbuser_app`.* TO', usr_sql)
                    self.assertNotIn('otherpma_secret', usr_sql)
                    self.assertNotIn('*.*', usr_sql)

                # Launch flow forwards W3PanelPMASignon cookie onto /phpmyadmin/ redirect
                c_adm, adm_extra = self._login('dbadmin', '/login/', '12087')

                class _FakeHeaders(list):
                    def get_all(self, name):
                        return [v for k, v in self if k.lower() == name.lower()]

                signon_hdrs = _FakeHeaders([('Set-Cookie', 'W3PanelPMASignon=phpsess999; path=/phpmyadmin; HttpOnly; SameSite=Lax')])
                signon_resp = MagicMock(status=200, headers=signon_hdrs)
                signon_resp.read.return_value = b'{"success":true}'
                fake_conn = MagicMock()
                fake_conn.getresponse.return_value = signon_resp

                with patch('services.database.manager.ensure_db_admin_webserver_configured', return_value={'success': True}), \
                     patch('services.database.manager.subprocess.run', return_value=MagicMock(returncode=0, stdout='', stderr='')), \
                     patch('services.database.manager.http.client.HTTPConnection', return_value=fake_conn):
                    launch = c_adm.get('/services/db-tool/phpmyadmin/', **adm_extra)
                    self.assertEqual(launch.status_code, 302)
                    self.assertEqual(launch.url, '/phpmyadmin/')
                    self.assertEqual(launch.cookies['W3PanelPMASignon'].value, 'phpsess999')
