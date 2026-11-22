"""
W3Panel v2 — Auth, Impersonation & Role Enforcement Tests
"""
from django.test import TestCase, Client
from packages.core.models import User, Package, LoginToken


class AuthAndRoleTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user('admin_test', 'admin@local.test', 'Pass123!', role='admin')
        self.user = User.objects.create_user('client_test', 'user@local.test', 'Pass123!', role='user')
        self.package = Package.objects.create(name='Pro Plan', disk_limit_mb=10000, bandwidth_limit_gb=50)

    def test_user_creation_and_roles(self):
        self.assertEqual(self.admin.role, 'admin')
        self.assertEqual(self.user.role, 'user')
        self.assertTrue(self.admin.check_password('Pass123!'))
        self.assertTrue(self.user.check_password('Pass123!'))

    def test_login_page_renders(self):
        # Admin / Host Manager login
        response = self.client.get('/login/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'W3Host Manager')
        self.assertContains(response, 'Host Manager')

        # User / Client Portal login
        user_resp = self.client.get('/user/login/')
        self.assertEqual(user_resp.status_code, 200)
        self.assertContains(user_resp, 'W3Client Portal')
        self.assertContains(user_resp, 'Client Portal')
        self.assertContains(user_resp, 'Port 2083')

    def test_admin_login_success(self):
        response = self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.session.get('user_id'), self.admin.id)

    def test_invalid_login_fails(self):
        response = self.client.post('/login/', {'username': 'admin_test', 'password': 'WrongPassword!'})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.client.session.get('user_id'))

    def test_admin_user_edit_and_password_reset(self):
        # Log in as admin
        self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})
        
        # 1. GET user edit page
        resp_get = self.client.get(f'/users/{self.user.id}/edit/')
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(resp_get, 'client_test')

        # 2. POST update user details and reset password
        resp_post = self.client.post(f'/users/{self.user.id}/edit/', {
            'email': 'updated@local.test',
            'package': self.package.id,
            'role': 'user',
            'password': 'BrandNewPassword999!',
            'is_active': '1',
            'shell_enabled': '1',
        })
        self.assertEqual(resp_post.status_code, 302)

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, 'updated@local.test')
        self.assertEqual(self.user.package_id, self.package.id)
        self.assertTrue(self.user.shell_enabled)
        self.assertTrue(self.user.is_active)
        self.assertTrue(self.user.check_password('BrandNewPassword999!'))

    def test_admin_user_toggle_status_and_shell(self):
        self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})

        # 1. Toggle status
        self.assertTrue(self.user.is_active)
        resp_status = self.client.post(f'/users/{self.user.id}/toggle-status/')
        self.assertEqual(resp_status.status_code, 302)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

        # 2. Toggle shell
        self.assertFalse(self.user.shell_enabled)
        resp_shell = self.client.post(f'/users/{self.user.id}/toggle-shell/')
        self.assertEqual(resp_shell.status_code, 302)
        self.user.refresh_from_db()
        self.assertTrue(self.user.shell_enabled)

    def test_impersonation_sso_flow(self):
        # Admin initiates autologin in new tab
        self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})
        resp_autologin = self.client.get(f'/users/{self.user.id}/autologin/')
        self.assertEqual(resp_autologin.status_code, 302)
        sso_url = resp_autologin.url
        self.assertIn('/sso/?token=', sso_url)

        token_str = sso_url.split('token=')[1]
        token_obj = LoginToken.objects.get(token=token_str)
        self.assertEqual(token_obj.user, self.user)
        self.assertEqual(token_obj.created_by, self.admin)
        self.assertFalse(token_obj.is_used)

        # Switch to user client session visiting SSO endpoint
        from importlib import import_module
        from django.conf import settings
        SessionStore = import_module(settings.SESSION_ENGINE).SessionStore

        sso_client = Client()
        resp_sso = sso_client.get(f'/sso/?token={token_str}', follow=True, SERVER_PORT='2083')
        self.assertEqual(resp_sso.status_code, 200)
        client_session = SessionStore(sso_client.cookies['w3p_client_session'].value)
        self.assertEqual(client_session.get('user_id'), self.user.id)
        self.assertEqual(client_session.get('impersonated_by'), self.admin.username)
        # Verify no impersonation banner is shown to user
        self.assertNotContains(resp_sso, 'Administrator Single Sign-On')
        self.assertNotContains(resp_sso, 'Impersonation')
        self.assertNotContains(resp_sso, 'Return to Host Manager')
        self.assertContains(resp_sso, 'client_test')

        # Verify token cannot be reused
        token_obj.refresh_from_db()
        self.assertTrue(token_obj.is_used)
        resp_reuse = sso_client.get(f'/sso/?token={token_str}', SERVER_PORT='2083')
        self.assertEqual(resp_reuse.status_code, 302)
        self.assertEqual(resp_reuse.url, '/login/')

    def test_reseller_autologin_scoping(self):
        reseller = User.objects.create_user('reseller_1', 'reseller@local.test', 'Pass123!', role='reseller')
        sub_user = User.objects.create_user('sub_user_1', 'sub@local.test', 'Pass123!', role='user', parent_reseller=reseller)
        other_user = User.objects.create_user('other_user', 'other@local.test', 'Pass123!', role='user')

        reseller_client = Client()
        reseller_client.post('/login/', {'username': 'reseller_1', 'password': 'Pass123!'})

        # Reseller can autologin to owned sub-user
        resp_allowed = reseller_client.get(f'/users/{sub_user.id}/autologin/')
        self.assertEqual(resp_allowed.status_code, 302)
        self.assertIn('/sso/?token=', resp_allowed.url)

        # Reseller blocked from autologin to unowned user
        resp_blocked = reseller_client.get(f'/users/{other_user.id}/autologin/')
        self.assertEqual(resp_blocked.status_code, 302)
        self.assertEqual(resp_blocked.url, '/users/')

    def test_terminal_admin_and_user_access(self):
        # 1. Admin terminal
        self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})
        resp_admin_term = self.client.get('/terminal/')
        self.assertEqual(resp_admin_term.status_code, 200)

        # Admin terminal exec safe command
        resp_admin_exec = self.client.post('/terminal/exec/', {'command': 'echo admin_ok'})
        self.assertEqual(resp_admin_exec.status_code, 200)
        data = resp_admin_exec.json()
        self.assertIn('admin_ok', data.get('stdout', ''))

        # Admin terminal blocked command
        resp_admin_blocked = self.client.post('/terminal/exec/', {'command': 'rm -rf /'})
        self.assertEqual(resp_admin_blocked.status_code, 200)
        self.assertIn('blocked', resp_admin_blocked.json().get('stderr', '').lower())

        # 2. User terminal
        user_client = Client()
        user_client.post('/user/login/', {'username': 'client_test', 'password': 'Pass123!'})
        
        # User terminal page renders
        resp_user_term = user_client.get('/user/terminal/')
        self.assertEqual(resp_user_term.status_code, 200)

        # User terminal exec with shell disabled (default False)
        resp_user_exec_dis = user_client.post('/user/terminal/exec/', {'command': 'whoami'})
        self.assertEqual(resp_user_exec_dis.status_code, 403)

        # User terminal exec with shell enabled
        self.user.shell_enabled = True
        self.user.save()
        resp_user_exec_en = user_client.post('/user/terminal/exec/', {'command': 'echo user_ok'})
        self.assertEqual(resp_user_exec_en.status_code, 200)
        user_data = resp_user_exec_en.json()
        self.assertIn('user_ok', user_data.get('stdout', ''))

    def test_create_account_role_restrictions(self):
        self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})
        # Attempting to select role='admin' on /users/create/ is ignored and forced to 'user'
        resp = self.client.post('/users/create/', {
            'username': 'attempted_admin',
            'password': 'Pass123!',
            'role': 'admin'
        })
        self.assertEqual(resp.status_code, 302)
        created = User.objects.get(username='attempted_admin')
        self.assertEqual(created.role, 'user')

        # Creating a reseller works
        resp_reseller = self.client.post('/users/create/', {
            'username': 'legit_reseller',
            'password': 'Pass123!',
            'role': 'reseller'
        })
        self.assertEqual(resp_reseller.status_code, 302)
        reseller_created = User.objects.get(username='legit_reseller')
        self.assertEqual(reseller_created.role, 'reseller')

    def test_administrator_dedicated_create(self):
        self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})
        resp = self.client.post('/administrators/', {
            'username': 'new_sysadmin',
            'email': 'sysadmin@test.local',
            'password': 'Pass123!'
        })
        self.assertEqual(resp.status_code, 302)
        new_admin = User.objects.get(username='new_sysadmin')
        self.assertEqual(new_admin.role, 'admin')

        # Reseller cannot create or view administrators
        reseller = User.objects.create_user('reseller_test', 'r@local.test', 'Pass123!', role='reseller')
        r_client = Client()
        r_client.post('/login/', {'username': 'reseller_test', 'password': 'Pass123!'})
        resp_r = r_client.post('/administrators/', {
            'username': 'hacked_admin',
            'password': 'Pass123!'
        })
        self.assertEqual(resp_r.status_code, 302)
        self.assertFalse(User.objects.filter(username='hacked_admin').exists())

    def test_vhosts_redirects_to_accounts(self):
        self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})
        resp = self.client.get('/services/vhosts/')
        self.assertEqual(resp.status_code, 302)
        self.assertRedirects(resp, '/users/')

        resp_websites = self.client.get('/websites/')
        self.assertEqual(resp_websites.status_code, 302)
        self.assertRedirects(resp_websites, '/users/')

        # Verify /features/ redirects to /plans/ and Feature Manager is removed from sidebar
        resp_features = self.client.get('/features/')
        self.assertEqual(resp_features.status_code, 302)
        self.assertRedirects(resp_features, '/plans/')

        resp_plans = self.client.get('/plans/')
        self.assertEqual(resp_plans.status_code, 200)
        self.assertNotContains(resp_plans, 'Feature Manager')

        # Verify Service Manager page displays core services without panel daemons
        resp_svc = self.client.get('/services/')
        self.assertEqual(resp_svc.status_code, 200)
        self.assertContains(resp_svc, 'Service Manager')
        self.assertContains(resp_svc, 'Nginx Web Server')
        self.assertNotContains(resp_svc, 'W3Host Manager (Port 2087)')
        self.assertNotContains(resp_svc, 'W3Client Portal (Port 2083)')

    def test_initial_setup_wizard_view_and_post(self):
        from packages.core.models import SystemSetting
        self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})
        
        # 1. Test GET /wizards/
        resp_get = self.client.get('/wizards/')
        self.assertEqual(resp_get.status_code, 200)
        self.assertContains(resp_get, 'Initial Server Setup Wizard')
        self.assertContains(resp_get, 'Web Server Selection')

        # 2. Test POST /wizards/
        resp_post = self.client.post('/wizards/', {
            'server_hostname': 'cloud.example.org',
            'server_ip': '203.0.113.10',
            'primary_ns': 'ns1.example.org',
            'secondary_ns': 'ns2.example.org',
            'admin_email': 'ops@example.org',
            'webserver_choice': 'nginx',
            'default_php': '8.3',
            'enable_mariadb': '1',
            'tune_mariadb': '1',
            'enable_postgresql': '0',
            'enable_mail': '1',
            'spam_filter': 'rspamd',
            'enable_dkim': '1',
            'enable_ftp': '1',
            'enable_ufw': '1',
        })
        self.assertEqual(resp_post.status_code, 302)
        self.assertRedirects(resp_post, '/settings/')

        # Verify values persisted in SystemSetting
        self.assertEqual(SystemSetting.get('server_hostname'), 'cloud.example.org')
        self.assertEqual(SystemSetting.get('server_ip'), '203.0.113.10')
        self.assertEqual(SystemSetting.get('primary_ns'), 'ns1.example.org')
        self.assertEqual(SystemSetting.get('secondary_ns'), 'ns2.example.org')
        self.assertEqual(SystemSetting.get('admin_email'), 'ops@example.org')
        self.assertEqual(SystemSetting.get('initial_setup_completed'), 'true')

        # 3. Test GET /settings/ displays updated data and wizard banner
        resp_settings = self.client.get('/settings/')
        self.assertEqual(resp_settings.status_code, 200)
        self.assertContains(resp_settings, 'cloud.example.org')
        self.assertContains(resp_settings, '203.0.113.10')
        self.assertContains(resp_settings, 'Completed')

        # 4. Test GET /wizards/ shows Baseline Setup Active
        resp_wizards = self.client.get('/wizards/')
        self.assertEqual(resp_wizards.status_code, 200)
        self.assertContains(resp_wizards, 'Baseline Setup Active')

    def test_admin_cron_management(self):
        from packages.core.models import CronJob
        self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})

        # 1. Seed tenant cron job
        job = CronJob.objects.create(
            owner=self.user,
            command='/usr/bin/php /home/client_test/public_html/cron.php',
            schedule='*/15 * * * *',
            description='WP Cron Task',
            is_active=True
        )

        # 2. Test GET /services/cron/ (Default: tab=user, user=all)
        resp_all = self.client.get('/services/cron/')
        self.assertEqual(resp_all.status_code, 200)
        self.assertContains(resp_all, 'Server Scheduled Tasks & Crontabs')
        self.assertContains(resp_all, 'All Accounts (System & Tenants)')
        self.assertContains(resp_all, 'root (Server Administrator)')
        self.assertContains(resp_all, 'System Crontabs')
        self.assertContains(resp_all, 'Maintenance Intervals')
        self.assertContains(resp_all, 'WP Cron Task')
        # Admin should NOT be listed as a tenant account in the dropdown
        self.assertNotContains(resp_all, 'admin_test (admin)')

        # 3. Test filter by root or admin (shows live root crontab card, suppresses tenant table)
        resp_root = self.client.get('/services/cron/?user=root')
        self.assertEqual(resp_root.status_code, 200)
        self.assertContains(resp_root, 'crontab -l -u root')
        self.assertNotContains(resp_root, 'All Tenant User Scheduled Tasks')

        # 4. Test filter by specific tenant user
        resp_user = self.client.get('/services/cron/?user=client_test')
        self.assertEqual(resp_user.status_code, 200)
        self.assertContains(resp_user, 'WP Cron Task')

        # 4. Test toggle status (pause)
        resp_toggle = self.client.post('/services/cron/', {
            'action': 'toggle_status',
            'job_id': job.id,
        })
        self.assertEqual(resp_toggle.status_code, 302)
        job.refresh_from_db()
        self.assertFalse(job.is_active)

        # 5. Test create cron job for tenant
        resp_create = self.client.post('/services/cron/', {
            'action': 'create_cron',
            'target_user': 'client_test',
            'schedule': '0 2 * * *',
            'command': '/usr/bin/python3 /home/client_test/backup.py',
            'description': 'Daily Tenant Backup',
        })
        self.assertEqual(resp_create.status_code, 302)
        new_job = CronJob.objects.filter(owner=self.user, command__contains='backup.py').first()
        self.assertIsNotNone(new_job)
        self.assertEqual(new_job.schedule, '0 2 * * *')
        self.assertEqual(new_job.description, 'Daily Tenant Backup')

        # 6. Test delete tenant cron job
        resp_delete = self.client.post('/services/cron/', {
            'action': 'delete',
            'job_id': new_job.id,
        })
        self.assertEqual(resp_delete.status_code, 302)
        self.assertFalse(CronJob.objects.filter(id=new_job.id).exists())

        # 7. Test system and maintenance interval tabs
        resp_sys = self.client.get('/services/cron/?tab=system')
        self.assertEqual(resp_sys.status_code, 200)
        self.assertContains(resp_sys, 'Parsed System Daemon Crontabs')

        resp_int = self.client.get('/services/cron/?tab=maintenance')
        self.assertEqual(resp_int.status_code, 200)
        self.assertContains(resp_int, 'Hourly Tasks (/etc/cron.hourly/)')

    def test_multiphp_manager(self):
        from packages.core.models import Website, SystemSetting
        self.client.post('/login/', {'username': 'admin_test', 'password': 'Pass123!'})

        # Seed website
        site = Website.objects.create(
            owner=self.user,
            domain='multiphp.local',
            doc_root='/tmp/w3panel_test/multiphp.local',
            php_version='8.3'
        )

        # 1. Test GET /settings/php/ (Manager tab)
        resp_mgr = self.client.get('/settings/php/')
        self.assertEqual(resp_mgr.status_code, 200)
        self.assertContains(resp_mgr, 'MultiPHP Manager')
        self.assertContains(resp_mgr, 'System Default PHP')
        self.assertNotContains(resp_mgr, 'Installed PHP Runtimes')
        self.assertContains(resp_mgr, 'Per-Domain PHP Version Assignment')
        self.assertContains(resp_mgr, 'multiphp.local')
        # Ensure DiamondWish is renamed to Enterprise Performance Profile
        self.assertNotContains(resp_mgr, 'DiamondWish')
        self.assertContains(resp_mgr, 'Enterprise High-Concurrency Performance Profile')

        # 2. Test GET /php/ shortcut route
        resp_short = self.client.get('/php/')
        self.assertEqual(resp_short.status_code, 200)
        self.assertContains(resp_short, 'MultiPHP Manager')

        # 3. Test POST set_default_php rejection of uninstalled version
        from apps.admin.views import get_installed_php_versions
        installed_list = [p['version'] for p in get_installed_php_versions() if p['installed']]
        valid_ver = installed_list[0] if installed_list else '8.3'

        resp_bad_def = self.client.post('/settings/php/', {
            'action': 'set_default_php',
            'default_php': '99.9',
        })
        self.assertEqual(resp_bad_def.status_code, 302)
        self.assertNotEqual(SystemSetting.get('default_php'), '99.9')

        # Test POST set_default_php with installed version
        resp_def = self.client.post('/settings/php/', {
            'action': 'set_default_php',
            'default_php': valid_ver,
        })
        self.assertEqual(resp_def.status_code, 302)
        self.assertEqual(SystemSetting.get('default_php'), valid_ver)

        # 4. Test POST set_domain_php rejection of uninstalled version
        resp_bad_dom = self.client.post('/settings/php/', {
            'action': 'set_domain_php',
            'website_id': site.id,
            'php_version': '99.9',
        })
        self.assertEqual(resp_bad_dom.status_code, 302)
        site.refresh_from_db()
        self.assertNotEqual(site.php_version, '99.9')

        # Test POST set_domain_php with installed version
        resp_dom = self.client.post('/settings/php/', {
            'action': 'set_domain_php',
            'website_id': site.id,
            'php_version': valid_ver,
        })
        self.assertEqual(resp_dom.status_code, 302)
        site.refresh_from_db()
        self.assertEqual(site.php_version, valid_ver)

        # 5. Test POST save_ini (Basic Mode)
        resp_ini = self.client.post('/settings/php/', {
            'action': 'save_ini',
            'php_version': '8.3',
            'memory_limit': '512M',
            'upload_max_filesize': '128M',
            'post_max_size': '128M',
            'max_execution_time': '300',
            'max_input_time': '120',
            'display_errors': 'Off',
        })
        self.assertEqual(resp_ini.status_code, 302)
        self.assertEqual(SystemSetting.get('php_8.3_memory_limit'), '512M')
        self.assertEqual(SystemSetting.get('php_8.3_upload_max_filesize'), '128M')

        # 6. Test GET Editor Mode (Whole Raw php.ini viewer)
        resp_editor = self.client.get('/settings/php/?tab=ini&mode=editor&php_version=8.3&target=fpm')
        self.assertEqual(resp_editor.status_code, 200)
        self.assertContains(resp_editor, 'Editor Mode (Raw php.ini)')
        self.assertContains(resp_editor, 'Runtime Target:')
        self.assertContains(resp_editor, 'name="ini_content"')
        self.assertContains(resp_editor, 'Save php.ini')

        # 7. Test POST save_raw_ini
        custom_raw = "; Custom W3Panel php.ini\nmemory_limit = 768M\nupload_max_filesize = 99M\n"
        resp_save_raw = self.client.post('/settings/php/', {
            'action': 'save_raw_ini',
            'php_version': '8.3',
            'ini_target': 'fpm',
            'ini_content': custom_raw,
        })
        self.assertEqual(resp_save_raw.status_code, 302)
        self.assertEqual(SystemSetting.get('php_8.3_memory_limit'), '768M')



