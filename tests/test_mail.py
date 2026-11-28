"""
W3Panel v2 — Isolated Email Stack Integration Tests
Tests Postfix/Dovecot/OpenDKIM/Rspamd provisioning, Sieve autoresponders, Catch-All,
DNS deliverability, delivery tracking, SnappyMail ZIP install + proxy + 1-click SSO,
Hostpanel views, Clientpanel views, and REST API email endpoints.
"""
import hashlib
import json
import os
import shutil
import subprocess as real_subproc
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.test import Client, TestCase

from packages.core.models import (
    APIToken,
    DNSRecord,
    EmailAutoresponder,
    EmailCatchAll,
    EmailForwarder,
    Mailbox,
    Package,
    SystemSetting,
    User,
    Website,
)
from services.mail import (
    configure_mail_stack,
    configure_webmail_webserver,
    create_mail_alias,
    create_mailbox,
    delete_mail_alias,
    delete_mail_queue,
    delete_mailbox,
    flush_mail_queue,
    get_domain_deliverability,
    get_mail_delivery_log,
    get_mail_queue,
    get_mail_stats,
    hash_mailbox_password,
    install_snappymail,
    remove_mailbox_sieve,
    repair_domain_deliverability,
    set_domain_catchall,
    set_mailbox_password,
    sync_mailbox_sieve,
    update_mailbox_quota,
)


class MailStackTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.temp_dir = Path(tempfile.mkdtemp(prefix='w3panel_mail_test_'))
        cls.env_patch = patch.dict(os.environ, {
            'W3PANEL_VMAIL_BASE': str(cls.temp_dir / 'vmail'),
            'W3PANEL_POSTFIX_DIR': str(cls.temp_dir / 'postfix'),
            'W3PANEL_DOVECOT_DIR': str(cls.temp_dir / 'dovecot'),
            'W3PANEL_OPENDKIM_DIR': str(cls.temp_dir / 'opendkim' / 'keys'),
            'W3PANEL_OPENDKIM_CONF_DIR': str(cls.temp_dir / 'opendkim'),
            'W3PANEL_OPENDKIM_CONF_FILE': str(cls.temp_dir / 'opendkim.conf'),
            'W3PANEL_RSPAMD_DIR': str(cls.temp_dir / 'rspamd' / 'local.d'),
            'W3PANEL_WEBMAIL_DIR': str(cls.temp_dir / 'webmail'),
            'W3PANEL_ETC_DIR': str(cls.temp_dir / 'etc_w3panel'),
            'W3PANEL_SSL_DIR': str(cls.temp_dir / 'ssl'),
            'W3PANEL_DNS_DIR': str(cls.temp_dir / 'dns'),
            'W3PANEL_MAIL_LOG': str(cls.temp_dir / 'mail.log'),
            'W3PANEL_NGINX_SITES_DIR': str(cls.temp_dir / 'nginx' / 'sites-available'),
            'W3PANEL_NGINX_ENABLED_DIR': str(cls.temp_dir / 'nginx' / 'sites-enabled'),
        })
        cls.env_patch.start()
        cls.sudo_patch_mail = patch('services.mail.manager._has_sudo', return_value=False)
        cls.sudo_patch_ws = patch('services.webserver.manager._has_sudo', return_value=False)
        cls.sudo_patch_db = patch('services.database.manager._has_sudo', return_value=False)
        cls.sudo_patch_mail.start()
        cls.sudo_patch_ws.start()
        cls.sudo_patch_db.start()

    @classmethod
    def tearDownClass(cls):
        cls.sudo_patch_db.stop()
        cls.sudo_patch_ws.stop()
        cls.sudo_patch_mail.stop()
        cls.env_patch.stop()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.client = Client()
        SystemSetting.set('initial_setup_completed', 'true')
        SystemSetting.set('server_ip', '203.0.113.10')
        SystemSetting.set('server_hostname', 'panel.myclientdomain.com')
        self.package = Package.objects.create(
            name='Standard Plan',
            websites_limit=3,
            databases_limit=3,
            email_limit=2,
            disk_limit_mb=5000,
            bandwidth_limit_gb=50,
        )
        self.admin = User.objects.create_user('admin_mail', 'admin@example.com', 'AdminPass123!', role='admin')
        self.user = User.objects.create_user('client_mail', 'client@example.com', 'ClientPass123!', role='user', package=self.package)
        self.other_user = User.objects.create_user('other_mail', 'other@example.com', 'OtherPass123!', role='user')

        self.website = Website.objects.create(
            owner=self.user,
            domain='myclientdomain.com',
            doc_root='/tmp/w3panel_test/myclientdomain.com',
            framework='none',
        )
        self.other_website = Website.objects.create(
            owner=self.other_user,
            domain='otherdomain.com',
            doc_root='/tmp/w3panel_test/otherdomain.com',
            framework='none',
        )

    def _login_admin(self, port='2087'):
        c = Client()
        resp = c.post('/login/', {'username': 'admin_mail', 'password': 'AdminPass123!'}, SERVER_PORT=port)
        self.assertEqual(resp.status_code, 302)
        return c, {'SERVER_PORT': port}

    def _login_user(self, user_obj=None, port='2083'):
        c = Client()
        uname = user_obj.username if user_obj else 'client_mail'
        pw = 'OtherPass123!' if uname == 'other_mail' else 'ClientPass123!'
        resp = c.post('/user/login/', {'username': uname, 'password': pw}, SERVER_PORT=port)
        self.assertEqual(resp.status_code, 302)
        return c, {'SERVER_PORT': port}

    # -----------------------------------------------------------------------
    # 1. Mail Service Manager, Quotas, Catch-All, Sieve, OpenDKIM & Delivery Log
    # -----------------------------------------------------------------------

    def test_create_quota_update_and_delete_mailbox(self):
        email = 'support@myclientdomain.com'
        res = create_mailbox(email, password='SecretPassword123!', quota_mb=512)
        self.assertTrue(res.get('success'))
        self.assertEqual(res.get('email'), email)

        maildir = Path(res.get('maildir'))
        for d in ('cur', 'new', 'tmp', 'sieve'):
            self.assertTrue((maildir / d).exists())

        vmailbox_file = Path(os.environ['W3PANEL_POSTFIX_DIR']) / 'vmailbox'
        vdomains_file = Path(os.environ['W3PANEL_POSTFIX_DIR']) / 'vmailbox_domains'
        self.assertIn(email, vmailbox_file.read_text())
        self.assertIn('myclientdomain.com OK', vdomains_file.read_text())

        dovecot_users = Path(os.environ['W3PANEL_DOVECOT_DIR']) / 'users'
        users_content = dovecot_users.read_text()
        self.assertIn(f'{email}:', users_content)
        self.assertIn(':5000:5000::', users_content)
        self.assertIn('userdb_quota_rule=*:storage=512M', users_content)

        # Updating quota preserves password hash and updates Dovecot rule
        update_mailbox_quota(email, 2048)
        updated_content = dovecot_users.read_text()
        self.assertIn('userdb_quota_rule=*:storage=2048M', updated_content)
        self.assertNotIn('storage=512M', updated_content)

        # Updating password preserves 2048M quota
        set_mailbox_password(email, 'NewSecretPassword789!')
        self.assertIn('userdb_quota_rule=*:storage=2048M', dovecot_users.read_text())

        del_res = delete_mailbox(email)
        self.assertTrue(del_res.get('success'))
        self.assertNotIn(email, vmailbox_file.read_text())
        self.assertNotIn(f'{email}:', dovecot_users.read_text())

    def test_password_hashing_valid_dovecot_schemes(self):
        pw_hash = hash_mailbox_password('MyStrongPassword123!')
        self.assertTrue(pw_hash.startswith('{SHA512-CRYPT}$6$') or pw_hash.startswith('{ARGON2ID}$argon2id$'))
        self.assertFalse(pw_hash.startswith('{SHA512.HEX}'))

    def test_mail_alias_forwarders_and_catchall(self):
        src = 'info@myclientdomain.com'
        alias_res = create_mail_alias(src, ['alice@external.com', 'bob@external.com'])
        self.assertTrue(alias_res.get('success'))
        virtual_file = Path(os.environ['W3PANEL_POSTFIX_DIR']) / 'virtual'
        self.assertIn('info@myclientdomain.com alice@external.com, bob@external.com', virtual_file.read_text())

        # Catch-all forward -> discard -> fail
        self.assertTrue(set_domain_catchall('myclientdomain.com', 'forward', 'catch@external.com')['success'])
        self.assertIn('@myclientdomain.com catch@external.com', virtual_file.read_text())

        self.assertTrue(set_domain_catchall('myclientdomain.com', 'discard')['success'])
        self.assertIn('@myclientdomain.com devnull@localhost', virtual_file.read_text())

        self.assertTrue(set_domain_catchall('myclientdomain.com', 'fail')['success'])
        self.assertFalse(any(ln.startswith('@myclientdomain.com ') for ln in virtual_file.read_text().splitlines()))

        self.assertTrue(delete_mail_alias(src)['success'])
        self.assertNotIn(src, virtual_file.read_text())

    def test_autoresponder_sieve_script_generation(self):
        email = 'vac@myclientdomain.com'
        res = sync_mailbox_sieve(
            email,
            subject='On "Holiday"',
            body='Back next Monday.',
            interval_hours=12,
            is_active=True,
        )
        self.assertTrue(res['success'])
        sieve_path = Path(res['path'])
        self.assertTrue(sieve_path.exists())
        sieve_txt = sieve_path.read_text()
        self.assertIn('vacation-seconds', sieve_txt)
        self.assertIn(':seconds 43200', sieve_txt)
        self.assertIn(':subject "On \\"Holiday\\""', sieve_txt)
        self.assertIn('"Back next Monday."', sieve_txt)

        remove_mailbox_sieve(email)
        self.assertFalse(sieve_path.exists())

    def test_configure_mail_stack_and_deliverability_repair(self):
        pf_dir = Path(os.environ['W3PANEL_POSTFIX_DIR'])
        main_cf_path = pf_dir / 'main.cf'
        main_cf_path.write_text(
            "mydestination = $myhostname, old.local, localhost\n"
            "smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem\n"
            "smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key\n"
        )
        cfg = configure_mail_stack(hostname='mail.myclientdomain.com', smtp_port='2587', spam_filter='rspamd', dkim_enabled=True, spam_threshold=5.5)
        self.assertTrue(cfg['success'])

        dc_dir = Path(os.environ['W3PANEL_DOVECOT_DIR'])
        rspamd_dir = Path(os.environ['W3PANEL_RSPAMD_DIR'])
        odkim_conf = Path(os.environ['W3PANEL_OPENDKIM_CONF_FILE'])

        main_cf = main_cf_path.read_text()
        self.assertIn('# mydestination = $myhostname, old.local, localhost', main_cf)
        self.assertIn('# smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem', main_cf)
        self.assertIn('virtual_transport = lmtp:unix:private/dovecot-lmtp', main_cf)
        self.assertIn('smtpd_sasl_type = dovecot', main_cf)
        self.assertIn('unix:opendkim/opendkim.sock', main_cf)
        self.assertIn('inet:127.0.0.1:11332', main_cf)

        master_cf = (pf_dir / 'master.cf').read_text()
        self.assertIn('submission inet', master_cf)
        self.assertIn('smtps     inet', master_cf)
        self.assertIn('2587 inet', master_cf)

        self.assertIn('auth_master_user_separator = *', (dc_dir / 'conf.d' / '10-auth.conf').read_text())
        self.assertIn('inbox = yes', (dc_dir / 'conf.d' / '10-mail.conf').read_text())
        self.assertIn('userdb {', (dc_dir / 'conf.d' / 'auth-passwdfile.conf.ext').read_text())
        self.assertIn('master = yes', (dc_dir / 'conf.d' / 'auth-master.conf.ext').read_text())
        self.assertIn('sieve_extensions = +vacation-seconds', (dc_dir / 'conf.d' / '90-sieve.conf').read_text())
        self.assertEqual((dc_dir / 'conf.d' / '20-imap.conf').read_text().strip(), 'protocol imap {\n  mail_plugins = $mail_plugins imap_quota\n}')
        self.assertIn('mail_plugins = $mail_plugins sieve', (dc_dir / 'conf.d' / '20-lmtp.conf').read_text())
        self.assertNotIn('$mail_plugins quota sieve', (dc_dir / 'conf.d' / '20-lmtp.conf').read_text())
        self.assertIn('w3p_master:', (dc_dir / 'passwd.masterusers').read_text())
        self.assertIn('bind_socket = "127.0.0.1:11332"', (rspamd_dir / 'worker-proxy.inc').read_text())
        self.assertIn('add_header = 5.5;', (rspamd_dir / 'actions.conf').read_text())
        odkim_txt = odkim_conf.read_text()
        self.assertIn('Socket local:/var/spool/postfix/opendkim/opendkim.sock', odkim_txt)
        self.assertIn('PidFile /run/opendkim/opendkim.pid', odkim_txt)
        self.assertIn('Background Yes', odkim_txt)

        # Deliverability check & auto-repair generates real RSA DKIM + MX/SPF/DMARC DNS records
        before = get_domain_deliverability(self.website)
        self.assertFalse(before['all_ok'])
        rep = repair_domain_deliverability(self.website)
        self.assertTrue(rep['success'])
        self.assertTrue(rep['status']['all_ok'])

        dkim_rec = DNSRecord.objects.get(domain=self.website, record_type='TXT', name='default._domainkey')
        self.assertIn('v=DKIM1; k=rsa; p=', dkim_rec.value)
        self.assertNotIn('MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0h7Y4', dkim_rec.value)
        self.assertTrue(DNSRecord.objects.filter(domain=self.website, record_type='MX', name='@').exists())
        self.assertTrue(DNSRecord.objects.filter(domain=self.website, record_type='TXT', name='_dmarc').exists())
        self.assertTrue((Path(os.environ['W3PANEL_DNS_DIR']) / 'myclientdomain.com.zone').exists())

    def test_mail_queue_delivery_log_and_stats(self):
        queue = get_mail_queue()
        self.assertTrue(queue['empty'])
        self.assertEqual(flush_mail_queue()['success'], True)
        self.assertEqual(delete_mail_queue('ALL')['success'], True)

        log_path = Path(os.environ['W3PANEL_MAIL_LOG'])
        log_path.write_text(
            "Nov 28 10:00:01 mail postfix/qmgr[120]: ABC12345: from=<alice@myclientdomain.com>, size=1234, nrcpt=1 (queue active)\n"
            "Nov 28 10:00:02 mail postfix/smtp[121]: ABC12345: to=<bob@example.org>, relay=mx.example.org[1.2.3.4]:25, delay=0.5, status=sent (250 2.0.0 OK)\n"
            "Nov 28 10:01:01 mail postfix/qmgr[120]: DEF67890: from=<alice@myclientdomain.com>, size=900, nrcpt=1\n"
            "Nov 28 10:01:02 mail postfix/smtp[122]: DEF67890: to=<bad@invalid.test>, relay=none, status=bounced (Host not found)\n"
        )
        events = get_mail_delivery_log(limit=10)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]['status'], 'bounced')
        self.assertEqual(events[1]['status'], 'sent')
        self.assertEqual(events[1]['sender'], 'alice@myclientdomain.com')

        stats = get_mail_stats()
        self.assertEqual(stats['sent_today'], 1)
        self.assertEqual(stats['bounced_today'], 1)
        self.assertEqual(stats['delivery_rate'], '50%')

    def test_snappymail_zip_install_nginx_proxy_and_sso(self):
        # Build a mock SnappyMail zip with a zip-slip traversal entry that must be skipped
        zip_path = self.temp_dir / 'snappymail-test.zip'
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr('index.php', '<?php echo "SNAPPYMAIL_OK"; ?>')
            zf.writestr('.htaccess', 'Deny from all')
            zf.writestr('snappymail/v/3.1.4/include.php', '<?php // ok')
            zf.writestr('../../evil_traversal.txt', 'pwned')

        with patch.dict(os.environ, {'W3PANEL_SNAPPYMAIL_ZIP': str(zip_path)}), \
             patch('services.mail.manager.shutil.which', return_value=None):
            res = install_snappymail()
            self.assertTrue(res['success'])
            webmail_dir = Path(res['path'])
            self.assertTrue((webmail_dir / 'index.php').exists())
            self.assertTrue((webmail_dir / '.htaccess').exists())
            self.assertFalse((self.temp_dir / 'evil_traversal.txt').exists())

            domain_json = json.loads((webmail_dir / 'data' / '_data_' / '_default_' / 'domains' / 'default.json').read_text())
            self.assertEqual(domain_json['IMAP']['port'], 143)
            self.assertEqual(domain_json['SMTP']['port'], 587)
            self.assertTrue(domain_json['Sieve']['enabled'])

            app_ini = (webmail_dir / 'data' / '_data_' / '_default_' / 'configs' / 'application.ini').read_text()
            self.assertIn('enabled_list = "w3p-master"', app_ini)
            self.assertIn('cookie_default_path = "/snappymail"', app_ini)
            self.assertIn('cookie_samesite = "Lax"', app_ini)

            plugin_php = webmail_dir / 'data' / '_data_' / '_default_' / 'plugins' / 'w3p-master' / 'index.php'
            signon_php = webmail_dir / 'w3p-signon.php'
            self.assertTrue(plugin_php.exists())
            self.assertTrue(signon_php.exists())

            if shutil.which('php'):
                for pf in (plugin_php, signon_php):
                    lint = real_subproc.run(['php', '-l', str(pf)], capture_output=True, text=True)
                    self.assertEqual(lint.returncode, 0, lint.stderr)

            nginx_res = configure_webmail_webserver()
            self.assertTrue(nginx_res['success'])
            nginx_conf = Path(nginx_res['config_path']).read_text()
            self.assertIn('listen 127.0.0.1:8091;', nginx_conf)
            self.assertIn('location ^~ /snappymail', nginx_conf)

            # Same-origin proxy requires auth, blocks data/ & w3p-signon.php, forwards cookies
            self.assertEqual(Client().get('/snappymail/', SERVER_PORT='2083').status_code, 302)
            c_usr, usr_extra = self._login_user()
            self.assertEqual(c_usr.get('/snappymail/data/_data_/_default_/configs/application.ini', **usr_extra).status_code, 403)
            self.assertEqual(c_usr.get('/snappymail/w3p-signon.php', **usr_extra).status_code, 403)

            # 1-click SSO launch enforces mailbox ownership and sets SnappyMail cookies
            own_mb = Mailbox.objects.create(owner=self.user, email='me@myclientdomain.com', domain='myclientdomain.com', quota_mb=1024)
            other_mb = Mailbox.objects.create(owner=self.other_user, email='them@otherdomain.com', domain='otherdomain.com', quota_mb=1024)

            self.assertEqual(c_usr.get(f'/emails/{other_mb.id}/webmail/', **usr_extra).status_code, 404)

            class _FakeHeaders(list):
                def get_all(self, name):
                    return [v for k, v in self if k.lower() == name.lower()]

            sso_hdrs = _FakeHeaders([('Set-Cookie', 'rlsession=tok999; path=/snappymail; HttpOnly; SameSite=Lax')])
            sso_resp = MagicMock(status=200, headers=sso_hdrs)
            sso_resp.read.return_value = b'{"success":true}'
            fake_conn = MagicMock()
            fake_conn.getresponse.return_value = sso_resp

            with patch('services.mail.manager.http.client.HTTPConnection', return_value=fake_conn):
                launch = c_usr.get(f'/emails/{own_mb.id}/webmail/', **usr_extra)
                self.assertEqual(launch.status_code, 302)
                self.assertEqual(launch.url, '/snappymail/')
                self.assertEqual(launch.cookies['rlsession'].value, 'tok999')

    # -----------------------------------------------------------------------
    # 2. Hostpanel (Admin) & Service Manager Views
    # -----------------------------------------------------------------------

    def test_admin_email_full_management_and_service_install_stream(self):
        c_adm, adm_extra = self._login_admin()

        resp = c_adm.get('/email/accounts/', **adm_extra)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Email Manager')
        self.assertContains(resp, 'Autoresponders')
        self.assertContains(resp, 'Default Address')
        self.assertContains(resp, 'Deliverability')

        # Create mailbox -> edit quota/password -> create forwarder -> autoresponder -> catchall -> repair DNS
        c_adm.post('/email/accounts/', {
            'action': 'create_mailbox',
            'username': 'adminbox',
            'domain': self.website.domain,
            'password': 'SecurePassword123!',
            'quota': '2048',
        }, **adm_extra)
        mb = Mailbox.objects.get(email=f'adminbox@{self.website.domain}')

        c_adm.post(f'/email/{mb.id}/edit/', {'password': 'BrandNewPassword999!', 'quota': '4096'}, **adm_extra)
        mb.refresh_from_db()
        self.assertEqual(mb.quota_mb, 4096)
        self.assertIn('userdb_quota_rule=*:storage=4096M', (Path(os.environ['W3PANEL_DOVECOT_DIR']) / 'users').read_text())

        c_adm.post('/email/accounts/', {
            'action': 'create_forwarder',
            'source_user': 'contact',
            'source_domain': self.website.domain,
            'destination': 'admin@externalcompany.com',
        }, **adm_extra)
        fwd = EmailForwarder.objects.get(source=f'contact@{self.website.domain}')

        c_adm.post('/email/accounts/', {
            'action': 'create_autoresponder',
            'ar_user': 'adminbox',
            'ar_domain': self.website.domain,
            'ar_interval': '12',
            'ar_subject': 'Away',
            'ar_body': 'Returning soon.',
        }, **adm_extra)
        ar = EmailAutoresponder.objects.get(email=mb.email)

        c_adm.post('/email/accounts/', {
            'action': 'set_catchall',
            'catchall_domain': self.website.domain,
            'catchall_action': 'forward',
            'catchall_destination': mb.email,
        }, **adm_extra)
        self.assertTrue(EmailCatchAll.objects.filter(domain=self.website.domain, action='forward').exists())

        c_adm.post('/email/accounts/', {'action': 'repair_deliverability', 'domain': self.website.domain}, **adm_extra)
        self.assertTrue(DNSRecord.objects.filter(domain=self.website, record_type='TXT', name='_dmarc').exists())

        # Delete resources
        c_adm.post(f'/email/autoresponders/{ar.id}/delete/', **adm_extra)
        self.assertFalse(EmailAutoresponder.objects.filter(id=ar.id).exists())
        c_adm.post(f'/email/forwarders/{fwd.id}/delete/', **adm_extra)
        self.assertFalse(EmailForwarder.objects.filter(id=fwd.id).exists())
        c_adm.post(f'/email/{mb.id}/delete/', **adm_extra)
        self.assertFalse(Mailbox.objects.filter(id=mb.id).exists())

        # Queue, Reports (Track Delivery), Settings (updates Postfix/Rspamd/DKIM)
        self.assertEqual(c_adm.get('/email/queue/', **adm_extra).status_code, 200)
        self.assertEqual(c_adm.post('/email/queue/flush/', **adm_extra).status_code, 302)
        rep_resp = c_adm.get('/email/reports/', **adm_extra)
        self.assertContains(rep_resp, 'Track Delivery Log')

        c_adm.post('/email/settings/', {
            'smtp_port': '587',
            'spam_filter': 'rspamd',
            'spam_threshold': '5.0',
            'dkim_enabled': 'on',
        }, **adm_extra)
        self.assertEqual(SystemSetting.get('email_spam_threshold'), '5.0')
        self.assertIn('add_header = 5.0;', (Path(os.environ['W3PANEL_RSPAMD_DIR']) / 'actions.conf').read_text())

        # Service Manager streaming install supports snappymail and postfix/dovecot
        with patch.dict(os.environ, {'W3PANEL_WEBMAIL_SKIP_DOWNLOAD': '1'}), \
             patch('services.mail.manager.shutil.which', return_value=None):
            sm_stream = c_adm.post('/services/install-stream/', {'service': 'snappymail'}, **adm_extra)
            self.assertEqual(sm_stream.status_code, 200)
            self.assertIn('"status": "complete"', b''.join(sm_stream.streaming_content).decode())

        with patch('apps.admin.views._stream_cmd', return_value=iter(['>> installed postfix'])), \
             patch('apps.admin.views._run_privileged', return_value=MagicMock(returncode=0)):
            pf_stream = c_adm.post('/services/install-stream/', {'service': 'postfix'}, **adm_extra)
            self.assertEqual(pf_stream.status_code, 200)
            self.assertIn('"status": "complete"', b''.join(pf_stream.streaming_content).decode())

    # -----------------------------------------------------------------------
    # 3. Clientpanel (User) Views & REST API Tests
    # -----------------------------------------------------------------------

    def test_user_emails_full_lifecycle_and_ownership(self):
        c_usr, usr_extra = self._login_user(port='2083')

        resp = c_usr.get('/emails/', **usr_extra)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.website.domain)
        self.assertContains(resp, 'panel.myclientdomain.com')
        self.assertNotContains(resp, 'mail.yourdomain.com')

        c_usr.post('/emails/', {
            'action': 'create_mailbox',
            'username': 'sales',
            'domain': self.website.domain,
            'password': 'ClientSecret123!',
            'quota': '1024',
        }, **usr_extra)
        mb = Mailbox.objects.get(owner=self.user, email=f'sales@{self.website.domain}')

        c_usr.post(f'/emails/{mb.id}/password/', {'password': 'NewClientSecret456!', 'quota': '2048'}, **usr_extra)
        mb.refresh_from_db()
        self.assertEqual(mb.quota_mb, 2048)

        c_usr.post('/emails/', {
            'action': 'create_autoresponder',
            'ar_user': 'sales',
            'ar_domain': self.website.domain,
            'ar_interval': '24',
            'ar_subject': 'OOO',
            'ar_body': 'Away.',
        }, **usr_extra)
        ar = EmailAutoresponder.objects.get(owner=self.user, email=mb.email)

        c_usr.post('/emails/', {
            'action': 'set_catchall',
            'catchall_domain': self.website.domain,
            'catchall_action': 'forward',
            'catchall_destination': mb.email,
        }, **usr_extra)
        self.assertTrue(EmailCatchAll.objects.filter(owner=self.user, domain=self.website.domain).exists())

        # Deliverability repair on own domain succeeds; another user's domain 404s
        self.assertEqual(c_usr.post('/emails/deliverability/repair/', {'domain': self.website.domain}, **usr_extra).status_code, 302)
        self.assertEqual(c_usr.post('/emails/deliverability/repair/', {'domain': self.other_website.domain}, **usr_extra).status_code, 404)

        # Ownership enforcement on unowned domain/mailbox/autoresponder
        c_usr.post('/emails/', {
            'action': 'set_catchall',
            'catchall_domain': self.other_website.domain,
            'catchall_action': 'forward',
            'catchall_destination': mb.email,
        }, **usr_extra)
        self.assertFalse(EmailCatchAll.objects.filter(domain=self.other_website.domain).exists())

        other_mb = Mailbox.objects.create(owner=self.other_user, email=f'victim@{self.other_website.domain}', domain=self.other_website.domain, quota_mb=1024)
        self.assertEqual(c_usr.post(f'/emails/{other_mb.id}/delete/', **usr_extra).status_code, 404)

        c_usr.post(f'/emails/autoresponders/{ar.id}/delete/', **usr_extra)
        self.assertFalse(EmailAutoresponder.objects.filter(id=ar.id).exists())
        c_usr.post(f'/emails/{mb.id}/delete/', **usr_extra)
        self.assertFalse(Mailbox.objects.filter(id=mb.id).exists())

    def test_user_email_package_limit_enforced(self):
        c_usr, usr_extra = self._login_user(port='2083')
        for idx in (1, 2, 3):
            c_usr.post('/emails/', {
                'action': 'create_mailbox',
                'username': f'box{idx}',
                'domain': self.website.domain,
                'password': f'Pass{idx}!',
                'quota': '512',
            }, **usr_extra)
        self.assertEqual(Mailbox.objects.filter(owner=self.user).count(), 2)
        self.assertFalse(Mailbox.objects.filter(email=f'box3@{self.website.domain}').exists())

    def test_rest_api_emails_create_with_password_and_delete(self):
        raw_token = 'w3p_mail_api_tok_123'
        APIToken.objects.create(user=self.user, name='Mail Token', token_hash=hashlib.sha256(raw_token.encode()).hexdigest())
        headers = {'HTTP_AUTHORIZATION': f'Bearer {raw_token}'}

        # Cannot create mailbox on another user's domain
        bad_res = self.client.post(
            '/api/v1/emails/',
            data=json.dumps({'username': 'evil', 'domain': self.other_website.domain, 'password': 'Pass123!'}),
            content_type='application/json',
            **headers,
        )
        self.assertEqual(bad_res.status_code, 403)

        ok_res = self.client.post(
            '/api/v1/emails/',
            data=json.dumps({'username': 'api', 'domain': self.website.domain, 'password': 'ApiPassword123!', 'quota_mb': 1536}),
            content_type='application/json',
            **headers,
        )
        self.assertEqual(ok_res.status_code, 201)
        self.assertIn(f'api@{self.website.domain}:', (Path(os.environ['W3PANEL_DOVECOT_DIR']) / 'users').read_text())

        del_res = self.client.delete(f'/api/v1/emails/?id={ok_res.json()["id"]}', **headers)
        self.assertEqual(del_res.status_code, 200)
        self.assertFalse(Mailbox.objects.filter(email=f'api@{self.website.domain}').exists())

    def test_snappymail_proxy_forwards_x_sm_token_and_wizard_wires_snappymail(self):
        # 1. SnappyMail JSON CSRF header X-SM-Token must be forwarded through proxy_http_upstream
        (Path(os.environ['W3PANEL_WEBMAIL_DIR']) / 'index.php').parent.mkdir(parents=True, exist_ok=True)
        (Path(os.environ['W3PANEL_WEBMAIL_DIR']) / 'index.php').write_text('<?php echo "ok"; ?>')
        c_usr, usr_extra = self._login_user()

        class _ProxyHeaders(list):
            def get_all(self, name):
                return []

        proxy_resp = MagicMock(status=200, headers=_ProxyHeaders())
        proxy_resp.read.return_value = b'{"Action":"Login","Result":true}'
        fake_conn = MagicMock()
        fake_conn.getresponse.return_value = proxy_resp

        with patch('services.database.manager.http.client.HTTPConnection', return_value=fake_conn):
            res = c_usr.post(
                '/snappymail/?/Json/',
                data=b'{"Action":"Login"}',
                content_type='application/json',
                HTTP_X_SM_TOKEN='sm_csrf_abc',
                **usr_extra,
            )
            self.assertEqual(res.status_code, 200)
            sent_headers = fake_conn.request.call_args.kwargs['headers']
            self.assertEqual(sent_headers.get('X-SM-Token'), 'sm_csrf_abc')

        # 2. Wizard _prepare_wizard_setup & admin_wizard_provision wire dovecot-managesieved and install_snappymail
        from django.test import RequestFactory
        from apps.admin.views import _prepare_wizard_setup, admin_wizard_provision
        rf = RequestFactory()
        req = rf.post('/wizards/provision/', {
            'server_hostname': 'panel.myclientdomain.com',
            'server_ip': '203.0.113.10',
            'primary_ns': 'ns1.myclientdomain.com',
            'secondary_ns': 'ns2.myclientdomain.com',
            'admin_email': 'admin@myclientdomain.com',
            'webserver_choice': 'nginx',
            'default_php': '8.3',
            'enable_mail': '1',
            'enable_dkim': '1',
            'enable_snappymail': '1',
            'spam_filter': 'rspamd',
        })
        stack_mock = {
            'webserver_nginx': {'installed': True, 'active': True},
            'webserver_apache': {'installed': False, 'active': False},
            'db_mariadb': {'installed': True, 'active': True},
            'db_postgresql': {'installed': False, 'active': False},
            'container_podman': {'installed': False, 'active': False},
            'mail_postfix': {'installed': False, 'active': False},
            'mail_dovecot': {'installed': False, 'active': False},
            'ftp_pureftpd': {'installed': False, 'active': False},
        }
        pkgs, _, opts = _prepare_wizard_setup(req.POST, stack_mock, mark_completed=False)
        self.assertIn('dovecot-managesieved', pkgs)
        self.assertTrue(opts['enable_snappymail'])

        c_adm, adm_extra = self._login_admin()
        with patch('apps.admin.views.get_server_stack_status', return_value={
                 **stack_mock,
                 'mail_postfix': {'installed': True, 'active': True},
             }), \
             patch('apps.admin.views._stream_cmd', return_value=iter([])), \
             patch('apps.admin.views._run_privileged', return_value=MagicMock(returncode=0)), \
             patch('services.mail.install_snappymail', return_value={'success': True, 'path': '/var/lib/w3panel/webmail'}) as sm_mock, \
             patch('services.mail.configure_mail_stack', return_value={'success': True}):
            prov = c_adm.post('/wizards/provision/', {
                'server_hostname': 'panel.myclientdomain.com',
                'server_ip': '203.0.113.10',
                'primary_ns': 'ns1.myclientdomain.com',
                'secondary_ns': 'ns2.myclientdomain.com',
                'admin_email': 'admin@myclientdomain.com',
                'webserver_choice': 'nginx',
                'default_php': '8.3',
                'enable_mail': '1',
                'enable_dkim': '1',
                'enable_snappymail': '1',
                'spam_filter': 'none',
            }, **adm_extra)
            body = b''.join(prov.streaming_content).decode()
            self.assertTrue(sm_mock.called)
            self.assertIn('SnappyMail Webmail configured', body)

    def test_resolve_dir_and_mail_unit_dispatch(self):
        from services.mail.manager import _control_mail_service, _resolve_dir, _resolve_mail_unit
        fake_root = self.temp_dir / 'priv_parent'
        fake_root.mkdir(parents=True, exist_ok=True)
        target = fake_root / 'vmail_new'
        with patch('services.mail.manager._has_sudo', return_value=True), \
             patch('services.mail.manager.os.geteuid', return_value=1000), \
             patch('services.mail.manager.os.access', return_value=False), \
             patch('services.mail.manager._mkdir_privileged', return_value=True) as mk_mock:
            res = _resolve_dir('W3PANEL_UNSET_DIR_CHECK', target, self.temp_dir / 'fallback')
            self.assertEqual(res, target)
            mk_mock.assert_called_once_with(target)

        with patch('services.mail.manager.shutil.which', return_value='/usr/bin/systemctl'), \
             patch('services.mail.manager.subprocess.run', return_value=MagicMock(returncode=0)):
            self.assertEqual(_resolve_mail_unit('postfix'), 'postfix@-')

        with patch('services.mail.manager._has_sudo', return_value=True), \
             patch('services.mail.manager.shutil.which', side_effect=lambda c: '/usr/bin/systemctl' if c == 'systemctl' else None), \
             patch('services.mail.manager.subprocess.run', side_effect=[
                 MagicMock(returncode=0, stdout='activating\n'),
                 MagicMock(returncode=0, stdout=''),
             ]) as sub_mock:
            ok = _control_mail_service('opendkim', 'restart', allow_inactive_restart=True)
            self.assertTrue(ok)
            self.assertEqual(sub_mock.call_args_list[1].args[0], ['sudo', '-n', 'systemctl', 'restart', 'opendkim'])
