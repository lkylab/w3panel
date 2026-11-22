"""
W3Panel v2 — W3Packager & Provisioning Engine Test Suite
Tests sequential EasyApache 4 parity steps, diff calculations,
domain lock safety checks, and SSE live log streaming during provisioning.
"""
import json
from unittest.mock import patch
from django.test import TestCase, Client
from packages.core.models import User, Website, Package, SystemSetting


class W3PackagerTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user('packager_admin', 'admin@packager.local', 'AdminPass123!', role='admin')
        # Configure admin session
        session = self.client.session
        session['user_id'] = self.admin.id
        session['username'] = self.admin.username
        session['role'] = 'admin'
        session.save()

    def test_w3packager_view_renders_correctly(self):
        """Verify W3Packager loads with terminal diff and provisioning containers."""
        response = self.client.get('/software/w3packager/')
        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertIn('Package Selection Manifest (EasyApache 4 Diff)', content)
        self.assertIn('W3Packager Provisioning Console (APT Transaction Stream)', content)
        self.assertIn('startProvisioning()', content)
        self.assertIn('toInstallList', content)
        self.assertIn('toUninstallList', content)

    @patch('apps.admin.views.get_installed_php_versions', return_value=['8.3'])
    @patch('apps.admin.views.get_installed_dpkg_packages', return_value=['nginx', 'php8.3-fpm', 'php8.3-curl'])
    @patch('apps.admin.views.get_available_apt_packages', return_value=['libnginx-mod-http-brotli-filter'])
    @patch('apps.admin.views.subprocess.run')
    def test_provision_stream_endpoint(self, mock_sub, mock_avail, mock_pkgs, mock_vers):
        """Verify streaming provisioning endpoint streams SSE events and completes."""
        payload = {
            'selected_runtimes': ['8.3', '8.4'],
            'selected_extensions': ['php8.3-curl', 'php8.4-curl'],
            'selected_web': ['nginx', 'brotli'],
            'selected_cli': ['composer'],
            'save_profile_name': 'Automated CI Profile',
        }

        response = self.client.post(
            '/software/w3packager/provision/',
            data=json.dumps(payload),
            content_type='application/json',
            HTTP_ACCEPT='text/event-stream'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/event-stream')
        self.assertEqual(response['X-Accel-Buffering'], 'no')

        # Consume stream
        stream_chunks = [chunk.decode('utf-8') for chunk in response.streaming_content]
        full_stream = "".join(stream_chunks)

        self.assertIn('Initializing W3Packager Provisioning Engine', full_stream)
        self.assertIn('PROVISION_COMPLETE', full_stream)
        self.assertIn('Stack Provisioning Completed Successfully!', full_stream)

        # Verify profile was saved
        saved_raw = SystemSetting.get('w3packager_saved_profiles', '[]')
        saved_profiles = json.loads(saved_raw)
        self.assertTrue(any(p.get('name') == 'Automated CI Profile' for p in saved_profiles))

    @patch('apps.admin.views.get_installed_php_versions', return_value=['8.1', '8.3'])
    @patch('apps.admin.views.get_installed_dpkg_packages', return_value=['nginx', 'php8.1-fpm', 'php8.3-fpm'])
    def test_domain_lock_prevents_removal_in_stream(self, mock_pkgs, mock_vers):
        """Ensure active website on PHP 8.1 halts removal with fatal error in SSE stream."""
        pkg = Package.objects.create(name='TestPlan', websites_limit=5, disk_limit_mb=1000)
        Website.objects.create(domain='locked-site.test', owner=self.admin, package=pkg, php_version='8.1')

        # Payload tries to keep only 8.3, removing 8.1
        payload = {
            'selected_runtimes': ['8.3'],
            'selected_extensions': [],
            'selected_web': ['nginx'],
            'selected_cli': [],
        }

        response = self.client.post(
            '/software/w3packager/provision/',
            data=json.dumps(payload),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        stream_content = "".join([c.decode('utf-8') for c in response.streaming_content])
        self.assertIn('FATAL', stream_content)
        self.assertIn('Cannot remove PHP 8.1: Currently used by 1 domain(s)', stream_content)
        self.assertNotIn('PROVISION_COMPLETE', stream_content)
