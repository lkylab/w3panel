"""
W3Panel v2 — Admin Views
Complete administration interface implementations.
"""
import os
import shutil
import psutil
import platform
import subprocess
import logging
from pathlib import Path
from django.db.models import Q
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.conf import settings

from packages.core.models import (
    User, Website, Package, SystemSetting, AuditLog, Notification,
    Database, Mailbox, DNSRecord, FTPAccount, CronJob, Backup, FirewallRule, APIToken
)
from packages.plugins.manager import PluginManager

logger = logging.getLogger('w3panel.admin')


def _sidebar_context(active_page=''):
    """Build sidebar navigation data matching OpenPanel reference."""
    unread_count = Notification.objects.filter(is_read=False).count()
    return {
        'active_page': active_page,
        'unread_notifications_count': unread_count,
        'sidebar_accounts': [
            {'label': 'List Accounts', 'url': '/users/', 'active': 'users'},
            {'label': 'Create a New Account', 'url': '/users/create/', 'active': 'user_create'},
            {'label': 'Resellers', 'url': '/resellers/', 'active': 'resellers'},
            {'label': 'Administrators', 'url': '/administrators/', 'active': 'administrators'},
        ],
        'sidebar_plans': [
            {'label': 'Hosting Packages', 'url': '/plans/', 'active': 'plans'},
        ],
        'sidebar_domains': [
            {'label': 'DNS Zone Editor', 'url': '/domains/dns/', 'active': 'dns'},
            {'label': 'DNS Cluster', 'url': '/domains/dns-cluster/', 'active': 'dns-cluster'},
        ],
        'sidebar_services': [
            {'label': 'Service Manager', 'url': '/services/', 'active': 'services'},
            {'label': 'System Monitoring', 'url': '/monitoring/', 'active': 'monitoring'},
            {'label': 'Terminal Console', 'url': '/terminal/', 'active': 'terminal'},
            {'label': 'Cron Jobs & Tasks', 'url': '/services/cron/', 'active': 'cron'},
            {'label': 'System Logs', 'url': '/services/logs/', 'active': 'logs'},
        ],
        'sidebar_settings': [
            {'label': 'Basic WebHost Setup', 'url': '/settings/', 'active': 'settings'},
            {'label': 'Initial Setup Wizard', 'url': '/wizards/', 'active': 'wizards'},
            {'label': 'MultiPHP Manager', 'url': '/settings/php/', 'active': 'php'},
            {'label': 'API Access', 'url': '/settings/api/', 'active': 'api'},
        ],
        'sidebar_security': [
            {'label': 'Firewall Manager', 'url': '/security/firewall/', 'active': 'firewall'},
            {'label': 'Two-Factor Auth', 'url': '/security/2fa/', 'active': '2fa'},
        ],
    }


# ===========================================================================
# 1. Auth & Dashboard
# ===========================================================================

def admin_login(request):
    """Admin login page (W3Host Manager style)."""
    if request.method == 'POST':
        from packages.core.auth import authenticate_user, create_session
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        
        try:
            user, is_2fa_required = authenticate_user(username, password, request.META.get('REMOTE_ADDR', ''))
            if user.role not in ('admin', 'reseller'):
                return render(request, 'login.html', {'error': 'Administrator / Reseller access only on W3Host Manager (port 2087).', 'username': username, 'panel_type': 'host'})
            
            create_session(request, user)
            return redirect('admin_dashboard')
        except ValueError as e:
            return render(request, 'login.html', {'error': str(e), 'username': username, 'panel_type': 'host'})
    
    return render(request, 'login.html', {'panel_type': 'host'})


def admin_logout(request):
    """Admin logout."""
    from packages.core.auth import destroy_session
    destroy_session(request)
    return redirect('admin_login')


def admin_dashboard(request):
    """Admin dashboard."""
    stats = {
        'users': User.objects.filter(is_active=True).count(),
        'packages': Package.objects.count(),
        'websites': Website.objects.filter(is_active=True).count(),
        'databases': Database.objects.count(),
        'plugins': len(PluginManager().list_plugins()),
    }
    
    cpu_percent = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    load = psutil.getloadavg()
    
    metrics = {
        'cpu': round(cpu_percent, 1),
        'ram_used': round(ram.used / (1024 * 1024)),
        'ram_total': round(ram.total / (1024 * 1024)),
        'ram_percent': round(ram.percent, 1),
        'disk_used': round(disk.used / (1024 ** 3), 1),
        'disk_total': round(disk.total / (1024 ** 3), 1),
        'disk_percent': round(disk.percent, 1),
        'load': round(load[0], 2),
        'load5': round(load[1], 2),
        'load15': round(load[2], 2),
    }
    
    activity_logs = AuditLog.objects.select_related('user').all()[:10]
    
    os_name = platform.system()
    try:
        with open('/etc/os-release') as f:
            for line in f:
                if line.startswith('PRETTY_NAME='):
                    os_name = line.split('=', 1)[1].strip().strip('"')
                    break
    except Exception:
        os_name = f"{platform.system()} {platform.release()}"

    system = {
        'hostname': platform.node(),
        'kernel': platform.release(),
        'os': os_name,
        'python_version': platform.python_version(),
        'django_version': '4.2',
        'podman_version': _get_podman_version(),
    }
    
    license_tier = SystemSetting.get('license_tier', 'free')
    
    return render(request, 'admin/dashboard.html', {
        **_sidebar_context('dashboard'),
        'stats': stats,
        'metrics': metrics,
        'activity_logs': activity_logs,
        'system': system,
        'license_tier': license_tier,
        'panel_version': getattr(settings, 'W3PANEL_VERSION', '2.0.0'),
    })


# ===========================================================================
# 2. Accounts (Users, Resellers, Administrators)
# ===========================================================================

def admin_users(request):
    """List standard users."""
    users = User.objects.filter(role='user').select_related('package')
    return render(request, 'admin/users.html', {
        **_sidebar_context('users'),
        'users': users,
        'account_type': 'User',
    })


def admin_user_create(request):
    """Create user, with optional primary domain auto-provisioning."""
    packages = Package.objects.all()
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        domain = request.POST.get('domain', '').strip().lower()
        package_id = request.POST.get('package')
        role = request.POST.get('role', 'user')
        shell_enabled = request.POST.get('shell_enabled') in ('1', 'true', 'on')

        # Restrict allowed roles for hosting account creation (admins are created via /administrators/)
        current_admin = getattr(request, 'panel_user', None)
        if current_admin and current_admin.role == 'admin':
            allowed_roles = ('user', 'reseller')
        else:
            allowed_roles = ('user',)
        if role not in allowed_roles:
            role = 'user'

        parent_reseller = current_admin if current_admin and current_admin.role == 'reseller' else None
        
        if username and password:
            if User.objects.filter(username=username).exists():
                messages.error(request, f'Username "{username}" already exists.')
            elif domain and Website.objects.filter(domain=domain).exists():
                messages.error(request, f'Domain "{domain}" is already registered.')
            else:
                pkg = Package.objects.filter(id=package_id).first() if package_id else None
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    role=role,
                    package=pkg,
                    parent_reseller=parent_reseller,
                    shell_enabled=shell_enabled
                )

                # Sync Linux system password & shell
                from services.webserver import sync_system_user_shell, sync_system_user_password
                sync_system_user_shell(user.username, shell_enabled)
                sync_system_user_password(user.username, password)
                
                # If optional primary domain is provided, provision website immediately
                if domain:
                    doc_root = f"/home/{user.username}/{domain}/public_html"
                    site = Website.objects.create(
                        owner=user,
                        domain=domain,
                        doc_root=doc_root,
                        framework='none',
                        php_version='8.3',
                    )
                    DNSRecord.objects.create(domain=site, record_type='A', name='@', value='127.0.0.1')
                    DNSRecord.objects.create(domain=site, record_type='CNAME', name='www', value=domain)
                    try:
                        from services.webserver import create_vhost
                        create_vhost(site)
                    except Exception as e:
                        logger.warning(f"Could not provision vhost for {domain}: {e}")
                    AuditLog.objects.create(user=user, action='website_created', target=domain)
                    messages.success(request, f'{role.capitalize()} "{username}" created with primary site "{domain}".')
                else:
                    try:
                        from services.webserver import create_user_php_pool
                        create_user_php_pool(username=user.username, php_version='8.3')
                    except Exception as e:
                        logger.warning(f"Could not provision PHP pool for {user.username}: {e}")
                    messages.success(request, f'{role.capitalize()} "{username}" created successfully.')

                if role == 'reseller':
                    return redirect('admin_resellers')
                elif role == 'admin':
                    return redirect('admin_administrators')
                return redirect('admin_users')
        else:
            messages.error(request, 'Username and password are required.')

    return render(request, 'admin/user_create.html', {
        **_sidebar_context('users'),
        'packages': packages,
        'default_role': 'user',
    })


def admin_user_edit(request, user_id):
    """Edit user account: email, package, role, password reset, active status, shell access."""
    target_user = get_object_or_404(User, id=user_id)
    packages = Package.objects.all()

    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        package_id = request.POST.get('package')
        role = request.POST.get('role', 'user')
        new_password = request.POST.get('password', '').strip()
        is_active = request.POST.get('is_active') in ('1', 'true', 'on')
        shell_enabled = request.POST.get('shell_enabled') in ('1', 'true', 'on')

        target_user.email = email
        target_user.role = role
        target_user.package = Package.objects.filter(id=package_id).first() if package_id else None

        status_changed = (target_user.is_active != is_active)
        shell_changed = (target_user.shell_enabled != shell_enabled)

        target_user.is_active = is_active
        target_user.shell_enabled = shell_enabled

        if new_password:
            target_user.set_password(new_password)
            from services.webserver import sync_system_user_password
            sync_system_user_password(target_user.username, new_password)

        target_user.save()

        from services.webserver import sync_system_user_shell, sync_system_user_status
        if shell_changed:
            sync_system_user_shell(target_user.username, shell_enabled)
        if status_changed:
            sync_system_user_status(target_user.username, is_active)

        AuditLog.objects.create(
            user=request.panel_user,
            action='user_modified',
            target=target_user.username,
            ip_address=request.META.get('REMOTE_ADDR')
        )
        messages.success(request, f'User "{target_user.username}" updated successfully.')
        if target_user.role == 'reseller':
            return redirect('admin_resellers')
        elif target_user.role == 'admin':
            return redirect('admin_administrators')
        return redirect('admin_users')

    return render(request, 'admin/user_edit.html', {
        **_sidebar_context('users'),
        'target_user': target_user,
        'packages': packages,
    })


def admin_user_toggle_status(request, user_id):
    """Toggle user active / suspended status."""
    if request.method == 'POST':
        target_user = get_object_or_404(User, id=user_id)
        if target_user.username == 'admin' or target_user.id == request.session.get('user_id'):
            messages.error(request, 'Cannot suspend primary administrator account.')
        else:
            target_user.is_active = not target_user.is_active
            target_user.save(update_fields=['is_active'])
            from services.webserver import sync_system_user_status
            sync_system_user_status(target_user.username, target_user.is_active)
            status_str = "activated" if target_user.is_active else "suspended"
            messages.success(request, f'User "{target_user.username}" {status_str}.')
    return redirect('admin_users')


def admin_user_toggle_shell(request, user_id):
    """Toggle user SSH / Terminal shell permission."""
    if request.method == 'POST':
        target_user = get_object_or_404(User, id=user_id)
        target_user.shell_enabled = not target_user.shell_enabled
        target_user.save(update_fields=['shell_enabled'])
        from services.webserver import sync_system_user_shell
        sync_system_user_shell(target_user.username, target_user.shell_enabled)
        state_str = "enabled" if target_user.shell_enabled else "disabled"
        messages.success(request, f'Terminal access {state_str} for "{target_user.username}".')
    return redirect('admin_users')


def admin_user_autologin(request, user_id):
    """W3Host-style 1-click autologin into W3Client Portal in a new tab."""
    admin_user = getattr(request, 'panel_user', None)
    if not admin_user:
        uid = request.session.get('user_id')
        if uid:
            admin_user = User.objects.filter(pk=uid, is_active=True).first()

    if not admin_user or admin_user.role not in ('admin', 'reseller'):
        messages.error(request, 'Unauthorized: Administrator access required.')
        return redirect('admin_login')

    target_user = get_object_or_404(User, id=user_id)

    # If reseller, restrict to accounts under their delegation
    if admin_user.role == 'reseller' and target_user.parent_reseller_id != admin_user.id and target_user.id != admin_user.id:
        messages.error(request, 'Permission denied: Cannot access accounts outside your reseller scope.')
        return redirect('admin_users')

    from packages.core.models import LoginToken
    token_obj = LoginToken.create_for_user(target_user, created_by=admin_user, validity_seconds=120)

    host = request.get_host()
    scheme = 'https' if request.is_secure() or request.META.get('HTTP_X_FORWARDED_PROTO') == 'https' else (request.scheme or 'http')

    if ':12087' in host:
        user_host = host.replace(':12087', ':12083')
    elif ':2087' in host:
        user_host = host.replace(':2087', ':2083')
    elif ':' in host:
        # Development / custom port (e.g. localhost:8000)
        user_host = host
    else:
        server_port = request.META.get('SERVER_PORT', '')
        if server_port in ('2087', '12087'):
            user_host = f"{host}:2083"
        else:
            user_host = host

    sso_url = f"{scheme}://{user_host}/sso/?token={token_obj.token}"
    return redirect(sso_url)


# Alias for backward compatibility
admin_user_impersonate = admin_user_autologin


def admin_terminal(request):
    """Admin Web Terminal Console."""
    server_ip = request.META.get('SERVER_NAME', '127.0.0.1')
    return render(request, 'admin/terminal.html', {
        **_sidebar_context('terminal'),
        'active_section': 'services',
        'server_ip': server_ip,
    })


def admin_terminal_exec(request):
    """Execute command in admin context."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)

    cmd = request.POST.get('command', '').strip()
    if not cmd:
        return JsonResponse({'stdout': '', 'stderr': '', 'returncode': 0})

    blocked = ['rm -rf /', 'mkfs', ':(){ :|:& };:']
    if any(b in cmd for b in blocked):
        return JsonResponse({'stderr': 'Command blocked by safety filter.', 'returncode': 1})

    try:
        from services.webserver.manager import _has_sudo
        if _has_sudo():
            run_cmd = ['sudo', '-n', 'bash', '-c', cmd]
        else:
            run_cmd = ['bash', '-c', cmd]

        res = subprocess.run(run_cmd, capture_output=True, text=True, timeout=20)
        return JsonResponse({
            'stdout': res.stdout,
            'stderr': res.stderr,
            'returncode': res.returncode,
            'cwd': '/root',
        })
    except subprocess.TimeoutExpired:
        return JsonResponse({'stderr': 'Command execution timed out after 20 seconds.', 'returncode': 124})
    except Exception as e:
        return JsonResponse({'stderr': str(e), 'returncode': 1})


def admin_user_delete(request, user_id):
    """Delete a user and clean up their tenant resources."""
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        if user.username == 'admin' or user.id == request.session.get('user_id'):
            messages.error(request, 'You cannot delete the primary admin account.')
        else:
            username = user.username
            role = user.role
            try:
                from services.webserver import remove_user_php_pool
                remove_user_php_pool(username=username)
            except Exception as e:
                logger.warning(f"Could not remove PHP pool for {username}: {e}")
            user.delete()
            messages.success(request, f'Account "{username}" has been deleted.')
            if role == 'reseller':
                return redirect('admin_resellers')
            elif role == 'admin':
                return redirect('admin_administrators')
    return redirect('admin_users')


def admin_resellers(request):
    """List resellers."""
    resellers = User.objects.filter(role='reseller')
    return render(request, 'admin/resellers.html', {
        **_sidebar_context('resellers'),
        'resellers': resellers,
    })


def admin_administrators(request):
    """List and create administrators."""
    admin_user = getattr(request, 'panel_user', None)
    if not admin_user or admin_user.role != 'admin':
        messages.error(request, 'Unauthorized: Administrator access required.')
        return redirect('admin_dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()

        if not username or not password:
            messages.error(request, 'Username and password are required.')
        elif User.objects.filter(username=username).exists():
            messages.error(request, f'Username "{username}" already exists.')
        else:
            User.objects.create_user(
                username=username,
                email=email,
                password=password,
                role='admin'
            )
            messages.success(request, f'Administrator "{username}" created successfully.')
            return redirect('admin_administrators')

    admins = User.objects.filter(role='admin')
    return render(request, 'admin/administrators.html', {
        **_sidebar_context('administrators'),
        'administrators': admins,
    })


# ===========================================================================
# 3. Hosting Plans & Feature Manager
# ===========================================================================

def admin_plans(request):
    """List and create hosting plans."""
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        websites_limit = int(request.POST.get('websites_limit', 5))
        databases_limit = int(request.POST.get('databases_limit', 5))
        ftp_limit = int(request.POST.get('ftp_limit', 5))
        email_limit = int(request.POST.get('email_limit', 10))
        disk_limit_mb = int(request.POST.get('disk_limit_mb', 10240))
        bandwidth_limit_gb = int(request.POST.get('bandwidth_limit_gb', 100))

        if name:
            Package.objects.create(
                name=name,
                description=description,
                websites_limit=websites_limit,
                databases_limit=databases_limit,
                ftp_limit=ftp_limit,
                email_limit=email_limit,
                disk_limit_mb=disk_limit_mb,
                bandwidth_limit_gb=bandwidth_limit_gb
            )
            messages.success(request, f'Package "{name}" created successfully.')
            return redirect('admin_plans')

    plans = Package.objects.all()
    return render(request, 'admin/plans.html', {
        **_sidebar_context('plans'),
        'plans': plans,
    })


def admin_plan_delete(request, plan_id):
    """Delete package plan."""
    if request.method == 'POST':
        plan = get_object_or_404(Package, id=plan_id)
        name = plan.name
        plan.delete()
        messages.success(request, f'Package "{name}" deleted successfully.')
    return redirect('admin_plans')


def admin_features(request):
    """Legacy Feature Manager redirects to Hosting Packages."""
    return redirect('admin_plans')


# ===========================================================================
# 4. Domains, DNS & Websites
# ===========================================================================

def admin_websites(request):
    """Websites and domains are managed per account inside W3Client Portal (Port 2083)."""
    messages.info(request, "Websites and domains are managed per account inside W3Client Portal. Click 'W3Client' next to any account to manage their websites.")
    return redirect('admin_users')



def admin_website_toggle_proxy(request, website_id):
    """Toggle Reverse Proxy Real-IP setting for a website."""
    if request.method == 'POST':
        site = get_object_or_404(Website, id=website_id)
        site.proxy_real_ip = not site.proxy_real_ip
        site.save(update_fields=['proxy_real_ip'])
        from services.webserver import create_vhost
        create_vhost(site)
        state = "enabled (Cloudflare/Proxy mode)" if site.proxy_real_ip else "disabled (Direct traffic mode)"
        messages.success(request, f'Reverse Proxy Client IP {state} for {site.domain}.')
    return redirect('admin_websites')


def admin_website_delete(request, website_id):
    """Delete a website."""
    if request.method == 'POST':
        site = get_object_or_404(Website, id=website_id)
        domain = site.domain
        from services.webserver import remove_vhost
        remove_vhost(domain)
        site.delete()
        messages.success(request, f'Domain "{domain}" and its VirtualHost configuration were removed.')
    return redirect('admin_websites')


def admin_website_vhost(request, website_id):
    """Host VirtualHost (Nginx configuration) editor with safety check and rollback."""
    site = get_object_or_404(Website, id=website_id)
    from services.webserver import get_vhost_content, save_custom_vhost, reset_vhost_to_default

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'save_vhost':
            content = request.POST.get('vhost_content', '')
            res = save_custom_vhost(site, content)
            if res.get('success'):
                messages.success(request, f'VirtualHost configuration for {site.domain} updated and validated successfully.')
                return redirect('admin_website_vhost', website_id=site.id)
            else:
                messages.error(request, f"Configuration Error: {res.get('error')}")
        elif action == 'reset_vhost':
            reset_vhost_to_default(site)
            messages.success(request, f'VirtualHost configuration for {site.domain} reset to default template.')
            return redirect('admin_website_vhost', website_id=site.id)

    vhost_content = get_vhost_content(site)
    return render(request, 'admin/website_vhost.html', {
        **_sidebar_context('websites'),
        'site': site,
        'vhost_content': vhost_content,
        'is_nginx_installed': bool(shutil.which('nginx')),
    })


def admin_dns_editor(request):
    """DNS Zone Editor."""
    websites = Website.objects.prefetch_related('dns_records').all()
    selected_domain_id = request.GET.get('domain_id')
    selected_domain = None
    records = []

    if selected_domain_id:
        selected_domain = Website.objects.filter(id=selected_domain_id).first()
    elif websites.exists():
        selected_domain = websites.first()

    if selected_domain:
        records = selected_domain.dns_records.all()

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'add_record' and selected_domain:
            rtype = request.POST.get('record_type', 'A')
            name = request.POST.get('name', '@').strip()
            value = request.POST.get('value', '').strip()
            ttl = int(request.POST.get('ttl', 3600))
            priority = request.POST.get('priority')
            priority_val = int(priority) if priority and priority.isdigit() else None
            if value:
                DNSRecord.objects.create(
                    domain=selected_domain,
                    record_type=rtype,
                    name=name,
                    value=value,
                    ttl=ttl,
                    priority=priority_val
                )
                from services.dns import export_zone_file
                export_zone_file(selected_domain.domain, selected_domain.dns_records.all())
                messages.success(request, f'DNS Record {name} {rtype} added and zone exported.')
                return redirect(f'/domains/dns/?domain_id={selected_domain.id}')

        elif action == 'delete_record':
            record_id = request.POST.get('record_id')
            DNSRecord.objects.filter(id=record_id).delete()
            if selected_domain:
                from services.dns import export_zone_file
                export_zone_file(selected_domain.domain, selected_domain.dns_records.all())
            messages.success(request, 'DNS record deleted and zone updated.')
            return redirect(f'/domains/dns/?domain_id={selected_domain.id if selected_domain else ""}')

    return render(request, 'admin/dns_editor.html', {
        **_sidebar_context('dns'),
        'websites': websites,
        'selected_domain': selected_domain,
        'records': records,
    })


def admin_dns_cluster(request):
    """DNS Cluster Configuration."""
    return render(request, 'admin/dns_cluster.html', {
        **_sidebar_context('dns-cluster'),
    })


# ===========================================================================
# 5. Services & Core Manager
# ===========================================================================

def admin_plugins(request):
    """Plugin management page."""
    manager = PluginManager()
    plugins = manager.list_plugins()
    
    if request.method == 'POST':
        plugin_id = request.POST.get('plugin_id')
        action = request.POST.get('action')
        
        if action == 'install':
            result = manager.install(plugin_id)
            if result['success']:
                messages.success(request, f'Plugin {plugin_id} installed successfully')
            else:
                messages.error(request, f'Failed to install plugin: {result["error"]}')
        elif action == 'uninstall':
            result = manager.uninstall(plugin_id)
            if result['success']:
                messages.success(request, f'Plugin {plugin_id} uninstalled successfully')
            else:
                messages.error(request, f'Failed to uninstall plugin: {result["error"]}')
        elif action == 'start':
            result = manager.start(plugin_id)
            if result['success']:
                messages.success(request, f'Plugin {plugin_id} started')
            else:
                messages.error(request, f'Failed to start plugin: {result["error"]}')
        elif action == 'stop':
            result = manager.stop(plugin_id)
            if result['success']:
                messages.success(request, f'Plugin {plugin_id} stopped')
            else:
                messages.error(request, f'Failed to stop plugin: {result["error"]}')
        
        return redirect('admin_plugins')
    
    return render(request, 'admin/plugins.html', {
        **_sidebar_context('plugins'),
        'plugins': plugins,
    })


def admin_services_status(request):
    """Services status and individual 1-click management/installation."""
    if request.method == 'POST':
        service_name = request.POST.get('service')
        action = request.POST.get('action')

        if action == 'install_service' and service_name:
            # Package mapping for individual services
            pkg_map = {
                'nginx': ['nginx'],
                'mariadb': ['mariadb-server', 'mariadb-client'],
                'postgresql': ['postgresql', 'postgresql-contrib'],
                'redis': ['redis-server'],
                'ufw': ['ufw'],
                'php': ['php-fpm', 'php-mysql', 'php-pgsql', 'php-curl', 'php-zip', 'php-gd', 'php-mbstring', 'php-xml'],
                'certbot': ['certbot', 'python3-certbot-nginx'],
            }
            pkgs = pkg_map.get(service_name, [service_name])
            try:
                subprocess.run(['sudo', 'apt-get', 'update', '-y'], timeout=60)
                cmd = ['sudo', 'apt-get', 'install', '-y'] + pkgs
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
                if res.returncode == 0:
                    daemon_name = 'mariadb' if service_name == 'mariadb' else service_name
                    subprocess.run(['sudo', 'systemctl', 'enable', '--now', daemon_name], timeout=10)
                    messages.success(request, f'{service_name.capitalize()} installed and started successfully!')
                else:
                    messages.error(request, f'Installation failed: {res.stderr}')
            except Exception as e:
                messages.error(request, f'Error installing {service_name}: {e}')
            return redirect('admin_services_status')

        elif action == 'uninstall_service' and service_name:
            pkg_map = {
                'nginx': ['nginx', 'nginx-common'],
                'mariadb': ['mariadb-server', 'mariadb-client'],
                'postgresql': ['postgresql', 'postgresql-contrib'],
                'redis': ['redis-server'],
                'ufw': ['ufw'],
            }
            pkgs = pkg_map.get(service_name, [service_name])
            try:
                subprocess.run(['sudo', 'systemctl', 'stop', service_name], timeout=10)
                cmd = ['sudo', 'apt-get', 'remove', '-y'] + pkgs
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if res.returncode == 0:
                    messages.success(request, f'{service_name.capitalize()} uninstalled successfully.')
                else:
                    messages.error(request, f'Uninstall failed: {res.stderr}')
            except Exception as e:
                messages.error(request, f'Error uninstalling {service_name}: {e}')
            return redirect('admin_services_status')

        elif action == 'optimize_database':
            from services.database import apply_database_tuning
            res = apply_database_tuning()
            if res.get('success'):
                messages.success(request, 'MariaDB tuned successfully! Applied skip-name-resolve, low-RAM buffer pool, and performance_schema=OFF.')
            else:
                messages.error(request, 'Failed to apply MariaDB optimization.')
            return redirect('admin_services_status')

        elif action in ('start', 'stop', 'restart') and service_name:
            try:
                subprocess.run(['sudo', '-n', 'systemctl', action, service_name], timeout=10)
                messages.success(request, f'Service {service_name} {action}ed successfully.')
            except Exception as e:
                messages.error(request, f'Error executing {action} on {service_name}: {e}')
            return redirect('admin_services_status')

    from services.database import get_database_tuning_status
    db_tuning = get_database_tuning_status()

    services_list = [
        {'name': 'nginx', 'display': 'Nginx Web Server', 'icon': 'ti ti-world', 'cmd': 'nginx', 'desc': 'High-Performance Web Server for User Websites (Ports 80 & 443)'},
        {'name': 'mariadb', 'display': 'MariaDB Database Server', 'icon': 'ti ti-database', 'cmd': 'mariadbd', 'desc': 'Relational MySQL Database Engine'},
        {'name': 'postgresql', 'display': 'PostgreSQL Database Server', 'icon': 'ti ti-database-import', 'cmd': 'psql', 'desc': 'Advanced Object-Relational SQL Database Engine'},
        {'name': 'php8.3-fpm', 'display': 'PHP-FPM 8.3 Daemon', 'icon': 'ti ti-brand-php', 'cmd': 'php-fpm8.3', 'desc': 'PHP FastCGI Process Manager for VirtualHosts'},
        {'name': 'ufw', 'display': 'UFW Host Firewall', 'icon': 'ti ti-shield', 'cmd': 'ufw', 'desc': 'Host Inbound Access Firewall'},
        {'name': 'ssh', 'display': 'SSH Remote Access', 'icon': 'ti ti-terminal-2', 'cmd': 'sshd', 'desc': 'Secure Shell Remote Administration'},
    ]

    for s in services_list:
        cmd_check = s.get('cmd', s['name'])
        is_installed = bool(shutil.which(cmd_check) or shutil.which(s['name']))
        if not is_installed:
            s['status'] = 'not_installed'
        else:
            try:
                res = subprocess.run(['systemctl', 'is-active', s['name']], capture_output=True, text=True, timeout=2)
                s['status'] = 'running' if res.stdout.strip() == 'active' else 'stopped'
            except Exception:
                s['status'] = 'stopped'

    return render(request, 'admin/services.html', {
        **_sidebar_context('services'),
        'services': services_list,
        'db_tuning': db_tuning,
    })


def admin_ftp_service(request):
    """FTP management."""
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        directory = request.POST.get('directory', '/').strip()
        if username:
            if FTPAccount.objects.filter(username=username).exists():
                messages.error(request, f'FTP username "{username}" already exists.')
            else:
                owner = request.panel_user or User.objects.filter(role='admin').first()
                FTPAccount.objects.create(owner=owner, username=username, directory=directory)
                messages.success(request, f'FTP user "{username}" created.')
                return redirect('admin_ftp_service')

    ftp_accounts = FTPAccount.objects.select_related('owner').all()
    return render(request, 'admin/ftp.html', {
        **_sidebar_context('ftp'),
        'ftp_accounts': ftp_accounts,
    })


def admin_system_logs(request):
    """Log file viewer."""
    log_files = {
        'panel': '/var/log/w3panel/error.log',
        'access': '/var/log/w3panel/access.log',
        'syslog': '/var/log/syslog',
        'auth': '/var/log/auth.log',
    }
    selected_log = request.GET.get('log', 'panel')
    file_path = log_files.get(selected_log, log_files['panel'])
    
    content = ""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', errors='ignore') as f:
                lines = f.readlines()
                content = "".join(lines[-150:])  # last 150 lines
        except Exception as e:
            content = f"Error reading log file: {e}"
    else:
        content = f"Log file {file_path} does not exist yet or is empty."

    return render(request, 'admin/logs.html', {
        **_sidebar_context('logs'),
        'selected_log': selected_log,
        'log_content': content,
    })


def get_root_cron_entries():
    """Retrieve crontab entries for root user."""
    try:
        res = subprocess.run(['sudo', '-n', 'crontab', '-l', '-u', 'root'], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            entries = []
            for line in res.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(None, 5)
                    if len(parts) >= 6:
                        entries.append({
                            'schedule': ' '.join(parts[:5]),
                            'command': parts[5],
                            'raw': line,
                        })
                    else:
                        entries.append({
                            'schedule': 'Custom',
                            'command': line,
                            'raw': line,
                        })
            return entries
    except Exception:
        pass
    return []


def get_system_crontabs():
    """Parse /etc/crontab and files in /etc/cron.d/ into structured entries."""
    system_entries = []
    
    # 1. /etc/crontab
    crontab_file = Path('/etc/crontab')
    if crontab_file.exists():
        try:
            for line in crontab_file.read_text(errors='ignore').splitlines():
                line = line.strip()
                if not line or line.startswith('#') or '=' in line.split()[0]:
                    continue
                parts = line.split(None, 6)
                if len(parts) >= 7:
                    system_entries.append({
                        'source': '/etc/crontab',
                        'file': 'crontab',
                        'schedule': ' '.join(parts[:5]),
                        'user': parts[5],
                        'command': parts[6],
                    })
        except Exception:
            pass

    # 2. /etc/cron.d/*
    cron_d = Path('/etc/cron.d')
    if cron_d.exists():
        try:
            for p in sorted(cron_d.glob('*')):
                if p.is_file() and not p.name.startswith('.'):
                    try:
                        content = p.read_text(errors='ignore')
                        for line in content.splitlines():
                            line = line.strip()
                            if not line or line.startswith('#') or line.startswith(('SHELL=', 'PATH=', 'MAILTO=')):
                                continue
                            parts = line.split(None, 6)
                            if len(parts) >= 7:
                                system_entries.append({
                                    'source': str(p),
                                    'file': p.name,
                                    'schedule': ' '.join(parts[:5]),
                                    'user': parts[5],
                                    'command': parts[6],
                                })
                    except Exception:
                        pass
        except Exception:
            pass

    return system_entries


def get_cron_interval_scripts():
    """List scripts in /etc/cron.daily, /etc/cron.hourly, /etc/cron.weekly, /etc/cron.monthly."""
    intervals = {}
    for name in ('hourly', 'daily', 'weekly', 'monthly'):
        dirpath = Path(f'/etc/cron.{name}')
        scripts = []
        if dirpath.exists():
            try:
                for s in sorted(dirpath.glob('*')):
                    if s.is_file() and not s.name.startswith('.'):
                        scripts.append({
                            'name': s.name,
                            'path': str(s),
                            'executable': os.access(s, os.X_OK),
                            'size': s.stat().st_size,
                        })
            except Exception:
                pass
        intervals[name] = scripts
    return intervals


def admin_cron(request):
    """
    Host Scheduled Tasks & Server Cron Manager.
    Allows inspecting root crontab, filtering by tenant account,
    viewing /etc/crontab & /etc/cron.d/ system tasks, and maintenance intervals.
    """
    from services.cron.manager import sync_cron_jobs
    
    if request.method == 'POST':
        action = request.POST.get('action')
        job_id = request.POST.get('job_id')
        
        if action == 'toggle_status' and job_id:
            job = get_object_or_404(CronJob, id=job_id)
            job.is_active = not job.is_active
            job.save(update_fields=['is_active'])
            sync_cron_jobs(job.owner.username, job.owner.cron_jobs.all())
            state = "activated" if job.is_active else "paused"
            messages.success(request, f'Cron job for {job.owner.username} was {state}.')
            return redirect(f'/services/cron/?user={job.owner.username}')

        elif action == 'delete' and job_id:
            job = get_object_or_404(CronJob, id=job_id)
            owner = job.owner
            job.delete()
            sync_cron_jobs(owner.username, owner.cron_jobs.all())
            messages.success(request, f'Cron job for {owner.username} was permanently deleted.')
            return redirect(f'/services/cron/?user={owner.username}')

        elif action == 'create_cron':
            target_user_str = request.POST.get('target_user', '').strip()
            schedule = request.POST.get('schedule', '').strip() or '0 0 * * *'
            command = request.POST.get('command', '').strip()
            description = request.POST.get('description', '').strip()

            if command:
                if target_user_str in ('root', 'admin'):
                    try:
                        res = subprocess.run(['sudo', '-n', 'crontab', '-l', '-u', 'root'], capture_output=True, text=True, timeout=3)
                        current = res.stdout if res.returncode == 0 else ""
                        new_content = current.rstrip() + f"\n{schedule} {command}\n"
                        proc = subprocess.Popen(['sudo', '-n', 'crontab', '-u', 'root', '-'], stdin=subprocess.PIPE, text=True)
                        proc.communicate(input=new_content, timeout=5)
                        messages.success(request, f'Root crontab entry added: {schedule} {command}')
                        return redirect('/services/cron/?user=root')
                    except Exception as e:
                        messages.error(request, f'Failed to write root crontab: {e}')
                else:
                    target_user = User.objects.filter(username=target_user_str, role__in=['user', 'reseller']).first()
                    if not target_user:
                        target_user = User.objects.filter(role='user').first()
                    
                    if target_user:
                        CronJob.objects.create(
                            owner=target_user,
                            command=command,
                            schedule=schedule,
                            description=description,
                            is_active=True
                        )
                        sync_cron_jobs(target_user.username, target_user.cron_jobs.all())
                        messages.success(request, f'Cron job scheduled for tenant {target_user.username}.')
                        return redirect(f'/services/cron/?user={target_user.username}')
                    else:
                        messages.error(request, 'No valid tenant account found to assign cron job.')
                        return redirect('/services/cron/')

        elif action == 'delete_root_cron':
            raw_entry = request.POST.get('raw_entry', '').strip()
            if raw_entry:
                try:
                    res = subprocess.run(['sudo', '-n', 'crontab', '-l', '-u', 'root'], capture_output=True, text=True, timeout=3)
                    if res.returncode == 0:
                        lines = [l for l in res.stdout.splitlines() if l.strip() != raw_entry]
                        new_content = "\n".join(lines) + "\n"
                        proc = subprocess.Popen(['sudo', '-n', 'crontab', '-u', 'root', '-'], stdin=subprocess.PIPE, text=True)
                        proc.communicate(input=new_content, timeout=5)
                        messages.success(request, 'Root crontab entry removed.')
                except Exception as e:
                    messages.error(request, f'Failed to delete root crontab entry: {e}')
            return redirect('/services/cron/?user=root')

    # GET handling
    selected_user = request.GET.get('user', 'all').strip()
    active_tab = request.GET.get('tab', 'user').strip()
    
    # Filter tenant users only (admin role is the root panel administrator, not a tenant)
    tenant_users = User.objects.filter(role__in=['user', 'reseller']).order_by('username')
    
    # Filter tenant cron jobs (exclude admin from tenant jobs table)
    cron_jobs = CronJob.objects.select_related('owner').filter(owner__role__in=['user', 'reseller']).order_by('-created_at')
    if selected_user and selected_user not in ('all', 'root', 'admin'):
        cron_jobs = cron_jobs.filter(owner__username=selected_user)

    # Fetch root crontab entries
    root_cron_entries = []
    if selected_user in ('all', 'root', 'admin'):
        root_cron_entries = get_root_cron_entries()

    # Parse system crontabs and maintenance intervals
    system_crontabs = get_system_crontabs()
    interval_scripts = get_cron_interval_scripts()

    return render(request, 'admin/cron.html', {
        **_sidebar_context('cron'),
        'users': tenant_users,
        'selected_user': selected_user,
        'active_tab': active_tab,
        'cron_jobs': cron_jobs,
        'root_cron_entries': root_cron_entries,
        'system_crontabs': system_crontabs,
        'interval_scripts': interval_scripts,
    })


# ===========================================================================
# 7. Settings & License
# ===========================================================================

def get_server_public_ip():
    """Detect server public or primary IP address."""
    cached = SystemSetting.get('server_ip', '')
    if cached:
        return cached
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_server_stack_status():
    """Detect presence and active status of all server hosting components."""
    def _check(cmd, service_name=None):
        svc = service_name or cmd
        installed = bool(shutil.which(cmd))
        active = False
        if installed:
            try:
                res = subprocess.run(['systemctl', 'is-active', svc], capture_output=True, text=True, timeout=2)
                active = (res.stdout.strip() == 'active')
            except Exception:
                active = False
        return {'installed': installed, 'active': active}

    return {
        'webserver_nginx': _check('nginx'),
        'webserver_apache': _check('apache2'),
        'db_mariadb': _check('mariadbd', 'mariadb'),
        'db_postgresql': _check('psql', 'postgresql'),
        'mail_postfix': _check('postfix'),
        'mail_dovecot': _check('dovecot'),
        'ftp_pureftpd': _check('pure-ftpd', 'pure-ftpd'),
        'security_ufw': _check('ufw'),
        'php_fpm': _check('php-fpm8.3', 'php8.3-fpm'),
    }


def admin_settings(request):
    """General panel & Basic WebHost settings."""
    if request.method == 'POST':
        panel_name = request.POST.get('panel_name', 'W3Panel').strip()
        server_hostname = request.POST.get('server_hostname', platform.node()).strip()
        server_ip = request.POST.get('server_ip', '').strip()
        primary_ns = request.POST.get('primary_ns', '').strip()
        secondary_ns = request.POST.get('secondary_ns', '').strip()
        admin_email = request.POST.get('admin_email', '').strip()
        default_php = request.POST.get('default_php', '8.3').strip()
        api_rate_limit = request.POST.get('api_rate_limit', '50').strip()
        
        SystemSetting.set('panel_name', panel_name)
        SystemSetting.set('server_hostname', server_hostname)
        if server_ip:
            SystemSetting.set('server_ip', server_ip)
        if primary_ns:
            SystemSetting.set('primary_ns', primary_ns)
        if secondary_ns:
            SystemSetting.set('secondary_ns', secondary_ns)
        if admin_email:
            SystemSetting.set('admin_email', admin_email)
        SystemSetting.set('default_php', default_php)
        SystemSetting.set('api_rate_limit', api_rate_limit)
        
        messages.success(request, 'Basic WebHost settings saved successfully.')
        return redirect('admin_settings')

    detected_ip = get_server_public_ip()
    hostname = SystemSetting.get('server_hostname', platform.node())

    return render(request, 'admin/settings.html', {
        **_sidebar_context('settings'),
        'panel_name': SystemSetting.get('panel_name', 'W3Panel'),
        'server_hostname': hostname,
        'server_ip': SystemSetting.get('server_ip', detected_ip),
        'primary_ns': SystemSetting.get('primary_ns', f'ns1.{hostname}'),
        'secondary_ns': SystemSetting.get('secondary_ns', f'ns2.{hostname}'),
        'admin_email': SystemSetting.get('admin_email', f'admin@{hostname}'),
        'default_php': SystemSetting.get('default_php', '8.3'),
        'api_rate_limit': SystemSetting.get('api_rate_limit', '50'),
        'panel_version': getattr(settings, 'W3PANEL_VERSION', '2.0.0'),
        'initial_completed': SystemSetting.get('initial_setup_completed', 'false') == 'true',
    })


def admin_license(request):
    """License management page."""
    from packages.license.models import License
    license_obj = License.objects.filter(is_active=True).first()
    
    if request.method == 'POST':
        license_key = request.POST.get('license_key', '').strip()
        if license_key:
            from packages.license.service import activate_license
            result = activate_license(license_key)
            if result['success']:
                messages.success(request, 'License activated successfully!')
                return redirect('admin_license')
            else:
                messages.error(request, f'License activation failed: {result["error"]}')
    
    return render(request, 'admin/license.html', {
        **_sidebar_context('license'),
        'license': license_obj,
        'tier': license_obj.tier if license_obj else 'free',
    })


def admin_api_settings(request):
    """API tokens and access management."""
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'generate_token':
            name = request.POST.get('token_name', 'Default API Token')
            user = request.panel_user or User.objects.filter(role='admin').first()
            raw_token = user.generate_api_token()
            messages.success(request, f'New API Token created: {raw_token} (Save it now, it won\'t be shown again!)')
            return redirect('admin_api_settings')
        elif action == 'revoke_token':
            token_id = request.POST.get('token_id')
            APIToken.objects.filter(id=token_id).delete()
            messages.success(request, 'API Token revoked.')
            return redirect('admin_api_settings')

    tokens = APIToken.objects.select_related('user').all()
    return render(request, 'admin/api_settings.html', {
        **_sidebar_context('api'),
        'tokens': tokens,
        'rate_limit': SystemSetting.get('api_rate_limit', '50'),
    })


def get_installed_php_versions():
    """Detect installed PHP versions and runtime statuses on server."""
    versions = ['8.1', '8.2', '8.3', '8.4']
    results = []
    for ver in versions:
        fpm_bin = Path(f"/usr/sbin/php-fpm{ver}")
        fpm_dir = Path(f"/etc/php/{ver}/fpm")
        cli_bin = shutil.which(f"php{ver}")
        
        is_installed = fpm_dir.exists() or fpm_bin.exists()
        if not is_installed and cli_bin:
            try:
                out = subprocess.run([cli_bin, '-v'], capture_output=True, text=True, timeout=2).stdout
                if f"PHP {ver}" in out:
                    is_installed = True
            except Exception:
                pass
        
        is_active = False
        if is_installed:
            try:
                res = subprocess.run(['systemctl', 'is-active', f'php{ver}-fpm'], capture_output=True, text=True, timeout=2)
                is_active = (res.stdout.strip() == 'active')
            except Exception:
                pass
                
        results.append({
            'version': ver,
            'installed': is_installed,
            'active': is_active,
            'fpm_dir': str(fpm_dir),
        })
    return results


def save_php_ini_directives(php_version: str, directives: dict):
    """Write customized INI directives to /etc/php/<ver>/fpm/conf.d/20-w3panel-directives.ini."""
    content = f"""; W3Panel MultiPHP Managed Directives for PHP {php_version}
memory_limit = {directives.get('memory_limit', '256M')}
upload_max_filesize = {directives.get('upload_max_filesize', '64M')}
post_max_size = {directives.get('post_max_size', '64M')}
max_execution_time = {directives.get('max_execution_time', '120')}
max_input_time = {directives.get('max_input_time', '60')}
display_errors = {directives.get('display_errors', 'Off')}
"""
    target_dir = Path(f"/etc/php/{php_version}/fpm/conf.d")
    if target_dir.exists():
        from services.webserver.manager import _write_privileged_file
        _write_privileged_file(target_dir / '20-w3panel-directives.ini', content)


def admin_php_settings(request):
    """
    MultiPHP Manager & INI Editor (WHM Parity).
    Manages system default PHP, installed runtimes, per-domain PHP handlers,
    runtime directives (php.ini), and Enterprise performance profiles.
    """
    from services.webserver import (
        apply_system_tuning,
        get_system_tuning_status,
        reload_php_fpm,
        reload_webserver,
        create_vhost,
        create_user_php_pool,
    )

    default_php = SystemSetting.get('default_php', '8.3')

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'set_default_php':
            new_default = request.POST.get('default_php', '8.3').strip()
            SystemSetting.set('default_php', new_default)
            messages.success(request, f"System default PHP updated to PHP {new_default}.")
            return redirect('/settings/php/?tab=manager')

        elif action == 'set_domain_php':
            website_id = request.POST.get('website_id')
            new_ver = request.POST.get('php_version', '8.3').strip()
            site = get_object_or_404(Website, id=website_id)
            site.php_version = new_ver
            site.save(update_fields=['php_version'])
            if site.owner and site.framework != 'nodejs':
                try:
                    create_user_php_pool(username=site.owner.username, php_version=new_ver)
                except Exception as e:
                    logger.warning(f"Failed to create PHP pool: {e}")
            create_vhost(site)
            reload_php_fpm(new_ver)
            reload_webserver()
            messages.success(request, f"Domain {site.domain} switched to PHP {new_ver}.")
            return redirect('/settings/php/?tab=manager')

        elif action == 'bulk_set_domain_php':
            website_ids = request.POST.getlist('selected_websites')
            target_ver = request.POST.get('target_php_version', '8.3').strip()
            if not website_ids:
                messages.warning(request, "No domains were selected for bulk PHP update.")
                return redirect('/settings/php/?tab=manager')
            sites = Website.objects.filter(id__in=website_ids).select_related('owner')
            for site in sites:
                site.php_version = target_ver
                site.save(update_fields=['php_version'])
                if site.owner and site.framework != 'nodejs':
                    try:
                        create_user_php_pool(username=site.owner.username, php_version=target_ver)
                    except Exception as e:
                        logger.warning(f"Failed to create PHP pool: {e}")
                create_vhost(site)
            reload_php_fpm(target_ver)
            reload_webserver()
            messages.success(request, f"Successfully switched {len(sites)} domain(s) to PHP {target_ver}.")
            return redirect('/settings/php/?tab=manager')

        elif action == 'install_php':
            ver = request.POST.get('php_version', '').strip()
            if ver in ('8.1', '8.2', '8.3', '8.4'):
                cmd = [
                    'sudo', '-n', 'apt-get', 'install', '-y',
                    f'php{ver}-fpm', f'php{ver}-cli', f'php{ver}-mysql',
                    f'php{ver}-curl', f'php{ver}-mbstring', f'php{ver}-xml',
                    f'php{ver}-zip', f'php{ver}-intl', f'php{ver}-bcmath'
                ]
                try:
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    if res.returncode == 0:
                        messages.success(request, f"PHP {ver}-FPM stack provisioned successfully.")
                    else:
                        messages.error(request, f"Failed to install PHP {ver}: {res.stderr[:200]}")
                except Exception as e:
                    messages.error(request, f"PHP installation error: {e}")
            return redirect('/settings/php/?tab=manager')

        elif action == 'save_ini':
            ver = request.POST.get('php_version', default_php).strip()
            directives = {
                'memory_limit': request.POST.get('memory_limit', '256M').strip(),
                'upload_max_filesize': request.POST.get('upload_max_filesize', '64M').strip(),
                'post_max_size': request.POST.get('post_max_size', '64M').strip(),
                'max_execution_time': request.POST.get('max_execution_time', '120').strip(),
                'max_input_time': request.POST.get('max_input_time', '60').strip(),
                'display_errors': request.POST.get('display_errors', 'Off').strip(),
            }
            for k, v in directives.items():
                SystemSetting.set(f"php_{ver}_{k}", v)
            if ver == default_php:
                SystemSetting.set('php_memory_limit', directives['memory_limit'])
                SystemSetting.set('php_upload_max_filesize', directives['upload_max_filesize'])
                SystemSetting.set('php_max_execution_time', directives['max_execution_time'])
            save_php_ini_directives(ver, directives)
            reload_php_fpm(ver)
            messages.success(request, f"PHP {ver} INI directives updated and service reloaded.")
            return redirect(f'/settings/php/?tab=ini&php_version={ver}')

        elif action == 'apply_tuning':
            res = apply_system_tuning(default_php)
            if res.get('success'):
                applied_str = ", ".join(res.get('applied', []))
                messages.success(request, f"Enterprise performance profile applied successfully: {applied_str}.")
            else:
                messages.error(request, f"Could not apply tuning: {res.get('errors', ['Unknown error'])}")
            return redirect('/settings/php/?tab=performance')

        elif action == 'reload_fpm':
            target_fpm = request.POST.get('php_version', default_php).strip()
            if reload_php_fpm(target_fpm):
                messages.success(request, f"PHP-FPM {target_fpm} reloaded successfully.")
            else:
                messages.warning(request, f"PHP-FPM {target_fpm} reload bypassed or service not active.")
            return redirect('/settings/php/?tab=manager')

    # GET handling
    active_tab = request.GET.get('tab', 'manager').strip()
    selected_php = request.GET.get('php_version', default_php).strip()
    search_query = request.GET.get('q', '').strip()

    installed_versions = get_installed_php_versions()

    websites = Website.objects.select_related('owner').all().order_by('domain')
    if search_query:
        websites = websites.filter(Q(domain__icontains=search_query) | Q(owner__username__icontains=search_query))

    ini_settings = {
        'memory_limit': SystemSetting.get(f'php_{selected_php}_memory_limit') or SystemSetting.get('php_memory_limit', '256M'),
        'upload_max_filesize': SystemSetting.get(f'php_{selected_php}_upload_max_filesize') or SystemSetting.get('php_upload_max_filesize', '64M'),
        'post_max_size': SystemSetting.get(f'php_{selected_php}_post_max_size', '64M'),
        'max_execution_time': SystemSetting.get(f'php_{selected_php}_max_execution_time') or SystemSetting.get('php_max_execution_time', '120'),
        'max_input_time': SystemSetting.get(f'php_{selected_php}_max_input_time', '60'),
        'display_errors': SystemSetting.get(f'php_{selected_php}_display_errors', 'Off'),
    }

    tuning_status = get_system_tuning_status(default_php)

    return render(request, 'admin/php_settings.html', {
        **_sidebar_context('php'),
        'active_tab': active_tab,
        'default_php': default_php,
        'selected_php': selected_php,
        'search_query': search_query,
        'installed_versions': installed_versions,
        'websites': websites,
        'ini_settings': ini_settings,
        'tuning_status': tuning_status,
        'memory_limit': ini_settings['memory_limit'],
        'max_execution_time': ini_settings['max_execution_time'],
        'upload_max_filesize': ini_settings['upload_max_filesize'],
    })


def admin_notifications_settings(request):
    """Notification alert channels."""
    if request.method == 'POST':
        email_alerts = request.POST.get('email_alerts', '').strip()
        webhook_url = request.POST.get('webhook_url', '').strip()
        
        SystemSetting.set('notify_email', email_alerts)
        SystemSetting.set('notify_webhook', webhook_url)
        messages.success(request, 'Notification channels saved.')
        return redirect('admin_notifications_settings')

    return render(request, 'admin/notifications_settings.html', {
        **_sidebar_context('notifications'),
        'notify_email': SystemSetting.get('notify_email', ''),
        'notify_webhook': SystemSetting.get('notify_webhook', ''),
    })


# ===========================================================================
# 8. Security (Firewall & 2FA)
# ===========================================================================

def admin_firewall(request):
    """Firewall management."""
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'add_rule':
            port = request.POST.get('port', '').strip()
            protocol = request.POST.get('protocol', 'tcp')
            f_action = request.POST.get('f_action', 'ALLOW')
            source_ip = request.POST.get('source_ip', '0.0.0.0/0').strip() or '0.0.0.0/0'
            comment = request.POST.get('comment', '').strip()

            if port:
                FirewallRule.objects.create(
                    port=port,
                    protocol=protocol,
                    action=f_action,
                    source_ip=source_ip,
                    comment=comment
                )
                try:
                    cmd = ['sudo', 'ufw', f_action.lower(), f'{port}/{protocol}']
                    subprocess.run(cmd, timeout=5)
                except Exception:
                    pass
                messages.success(request, f'Firewall rule for port {port}/{protocol} added.')
                return redirect('admin_firewall')

        elif action == 'delete_rule':
            rule_id = request.POST.get('rule_id')
            rule = get_object_or_404(FirewallRule, id=rule_id)
            try:
                subprocess.run(['sudo', 'ufw', 'delete', rule.action.lower(), f'{rule.port}/{rule.protocol}'], timeout=5)
            except Exception:
                pass
            rule.delete()
            messages.success(request, 'Firewall rule removed.')
            return redirect('admin_firewall')

    rules = FirewallRule.objects.all()
    return render(request, 'admin/firewall.html', {
        **_sidebar_context('firewall'),
        'rules': rules,
    })


def admin_2fa_settings(request):
    """Two-factor authentication management."""
    return render(request, 'admin/2fa.html', {
        **_sidebar_context('2fa'),
    })


# ===========================================================================
# 9. General (Notifications, Wizards, Monitoring)
# ===========================================================================

def admin_notifications(request):
    """Notifications inbox."""
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'mark_all_read':
            Notification.objects.filter(is_read=False).update(is_read=True)
            messages.success(request, 'All notifications marked as read.')
            return redirect('admin_notifications')

    notifs = Notification.objects.all()[:50]
    return render(request, 'admin/notifications.html', {
        **_sidebar_context('notifications'),
        'notifications': notifs,
    })


def wizard_dashboard(request):
    """
    Initial Server Setup Wizard (Basic WebHost Setup).
    Guides administrator through core server identity, web server selection,
    database engine, mail stack, FTP configuration, and security baselines.
    """
    from services.database import get_database_tuning_status, apply_database_tuning

    stack_status = get_server_stack_status()

    if request.method == 'POST':
        server_hostname = request.POST.get('server_hostname', '').strip() or platform.node()
        server_ip = request.POST.get('server_ip', '').strip()
        primary_ns = request.POST.get('primary_ns', '').strip()
        secondary_ns = request.POST.get('secondary_ns', '').strip()
        admin_email = request.POST.get('admin_email', '').strip()
        
        webserver_choice = request.POST.get('webserver_choice', 'nginx')
        default_php = request.POST.get('default_php', '8.3')
        
        enable_mariadb = request.POST.get('enable_mariadb') in ('1', 'true', 'on')
        enable_postgresql = request.POST.get('enable_postgresql') in ('1', 'true', 'on')
        tune_mariadb = request.POST.get('tune_mariadb') in ('1', 'true', 'on')
        
        enable_mail = request.POST.get('enable_mail') in ('1', 'true', 'on')
        spam_filter = request.POST.get('spam_filter', 'rspamd')
        enable_dkim = request.POST.get('enable_dkim') in ('1', 'true', 'on')
        
        enable_ftp = request.POST.get('enable_ftp') in ('1', 'true', 'on')
        enable_ufw = request.POST.get('enable_ufw') in ('1', 'true', 'on')

        # Save system identity & stack preferences
        SystemSetting.set('server_hostname', server_hostname)
        if server_ip:
            SystemSetting.set('server_ip', server_ip)
        if primary_ns:
            SystemSetting.set('primary_ns', primary_ns)
        if secondary_ns:
            SystemSetting.set('secondary_ns', secondary_ns)
        if admin_email:
            SystemSetting.set('admin_email', admin_email)
        SystemSetting.set('webserver_choice', webserver_choice)
        SystemSetting.set('default_php', default_php)
        SystemSetting.set('db_mariadb_enabled', 'true' if enable_mariadb else 'false')
        SystemSetting.set('db_postgresql_enabled', 'true' if enable_postgresql else 'false')
        SystemSetting.set('mail_stack_enabled', 'true' if enable_mail else 'false')
        SystemSetting.set('mail_spam_filter', spam_filter)
        SystemSetting.set('mail_dkim_enabled', 'true' if enable_dkim else 'false')
        SystemSetting.set('ftp_stack_enabled', 'true' if enable_ftp else 'false')
        SystemSetting.set('initial_setup_completed', 'true')

        # Execute package installations on-demand for selected services that are missing
        install_pkgs = []
        services_to_start = []
        if webserver_choice == 'nginx' and not stack_status['webserver_nginx']['installed']:
            install_pkgs.extend(['nginx', 'nginx-common'])
            services_to_start.append('nginx')
        elif webserver_choice == 'apache' and not stack_status['webserver_apache']['installed']:
            install_pkgs.extend(['apache2'])
            services_to_start.append('apache2')

        if enable_mariadb and not stack_status['db_mariadb']['installed']:
            install_pkgs.extend(['mariadb-server', 'mariadb-client'])
            services_to_start.append('mariadb')
        if enable_postgresql and not stack_status['db_postgresql']['installed']:
            install_pkgs.extend(['postgresql', 'postgresql-contrib'])
            services_to_start.append('postgresql')

        if enable_mail and not stack_status['mail_postfix']['installed']:
            install_pkgs.extend(['postfix', 'dovecot-imapd', 'dovecot-pop3d'])
            services_to_start.extend(['postfix', 'dovecot'])

        if enable_ftp and not stack_status['ftp_pureftpd']['installed']:
            install_pkgs.extend(['pure-ftpd'])
            services_to_start.append('pure-ftpd')

        installed_count = len(install_pkgs)
        if install_pkgs:
            try:
                subprocess.run(['sudo', '-n', 'apt-get', 'update', '-y'], timeout=60)
                cmd = ['sudo', '-n', 'apt-get', 'install', '-y'] + install_pkgs
                env = os.environ.copy()
                env['DEBIAN_FRONTEND'] = 'noninteractive'
                subprocess.run(cmd, env=env, timeout=300)
                for svc in services_to_start:
                    subprocess.run(['sudo', '-n', 'systemctl', 'enable', '--now', svc], timeout=10)
            except Exception as e:
                logger.warning(f"Wizard package install exception: {e}")

        # Database Low-RAM optimization
        if tune_mariadb:
            try:
                apply_database_tuning()
            except Exception:
                pass

        # Firewall port setup
        if enable_ufw:
            try:
                subprocess.run(['sudo', '-n', 'ufw', 'default', 'deny', 'incoming'], timeout=5)
                subprocess.run(['sudo', '-n', 'ufw', 'default', 'allow', 'outgoing'], timeout=5)
                for port_proto in ['22/tcp', '80/tcp', '443/tcp', '2087/tcp', '2083/tcp']:
                    subprocess.run(['sudo', '-n', 'ufw', 'allow', port_proto], timeout=5)
                if enable_mail:
                    for mp in ['25/tcp', '587/tcp', '465/tcp', '993/tcp', '995/tcp']:
                        subprocess.run(['sudo', '-n', 'ufw', 'allow', mp], timeout=5)
                if enable_ftp:
                    for fp in ['21/tcp', '30000:31000/tcp']:
                        subprocess.run(['sudo', '-n', 'ufw', 'allow', fp], timeout=5)
                subprocess.run(['sudo', '-n', 'ufw', '--force', 'enable'], timeout=5)
            except Exception:
                pass

        msg = 'Initial Server Setup completed successfully! All stack configurations and networking defaults have been applied.'
        if installed_count:
            msg += f' Provisioned {installed_count} background server packages.'
        messages.success(request, msg)
        return redirect('admin_settings')

    detected_ip = get_server_public_ip()
    hostname = SystemSetting.get('server_hostname', platform.node())
    primary_ns = SystemSetting.get('primary_ns', f"ns1.{hostname}")
    secondary_ns = SystemSetting.get('secondary_ns', f"ns2.{hostname}")
    admin_email = SystemSetting.get('admin_email', f"admin@{hostname}")
    server_ip = SystemSetting.get('server_ip', detected_ip)
    default_php = SystemSetting.get('default_php', '8.3')
    db_tuning = get_database_tuning_status()

    return render(request, 'admin/wizards.html', {
        **_sidebar_context('wizards'),
        'stack_status': stack_status,
        'hostname': hostname,
        'server_ip': server_ip,
        'primary_ns': primary_ns,
        'secondary_ns': secondary_ns,
        'admin_email': admin_email,
        'default_php': default_php,
        'db_tuning': db_tuning,
        'initial_completed': SystemSetting.get('initial_setup_completed', 'false') == 'true',
    })


def monitoring_dashboard(request):
    """Resource monitoring page with live metrics and processes."""
    processes = []
    try:
        for p in sorted(psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']), key=lambda x: x.info['cpu_percent'] or 0, reverse=True)[:15]:
            processes.append(p.info)
    except Exception:
        pass

    return render(request, 'admin/monitoring.html', {
        **_sidebar_context('monitoring'),
        'processes': processes,
    })


def api_metrics(request):
    """JSON endpoint for live metrics polling."""
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    load = psutil.getloadavg()
    return JsonResponse({
        'cpu': round(psutil.cpu_percent(interval=0.1), 1),
        'ram_used': round(mem.used / (1024 * 1024)),
        'ram_total': round(mem.total / (1024 * 1024)),
        'ram_percent': round(mem.percent, 1),
        'disk_used': round(disk.used / (1024 ** 3), 1),
        'disk_total': round(disk.total / (1024 ** 3), 1),
        'disk_percent': round(disk.percent, 1),
        'load': round(load[0], 2),
        'load5': round(load[1], 2),
        'load15': round(load[2], 2),
    })


def _get_podman_version():
    """Get Podman version."""
    try:
        result = subprocess.run(['podman', '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip().replace('podman version ', '')
    except Exception:
        pass
    return 'N/A'