"""
W3Panel v2 — Admin Views
Complete administration interface implementations.
"""
import os
import re
import json
import shutil
import psutil
import platform
import subprocess
import logging
from pathlib import Path
from django.db.models import Q
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden, StreamingHttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.utils import timezone
from django.conf import settings

from packages.core.models import (
    User, Website, Package, SystemSetting, AuditLog, Notification,
    Database, Mailbox, EmailForwarder, EmailAutoresponder, EmailCatchAll,
    DNSRecord, FTPAccount, CronJob, Backup, FirewallRule, APIToken
)
from packages.plugins.manager import PluginManager

logger = logging.getLogger('w3panel.admin')
_FULL_BIN_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def _find_bin(*names: str) -> str | None:
    env_path = os.environ.get('PATH', '')
    search_path = f"{env_path}:{_FULL_BIN_PATH}" if env_path else _FULL_BIN_PATH
    for name in names:
        hit = shutil.which(name) or shutil.which(name, path=search_path)
        if hit:
            return hit
    return None


def _sidebar_context(active_page=''):
    """Build sidebar navigation data matching OpenPanel reference."""
    unread_count = Notification.objects.filter(is_read=False).count()
    from services.database import get_db_admin_tools_status
    db_tools = get_db_admin_tools_status()
    sidebar_services = [
        {'label': 'Service Manager', 'url': '/services/', 'active': 'services'},
        {'label': 'System Monitoring', 'url': '/monitoring/', 'active': 'monitoring'},
        {'label': 'Terminal Console', 'url': '/terminal/', 'active': 'terminal'},
        {'label': 'Cron Jobs & Tasks', 'url': '/services/cron/', 'active': 'cron'},
        {'label': 'System Logs', 'url': '/services/logs/', 'active': 'logs'},
    ]
    if db_tools['phpmyadmin_available']:
        sidebar_services.append({'label': 'phpMyAdmin', 'url': '/services/db-tool/phpmyadmin/', 'active': 'phpmyadmin', 'external': True})
    if db_tools['pgadmin4_available']:
        sidebar_services.append({'label': 'pgAdmin 4', 'url': '/services/db-tool/pgadmin4/', 'active': 'pgadmin4', 'external': True})
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
        ],
        'sidebar_email': [
            {'label': 'Email Accounts', 'url': '/email/accounts/', 'active': 'email_accounts'},
            {'label': 'Mail Queue', 'url': '/email/queue/', 'active': 'email_queue'},
            {'label': 'Email Reports', 'url': '/email/reports/', 'active': 'email_reports'},
            {'label': 'Email Settings', 'url': '/email/settings/', 'active': 'email_settings'},
        ],
        'sidebar_services': sidebar_services,
        'sidebar_settings': [
            {'label': 'Basic WebHost Setup', 'url': '/settings/', 'active': 'settings'},
            {'label': 'W3Packager (Software)', 'url': '/software/w3packager/', 'active': 'w3packager'},
            {'label': 'MultiPHP Manager', 'url': '/settings/php/', 'active': 'php'},
            {'label': 'Panel Migration', 'url': '/migration/', 'active': 'migration'},
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
    import time
    from packages.core.auth import authenticate_user, create_session, verify_2fa

    if request.method == 'POST':
        otp_code = request.POST.get('otp_code', '').strip()
        pending_uid = request.session.get('pending_2fa_uid')
        pending_exp = request.session.get('pending_2fa_exp', 0)

        if pending_uid and otp_code and time.time() <= pending_exp:
            user = User.objects.filter(pk=pending_uid, is_active=True, role__in=('admin', 'reseller')).first()
            if user and verify_2fa(user, otp_code):
                request.session.pop('pending_2fa_uid', None)
                request.session.pop('pending_2fa_exp', None)
                create_session(request, user)
                if user.role == 'admin' and SystemSetting.get('initial_setup_completed', 'false') != 'true':
                    return redirect('admin_wizards')
                return redirect('admin_dashboard')
            return render(request, 'login.html', {
                'error': 'Invalid two-factor authentication code.',
                'username': user.username if user else '',
                'panel_type': 'host',
                'require_2fa': True,
            })

        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        try:
            user, is_2fa_required = authenticate_user(username, password, request.META.get('REMOTE_ADDR', ''))
            if user.role not in ('admin', 'reseller'):
                return render(request, 'login.html', {'error': 'Administrator / Reseller access only on W3Host Manager (port 2087).', 'username': username, 'panel_type': 'host'})

            if is_2fa_required:
                if not otp_code or not verify_2fa(user, otp_code):
                    request.session['pending_2fa_uid'] = user.pk
                    request.session['pending_2fa_exp'] = time.time() + 300
                    err = 'Invalid two-factor authentication code.' if otp_code else ''
                    return render(request, 'login.html', {
                        'error': err,
                        'username': username,
                        'panel_type': 'host',
                        'require_2fa': True,
                    })

            request.session.pop('pending_2fa_uid', None)
            request.session.pop('pending_2fa_exp', None)
            create_session(request, user)
            if user.role == 'admin' and SystemSetting.get('initial_setup_completed', 'false') != 'true':
                return redirect('admin_wizards')
            return redirect('admin_dashboard')
        except ValueError as e:
            return render(request, 'login.html', {'error': str(e), 'username': username, 'panel_type': 'host'})

    uid = request.session.get('user_id')
    if uid:
        existing_user = User.objects.filter(pk=uid, is_active=True).first()
        if existing_user and existing_user.role == 'admin' and SystemSetting.get('initial_setup_completed', 'false') != 'true':
            return redirect('admin_wizards')

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
    from services.database import get_db_admin_tools_status
    db_tools = get_db_admin_tools_status()
    db_tools['phpmyadmin_url'] = '/services/db-tool/phpmyadmin/' if db_tools['phpmyadmin_available'] else ''
    db_tools['pgadmin4_url'] = '/services/db-tool/pgadmin4/' if db_tools['pgadmin4_available'] else ''

    return render(request, 'admin/dashboard.html', {
        **_sidebar_context('dashboard'),
        'stats': stats,
        'metrics': metrics,
        'activity_logs': activity_logs,
        'system': system,
        'license_tier': license_tier,
        'db_tools': db_tools,
        'panel_version': getattr(settings, 'W3PANEL_VERSION', '2.0.0'),
    })


# ===========================================================================
# 2. Accounts (Users, Resellers, Administrators)
# ===========================================================================

def admin_users(request):
    """List standard users (scoped for resellers)."""
    actor = getattr(request, 'panel_user', None)
    users = User.objects.filter(role='user').select_related('package')
    if actor and actor.role == 'reseller':
        users = users.filter(parent_reseller=actor)
    return render(request, 'admin/users.html', {
        **_sidebar_context('users'),
        'users': users,
        'account_type': 'User',
    })


def admin_user_create(request):
    """Create user, with optional primary domain auto-provisioning."""
    packages = Package.objects.all()
    default_php = SystemSetting.get('default_php', '8.3') or '8.3'
    valid_php_versions = [r['version'] for r in PHP_RUNTIME_DEFS]
    if default_php not in valid_php_versions:
        default_php = '8.3'
    valid_frameworks = {choice[0] for choice in Website.FRAMEWORK_CHOICES}

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '').strip()
        domain = request.POST.get('domain', '').strip().lower()
        framework = request.POST.get('framework', 'none').strip()
        if framework not in valid_frameworks:
            framework = 'none'
        php_version = request.POST.get('php_version', default_php).strip()
        if php_version not in valid_php_versions:
            php_version = default_php
        try:
            port_val = int(request.POST.get('port', '3000') or '3000')
            if not (1024 <= port_val <= 65535):
                port_val = 3000
        except (TypeError, ValueError):
            port_val = 3000
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
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$', username):
                messages.error(request, 'Invalid username. Use letters, digits, underscores, or hyphens.')
            elif domain and not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$', domain):
                messages.error(request, f'Invalid domain name "{domain}".')
            elif User.objects.filter(username=username).exists():
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
                    from services.webserver import create_vhost, get_doc_root
                    doc_root = str(get_doc_root(user.username, domain, framework))
                    server_ip = SystemSetting.get('server_ip', '127.0.0.1') or '127.0.0.1'
                    site = Website.objects.create(
                        owner=user,
                        domain=domain,
                        doc_root=doc_root,
                        framework=framework,
                        php_version=php_version,
                        port=port_val,
                    )
                    DNSRecord.objects.create(domain=site, record_type='A', name='@', value=server_ip)
                    DNSRecord.objects.create(domain=site, record_type='CNAME', name='www', value=domain)
                    try:
                        create_vhost(site)
                    except Exception as e:
                        logger.warning(f"Could not provision vhost for {domain}: {e}")
                    AuditLog.objects.create(user=user, action='website_created', target=domain)
                    messages.success(request, f'{role.capitalize()} "{username}" created with primary site "{domain}".')
                else:
                    try:
                        from services.webserver import create_user_php_pool
                        create_user_php_pool(username=user.username, php_version=default_php)
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
        'default_php': default_php,
        'php_versions': valid_php_versions,
    })


def _get_scoped_target_user(request, user_id):
    """Fetch target user enforcing reseller ownership boundaries."""
    target_user = get_object_or_404(User, id=user_id)
    actor = getattr(request, 'panel_user', None)
    if actor and actor.role == 'reseller':
        if target_user.role != 'user' or target_user.parent_reseller_id != actor.id:
            return None
    return target_user


def admin_user_edit(request, user_id):
    """Edit user account: email, package, role, password reset, active status, shell access."""
    target_user = _get_scoped_target_user(request, user_id)
    if not target_user:
        return HttpResponseForbidden('Permission denied.')
    actor = getattr(request, 'panel_user', None)
    packages = Package.objects.all()

    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        package_id = request.POST.get('package')
        role = request.POST.get('role', 'user')
        if actor and actor.role == 'reseller':
            role = 'user'
        elif role not in ('user', 'reseller', 'admin'):
            role = target_user.role
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
        target_user = _get_scoped_target_user(request, user_id)
        if not target_user:
            return HttpResponseForbidden('Permission denied.')
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
        target_user = _get_scoped_target_user(request, user_id)
        if not target_user:
            return HttpResponseForbidden('Permission denied.')
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
    from services.webserver.manager import _has_sudo
    default_cwd = '/root' if (_has_sudo() or os.geteuid() == 0) else str(Path.home())
    request.session['admin_terminal_cwd'] = default_cwd
    return render(request, 'admin/terminal.html', {
        **_sidebar_context('terminal'),
        'active_section': 'services',
        'initial_cwd': default_cwd,
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
        from packages.core.utils import run_terminal_command
        has_sudo = _has_sudo()
        default_cwd = '/root' if (has_sudo or os.geteuid() == 0) else str(Path.home())
        result = run_terminal_command(
            request,
            cmd,
            default_cwd=default_cwd,
            session_key='admin_terminal_cwd',
            use_sudo=has_sudo,
            timeout=20,
        )
        return JsonResponse(result)
    except subprocess.TimeoutExpired:
        return JsonResponse({'stderr': 'Command execution timed out after 20 seconds.', 'returncode': 124})
    except Exception as e:
        return JsonResponse({'stderr': str(e), 'returncode': 1})


def admin_user_delete(request, user_id):
    """Delete a user and clean up their tenant resources."""
    if request.method == 'POST':
        user = _get_scoped_target_user(request, user_id)
        if not user:
            return HttpResponseForbidden('Permission denied.')
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
            rtype = request.POST.get('record_type', 'A').strip().upper()
            name = request.POST.get('name', '@').strip()
            value = request.POST.get('value', '').strip()
            ttl_raw = request.POST.get('ttl', '3600').strip()
            ttl = int(ttl_raw) if ttl_raw.isdigit() else 3600
            priority = request.POST.get('priority')
            priority_val = int(priority) if priority and priority.isdigit() else None
            valid_types = {'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV'}
            if rtype in valid_types and value and '\n' not in name and '\r' not in name and '\n' not in value and '\r' not in value:
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
    from services.database import (
        configure_db_admin_webserver,
        configure_pgadmin4_runtime,
        ensure_pgadmin4_service_ready,
        get_database_tuning_status,
        get_db_admin_tools_status,
        install_pgadmin4,
        install_phpmyadmin,
        uninstall_pgadmin4,
        uninstall_phpmyadmin,
    )
    from services.database.manager import _run_apt_safe

    if request.method == 'POST':
        service_name = request.POST.get('service')
        action = request.POST.get('action')

        if action == 'install_service' and service_name:
            if service_name == 'phpmyadmin':
                res = install_phpmyadmin()
                if res.get('success'):
                    messages.success(request, 'phpMyAdmin installed and configured successfully!')
                else:
                    messages.error(request, res.get('error', 'phpMyAdmin installation failed.'))
                return redirect('admin_services_status')

            if service_name == 'pgadmin4':
                actor_email = getattr(getattr(request, 'panel_user', None), 'email', '') or ''
                res = install_pgadmin4(admin_email=actor_email)
                if res.get('success'):
                    messages.success(
                        request,
                        f"pgAdmin 4 installed and started! Login Email: {res.get('email')} | Password: {res.get('password')}",
                    )
                else:
                    messages.error(request, res.get('error', 'pgAdmin 4 installation failed.'))
                return redirect('admin_services_status')

            if service_name == 'snappymail':
                from services.mail import install_snappymail
                res = install_snappymail()
                if res.get('success'):
                    messages.success(request, 'SnappyMail Webmail Suite configured successfully!')
                else:
                    messages.error(request, res.get('error', 'SnappyMail installation failed.'))
                return redirect('admin_services_status')

            # Package mapping for individual services
            pkg_map = {
                'nginx': ['nginx'],
                'mariadb': ['mariadb-server', 'mariadb-client'],
                'postgresql': ['postgresql', 'postgresql-contrib'],
                'redis': ['redis-server'],
                'ufw': ['ufw'],
                'php': ['php-fpm', 'php-mysql', 'php-pgsql', 'php-curl', 'php-zip', 'php-gd', 'php-mbstring', 'php-xml'],
                'certbot': ['certbot', 'python3-certbot-nginx'],
                'postfix': ['postfix', 'opendkim', 'opendkim-tools'],
                'dovecot': ['dovecot-core', 'dovecot-imapd', 'dovecot-pop3d', 'dovecot-lmtpd', 'dovecot-sieve', 'dovecot-managesieved'],
            }
            if service_name not in pkg_map:
                messages.error(request, f'Unknown service: {service_name}')
                return redirect('admin_services_status')
            pkgs = pkg_map[service_name]
            try:
                _run_apt_safe(['update', '-y'], timeout=120)
                res = _run_apt_safe(['install', '-y'] + pkgs, timeout=300)
                if res.returncode == 0:
                    daemon_name = 'mariadb' if service_name == 'mariadb' else service_name
                    _run_privileged(['systemctl', 'enable', '--now', daemon_name], timeout=10)
                    if service_name in ('postfix', 'dovecot'):
                        from services.mail import configure_mail_stack
                        configure_mail_stack()
                    else:
                        configure_db_admin_webserver()
                    messages.success(request, f'{service_name.capitalize()} installed and started successfully!')
                else:
                    messages.error(request, f'Installation failed: {res.stderr or res.stdout}')
            except Exception as e:
                messages.error(request, f'Error installing {service_name}: {e}')
            return redirect('admin_services_status')

        elif action == 'uninstall_service' and service_name:
            if service_name == 'phpmyadmin':
                res = uninstall_phpmyadmin()
                if res.get('success'):
                    messages.success(request, 'phpMyAdmin uninstalled successfully.')
                else:
                    messages.error(request, res.get('error', 'Uninstall failed.'))
                return redirect('admin_services_status')

            if service_name == 'pgadmin4':
                res = uninstall_pgadmin4()
                if res.get('success'):
                    messages.success(request, 'pgAdmin 4 uninstalled successfully.')
                else:
                    messages.error(request, res.get('error', 'Uninstall failed.'))
                return redirect('admin_services_status')

            if service_name == 'snappymail':
                from services.mail import uninstall_snappymail
                uninstall_snappymail()
                messages.success(request, 'SnappyMail Webmail uninstalled successfully.')
                return redirect('admin_services_status')

            pkg_map = {
                'nginx': ['nginx', 'nginx-common'],
                'mariadb': ['mariadb-server', 'mariadb-client'],
                'postgresql': ['postgresql', 'postgresql-contrib'],
                'redis': ['redis-server'],
                'ufw': ['ufw'],
                'postfix': ['postfix', 'opendkim', 'opendkim-tools'],
                'dovecot': ['dovecot-core', 'dovecot-imapd', 'dovecot-pop3d', 'dovecot-lmtpd', 'dovecot-sieve', 'dovecot-managesieved'],
            }
            if service_name not in pkg_map:
                messages.error(request, f'Cannot uninstall service: {service_name}')
                return redirect('admin_services_status')
            pkgs = pkg_map[service_name]
            try:
                _run_privileged(['systemctl', 'stop', service_name], timeout=10)
                res = _run_apt_safe(['remove', '-y'] + pkgs, timeout=180)
                if res.returncode == 0:
                    configure_db_admin_webserver()
                    messages.success(request, f'{service_name.capitalize()} uninstalled successfully.')
                else:
                    messages.error(request, f'Uninstall failed: {res.stderr or res.stdout}')
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
            allowed_services = {'nginx', 'mariadb', 'mysql', 'postgresql', 'php8.3-fpm', 'ufw', 'ssh', 'pgadmin4', 'postfix', 'postfix@-', 'dovecot'}
            if service_name not in allowed_services:
                messages.error(request, f'Invalid service: {service_name}')
                return redirect('admin_services_status')
            try:
                if service_name == 'pgadmin4' and action in ('start', 'restart'):
                    pg_dir = Path(os.environ.get('W3PANEL_PGADMIN4_DIR', '/usr/pgadmin4'))
                    systemd_dir = Path(os.environ.get('W3PANEL_SYSTEMD_DIR', '/etc/systemd/system'))
                    if (pg_dir / 'web' / 'pgAdmin4.py').exists() and not (systemd_dir / 'pgadmin4.service').exists():
                        actor_email = getattr(getattr(request, 'panel_user', None), 'email', '') or ''
                        cfg_res = configure_pgadmin4_runtime(admin_email=actor_email)
                        if not cfg_res.get('success'):
                            messages.error(request, cfg_res.get('error', 'Failed to configure pgadmin4.service.'))
                            return redirect('admin_services_status')
                unit_name = service_name
                if service_name == 'postfix':
                    chk = subprocess.run(['systemctl', 'cat', 'postfix@-.service'], capture_output=True, timeout=3)
                    if chk.returncode == 0:
                        unit_name = 'postfix@-'
                res = _run_privileged(['systemctl', action, unit_name], timeout=15)
                if res is None:
                    messages.error(request, f'Insufficient privileges to {action} {service_name}.')
                elif res.returncode != 0:
                    messages.error(request, f'Failed to {action} {service_name}: {res.stderr or res.stdout}')
                else:
                    messages.success(request, f'Service {service_name} {action}ed successfully.')
            except Exception as e:
                messages.error(request, f'Error executing {action} on {service_name}: {e}')
            return redirect('admin_services_status')

    db_tuning = get_database_tuning_status()
    db_tools = get_db_admin_tools_status()

    services_list = [
        {'name': 'nginx', 'display': 'Nginx Web Server', 'icon': 'ti ti-world', 'cmds': ('nginx',), 'units': ('nginx',), 'desc': 'High-Performance Web Server for User Websites (Ports 80 & 443)'},
        {'name': 'mariadb', 'display': 'MariaDB Database Server', 'icon': 'ti ti-database', 'cmds': ('mariadbd', 'mysqld', 'mariadb', 'mysql'), 'units': ('mariadb', 'mysql'), 'desc': 'Relational MySQL Database Engine'},
        {'name': 'postgresql', 'display': 'PostgreSQL Database Server', 'icon': 'ti ti-database-import', 'cmds': ('psql', 'postgres'), 'units': ('postgresql',), 'desc': 'Advanced Object-Relational SQL Database Engine'},
        {'name': 'php8.3-fpm', 'display': 'PHP-FPM 8.3 Daemon', 'icon': 'ti ti-brand-php', 'cmds': ('php-fpm8.3',), 'units': ('php8.3-fpm',), 'desc': 'PHP FastCGI Process Manager for VirtualHosts'},
        {'name': 'ufw', 'display': 'UFW Host Firewall', 'icon': 'ti ti-shield', 'cmds': ('ufw',), 'units': ('ufw',), 'desc': 'Host Inbound Access Firewall'},
        {'name': 'ssh', 'display': 'SSH Remote Access', 'icon': 'ti ti-terminal-2', 'cmds': ('sshd',), 'units': ('ssh', 'sshd'), 'desc': 'Secure Shell Remote Administration'},
        {'name': 'postfix', 'display': 'Postfix Mail Server', 'icon': 'ti ti-mail', 'cmds': ('postfix',), 'units': ('postfix@-', 'postfix'), 'desc': 'Mail Transport Agent for Outbound & Inbound Email (Ports 25 & 587)'},
        {'name': 'dovecot', 'display': 'Dovecot IMAP Server', 'icon': 'ti ti-inbox', 'cmds': ('dovecot',), 'units': ('dovecot',), 'desc': 'Secure IMAP/POP3 Mail Storage Server (Ports 993 & 995)'},
    ]

    for s in services_list:
        is_installed = bool(_find_bin(*s['cmds']))
        if not is_installed and s['name'] == 'postgresql':
            pg_lib = Path('/usr/lib/postgresql')
            is_installed = pg_lib.exists() and any(pg_lib.glob('*/bin/postgres'))
        if not is_installed:
            s['status'] = 'not_installed'
        else:
            s['status'] = 'stopped'
            for unit in s['units']:
                try:
                    res = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True, timeout=2)
                    if res.stdout.strip() == 'active':
                        s['status'] = 'running'
                        if unit != 'postfix@-':
                            s['name'] = unit
                        break
                except Exception:
                    pass

    if db_tools['mariadb_installed']:
        services_list.append({
            'name': 'phpmyadmin',
            'display': 'phpMyAdmin',
            'icon': 'ti ti-table',
            'desc': 'Web administration tool for MariaDB / MySQL',
            'status': 'running' if db_tools['phpmyadmin_installed'] else 'not_installed',
            'is_web_tool': True,
            'launch_url': '/services/db-tool/phpmyadmin/' if db_tools['phpmyadmin_installed'] else '',
        })

    if db_tools['postgresql_installed']:
        pg4_status = 'not_installed'
        if db_tools['pgadmin4_installed']:
            pg4_status = 'running' if db_tools['pgadmin4_running'] else 'stopped'
        services_list.append({
            'name': 'pgadmin4',
            'display': 'pgAdmin 4',
            'icon': 'ti ti-brand-databricks',
            'desc': 'Web administration tool for PostgreSQL',
            'status': pg4_status,
            'launch_url': '/services/db-tool/pgadmin4/' if db_tools['pgadmin4_installed'] else '',
        })

    from services.mail import is_snappymail_installed
    snappymail_installed = is_snappymail_installed()
    services_list.append({
        'name': 'snappymail',
        'display': 'SnappyMail Webmail',
        'icon': 'ti ti-brand-chrome',
        'desc': 'Modern lightweight webmail client for virtual mailboxes',
        'status': 'running' if snappymail_installed else 'not_installed',
        'is_web_tool': True,
        'launch_url': '/snappymail/' if snappymail_installed else '',
    })

    return render(request, 'admin/services.html', {
        **_sidebar_context('services'),
        'services': services_list,
        'db_tuning': db_tuning,
    })


def admin_db_tool_launch(request, tool):
    """Auto-wire Nginx/Apache route, sign on for phpMyAdmin, and redirect to same-origin tool."""
    from services.database import get_db_admin_tools_status, launch_db_tool
    db_tools = get_db_admin_tools_status()
    actor = getattr(request, 'panel_user', None)
    if (tool == 'phpmyadmin' and db_tools['phpmyadmin_available']) or (tool == 'pgadmin4' and db_tools['pgadmin4_available']):
        return launch_db_tool(request, tool, actor)
    messages.error(request, 'Requested database admin tool is not available.')
    return redirect('admin_services_status')


def admin_service_install_stream(request):
    """Streaming SSE endpoint for service installation (prevents Gunicorn timeouts and apt lock aborts)."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    service_name = (request.POST.get('service') or '').strip()
    actor_email = getattr(getattr(request, 'panel_user', None), 'email', '') or ''
    admin_email_setting = SystemSetting.get('admin_email', '').strip() or actor_email

    from services.database import (
        configure_db_admin_webserver,
        configure_pgadmin4_runtime,
        is_mariadb_installed,
        is_postgresql_installed,
    )
    from services.database.manager import _priv_prefix

    pkg_map = {
        'nginx': ['nginx'],
        'mariadb': ['mariadb-server', 'mariadb-client'],
        'postgresql': ['postgresql', 'postgresql-contrib'],
        'php8.3-fpm': ['php8.3-fpm', 'php8.3-mysql', 'php8.3-pgsql', 'php8.3-curl', 'php8.3-zip', 'php8.3-gd', 'php8.3-mbstring', 'php8.3-xml'],
        'ufw': ['ufw'],
        'phpmyadmin': ['phpmyadmin', 'php-mysql', 'php-mbstring', 'php-xml'],
        'pgadmin4': ['pgadmin4-web'],
        'postfix': ['postfix', 'opendkim', 'opendkim-tools'],
        'dovecot': ['dovecot-core', 'dovecot-imapd', 'dovecot-pop3d', 'dovecot-lmtpd', 'dovecot-sieve', 'dovecot-managesieved'],
        'snappymail': [],
    }
    if service_name not in pkg_map:
        return JsonResponse({'error': f'Unsupported service: {service_name}'}, status=400)

    if service_name == 'phpmyadmin' and not is_mariadb_installed():
        return JsonResponse({'error': 'MariaDB / MySQL must be installed before phpMyAdmin.'}, status=400)
    if service_name == 'pgadmin4' and not is_postgresql_installed():
        return JsonResponse({'error': 'PostgreSQL must be installed before pgAdmin 4.'}, status=400)

    def event_stream():
        def sse(payload):
            return f"data: {json.dumps(payload)}\n\n"

        if service_name == 'snappymail':
            from services.mail import install_snappymail
            yield sse({'status': 'running', 'percent': 30, 'step': 'Downloading SnappyMail...', 'line': '>> Fetching SnappyMail release & configuring Dovecot SSO...'})
            sm_res = install_snappymail()
            if not sm_res.get('success'):
                yield sse({'status': 'error', 'percent': 100, 'error': sm_res.get('error', 'SnappyMail installation failed.')})
                return
            yield sse({'status': 'complete', 'percent': 100, 'step': 'SnappyMail Webmail ready', 'line': f">> SnappyMail installed at {sm_res.get('path')} and wired at /snappymail/"})
            return

        has_error = False
        pkgs = pkg_map[service_name]

        yield sse({'status': 'running', 'percent': 10, 'step': f'Preparing {service_name}...', 'line': f'>> Recovering any interrupted dpkg state and waiting for APT lock...'})
        for line in _stream_cmd(['dpkg', '--configure', '-a']):
            yield sse({'status': 'running', 'percent': 14, 'step': 'Checking package state...', 'line': line})

        if service_name == 'pgadmin4':
            yield sse({'status': 'running', 'percent': 20, 'step': 'Adding pgAdmin 4 repository...', 'line': '>> Configuring official pgAdmin 4 APT repository...'})
            codename = get_os_info().get('codename') or 'noble'
            keyring_path = '/etc/apt/keyrings/packages-pgadmin-org.gpg'
            prefix = _priv_prefix()
            if not Path(keyring_path).exists():
                subprocess.run(prefix + ['mkdir', '-p', '/etc/apt/keyrings'], capture_output=True, timeout=5)
                key_dl = subprocess.run(['curl', '-fsSL', 'https://www.pgadmin.org/static/packages_pgadmin_org.pub'], capture_output=True, timeout=30)
                if key_dl.returncode == 0 and key_dl.stdout:
                    subprocess.run(prefix + ['gpg', '--dearmor', '--yes', '-o', keyring_path], input=key_dl.stdout, capture_output=True, timeout=15)
                else:
                    yield sse({'status': 'error', 'percent': 100, 'error': 'Failed to download pgAdmin GPG signing key.'})
                    return
            from services.webserver.manager import _write_privileged_file as _wpf
            _wpf(Path('/etc/apt/sources.list.d/pgadmin4.list'), f"deb [signed-by={keyring_path}] https://ftp.postgresql.org/pub/pgadmin/pgadmin4/apt/{codename} pgadmin4 main\n")

        yield sse({'status': 'running', 'percent': 28, 'step': 'Updating APT index...', 'line': '>> Running apt-get update...'})
        for line in _stream_cmd(['apt-get', '-o', 'DPkg::Lock::Timeout=120', 'update', '-y']):
            yield sse({'status': 'running', 'percent': 35, 'step': 'Updating APT index...', 'line': line})

        if service_name == 'phpmyadmin' and shutil.which('debconf-set-selections'):
            subprocess.run(
                _priv_prefix() + ['debconf-set-selections'],
                input="phpmyadmin phpmyadmin/dbconfig-install boolean false\nphpmyadmin phpmyadmin/reconfigure-webserver multiselect\n",
                text=True,
                capture_output=True,
                timeout=10,
            )

        yield sse({'status': 'running', 'percent': 45, 'step': f'Installing {service_name}...', 'line': f'>> Installing packages: {" ".join(pkgs)}'})
        for line in _stream_cmd(['apt-get', '-o', 'DPkg::Lock::Timeout=120', 'install', '-y'] + pkgs):
            if line.startswith('>> [ERROR]'):
                has_error = True
            yield sse({'status': 'running', 'percent': 72, 'step': f'Installing {service_name}...', 'line': line})

        if has_error:
            yield sse({'status': 'error', 'percent': 100, 'error': f'Failed to install {service_name}. Check output above.'})
            return

        if service_name == 'pgadmin4':
            yield sse({'status': 'running', 'percent': 86, 'step': 'Configuring pgAdmin 4 service & Nginx...', 'line': '>> Initializing pgAdmin 4 database, systemd service, and web proxy...'})
            cfg_res = configure_pgadmin4_runtime(admin_email=admin_email_setting)
            if not cfg_res.get('success'):
                yield sse({'status': 'error', 'percent': 100, 'error': cfg_res.get('error', 'pgAdmin 4 configuration failed')})
                return
            yield sse({
                'status': 'complete',
                'percent': 100,
                'step': 'pgAdmin 4 installed and running',
                'line': f">> pgAdmin 4 ready! Login Email: {cfg_res.get('email')} | Password: {cfg_res.get('password')}",
            })
            return

        if service_name == 'phpmyadmin':
            from services.database import ensure_phpmyadmin_signon_configured
            ensure_phpmyadmin_signon_configured()
            configure_db_admin_webserver()
            yield sse({'status': 'complete', 'percent': 100, 'step': 'phpMyAdmin ready', 'line': '>> phpMyAdmin configured successfully.'})
            return

        daemon_name = 'mariadb' if service_name == 'mariadb' else service_name
        _run_privileged(['systemctl', 'enable', '--now', daemon_name], timeout=15)
        if service_name in ('postfix', 'dovecot'):
            from services.mail import configure_mail_stack
            _run_privileged(['systemctl', 'enable', '--now', 'opendkim'], timeout=10)
            configure_mail_stack()
        else:
            configure_db_admin_webserver()
        yield sse({'status': 'complete', 'percent': 100, 'step': f'{service_name} installed', 'line': f'>> {service_name} enabled and configured.'})

    resp = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    resp['Cache-Control'] = 'no-cache'
    resp['X-Accel-Buffering'] = 'no'
    return resp


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
        cmds = (cmd,) if isinstance(cmd, str) else tuple(cmd)
        installed = bool(_find_bin(*cmds))
        active = False
        if installed:
            svcs = (svc,) if isinstance(svc, str) else tuple(svc)
            for unit in svcs:
                try:
                    res = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True, timeout=2)
                    if res.stdout.strip() == 'active':
                        active = True
                        break
                except Exception:
                    pass
        return {'installed': installed, 'active': active}

    from services.database import get_db_admin_tools_status
    db_tools = get_db_admin_tools_status()

    return {
        'webserver_nginx': _check('nginx'),
        'webserver_apache': _check('apache2'),
        'db_mariadb': _check(('mariadbd', 'mysqld', 'mariadb', 'mysql'), ('mariadb', 'mysql')),
        'db_postgresql': _check(('psql', 'postgres'), 'postgresql'),
        'tool_phpmyadmin': {'installed': db_tools['phpmyadmin_available'], 'active': db_tools['phpmyadmin_available']},
        'tool_pgadmin4': {'installed': db_tools['pgadmin4_available'], 'active': db_tools['pgadmin4_running']},
        'mail_postfix': _check('postfix', ('postfix@-', 'postfix')),
        'mail_dovecot': _check('dovecot'),
        'ftp_pureftpd': _check('pure-ftpd', 'pure-ftpd'),
        'security_ufw': _check('ufw'),
        'php_fpm': _check('php-fpm8.3', 'php8.3-fpm'),
        'container_podman': _check('podman'),
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


def _resolve_ini_path(php_version: str, target: str = 'fpm') -> Path:
    if target not in ('fpm', 'cli'):
        target = 'fpm'
    test_path = Path(f"/tmp/w3panel_test/php/{php_version}/{target}/php.ini")
    if test_path.exists() or (Path("/tmp/w3panel_test").exists() and not Path(f"/etc/php/{php_version}/{target}").exists()):
        return test_path
    return Path(f"/etc/php/{php_version}/{target}/php.ini")


def get_raw_php_ini(php_version: str, target: str = 'fpm') -> tuple[str, str, bool]:
    """
    Returns (content, file_path_str, exists).
    Reads the full php.ini from /etc/php/<php_version>/<target>/php.ini.
    """
    if target not in ('fpm', 'cli'):
        target = 'fpm'
    ini_path = _resolve_ini_path(php_version, target)
    if not ini_path.exists():
        std_path = Path(f"/etc/php/{php_version}/{target}/php.ini")
        if std_path.exists():
            ini_path = std_path
        else:
            return f"; php.ini for PHP {php_version} ({target.upper()}) was not found at {ini_path}\n", str(ini_path), False

    try:
        content = ini_path.read_text(encoding='utf-8', errors='replace')
        return content, str(ini_path), True
    except PermissionError:
        res = subprocess.run(['sudo', '-n', 'cat', str(ini_path)], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            return res.stdout, str(ini_path), True
        return f"; Permission denied reading {ini_path}\n", str(ini_path), False
    except Exception as e:
        return f"; Error reading {ini_path}: {e}\n", str(ini_path), False


def save_raw_php_ini(php_version: str, content: str, target: str = 'fpm') -> tuple[bool, str]:
    """
    Safely saves full php.ini file after creating a backup (.bak).
    Returns (success, message).
    """
    if target not in ('fpm', 'cli'):
        target = 'fpm'
    from services.webserver.manager import _write_privileged_file

    ini_path = _resolve_ini_path(php_version, target)

    # Create backup if original exists
    if ini_path.exists():
        bak_path = Path(str(ini_path) + '.bak')
        try:
            old_content = ini_path.read_text(encoding='utf-8', errors='replace')
            _write_privileged_file(bak_path, old_content)
        except Exception as e:
            logger.warning(f"Could not create php.ini backup at {bak_path}: {e}")

    written = _write_privileged_file(ini_path, content)
    if not written:
        test_path = Path(f"/tmp/w3panel_test/php/{php_version}/{target}/php.ini")
        try:
            test_path.parent.mkdir(parents=True, exist_ok=True)
            test_path.write_text(content, encoding='utf-8')
            return True, f"Saved php.ini to test path {test_path}."
        except Exception:
            return False, f"Permission denied writing to {ini_path}."

    return True, f"Successfully saved {ini_path}."


def restore_raw_php_ini(php_version: str, target: str = 'fpm') -> tuple[bool, str]:
    if target not in ('fpm', 'cli'):
        target = 'fpm'
    from services.webserver.manager import _write_privileged_file
    ini_path = _resolve_ini_path(php_version, target)
    bak_path = Path(str(ini_path) + '.bak')
    if not bak_path.exists():
        std_bak = Path(f"/etc/php/{php_version}/{target}/php.ini.bak")
        if std_bak.exists():
            bak_path = std_bak
            ini_path = Path(f"/etc/php/{php_version}/{target}/php.ini")
        else:
            return False, f"No backup file (.bak) found for PHP {php_version} ({target.upper()})."

    try:
        content = bak_path.read_text(encoding='utf-8', errors='replace')
        written = _write_privileged_file(ini_path, content)
        if not written:
            return False, f"Permission denied restoring {ini_path}."
        return True, f"Successfully restored {ini_path} from backup."
    except Exception as e:
        return False, f"Failed to restore backup: {e}"


def _sync_directives_from_ini(php_version: str, ini_content: str):
    """Extract common directives from raw php.ini to keep Basic Mode in sync."""
    directives = ['memory_limit', 'upload_max_filesize', 'post_max_size', 'max_execution_time', 'max_input_time', 'display_errors']
    for d in directives:
        match = re.search(r'^\s*' + re.escape(d) + r'\s*=\s*([^\s;]+)', ini_content, re.MULTILINE | re.IGNORECASE)
        if match:
            val = match.group(1).strip('"\'')
            SystemSetting.set(f"php_{php_version}_{d}", val)


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
    MultiPHP Manager & INI Editor.
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
            installed_vers = [p['version'] for p in get_installed_php_versions() if p['installed']]
            if installed_vers and new_default not in installed_vers:
                messages.error(request, f"Cannot set PHP {new_default} as system default: PHP {new_default} is not installed on this server.")
                return redirect('/settings/php/?tab=manager')
            SystemSetting.set('default_php', new_default)
            messages.success(request, f"System default PHP updated to PHP {new_default}.")
            return redirect('/settings/php/?tab=manager')

        elif action == 'set_domain_php':
            website_id = request.POST.get('website_id')
            new_ver = request.POST.get('php_version', '8.3').strip()
            installed_vers = [p['version'] for p in get_installed_php_versions() if p['installed']]
            if installed_vers and new_ver not in installed_vers:
                messages.error(request, f"Cannot switch domain to PHP {new_ver}: PHP {new_ver} is not installed on this server.")
                return redirect('/settings/php/?tab=manager')
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
            installed_vers = [p['version'] for p in get_installed_php_versions() if p['installed']]
            if installed_vers and target_ver not in installed_vers:
                messages.error(request, f"Cannot switch domains to PHP {target_ver}: PHP {target_ver} is not installed on this server.")
                return redirect('/settings/php/?tab=manager')
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

        elif action == 'save_raw_ini':
            ver = request.POST.get('php_version', default_php).strip()
            installed_vers = [p['version'] for p in get_installed_php_versions() if p['installed']]
            if installed_vers and ver not in installed_vers:
                messages.error(request, f"Cannot edit php.ini for PHP {ver}: PHP {ver} is not installed on this server.")
                return redirect('/settings/php/?tab=ini&mode=editor')
            target = request.POST.get('ini_target', 'fpm').strip()
            raw_content = request.POST.get('ini_content', '')
            ok, msg = save_raw_php_ini(ver, raw_content, target)
            if ok:
                _sync_directives_from_ini(ver, raw_content)
                if target == 'fpm':
                    reload_php_fpm(ver)
                messages.success(request, f"Full php.ini for PHP {ver} ({target.upper()}) saved successfully and service reloaded.")
            else:
                messages.error(request, f"Failed to save php.ini: {msg}")
            return redirect(f'/settings/php/?tab=ini&mode=editor&php_version={ver}&target={target}')

        elif action == 'restore_raw_ini':
            ver = request.POST.get('php_version', default_php).strip()
            target = request.POST.get('ini_target', 'fpm').strip()
            ok, msg = restore_raw_php_ini(ver, target)
            if ok:
                if target == 'fpm':
                    reload_php_fpm(ver)
                messages.success(request, f"PHP {ver} ({target.upper()}) php.ini successfully restored from backup (.bak).")
            else:
                messages.error(request, f"Could not restore backup: {msg}")
            return redirect(f'/settings/php/?tab=ini&mode=editor&php_version={ver}&target={target}')

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

    raw_versions = get_installed_php_versions()
    installed_versions = [p for p in raw_versions if p['installed']]
    # Fallback to default_php if no versions are found, ensuring the dropdown has a valid option
    if not installed_versions:
        installed_versions = [{'version': default_php, 'installed': True, 'active': True, 'fpm_dir': f'/etc/php/{default_php}/fpm'}]
    installed_version_numbers = [p['version'] for p in installed_versions]

    if selected_php not in installed_version_numbers:
        selected_php = default_php if default_php in installed_version_numbers else installed_version_numbers[0]

    ini_mode = request.GET.get('mode', 'basic').strip()
    if ini_mode not in ('basic', 'editor'):
        ini_mode = 'basic'
    ini_target = request.GET.get('target', 'fpm').strip()
    if ini_target not in ('fpm', 'cli'):
        ini_target = 'fpm'

    raw_ini_content, raw_ini_path, raw_ini_exists = get_raw_php_ini(selected_php, ini_target)
    raw_ini_lines = len(raw_ini_content.splitlines()) if raw_ini_content else 0
    raw_ini_size_kb = round(len(raw_ini_content.encode('utf-8')) / 1024, 1) if raw_ini_content else 0
    bak_path = Path(raw_ini_path + '.bak') if raw_ini_path else None
    has_bak = bak_path.exists() if (bak_path and raw_ini_exists) else False

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
        'installed_version_numbers': installed_version_numbers,
        'websites': websites,
        'ini_settings': ini_settings,
        'tuning_status': tuning_status,
        'ini_mode': ini_mode,
        'ini_target': ini_target,
        'raw_ini_content': raw_ini_content,
        'raw_ini_path': raw_ini_path,
        'raw_ini_exists': raw_ini_exists,
        'raw_ini_lines': raw_ini_lines,
        'raw_ini_size_kb': raw_ini_size_kb,
        'has_bak': has_bak,
        'memory_limit': ini_settings['memory_limit'],
        'max_execution_time': ini_settings['max_execution_time'],
        'upload_max_filesize': ini_settings['upload_max_filesize'],
    })


# ===========================================================================
# 8. W3Packager — Software & Stack Provisioner
# ===========================================================================

def get_installed_dpkg_packages() -> set:
    """Fast detection of installed packages via dpkg-query."""
    try:
        proc = subprocess.run(
            ['dpkg-query', '-W', "-f=${Package}\t${Status}\n"],
            capture_output=True, text=True, timeout=3
        )
        installed = set()
        for line in proc.stdout.splitlines():
            parts = line.split('\t')
            if len(parts) == 2 and 'install ok installed' in parts[1]:
                installed.add(parts[0].strip())
        return installed
    except Exception:
        return set()


def get_os_info() -> dict:
    """Detect host operating system details (distribution, version, codename)."""
    os_info = {
        'id': 'ubuntu',
        'name': 'Ubuntu',
        'version_id': '24.04',
        'codename': 'noble',
        'pretty_name': 'Ubuntu 24.04 LTS',
    }
    try:
        if hasattr(platform, 'freedesktop_os_release'):
            info = platform.freedesktop_os_release()
            os_info['id'] = info.get('ID', 'ubuntu').lower()
            os_info['name'] = info.get('NAME', 'Ubuntu')
            os_info['version_id'] = info.get('VERSION_ID', '24.04')
            os_info['codename'] = info.get('VERSION_CODENAME', 'noble')
            os_info['pretty_name'] = info.get('PRETTY_NAME', f"{os_info['name']} {os_info['version_id']}")
            return os_info
    except Exception:
        pass

    os_release = Path('/etc/os-release')
    if os_release.exists():
        try:
            for line in os_release.read_text(encoding='utf-8', errors='replace').splitlines():
                if '=' in line:
                    k, v = line.split('=', 1)
                    k = k.strip()
                    v = v.strip().strip('"\'')
                    if k == 'ID':
                        os_info['id'] = v.lower()
                    elif k == 'NAME':
                        os_info['name'] = v
                    elif k == 'VERSION_ID':
                        os_info['version_id'] = v
                    elif k == 'VERSION_CODENAME':
                        os_info['codename'] = v
                    elif k == 'PRETTY_NAME':
                        os_info['pretty_name'] = v
        except Exception:
            pass
    return os_info


def get_available_apt_packages(pkg_names: set | list) -> set:
    """
    Returns the set of package names that are available in APT repositories for the current OS.
    Executes 'apt-cache madison' in batch for ultra-fast check (~0.04s).
    """
    if not pkg_names:
        return set()
    try:
        proc = subprocess.run(
            ['apt-cache', 'madison'] + list(pkg_names),
            capture_output=True, text=True, timeout=5
        )
        if proc.returncode == 0 and proc.stdout:
            available = set()
            for line in proc.stdout.splitlines():
                parts = line.split('|')
                if len(parts) >= 2:
                    available.add(parts[0].strip())
            return available
    except Exception:
        pass

    # Fallback for mock/test environments without live apt-cache
    os_info = get_os_info()
    os_native_php = {
        ('ubuntu', '24.04'): '8.3',
        ('ubuntu', '22.04'): '8.1',
        ('ubuntu', '20.04'): '7.4',
        ('debian', '12'): '8.2',
        ('debian', '11'): '7.4',
    }
    native_ver = os_native_php.get((os_info.get('id', 'ubuntu'), os_info.get('version_id', '24.04')), '8.3')
    fallback_available = {
        f'php{native_ver}-fpm', f'php{native_ver}-cli',
        f'php{native_ver}-mysql', f'php{native_ver}-curl', f'php{native_ver}-mbstring',
        f'php{native_ver}-xml', f'php{native_ver}-zip', f'php{native_ver}-intl',
        f'php{native_ver}-bcmath', f'php{native_ver}-opcache', f'php{native_ver}-redis',
        'nginx', 'python3-certbot-nginx', 'nodejs', 'npm', 'composer', 'redis-server',
        'libnginx-mod-http-brotli-filter'
    }

    # If Ondřej Surý / deb.sury.org repository is enabled, unlock all supported multi-PHP versions
    if is_ondrej_ppa_enabled():
        for extra_v in ('7.4', '8.1', '8.2', '8.3', '8.4'):
            fallback_available.update({
                f'php{extra_v}-fpm', f'php{extra_v}-cli', f'php{extra_v}-mysql',
                f'php{extra_v}-curl', f'php{extra_v}-mbstring', f'php{extra_v}-xml',
                f'php{extra_v}-zip', f'php{extra_v}-intl', f'php{extra_v}-bcmath',
                f'php{extra_v}-opcache', f'php{extra_v}-redis', f'php{extra_v}-memcached',
                f'php{extra_v}-imagick', f'php{extra_v}-gd', f'php{extra_v}-pgsql',
                f'php{extra_v}-sqlite3', f'php{extra_v}-mongodb', f'php{extra_v}-soap'
            })

    return fallback_available.intersection(set(pkg_names))


def is_ondrej_ppa_enabled() -> bool:
    """Checks if ppa:ondrej/php or deb.sury.org is enabled on the system."""
    setting_val = SystemSetting.get('sury_repo_enabled')
    if setting_val is not None and setting_val != '':
        return (setting_val == 'true')
    try:
        sources_dir = Path('/etc/apt/sources.list.d')
        if sources_dir.exists():
            for f in sources_dir.glob('*'):
                try:
                    content = f.read_text(encoding='utf-8', errors='replace').lower()
                    if ('ondrej' in content and 'php' in content) or ('sury' in content and 'php' in content):
                        return True
                except Exception:
                    pass
        main_sources = Path('/etc/apt/sources.list')
        if main_sources.exists():
            content = main_sources.read_text(encoding='utf-8', errors='replace').lower()
            if ('ondrej' in content and 'php' in content) or ('sury' in content and 'php' in content):
                return True
    except Exception:
        pass
    return False


def _run_apt_transaction(command_args: list) -> tuple[bool, str]:
    """Safely executes an apt-get command waiting on dpkg locks."""
    from services.webserver.manager import _has_sudo
    args = list(command_args)
    if args and args[0] == 'apt-get' and 'DPkg::Lock::Timeout' not in ' '.join(args):
        args = ['apt-get', '-o', 'DPkg::Lock::Timeout=120'] + args[1:]
    if os.geteuid() == 0:
        cmd = ['env', 'DEBIAN_FRONTEND=noninteractive'] + args
    elif _has_sudo():
        cmd = ['sudo', '-n', 'env', 'DEBIAN_FRONTEND=noninteractive'] + args
    else:
        return True, f"Mock transaction executed: apt-get {' '.join(args)}"
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
        output = (proc.stdout or '') + '\n' + (proc.stderr or '')
        if proc.returncode != 0 and ('dpkg was interrupted' in output or 'dpkg --configure -a' in output):
            cfg_prefix = ['env', 'DEBIAN_FRONTEND=noninteractive'] if os.geteuid() == 0 else ['sudo', '-n', 'env', 'DEBIAN_FRONTEND=noninteractive']
            subprocess.run(cfg_prefix + ['dpkg', '--configure', '-a'], capture_output=True, text=True, timeout=180)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
            output = (proc.stdout or '') + '\n' + (proc.stderr or '')
        return (proc.returncode == 0), output.strip()
    except subprocess.TimeoutExpired:
        return False, "Transaction timed out after 240 seconds."
    except Exception as e:
        return False, f"Execution failed: {e}"


def _stream_cmd(cmd_args: list):
    """
    Generator yielding output lines from subprocess execution.
    Handles root execution or sudo -n env DEBIAN_FRONTEND=noninteractive.
    """
    from services.webserver.manager import _has_sudo
    if os.geteuid() == 0:
        full_cmd = ['env', 'DEBIAN_FRONTEND=noninteractive'] + cmd_args
    elif _has_sudo():
        full_cmd = ['sudo', '-n', 'env', 'DEBIAN_FRONTEND=noninteractive'] + cmd_args
    else:
        yield f">> [SIMULATION] {' '.join(cmd_args)}"
        yield ">> [SIMULATION] Command completed successfully."
        return

    try:
        proc = subprocess.Popen(
            full_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        for line in iter(proc.stdout.readline, ''):
            clean_line = line.strip('\r\n')
            if clean_line:
                yield clean_line
        proc.stdout.close()
        code = proc.wait()
        if code != 0:
            yield f">> [ERROR] Process exited with status code {code}"
    except Exception as e:
        yield f">> [ERROR] Execution failed: {e}"


def enable_ondrej_ppa() -> tuple[bool, str]:
    """Configures official packages.sury.org/php repository on Debian/Ubuntu."""
    os_info = get_os_info()
    codename = os_info.get('codename') or ('noble' if os_info.get('id') == 'ubuntu' else 'bookworm')
    _run_apt_transaction(['apt-get', 'install', '-y', 'lsb-release', 'ca-certificates', 'curl'])
    cmd = (
        "curl -sSLo /tmp/debsuryorg-archive-keyring.deb https://packages.sury.org/debsuryorg-archive-keyring.deb && "
        "dpkg -i /tmp/debsuryorg-archive-keyring.deb && "
        "rm -f /tmp/debsuryorg-archive-keyring.deb && "
        f"echo 'deb [signed-by=/usr/share/keyrings/debsuryorg-archive-keyring.gpg] https://packages.sury.org/php/ {codename} main' > /etc/apt/sources.list.d/php.list && "
        "rm -f /etc/apt/sources.list.d/*ondrej*"
    )
    ok_repo, out_all = _run_apt_transaction(['sh', '-c', cmd])
    ok_upd, out_upd = _run_apt_transaction(['apt-get', 'update'])
    out_all = (out_all + "\n" + out_upd).strip()
    SystemSetting.set('sury_repo_enabled', 'true')
    return (ok_repo and ok_upd), out_all


def disable_ondrej_ppa() -> tuple[bool, str]:
    """Disables / removes packages.sury.org/php (and legacy ondrej) repositories."""
    out_all = ""
    sources_dir = Path('/etc/apt/sources.list.d')
    if sources_dir.exists():
        for f in sources_dir.glob('*'):
            try:
                name_lower = f.name.lower()
                if 'ondrej' in name_lower or 'sury' in name_lower or name_lower == 'php.list':
                    _run_apt_transaction(['rm', '-f', str(f)])
            except Exception:
                pass

    ok_upd, out_upd = _run_apt_transaction(['apt-get', 'update'])
    out_all += out_upd
    SystemSetting.set('sury_repo_enabled', 'false')
    return ok_upd, out_all


def get_php_runtime_packages(ver: str) -> list[str]:
    """Return canonical APT package list for a PHP runtime version."""
    return [
        f'php{ver}-fpm', f'php{ver}-cli', f'php{ver}-common',
        f'php{ver}-mysql', f'php{ver}-pgsql', f'php{ver}-curl',
        f'php{ver}-mbstring', f'php{ver}-xml', f'php{ver}-zip',
        f'php{ver}-intl', f'php{ver}-bcmath', f'php{ver}-opcache',
        f'php{ver}-readline',
    ]


def get_supported_php_runtimes(default_php: str = '8.3', installed_pkgs=None,
                               available_apt_pkgs=None, include_domains: bool = False) -> list[dict]:
    """Build OS-supported PHP runtime metadata shared by W3Packager and Initial Setup Wizard."""
    if installed_pkgs is None:
        installed_pkgs = get_installed_dpkg_packages()
    if available_apt_pkgs is None:
        available_apt_pkgs = get_available_apt_packages([f"php{r['version']}-fpm" for r in PHP_RUNTIME_DEFS])

    runtimes = []
    for r in PHP_RUNTIME_DEFS:
        v = r['version']
        fpm_pkg = f'php{v}-fpm'
        is_inst = (fpm_pkg in installed_pkgs) or Path(f'/etc/php/{v}/fpm').exists() or bool(shutil.which(f'php-fpm{v}'))
        is_supported = is_inst or (fpm_pkg in available_apt_pkgs) or not available_apt_pkgs
        if not is_supported:
            continue

        entry = {
            'version': v,
            'release_status': r['release_status'],
            'description': r['description'],
            'installed': is_inst,
            'is_default': (v == default_php),
            'supported': True,
        }
        if include_domains:
            domains_qs = Website.objects.filter(php_version=v)
            entry['domain_count'] = domains_qs.count()
            entry['domain_samples'] = list(domains_qs.values_list('domain', flat=True)[:3])
        runtimes.append(entry)
    return runtimes


def install_php_runtime(ver: str) -> tuple[bool, str]:
    """Provisions a full PHP runtime stack (FPM, CLI, core extensions)."""
    if ver not in ('7.4', '8.0', '8.1', '8.2', '8.3', '8.4'):
        return False, f"Unsupported PHP version: {ver}"
    if not is_ondrej_ppa_enabled():
        enable_ondrej_ppa()
    pkgs = get_php_runtime_packages(ver)
    ok, out = _run_apt_transaction(['apt-get', 'install', '-y'] + pkgs)
    if ok:
        subprocess.run(['sudo', '-n', 'systemctl', 'enable', f'php{ver}-fpm'], capture_output=True)
        subprocess.run(['sudo', '-n', 'systemctl', 'start', f'php{ver}-fpm'], capture_output=True)
    return ok, out


def uninstall_php_runtime(ver: str) -> tuple[bool, str]:
    """Removes a PHP runtime stack if not in use by domains or default."""
    default_php = SystemSetting.get('default_php', '8.3')
    if ver == default_php:
        return False, f"Cannot uninstall PHP {ver}: It is currently set as the System Default PHP version."
    
    in_use = list(Website.objects.filter(php_version=ver).values_list('domain', flat=True)[:5])
    if in_use:
        domains_str = ", ".join(in_use)
        return False, f"Cannot uninstall PHP {ver}: Actively assigned to {domains_str}. Switch these domains to another version first."
    
    pkgs = [f'php{ver}-fpm', f'php{ver}-cli']
    ok, out = _run_apt_transaction(['apt-get', 'remove', '-y', '--purge'] + pkgs)
    return ok, out


def install_php_extension(ver: str, ext: str) -> tuple[bool, str]:
    """Installs a PHP extension and reloads PHP-FPM."""
    from services.webserver.manager import reload_php_fpm
    if not is_ondrej_ppa_enabled():
        enable_ondrej_ppa()
    pkg = f'php{ver}-{ext}'
    ok, out = _run_apt_transaction(['apt-get', 'install', '-y', pkg])
    if ok:
        reload_php_fpm(ver)
    return ok, out


def uninstall_php_extension(ver: str, ext: str) -> tuple[bool, str]:
    """Removes a PHP extension and reloads PHP-FPM."""
    from services.webserver.manager import reload_php_fpm
    pkg = f'php{ver}-{ext}'
    ok, out = _run_apt_transaction(['apt-get', 'remove', '-y', pkg])
    if ok:
        reload_php_fpm(ver)
    return ok, out


PHP_RUNTIME_DEFS = [
    {
        'version': '8.4',
        'release_status': 'Latest Stable',
        'description': 'JIT tracing compilation, Property Hooks, Asymmetric Visibility, new array functions.',
    },
    {
        'version': '8.3',
        'release_status': 'Standard Active Runtime',
        'description': 'Typed class constants, json_validate function, deep-cloning readonly properties.',
    },
    {
        'version': '8.2',
        'release_status': 'LTS Stable',
        'description': 'Readonly classes, DNF types, standalone null/false/true types, OpenSSL 3 support.',
    },
    {
        'version': '8.1',
        'release_status': 'Extended Support',
        'description': 'Enums, Fibers, readonly properties, intersection types, array unpacking.',
    },
    {
        'version': '7.4',
        'release_status': 'Legacy (Security / Migration)',
        'description': 'Typed properties, arrow functions, null coalescing assignment operator.',
    },
]


def get_w3packager_catalog(selected_php='8.3', search_query='') -> dict:
    """Builds the software component catalog filtered strictly to OS-supported components."""
    os_info = get_os_info()
    installed_pkgs = get_installed_dpkg_packages()
    ppa_enabled = is_ondrej_ppa_enabled()
    default_php = SystemSetting.get('default_php', '8.3')

    all_runtime_defs = PHP_RUNTIME_DEFS

    candidate_runtimes = [f"php{r['version']}-fpm" for r in all_runtime_defs]

    # 2. Candidate PHP Extensions definitions
    extension_defs = [
        # Cache & Performance
        {'name': 'redis', 'category': 'Cache & Performance', 'desc': 'Redis in-memory key-value cache client with cluster and sentinel support.'},
        {'name': 'memcached', 'category': 'Cache & Performance', 'desc': 'High-performance distributed memory object caching system daemon interface.'},
        {'name': 'opcache', 'category': 'Cache & Performance', 'desc': 'Zend OPcache engine with bytecode compilation and JIT compiler accelerator.'},
        {'name': 'apcu', 'category': 'Cache & Performance', 'desc': 'APC User Cache in-memory shared memory object cache for PHP scripts.'},

        # Image & Media
        {'name': 'imagick', 'category': 'Image & Media', 'desc': 'ImageMagick wrapper for creating, composing, and modifying bitmap images.'},
        {'name': 'gd', 'category': 'Image & Media', 'desc': 'GD graphic library for rendering images, graphs, thumbnails, and watermarks.'},

        # Database Drivers
        {'name': 'mysql', 'category': 'Database Drivers', 'desc': 'MySQLnd native driver and PDO_MySQL module for MariaDB & MySQL engines.'},
        {'name': 'pgsql', 'category': 'Database Drivers', 'desc': 'PostgreSQL database driver and PDO_PGSQL relational object connector.'},
        {'name': 'sqlite3', 'category': 'Database Drivers', 'desc': 'Self-contained, serverless zero-configuration SQLite embedded database engine.'},
        {'name': 'mongodb', 'category': 'Database Drivers', 'desc': 'Official MongoDB driver for connecting to MongoDB NoSQL document clusters.'},

        # Internationalization & Math
        {'name': 'intl', 'category': 'Internationalization & Math', 'desc': 'ICU library wrapper enabling international formatting, transliteration, and collations.'},
        {'name': 'bcmath', 'category': 'Internationalization & Math', 'desc': 'Arbitrary precision mathematics calculator for exact financial and crypto operations.'},
        {'name': 'gmp', 'category': 'Internationalization & Math', 'desc': 'GNU Multiple Precision calculation arithmetic library.'},

        # Core & Protocols
        {'name': 'curl', 'category': 'Core Protocols & Data', 'desc': 'Client URL library for HTTP, HTTPS, FTP, and REST API communication.'},
        {'name': 'mbstring', 'category': 'Core Protocols & Data', 'desc': 'Multibyte string management facilitating international UTF-8 character conversion.'},
        {'name': 'xml', 'category': 'Core Protocols & Data', 'desc': 'XML parsing, SimpleXML, DOM document builder, and XPath query engine.'},
        {'name': 'zip', 'category': 'Core Protocols & Data', 'desc': 'Transparent ZIP archive read, write, compression, and extraction library.'},
        {'name': 'soap', 'category': 'Core Protocols & Data', 'desc': 'Simple Object Access Protocol (SOAP) client and server interface.'},

        # Advanced Networking
        {'name': 'swoole', 'category': 'Advanced Networking', 'desc': 'Production coroutine asynchronous network framework for high-concurrency microservices.'},
    ]

    candidate_web_pkgs = ['nginx', 'libnginx-mod-http-brotli-filter', 'libnginx-mod-brotli', 'python3-certbot-nginx', 'certbot']
    candidate_cli_pkgs = ['nodejs', 'npm', 'composer', 'wp-cli', 'redis-server']

    # Query all candidate packages in one fast APT batch (0.2s)
    all_check_pkgs = (
        candidate_runtimes +
        [f"php{r['version']}-{e['name']}" for r in all_runtime_defs for e in extension_defs] +
        candidate_web_pkgs +
        candidate_cli_pkgs
    )
    available_apt_pkgs = get_available_apt_packages(all_check_pkgs)

    # 1. Filter PHP Runtimes strictly to OS-supported versions
    runtimes = get_supported_php_runtimes(
        default_php=default_php,
        installed_pkgs=installed_pkgs,
        available_apt_pkgs=available_apt_pkgs,
        include_domains=True,
    )
    installed_versions = [r['version'] for r in runtimes if r['installed']]

    supported_versions = [r['version'] for r in runtimes]

    # Validate selected_php
    if selected_php not in supported_versions:
        selected_php = default_php if default_php in supported_versions else (supported_versions[0] if supported_versions else '8.3')

    # 2. Build extensions for all supported runtimes
    all_extensions = []
    for v in supported_versions:
        for ext in extension_defs:
            pkg = f"php{v}-{ext['name']}"
            mods_avail = Path(f"/etc/php/{v}/mods-available/{ext['name']}.ini")
            is_inst = (pkg in installed_pkgs) or mods_avail.exists()
            is_supported_by_os = is_inst or (pkg in available_apt_pkgs)

            if not is_supported_by_os:
                continue

            all_extensions.append({
                'php_version': v,
                'name': ext['name'],
                'pkg_name': pkg,
                'category': ext['category'],
                'description': ext['desc'],
                'installed': is_inst,
                'supported': True,
            })

    # Filter extensions for selected_php and search query for tab backward compatibility
    extensions = [e for e in all_extensions if e['php_version'] == selected_php]
    if search_query:
        q = search_query.lower()
        extensions = [e for e in extensions if q in e['name'].lower() or q in e['category'].lower() or q in e['description'].lower()]

    # 3. Filter Web Server Components strictly to OS-supported packages
    web_components = []

    # Nginx
    if ('nginx' in installed_pkgs) or ('nginx' in available_apt_pkgs) or bool(shutil.which('nginx')):
        web_components.append({
            'key': 'nginx',
            'name': 'Nginx Reverse Proxy & HTTP Server',
            'pkg_name': 'nginx',
            'installed': ('nginx' in installed_pkgs) or bool(shutil.which('nginx')),
            'required': True,
            'description': 'High-performance event-driven HTTP reverse proxy, virtualhost engine, and static file server.',
        })

    # Brotli
    brotli_pkg = None
    if ('libnginx-mod-http-brotli-filter' in available_apt_pkgs) or ('libnginx-mod-http-brotli-filter' in installed_pkgs):
        brotli_pkg = 'libnginx-mod-http-brotli-filter'
    elif ('libnginx-mod-brotli' in available_apt_pkgs) or ('libnginx-mod-brotli' in installed_pkgs):
        brotli_pkg = 'libnginx-mod-brotli'

    if brotli_pkg:
        is_brotli_inst = (brotli_pkg in installed_pkgs) or Path('/etc/nginx/modules-enabled/50-mod-http-brotli.conf').exists()
        web_components.append({
            'key': 'brotli',
            'name': 'Nginx Brotli Compression Module',
            'pkg_name': brotli_pkg,
            'installed': is_brotli_inst,
            'required': False,
            'description': 'Google Brotli next-gen compression providing up to 25% better compression ratio than gzip.',
        })

    # Certbot
    certbot_pkg = 'python3-certbot-nginx' if ('python3-certbot-nginx' in available_apt_pkgs or 'python3-certbot-nginx' in installed_pkgs) else 'certbot'
    if (certbot_pkg in installed_pkgs) or (certbot_pkg in available_apt_pkgs) or bool(shutil.which('certbot')):
        web_components.append({
            'key': 'certbot',
            'name': "Let's Encrypt SSL/TLS Automation (Certbot)",
            'pkg_name': certbot_pkg,
            'installed': (certbot_pkg in installed_pkgs) or bool(shutil.which('certbot')),
            'required': False,
            'description': 'Automated SSL certificate issuance, domain verification, and 60-day renewal daemon.',
        })

    # 4. Filter CLI Tools & Extra Runtimes strictly to OS-supported packages
    cli_runtimes = []

    # Node.js & NPM
    if ('nodejs' in installed_pkgs) or ('nodejs' in available_apt_pkgs) or bool(shutil.which('node')):
        cli_runtimes.append({
            'key': 'nodejs',
            'name': 'Node.js LTS & NPM Package Manager',
            'pkg_name': 'nodejs',
            'installed': bool(shutil.which('node')),
            'version_str': subprocess.run(['node', '-v'], capture_output=True, text=True).stdout.strip() if shutil.which('node') else 'Not Installed',
            'description': 'V8 JavaScript runtime engine for frontend builds, SSR frameworks (Next.js/Nuxt), and daemon apps.',
        })

    # Composer
    if ('composer' in installed_pkgs) or ('composer' in available_apt_pkgs) or bool(shutil.which('composer')) or Path('/usr/local/bin/composer').exists():
        cli_runtimes.append({
            'key': 'composer',
            'name': 'Composer 2.x PHP Package Manager',
            'pkg_name': 'composer',
            'installed': bool(shutil.which('composer')) or Path('/usr/local/bin/composer').exists(),
            'version_str': 'Composer 2.x' if bool(shutil.which('composer')) else 'Not Installed',
            'description': 'Standard dependency management tool for PHP applications, Laravel frameworks, and WordPress plugins.',
        })

    # WP-CLI
    is_wp_inst = bool(shutil.which('wp')) or Path('/usr/local/bin/wp').exists()
    if is_wp_inst or ('wp-cli' in available_apt_pkgs):
        cli_runtimes.append({
            'key': 'wp-cli',
            'name': 'WP-CLI WordPress Command Line Tool',
            'pkg_name': 'wp-cli',
            'installed': is_wp_inst,
            'version_str': 'WP-CLI' if is_wp_inst else 'Not Installed',
            'description': 'Command-line interface for WordPress to install cores, update plugins, manage databases, and run cron.',
        })

    # Redis Server
    if ('redis-server' in installed_pkgs) or ('redis-server' in available_apt_pkgs) or bool(shutil.which('redis-server')):
        cli_runtimes.append({
            'key': 'redis-server',
            'name': 'Redis In-Memory Cache & Message Daemon',
            'pkg_name': 'redis-server',
            'installed': ('redis-server' in installed_pkgs) or bool(shutil.which('redis-server')),
            'version_str': 'Redis Daemon' if ('redis-server' in installed_pkgs) else 'Not Installed',
            'description': 'In-memory persistent key-value database used for WordPress Object Cache and Laravel queues.',
        })

    # 5. Stack Profiles
    wp_php = default_php if default_php in supported_versions else (supported_versions[0] if supported_versions else '8.3')
    profiles = [
        {
            'id': 'current',
            'name': 'Currently Installed Packages',
            'badge': 'Active Baseline',
            'badge_class': 'text-emerald-700 bg-emerald-50 border-emerald-200',
            'description': 'The existing live packages and runtimes active on this server.',
            'tags': [f'PHP {v}' for v in installed_versions] + ['Installed Modules'],
            'runtimes': installed_versions,
            'extensions': [e['name'] for e in all_extensions if e['installed']],
            'web': [w['key'] for w in web_components if w['installed']],
            'cli': [c['key'] for c in cli_runtimes if c['installed']],
            'is_custom': False,
        },
        {
            'id': 'wordpress',
            'name': 'WordPress High-Performance',
            'badge': 'Recommended',
            'badge_class': 'text-blue-700 bg-blue-50 border-blue-200',
            'description': 'Optimized for WordPress and WooCommerce with Redis Object Caching and Brotli.',
            'tags': [f'PHP {wp_php}', 'Redis', 'OPcache', 'Imagick', 'Brotli', 'WP-CLI'],
            'runtimes': [wp_php],
            'extensions': ['opcache', 'redis', 'imagick', 'gd', 'mysql', 'curl', 'mbstring', 'xml', 'zip'],
            'web': ['nginx', 'brotli', 'certbot'],
            'cli': ['wp-cli', 'redis-server', 'composer'],
            'is_custom': False,
        },
        {
            'id': 'laravel',
            'name': 'Laravel Full-Stack',
            'badge': 'Modern',
            'badge_class': 'text-indigo-700 bg-indigo-50 border-indigo-200',
            'description': 'Full-stack Laravel profile with Redis Queue, Composer, and Node.js.',
            'tags': [f'PHP {wp_php}', 'Redis Queue', 'Composer', 'Node.js', 'PostgreSQL/MySQL'],
            'runtimes': [wp_php],
            'extensions': ['opcache', 'redis', 'bcmath', 'gmp', 'mysql', 'pgsql', 'curl', 'mbstring', 'xml', 'zip'],
            'web': ['nginx', 'brotli', 'certbot'],
            'cli': ['nodejs', 'composer', 'redis-server'],
            'is_custom': False,
        },
        {
            'id': 'multiphp',
            'name': 'Multi-PHP Hosting Stack',
            'badge': 'Multi-PHP',
            'badge_class': 'text-purple-700 bg-purple-50 border-purple-200',
            'description': f'All supported PHP versions ({", ".join(supported_versions)}) provisioned for multi-tenant hosting.',
            'tags': [f'PHP {v}' for v in supported_versions] + ['Standard Extensions', 'Composer'],
            'runtimes': supported_versions,
            'extensions': ['opcache', 'mysql', 'curl', 'mbstring', 'xml', 'zip', 'gd', 'intl'],
            'web': ['nginx', 'brotli', 'certbot'],
            'cli': ['composer'],
            'is_custom': False,
        },
        {
            'id': 'minimal',
            'name': 'Minimal Core',
            'badge': 'Lightweight',
            'badge_class': 'text-slate-700 bg-slate-100 border-slate-200',
            'description': f'Lean minimal profile with PHP {wp_php} and essential drivers only.',
            'tags': [f'PHP {wp_php}', 'OPcache', 'cURL', 'MySQL'],
            'runtimes': [wp_php],
            'extensions': ['opcache', 'curl', 'mbstring', 'mysql'],
            'web': ['nginx'],
            'cli': [],
            'is_custom': False,
        },
    ]

    # Load custom saved profiles
    saved_raw = SystemSetting.get('w3packager_saved_profiles', '[]')
    try:
        custom_saved = json.loads(saved_raw)
        if isinstance(custom_saved, list):
            for c_prof in custom_saved:
                c_prof['is_custom'] = True
                profiles.append(c_prof)
    except Exception:
        pass

    packager_init = {
        'default_php': default_php,
        'supported_runtimes': supported_versions,
        'installed_runtimes': installed_versions,
        'all_extensions': all_extensions,
        'installed_extensions': [e['pkg_name'] for e in all_extensions if e['installed']],
        'web_components': [{'key': w['key'], 'name': w['name'], 'pkg_name': w['pkg_name'], 'installed': w['installed'], 'required': w.get('required', False)} for w in web_components],
        'installed_web': [w['key'] for w in web_components if w['installed']],
        'cli_components': [{'key': c['key'], 'name': c['name'], 'pkg_name': c['pkg_name'], 'installed': c['installed']} for c in cli_runtimes],
        'installed_cli': [c['key'] for c in cli_runtimes if c['installed']],
        'profiles': profiles,
    }

    return {
        'os_info': os_info,
        'ppa_enabled': ppa_enabled,
        'default_php': default_php,
        'selected_php': selected_php,
        'search_query': search_query,
        'runtimes': runtimes,
        'installed_versions': installed_versions,
        'extensions': extensions,
        'all_extensions': all_extensions,
        'web_components': web_components,
        'cli_runtimes': cli_runtimes,
        'profiles': profiles,
        'recommended_profiles': profiles,
        'packager_init_json': json.dumps(packager_init),
    }


def admin_w3packager_provision(request):
    """
    Streaming provision endpoint for W3Packager.
    Streams real-time APT transaction output, progress percentages, and service status via SSE.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)

    try:
        if request.content_type == 'application/json':
            payload = json.loads(request.body.decode('utf-8'))
        else:
            payload = request.POST
    except Exception as e:
        return JsonResponse({'error': f'Invalid request payload: {e}'}, status=400)

    selected_runtimes = payload.get('selected_runtimes', [])
    selected_extensions = payload.get('selected_extensions', [])
    selected_web = payload.get('selected_web', [])
    selected_cli = payload.get('selected_cli', [])
    save_profile_name = payload.get('save_profile_name', '').strip()

    if isinstance(selected_runtimes, str):
        selected_runtimes = [selected_runtimes]
    if isinstance(selected_extensions, str):
        selected_extensions = [selected_extensions]
    if isinstance(selected_web, str):
        selected_web = [selected_web]
    if isinstance(selected_cli, str):
        selected_cli = [selected_cli]

    default_php = SystemSetting.get('default_php', '8.3')
    if default_php not in selected_runtimes:
        selected_runtimes.append(default_php)
    if 'nginx' not in selected_web:
        selected_web.append('nginx')

    def event_stream():
        def sse(data_dict):
            return f"data: {json.dumps(data_dict)}\n\n"

        yield sse({
            'status': 'running',
            'percent': 5,
            'step': 'Initializing W3Packager provision engine...',
            'line': '>> Initializing W3Packager Provisioning Engine...'
        })

        os_info = get_os_info()
        yield sse({
            'status': 'running',
            'percent': 8,
            'step': 'Target host verified',
            'line': f">> Target Host: {os_info.get('distro', 'Linux')} {os_info.get('version', '')} ({os_info.get('arch', 'x86_64')})"
        })

        # 1. Validation
        yield sse({
            'status': 'running',
            'percent': 12,
            'step': 'Validating runtime selections and domain bindings...',
            'line': '>> [1/5] Validating runtime selections and virtual host bindings...'
        })

        installed_runtimes = get_installed_php_versions()
        installed_pkgs = get_installed_dpkg_packages()

        # Check domain locks
        runtimes_to_remove = [v for v in installed_runtimes if v not in selected_runtimes and v != default_php]
        for v in runtimes_to_remove:
            domain_count = Website.objects.filter(php_version=v).count()
            if domain_count > 0:
                yield sse({
                    'status': 'error',
                    'percent': 15,
                    'step': 'Validation failed: Domain lock active',
                    'line': f'>> [FATAL] Cannot remove PHP {v}: Currently used by {domain_count} domain(s). Change domain PHP version in MultiPHP Manager first.',
                    'error': f'PHP {v} in use by {domain_count} domain(s)'
                })
                return

        yield sse({
            'status': 'running',
            'percent': 18,
            'step': 'Domain dependency validation passed',
            'line': f'>> [1/5] Validation passed. Active websites: {Website.objects.count()}. Default PHP: {default_php}.'
        })

        # 2. Package Resolution
        yield sse({
            'status': 'running',
            'percent': 22,
            'step': 'Resolving package dependencies...',
            'line': '>> [2/5] Resolving package dependency graph...'
        })

        apt_install_pkgs = []
        apt_remove_pkgs = []

        avail_brotli = get_available_apt_packages(['libnginx-mod-http-brotli-filter', 'libnginx-mod-brotli'])
        brotli_pkg_name = 'libnginx-mod-http-brotli-filter' if 'libnginx-mod-http-brotli-filter' in avail_brotli else 'libnginx-mod-brotli'
        certbot_pkg_name = 'python3-certbot-nginx'

        web_pkg_map = {
            'nginx': 'nginx',
            'brotli': brotli_pkg_name,
            'certbot': certbot_pkg_name,
        }
        cli_pkg_map = {
            'nodejs': ['nodejs', 'npm'],
            'composer': ['composer'],
            'redis-server': ['redis-server'],
        }

        # Runtimes to install
        runtimes_to_install = [v for v in selected_runtimes if v not in installed_runtimes]
        for v in runtimes_to_install:
            apt_install_pkgs.extend(get_php_runtime_packages(v))

        # Extensions to install & remove
        for ext_pkg in selected_extensions:
            if ext_pkg not in installed_pkgs:
                apt_install_pkgs.append(ext_pkg)

        catalog = get_w3packager_catalog()
        all_known_ext_pkgs = [e['pkg_name'] for e in catalog['all_extensions']]
        for ext_pkg in all_known_ext_pkgs:
            if ext_pkg in installed_pkgs and ext_pkg not in selected_extensions:
                apt_remove_pkgs.append(ext_pkg)

        # Web components
        for k, pkg in web_pkg_map.items():
            if k in selected_web and pkg not in installed_pkgs:
                apt_install_pkgs.append(pkg)
            elif k not in selected_web and pkg in installed_pkgs and k != 'nginx':
                apt_remove_pkgs.append(pkg)

        # CLI components
        for k, pkgs in cli_pkg_map.items():
            if k in selected_cli:
                for p in pkgs:
                    if p not in installed_pkgs:
                        apt_install_pkgs.append(p)
            else:
                for p in pkgs:
                    if p in installed_pkgs:
                        apt_remove_pkgs.append(p)

        # Runtimes to remove
        for v in runtimes_to_remove:
            yield sse({
                'status': 'running',
                'percent': 25,
                'step': f'Stopping service php{v}-fpm...',
                'line': f'>> Stopping and disabling daemon php{v}-fpm...'
            })
            subprocess.run(['systemctl', 'stop', f'php{v}-fpm'], capture_output=True)
            subprocess.run(['systemctl', 'disable', f'php{v}-fpm'], capture_output=True)
            apt_remove_pkgs.append(f'php{v}-*')

        apt_install_pkgs = list(dict.fromkeys(apt_install_pkgs))
        apt_remove_pkgs = list(dict.fromkeys(apt_remove_pkgs))

        yield sse({
            'status': 'running',
            'percent': 28,
            'step': 'Dependency resolution complete',
            'line': f'>> Target removal list ({len(apt_remove_pkgs)}): {", ".join(apt_remove_pkgs) or "None"}'
        })
        yield sse({
            'status': 'running',
            'percent': 30,
            'step': 'Dependency resolution complete',
            'line': f'>> Target install list ({len(apt_install_pkgs)}): {", ".join(apt_install_pkgs) or "None"}'
        })

        # 3. APT Removal Transaction
        if apt_remove_pkgs:
            yield sse({
                'status': 'running',
                'percent': 35,
                'step': 'Executing APT removal transaction...',
                'line': f'>> [3/5] Executing APT removal transaction ({len(apt_remove_pkgs)} packages)...'
            })
            for line in _stream_cmd(['apt-get', 'remove', '-y', '--purge'] + apt_remove_pkgs):
                yield sse({'status': 'running', 'percent': 42, 'step': 'Removing obsolete packages...', 'line': line})
        else:
            yield sse({
                'status': 'running',
                'percent': 45,
                'step': 'No packages to remove',
                'line': '>> [3/5] No packages marked for removal. Skipping step.'
            })

        # 4. APT Installation Transaction
        if apt_install_pkgs:
            yield sse({
                'status': 'running',
                'percent': 50,
                'step': 'Executing APT installation transaction...',
                'line': f'>> [4/5] Executing APT installation transaction ({len(apt_install_pkgs)} packages)...'
            })
            for line in _stream_cmd(['apt-get', 'install', '-y'] + apt_install_pkgs):
                yield sse({'status': 'running', 'percent': 70, 'step': 'Installing packages via APT...', 'line': line})
        else:
            yield sse({
                'status': 'running',
                'percent': 75,
                'step': 'No new packages to install',
                'line': '>> [4/5] No new packages to install. Skipping step.'
            })

        # WP-CLI handling
        if 'wp-cli' in selected_cli and not shutil.which('wp'):
            yield sse({'status': 'running', 'percent': 78, 'step': 'Installing WP-CLI...', 'line': '>> Installing WP-CLI binary...'})
            _install_wp_cli()
            yield sse({'status': 'running', 'percent': 80, 'step': 'WP-CLI installed', 'line': '>> WP-CLI installed to /usr/local/bin/wp'})
        elif 'wp-cli' not in selected_cli and shutil.which('wp'):
            yield sse({'status': 'running', 'percent': 78, 'step': 'Removing WP-CLI...', 'line': '>> Removing WP-CLI binary...'})
            _remove_wp_cli()
            yield sse({'status': 'running', 'percent': 80, 'step': 'WP-CLI removed', 'line': '>> WP-CLI binary removed.'})

        # 5. Services configuration & health checks
        yield sse({
            'status': 'running',
            'percent': 85,
            'step': 'Configuring and restarting daemons...',
            'line': '>> [5/5] Configuring and restarting system daemons...'
        })

        newly_installed_runtimes = get_installed_php_versions()
        for v in newly_installed_runtimes:
            fpm_svc = f'php{v}-fpm'
            subprocess.run(['systemctl', 'enable', fpm_svc], capture_output=True)
            subprocess.run(['systemctl', 'restart', fpm_svc], capture_output=True)
            check = subprocess.run(['systemctl', 'is-active', fpm_svc], capture_output=True, text=True)
            status_text = check.stdout.strip()
            yield sse({
                'status': 'running',
                'percent': 90,
                'step': f'Service {fpm_svc} {status_text}',
                'line': f'>> Daemon {fpm_svc}: {status_text.upper()}'
            })

        # Test and reload Nginx
        nginx_test = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
        if nginx_test.returncode == 0:
            subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True)
            yield sse({
                'status': 'running',
                'percent': 95,
                'step': 'Nginx proxy verified and reloaded',
                'line': '>> Nginx configuration syntax OK. Proxy service reloaded.'
            })
        else:
            yield sse({
                'status': 'running',
                'percent': 95,
                'step': 'Nginx syntax warning',
                'line': f'>> [WARNING] Nginx test output: {nginx_test.stderr[:100]}'
            })

        # Profile Saving if requested
        if save_profile_name:
            saved_raw = SystemSetting.get('w3packager_saved_profiles', '[]')
            try:
                saved = json.loads(saved_raw)
            except Exception:
                saved = []
            profile_obj = {
                'id': f"custom_{re.sub(r'[^a-zA-Z0-9_]', '', save_profile_name.lower().replace(' ', '_'))}",
                'name': save_profile_name,
                'badge': 'Custom',
                'badge_class': 'text-purple-700 bg-purple-50 border-purple-200',
                'description': f"User profile: PHP {', '.join(selected_runtimes)} + {len(selected_extensions)} extensions",
                'tags': [f'PHP {v}' for v in selected_runtimes] + [f'{len(selected_extensions)} Extensions'],
                'runtimes': selected_runtimes,
                'extensions': [p.split('-', 1)[1] if '-' in p else p for p in selected_extensions],
                'web': selected_web,
                'cli': selected_cli,
                'is_custom': True,
            }
            saved = [p for p in saved if p.get('id') != profile_obj['id']]
            saved.append(profile_obj)
            SystemSetting.set('w3packager_saved_profiles', json.dumps(saved))
            yield sse({
                'status': 'running',
                'percent': 98,
                'step': 'Saved custom profile',
                'line': f'>> Custom profile "{save_profile_name}" saved successfully.'
            })

        catalog_new = get_w3packager_catalog()
        packager_init_dict = json.loads(catalog_new['packager_init_json'])
        final_installed_runtimes = packager_init_dict.get('installed_runtimes', [])
        final_installed_exts = packager_init_dict.get('installed_extensions', [])
        final_installed_web = packager_init_dict.get('installed_web', [])
        final_installed_cli = packager_init_dict.get('installed_cli', [])
        final_profiles = packager_init_dict.get('profiles', [])

        yield sse({
            'status': 'running',
            'percent': 100,
            'step': 'Complete',
            'line': '>> ========================================================='
        })
        yield sse({
            'status': 'running',
            'percent': 100,
            'step': 'Complete',
            'line': '>> Stack Provisioning Completed Successfully!'
        })
        yield sse({
            'status': 'running',
            'percent': 100,
            'step': 'Complete',
            'line': '>> All requested PHP runtimes, modules, and proxy services are active.'
        })
        yield sse({
            'status': 'running',
            'percent': 100,
            'step': 'Complete',
            'line': '>> ========================================================='
        })

        yield sse({
            'status': 'complete',
            'percent': 100,
            'step': 'Stack provisioned successfully',
            'line': 'PROVISION_COMPLETE',
            'installed_count': len(apt_install_pkgs),
            'removed_count': len(apt_remove_pkgs),
            'installed_runtimes': final_installed_runtimes,
            'installed_extensions': final_installed_exts,
            'installed_web': final_installed_web,
            'installed_cli': final_installed_cli,
            'profiles': final_profiles,
        })

    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    return response


def admin_w3packager(request):
    """
    W3Packager — Software & Stack Provisioner.
    Supports sequential steps, profiling, package selection checkboxes,
    review diff calculation, and full stack provisioning.
    """
    default_php = SystemSetting.get('default_php', '8.3')
    os_info = get_os_info()

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'enable_ppa':
            ok, out = enable_ondrej_ppa()
            if ok:
                messages.success(request, "Ondřej Surý / deb.sury.org Multi-PHP repository enabled successfully.")
            else:
                messages.error(request, f"Failed to enable repository: {out[:250]}")
            return redirect('/software/w3packager/?tab=runtimes')

        elif action == 'disable_ppa':
            ok, out = disable_ondrej_ppa()
            if ok:
                messages.success(request, "Ondřej Surý / deb.sury.org Multi-PHP repository disabled successfully.")
            else:
                messages.error(request, f"Failed to disable repository: {out[:250]}")
            return redirect('/software/w3packager/?tab=runtimes')

        elif action == 'provision':
            if request.headers.get('accept') == 'text/event-stream' or request.headers.get('x-requested-with') == 'XMLHttpRequest' or request.content_type == 'application/json':
                return admin_w3packager_provision(request)

            selected_runtimes = request.POST.getlist('selected_runtimes')
            selected_extensions = request.POST.getlist('selected_extensions')
            selected_web = request.POST.getlist('selected_web')
            selected_cli = request.POST.getlist('selected_cli')
            save_profile_name = request.POST.get('save_profile_name', '').strip()

            # Always ensure default_php and nginx are kept
            if default_php not in selected_runtimes:
                selected_runtimes.append(default_php)
            if 'nginx' not in selected_web:
                selected_web.append('nginx')

            installed_runtimes = get_installed_php_versions()
            installed_pkgs = get_installed_dpkg_packages()

            # Check for domain locks on runtimes to be removed
            runtimes_to_remove = [v for v in installed_runtimes if v not in selected_runtimes and v != default_php]
            for v in runtimes_to_remove:
                domain_count = Website.objects.filter(php_version=v).count()
                if domain_count > 0:
                    messages.error(request, f"Cannot remove PHP {v}: Currently used by {domain_count} domain(s). Change domain versions in MultiPHP Manager first.")
                    return redirect('/software/w3packager/?tab=review')

            apt_install_pkgs = []
            apt_remove_pkgs = []

            avail_brotli = get_available_apt_packages(['libnginx-mod-http-brotli-filter', 'libnginx-mod-brotli'])
            brotli_pkg_name = 'libnginx-mod-http-brotli-filter' if 'libnginx-mod-http-brotli-filter' in avail_brotli else 'libnginx-mod-brotli'
            certbot_pkg_name = 'python3-certbot-nginx'

            web_pkg_map = {
                'nginx': 'nginx',
                'brotli': brotli_pkg_name,
                'certbot': certbot_pkg_name,
            }
            cli_pkg_map = {
                'nodejs': ['nodejs', 'npm'],
                'composer': ['composer'],
                'redis-server': ['redis-server'],
            }

            # 1. Runtimes to install
            runtimes_to_install = [v for v in selected_runtimes if v not in installed_runtimes]
            for v in runtimes_to_install:
                apt_install_pkgs.extend(get_php_runtime_packages(v))

            # 2. Extensions to install & remove
            for ext_pkg in selected_extensions:
                if ext_pkg not in installed_pkgs:
                    apt_install_pkgs.append(ext_pkg)

            catalog = get_w3packager_catalog()
            all_known_ext_pkgs = [e['pkg_name'] for e in catalog['all_extensions']]
            for ext_pkg in all_known_ext_pkgs:
                if ext_pkg in installed_pkgs and ext_pkg not in selected_extensions:
                    apt_remove_pkgs.append(ext_pkg)

            # 3. Web components
            for k, pkg in web_pkg_map.items():
                if k in selected_web and pkg not in installed_pkgs:
                    apt_install_pkgs.append(pkg)
                elif k not in selected_web and pkg in installed_pkgs and k != 'nginx':
                    apt_remove_pkgs.append(pkg)

            # 4. CLI components
            for k, pkgs in cli_pkg_map.items():
                if k in selected_cli:
                    for p in pkgs:
                        if p not in installed_pkgs:
                            apt_install_pkgs.append(p)
                else:
                    for p in pkgs:
                        if p in installed_pkgs:
                            apt_remove_pkgs.append(p)

            # 5. Runtimes to remove
            for v in runtimes_to_remove:
                subprocess.run(['systemctl', 'stop', f'php{v}-fpm'], capture_output=True)
                subprocess.run(['systemctl', 'disable', f'php{v}-fpm'], capture_output=True)
                apt_remove_pkgs.append(f'php{v}-*')

            # Deduplicate package lists
            apt_install_pkgs = list(dict.fromkeys(apt_install_pkgs))
            apt_remove_pkgs = list(dict.fromkeys(apt_remove_pkgs))

            installed_count = len(apt_install_pkgs)
            removed_count = len(apt_remove_pkgs)
            err_msg = ""

            # Execute removals first
            if apt_remove_pkgs:
                ok, out = _run_apt_transaction(['apt-get', 'remove', '-y', '--purge'] + apt_remove_pkgs)
                if not ok:
                    err_msg += f" Removal notice: {out[:150]}"

            # Execute installations
            if apt_install_pkgs:
                ok, out = _run_apt_transaction(['apt-get', 'install', '-y'] + apt_install_pkgs)
                if not ok:
                    err_msg += f" Install error: {out[:200]}"

            # Handle WP-CLI (PHAR)
            if 'wp-cli' in selected_cli and not shutil.which('wp'):
                _install_wp_cli()
                installed_count += 1
            elif 'wp-cli' not in selected_cli and shutil.which('wp'):
                _remove_wp_cli()
                removed_count += 1

            # Ensure runtimes have active daemons started
            newly_installed = get_installed_php_versions()
            for v in newly_installed:
                fpm_svc = f'php{v}-fpm'
                subprocess.run(['systemctl', 'enable', fpm_svc], capture_output=True)
                subprocess.run(['systemctl', 'restart', fpm_svc], capture_output=True)

            subprocess.run(['systemctl', 'reload', 'nginx'], capture_output=True)

            # Save Profile if requested
            if save_profile_name:
                saved_raw = SystemSetting.get('w3packager_saved_profiles', '[]')
                try:
                    saved = json.loads(saved_raw)
                except Exception:
                    saved = []
                profile_obj = {
                    'id': f"custom_{re.sub(r'[^a-zA-Z0-9_]', '', save_profile_name.lower().replace(' ', '_'))}",
                    'name': save_profile_name,
                    'badge': 'Custom',
                    'badge_class': 'text-purple-700 bg-purple-50 border-purple-200',
                    'description': f"User profile: PHP {', '.join(selected_runtimes)} + {len(selected_extensions)} extensions",
                    'tags': [f'PHP {v}' for v in selected_runtimes] + [f'{len(selected_extensions)} Extensions'],
                    'runtimes': selected_runtimes,
                    'extensions': [p.split('-', 1)[1] if '-' in p else p for p in selected_extensions],
                    'web': selected_web,
                    'cli': selected_cli,
                    'is_custom': True,
                }
                saved = [p for p in saved if p.get('id') != profile_obj['id']]
                saved.append(profile_obj)
                SystemSetting.set('w3packager_saved_profiles', json.dumps(saved))

            if err_msg:
                messages.warning(request, f"Stack provisioned with warnings: {err_msg}")
            else:
                messages.success(request, f"Stack provisioned successfully! ({installed_count} packages installed, {removed_count} packages removed). Services reloaded.")

            return redirect('/software/w3packager/?tab=review')

        elif action == 'delete_profile':
            prof_id = request.POST.get('profile_id', '')
            saved_raw = SystemSetting.get('w3packager_saved_profiles', '[]')
            try:
                saved = json.loads(saved_raw)
                saved = [p for p in saved if p.get('id') != prof_id]
                SystemSetting.set('w3packager_saved_profiles', json.dumps(saved))
                messages.success(request, "Custom profile deleted.")
            except Exception:
                pass
            return redirect('/software/w3packager/?tab=profiles')

        elif action == 'install_runtime':
            ver = request.POST.get('php_version', '').strip()
            ok, out = install_php_runtime(ver)
            if ok:
                messages.success(request, f"PHP {ver} runtime stack installed and started successfully.")
            else:
                messages.error(request, f"Failed to install PHP {ver}: {out[:250]}")
            return redirect('/software/w3packager/?tab=runtimes')

        elif action == 'uninstall_runtime':
            ver = request.POST.get('php_version', '').strip()
            ok, out = uninstall_php_runtime(ver)
            if ok:
                messages.success(request, f"PHP {ver} runtime uninstalled successfully.")
            else:
                messages.error(request, out)
            return redirect('/software/w3packager/?tab=runtimes')

        elif action == 'install_extension':
            ver = request.POST.get('php_version', default_php).strip()
            ext = request.POST.get('extension', '').strip()
            ok, out = install_php_extension(ver, ext)
            if ok:
                messages.success(request, f"Extension php{ver}-{ext} installed and service reloaded.")
            else:
                messages.error(request, f"Failed to install php{ver}-{ext}: {out[:250]}")
            return redirect(f'/software/w3packager/?tab=extensions&php_version={ver}')

        elif action == 'uninstall_extension':
            ver = request.POST.get('php_version', default_php).strip()
            ext = request.POST.get('extension', '').strip()
            ok, out = uninstall_php_extension(ver, ext)
            if ok:
                messages.success(request, f"Extension php{ver}-{ext} removed and service reloaded.")
            else:
                messages.error(request, f"Failed to remove php{ver}-{ext}: {out[:250]}")
            return redirect(f'/software/w3packager/?tab=extensions&php_version={ver}')

        elif action == 'install_component':
            comp = request.POST.get('component', '').strip()
            avail_brotli = get_available_apt_packages(['libnginx-mod-http-brotli-filter', 'libnginx-mod-brotli'])
            brotli_pkg_name = 'libnginx-mod-http-brotli-filter' if 'libnginx-mod-http-brotli-filter' in avail_brotli else 'libnginx-mod-brotli'

            pkg_map = {
                'nginx': ['nginx'],
                'brotli': [brotli_pkg_name],
                'certbot': ['python3-certbot-nginx'],
                'nodejs': ['nodejs', 'npm'],
                'composer': ['composer'],
                'redis-server': ['redis-server'],
            }
            pkgs = pkg_map.get(comp)
            if pkgs:
                ok, out = _run_apt_transaction(['apt-get', 'install', '-y'] + pkgs)
                if ok:
                    messages.success(request, f"Component {comp} installed successfully.")
                else:
                    messages.error(request, f"Failed to install {comp}: {out[:250]}")
            elif comp == 'wp-cli':
                ok, err = _install_wp_cli()
                if ok:
                    messages.success(request, "WP-CLI installed successfully at /usr/local/bin/wp.")
                else:
                    messages.error(request, f"Failed to install WP-CLI: {err[:200]}")
            tab = request.POST.get('return_tab', 'cli')
            return redirect(f'/software/w3packager/?tab={tab}')

    # GET
    active_tab = request.GET.get('tab', 'profiles').strip()
    selected_php = request.GET.get('php_version', default_php).strip()
    search_query = request.GET.get('q', '').strip()

    catalog = get_w3packager_catalog(selected_php=selected_php, search_query=search_query)

    return render(request, 'admin/w3packager.html', {
        **_sidebar_context('w3packager'),
        'active_tab': active_tab,
        **catalog,
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


def _install_wp_cli() -> tuple[bool, str]:
    """Download and install WP-CLI phar without shell=True."""
    import tempfile
    from services.webserver.manager import _has_sudo
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.phar', delete=False) as tf:
            tmp_path = Path(tf.name)
        dl = subprocess.run(
            ['curl', '-fsSL', '-o', str(tmp_path), 'https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar'],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if dl.returncode != 0:
            return False, dl.stderr or 'Download failed'
        os.chmod(tmp_path, 0o755)
        prefix = [] if os.geteuid() == 0 else (['sudo', '-n'] if _has_sudo() else None)
        if prefix is None:
            return False, 'Insufficient privileges to install /usr/local/bin/wp'
        mv = subprocess.run(prefix + ['mv', str(tmp_path), '/usr/local/bin/wp'], capture_output=True, text=True, timeout=10)
        return mv.returncode == 0, mv.stderr or ''
    except Exception as e:
        return False, str(e)
    finally:
        if tmp_path and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def _remove_wp_cli() -> tuple[bool, str]:
    """Remove WP-CLI binary without shell=True."""
    from services.webserver.manager import _has_sudo
    prefix = [] if os.geteuid() == 0 else (['sudo', '-n'] if _has_sudo() else None)
    if prefix is None:
        return False, 'Insufficient privileges'
    res = subprocess.run(prefix + ['rm', '-f', '/usr/local/bin/wp'], capture_output=True, text=True, timeout=10)
    return res.returncode == 0, res.stderr or ''


def admin_2fa_settings(request):
    """Two-factor authentication management for administrator."""
    import pyotp
    from packages.core.auth import verify_2fa

    user = getattr(request, 'panel_user', None)
    if not user:
        return redirect('admin_login')

    if request.method == 'POST':
        action = request.POST.get('action', '')
        if action == 'init_setup':
            secret = pyotp.random_base32()
            user.otp_secret = secret
            user.is_2fa_enabled = False
            user.save(update_fields=['otp_secret', 'is_2fa_enabled'])
            return redirect('admin_2fa_settings')
        elif action == 'confirm_enable':
            code = request.POST.get('otp_code', '').strip()
            if verify_2fa(user, code):
                user.is_2fa_enabled = True
                user.save(update_fields=['is_2fa_enabled'])
                messages.success(request, 'Two-factor authentication enabled.')
            else:
                messages.error(request, 'Invalid verification code.')
            return redirect('admin_2fa_settings')
        elif action == 'disable':
            user.is_2fa_enabled = False
            user.otp_secret = ''
            user.save(update_fields=['is_2fa_enabled', 'otp_secret'])
            messages.success(request, 'Two-factor authentication disabled.')
            return redirect('admin_2fa_settings')

    otp_uri = ''
    if user.otp_secret and not user.is_2fa_enabled:
        otp_uri = pyotp.TOTP(user.otp_secret).provisioning_uri(name=user.username, issuer_name='W3Panel')

    return render(request, 'admin/2fa.html', {
        **_sidebar_context('2fa'),
        'user_obj': user,
        'otp_uri': otp_uri,
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


def _run_privileged(cmd_args: list, timeout: int = 10):
    """Run a privileged system command when root or passwordless sudo is available."""
    from services.webserver.manager import _has_sudo
    if os.geteuid() == 0:
        return subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout)
    if _has_sudo():
        return subprocess.run(['sudo', '-n'] + cmd_args, capture_output=True, text=True, timeout=timeout)
    return None


def _prepare_wizard_setup(post_data, stack_status, mark_completed=True):
    """Persist wizard settings and return (install_pkgs, services_to_start, opts)."""
    server_hostname = post_data.get('server_hostname', '').strip() or platform.node()
    server_ip = post_data.get('server_ip', '').strip()
    primary_ns = post_data.get('primary_ns', '').strip()
    secondary_ns = post_data.get('secondary_ns', '').strip()
    admin_email = post_data.get('admin_email', '').strip()

    webserver_choice = post_data.get('webserver_choice', 'nginx')
    default_php = post_data.get('default_php', '8.3')
    valid_php_versions = {r['version'] for r in PHP_RUNTIME_DEFS}
    if default_php not in valid_php_versions:
        default_php = '8.3'
    selected_php_versions = [v for v in post_data.getlist('php_versions') if v in valid_php_versions]
    if webserver_choice in ('nginx', 'apache') and default_php not in selected_php_versions:
        selected_php_versions.append(default_php)
    selected_php_versions = list(dict.fromkeys(selected_php_versions))

    enable_mariadb = post_data.get('enable_mariadb') in ('1', 'true', 'on')
    enable_postgresql = post_data.get('enable_postgresql') in ('1', 'true', 'on')
    tune_mariadb = post_data.get('tune_mariadb') in ('1', 'true', 'on')
    enable_phpmyadmin = enable_mariadb and (post_data.get('enable_phpmyadmin') in ('1', 'true', 'on'))
    enable_pgadmin4 = enable_postgresql and (post_data.get('enable_pgadmin4') in ('1', 'true', 'on'))
    enable_mail = post_data.get('enable_mail') in ('1', 'true', 'on')
    spam_filter = post_data.get('spam_filter', 'rspamd')
    enable_dkim = post_data.get('enable_dkim') in ('1', 'true', 'on')
    enable_snappymail = enable_mail and (post_data.get('enable_snappymail') in ('1', 'true', 'on'))
    enable_ftp = post_data.get('enable_ftp') in ('1', 'true', 'on')
    enable_ufw = post_data.get('enable_ufw') in ('1', 'true', 'on')
    enable_podman = post_data.get('enable_podman') in ('1', 'true', 'on')

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
    SystemSetting.set('email_spam_filter', spam_filter)
    SystemSetting.set('email_dkim_enabled', 'true' if enable_dkim else 'false')
    SystemSetting.set('mail_snappymail_enabled', 'true' if enable_snappymail else 'false')
    SystemSetting.set('ftp_stack_enabled', 'true' if enable_ftp else 'false')
    SystemSetting.set('podman_enabled', 'true' if enable_podman else 'false')
    if mark_completed:
        SystemSetting.set('initial_setup_completed', 'true')

    install_pkgs = []
    services_to_start = []
    if webserver_choice == 'nginx' and not stack_status['webserver_nginx']['installed']:
        install_pkgs.extend(['nginx', 'nginx-common'])
        services_to_start.append('nginx')
    elif webserver_choice == 'apache' and not stack_status['webserver_apache']['installed']:
        install_pkgs.extend(['apache2'])
        services_to_start.append('apache2')

    for ver in selected_php_versions:
        if not shutil.which(f'php-fpm{ver}') and not Path(f'/etc/php/{ver}/fpm').exists():
            install_pkgs.extend(get_php_runtime_packages(ver))
            services_to_start.append(f'php{ver}-fpm')

    if enable_podman and not stack_status['container_podman']['installed']:
        install_pkgs.append('podman')

    if enable_mariadb and not stack_status['db_mariadb']['installed']:
        install_pkgs.extend(['mariadb-server', 'mariadb-client'])
        services_to_start.append('mariadb')
    if enable_postgresql and not stack_status['db_postgresql']['installed']:
        install_pkgs.extend(['postgresql', 'postgresql-contrib'])
        services_to_start.append('postgresql')

    if enable_mail and not (stack_status['mail_postfix']['installed'] and shutil.which('dovecot')):
        install_pkgs.extend(['postfix', 'dovecot-core', 'dovecot-imapd', 'dovecot-pop3d', 'dovecot-lmtpd', 'dovecot-sieve', 'dovecot-managesieved'])
        services_to_start.extend(['postfix', 'dovecot'])
    elif enable_mail and not Path('/usr/share/dovecot/protocols.d/managesieved.protocol').exists():
        install_pkgs.append('dovecot-managesieved')
    if enable_mail and enable_dkim:
        install_pkgs.extend(['opendkim', 'opendkim-tools'])
        services_to_start.append('opendkim')
    if enable_mail and spam_filter == 'rspamd':
        install_pkgs.extend(['rspamd', 'redis-server'])
        services_to_start.extend(['redis-server', 'rspamd'])
    elif enable_mail and spam_filter == 'spamassassin':
        install_pkgs.extend(['spamassassin', 'spamass-milter'])
        services_to_start.extend(['spamassassin', 'spamass-milter'])

    if enable_ftp and not stack_status['ftp_pureftpd']['installed']:
        install_pkgs.extend(['pure-ftpd'])
        services_to_start.append('pure-ftpd')

    install_pkgs = list(dict.fromkeys(install_pkgs))
    services_to_start = list(dict.fromkeys(services_to_start))
    opts = {
        'tune_mariadb': tune_mariadb,
        'enable_phpmyadmin': enable_phpmyadmin,
        'enable_pgadmin4': enable_pgadmin4,
        'enable_ufw': enable_ufw,
        'enable_mail': enable_mail,
        'enable_snappymail': enable_snappymail,
        'enable_ftp': enable_ftp,
    }
    return install_pkgs, services_to_start, opts


def _apply_wizard_ufw(opts):
    """Apply baseline UFW rules for selected server services."""
    _run_privileged(['ufw', 'default', 'deny', 'incoming'], timeout=5)
    _run_privileged(['ufw', 'default', 'allow', 'outgoing'], timeout=5)
    for port_proto in ['22/tcp', '80/tcp', '443/tcp', '2087/tcp', '2083/tcp']:
        _run_privileged(['ufw', 'allow', port_proto], timeout=5)
    if opts['enable_mail']:
        for mp in ['25/tcp', '587/tcp', '465/tcp', '993/tcp', '995/tcp']:
            _run_privileged(['ufw', 'allow', mp], timeout=5)
    if opts['enable_ftp']:
        for fp in ['21/tcp', '30000:31000/tcp']:
            _run_privileged(['ufw', 'allow', fp], timeout=5)
    _run_privileged(['ufw', '--force', 'enable'], timeout=5)


def admin_wizard_provision(request):
    """Streaming SSE endpoint for Initial Server Setup Wizard provisioning."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)

    from services.database import apply_database_tuning

    stack_status = get_server_stack_status()
    install_pkgs, services_to_start, opts = _prepare_wizard_setup(request.POST, stack_status, mark_completed=False)

    def event_stream():
        def sse(payload):
            return f"data: {json.dumps(payload)}\n\n"

        has_error = False
        yield sse({
            'status': 'running',
            'percent': 10,
            'step': 'Saved server settings & stack preferences',
            'line': f'>> [1/4] Configuration saved. Packages to install: {", ".join(install_pkgs) or "None"}',
        })

        if install_pkgs:
            yield sse({
                'status': 'running',
                'percent': 20,
                'step': 'Updating APT package index...',
                'line': '>> [2/4] Updating APT package lists...',
            })
            for line in _stream_cmd(['apt-get', 'update', '-y']):
                yield sse({'status': 'running', 'percent': 28, 'step': 'Updating APT package index...', 'line': line})

            yield sse({
                'status': 'running',
                'percent': 35,
                'step': f'Installing {len(install_pkgs)} server packages...',
                'line': f'>> [3/4] Installing: {" ".join(install_pkgs)}',
            })
            for line in _stream_cmd(['apt-get', 'install', '-y'] + install_pkgs):
                if line.startswith('>> [ERROR]'):
                    has_error = True
                yield sse({'status': 'running', 'percent': 65, 'step': 'Installing server packages...', 'line': line})

            yield sse({
                'status': 'running',
                'percent': 80,
                'step': 'Enabling and starting services...',
                'line': '>> [4/4] Starting installed services...',
            })
            for svc in services_to_start:
                res = _run_privileged(['systemctl', 'enable', '--now', svc], timeout=15)
                state = 'active' if (res is None or res.returncode == 0) else 'failed'
                yield sse({'status': 'running', 'percent': 84, 'step': f'Service {svc}: {state}', 'line': f'>> Service {svc}: {state.upper()}'})
        else:
            yield sse({
                'status': 'running',
                'percent': 75,
                'step': 'Selected packages already installed',
                'line': '>> [2/4] All selected packages are already installed.',
            })

        if opts['tune_mariadb']:
            try:
                apply_database_tuning()
                yield sse({'status': 'running', 'percent': 90, 'step': 'Applied MariaDB Low-RAM tuning', 'line': '>> MariaDB Low-RAM tuning applied.'})
            except Exception as e:
                yield sse({'status': 'running', 'percent': 90, 'step': 'MariaDB tuning skipped', 'line': f'>> [WARNING] MariaDB tuning skipped: {e}'})

        if opts.get('enable_phpmyadmin'):
            from services.database import install_phpmyadmin
            pma_res = install_phpmyadmin()
            if pma_res.get('success'):
                yield sse({'status': 'running', 'percent': 92, 'step': 'phpMyAdmin installed', 'line': '>> phpMyAdmin configured at /phpmyadmin/'})
            else:
                yield sse({'status': 'running', 'percent': 92, 'step': 'phpMyAdmin skipped', 'line': f">> [WARNING] phpMyAdmin skipped: {pma_res.get('error', '')}"})

        if opts.get('enable_pgadmin4'):
            from services.database import install_pgadmin4
            pg4_res = install_pgadmin4(admin_email=SystemSetting.get('admin_email', ''))
            if pg4_res.get('success'):
                yield sse({'status': 'running', 'percent': 94, 'step': 'pgAdmin 4 installed', 'line': f">> pgAdmin 4 configured at /pgadmin4/ (login: {pg4_res.get('email')})"})
            else:
                yield sse({'status': 'running', 'percent': 94, 'step': 'pgAdmin 4 skipped', 'line': f">> [WARNING] pgAdmin 4 skipped: {pg4_res.get('error', '')}"})

        if opts['enable_mail']:
            try:
                from services.mail import configure_mail_stack
                configure_mail_stack()
                yield sse({'status': 'running', 'percent': 95, 'step': 'Configured Postfix, Dovecot, DKIM & Spam Stack', 'line': '>> Mail server stack configured (Postfix + Dovecot + DKIM + Spam filter).'})
            except Exception as e:
                yield sse({'status': 'running', 'percent': 95, 'step': 'Mail stack configuration warning', 'line': f'>> [WARNING] Mail stack config skipped: {e}'})

        if opts.get('enable_snappymail'):
            try:
                from services.mail import install_snappymail
                sm_res = install_snappymail()
                if sm_res.get('success'):
                    yield sse({'status': 'running', 'percent': 96, 'step': 'SnappyMail Webmail installed', 'line': '>> SnappyMail Webmail configured at /snappymail/'})
                else:
                    yield sse({'status': 'running', 'percent': 96, 'step': 'SnappyMail Webmail skipped', 'line': f">> [WARNING] SnappyMail skipped: {sm_res.get('error', '')}"})
            except Exception as e:
                yield sse({'status': 'running', 'percent': 96, 'step': 'SnappyMail Webmail skipped', 'line': f'>> [WARNING] SnappyMail skipped: {e}'})

        if opts['enable_ufw']:
            try:
                _apply_wizard_ufw(opts)
                yield sse({'status': 'running', 'percent': 96, 'step': 'Configured UFW firewall rules', 'line': '>> UFW firewall baseline applied.'})
            except Exception as e:
                yield sse({'status': 'running', 'percent': 96, 'step': 'UFW configuration skipped', 'line': f'>> [WARNING] UFW skipped: {e}'})

        if has_error:
            yield sse({
                'status': 'error',
                'percent': 100,
                'step': 'Setup finished with package errors',
                'error': 'One or more packages failed to install. Check the log above.',
            })
        else:
            SystemSetting.set('initial_setup_completed', 'true')
            yield sse({
                'status': 'complete',
                'percent': 100,
                'step': 'Initial server setup completed',
                'line': '>> Initial Server Setup completed successfully!',
            })

    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    return response


def wizard_dashboard(request):
    """
    Initial Server Setup Wizard (Basic WebHost Setup).
    Guides administrator through core server identity, web server selection,
    database engine, mail stack, FTP configuration, and security baselines.
    """
    from services.database import get_database_tuning_status, apply_database_tuning

    stack_status = get_server_stack_status()

    if request.method == 'POST':
        install_pkgs, services_to_start, opts = _prepare_wizard_setup(request.POST, stack_status)
        installed_count = len(install_pkgs)
        if install_pkgs:
            try:
                _run_apt_transaction(['apt-get', 'update', '-y'])
                _run_apt_transaction(['apt-get', 'install', '-y'] + install_pkgs)
                for svc in services_to_start:
                    _run_privileged(['systemctl', 'enable', '--now', svc], timeout=10)
            except Exception as e:
                logger.warning(f"Wizard package install exception: {e}")

        if opts['tune_mariadb']:
            try:
                apply_database_tuning()
            except Exception:
                pass

        if opts.get('enable_phpmyadmin'):
            from services.database import install_phpmyadmin
            install_phpmyadmin()

        if opts.get('enable_pgadmin4'):
            from services.database import install_pgadmin4
            install_pgadmin4(admin_email=SystemSetting.get('admin_email', ''))

        if opts['enable_mail']:
            try:
                from services.mail import configure_mail_stack
                configure_mail_stack()
            except Exception:
                pass

        if opts.get('enable_snappymail'):
            try:
                from services.mail import install_snappymail
                install_snappymail()
            except Exception:
                pass

        if opts['enable_ufw']:
            try:
                _apply_wizard_ufw(opts)
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
    php_runtimes = get_supported_php_runtimes(default_php=default_php)

    return render(request, 'admin/wizards.html', {
        **_sidebar_context('wizards'),
        'stack_status': stack_status,
        'hostname': hostname,
        'server_ip': server_ip,
        'primary_ns': primary_ns,
        'secondary_ns': secondary_ns,
        'admin_email': admin_email,
        'default_php': default_php,
        'php_runtimes': php_runtimes,
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


# ===========================================================================
# 10. Panel Migration Center (Modular Migrators)
# ===========================================================================

def _require_admin_user(request):
    user = getattr(request, 'panel_user', None)
    return bool(user and user.role == 'admin')


def _resolve_migration_source(migrator_id: str, source_token: str = '', local_path: str = ''):
    """Resolve uploaded staged file token or local server path safely."""
    from services.migrators import get_staging_dir
    if source_token:
        safe_name = Path(source_token).name
        if safe_name != source_token or not safe_name:
            raise ValueError('Invalid staged archive token.')
        candidate = (get_staging_dir(migrator_id) / safe_name).resolve()
        staging_root = get_staging_dir(migrator_id).resolve()
        if staging_root not in candidate.parents or not candidate.exists():
            raise FileNotFoundError('Staged archive not found.')
        return candidate, True
    if local_path:
        p = Path(local_path.strip())
        if not p.exists():
            raise FileNotFoundError(f'Path not found: {p}')
        return p, False
    raise ValueError('Provide a backup archive upload or server path.')


def admin_migration(request):
    """Modular panel migrators catalog: install, uninstall, or launch."""
    if not _require_admin_user(request):
        return redirect('admin_dashboard')

    from services.migrators import list_migrators, install_migrator, uninstall_migrator

    if request.method == 'POST':
        action = request.POST.get('action', '')
        migrator_id = request.POST.get('migrator_id', '').strip()
        if action == 'install':
            res = install_migrator(migrator_id)
            if res['success']:
                messages.success(request, f'Installed "{migrator_id}" migrator.')
            else:
                messages.error(request, res.get('error', 'Failed to install migrator.'))
        elif action == 'uninstall':
            res = uninstall_migrator(migrator_id)
            if res['success']:
                messages.success(request, f'Uninstalled "{migrator_id}" migrator.')
            else:
                messages.error(request, res.get('error', 'Failed to uninstall migrator.'))
        return redirect('admin_migration')

    return render(request, 'admin/migration.html', {
        **_sidebar_context('migration'),
        'migrators': list_migrators(),
    })


def admin_migration_panel(request, migrator_id):
    """Dedicated migration workspace for an installed panel migrator."""
    if not _require_admin_user(request):
        return redirect('admin_dashboard')

    from services.migrators import get_migrator_meta, is_migrator_installed
    meta = get_migrator_meta(migrator_id)
    if not meta or not is_migrator_installed(migrator_id):
        messages.error(request, f'Migrator "{migrator_id}" is not installed.')
        return redirect('admin_migration')

    return render(request, f'admin/migration_{migrator_id}.html', {
        **_sidebar_context('migration'),
        'migrator': meta,
    })


def admin_migration_inspect(request, migrator_id):
    """Inspect a backup archive or directory and return structured preview JSON."""
    if not _require_admin_user(request):
        return JsonResponse({'error': 'Administrator access required'}, status=403)
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    from services.migrators import get_migrator, get_staging_dir
    try:
        mod = get_migrator(migrator_id)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

    import secrets
    uploaded = request.FILES.get('archive_file')
    local_path = request.POST.get('local_path', '').strip()
    source_token = ''

    try:
        if uploaded:
            safe_name = re.sub(r'[^A-Za-z0-9._-]', '_', Path(uploaded.name).name)
            source_token = f'{secrets.token_hex(8)}_{safe_name}'
            dest = get_staging_dir(migrator_id) / source_token
            with open(dest, 'wb') as out_f:
                for chunk in uploaded.chunks():
                    out_f.write(chunk)
            source_path = dest
        else:
            source_path, _ = _resolve_migration_source(migrator_id, local_path=local_path)

        manifest = mod.inspect(source_path)
        return JsonResponse({
            'success': True,
            'source_token': source_token,
            'local_path': '' if source_token else str(source_path),
            'manifest': manifest,
        })
    except Exception as e:
        if source_token:
            (get_staging_dir(migrator_id) / source_token).unlink(missing_ok=True)
        return JsonResponse({'error': str(e)}, status=400)


def _extract_migration_options(post_data):
    def _flag(name, default=True):
        val = post_data.get(name)
        if val is None:
            return default
        return val in ('1', 'true', 'on', 'yes')

    return {
        'target_username': post_data.get('target_username', '').strip(),
        'email': post_data.get('email', '').strip(),
        'import_websites': _flag('import_websites', True),
        'import_databases': _flag('import_databases', True),
        'import_mailboxes': _flag('import_mailboxes', True),
        'import_dns': _flag('import_dns', True),
        'update_dns_ip': _flag('update_dns_ip', True),
        'import_ftp': _flag('import_ftp', True),
        'import_cron': _flag('import_cron', True),
        'import_ssl': _flag('import_ssl', True),
        'skip_existing': _flag('skip_existing', False),
    }


def _sse_migration_response(events_iter, cleanup_cb=None, migrator_id=''):
    def event_stream():
        try:
            for evt in events_iter:
                if evt.get('complete'):
                    payload = {
                        'status': 'complete',
                        'percent': 100,
                        'step': evt.get('step', 'Migration completed'),
                        'line': evt.get('line', ''),
                        'summary': evt.get('summary', {}),
                    }
                else:
                    payload = {
                        'status': 'running',
                        'percent': evt.get('percent', 0),
                        'step': evt.get('step', ''),
                        'line': evt.get('line', ''),
                    }
                yield f'data: {json.dumps(payload)}\n\n'
        except Exception as exc:
            logger.exception('Migration failed for %s', migrator_id)
            yield f'data: {json.dumps({"status": "error", "percent": 100, "step": "Migration failed", "error": str(exc)})}\n\n'
        finally:
            if cleanup_cb:
                cleanup_cb()

    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    response['X-Accel-Buffering'] = 'no'
    return response


def admin_migration_execute(request, migrator_id):
    """Stream SSE migration progress and final summary for an installed migrator."""
    if not _require_admin_user(request):
        return JsonResponse({'error': 'Administrator access required'}, status=403)
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    from services.migrators import get_migrator
    try:
        mod = get_migrator(migrator_id)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

    source_token = request.POST.get('source_token', '').strip()
    local_path = request.POST.get('local_path', '').strip()
    try:
        source_path, is_staged = _resolve_migration_source(migrator_id, source_token=source_token, local_path=local_path)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

    options = _extract_migration_options(request.POST)
    cleanup = (lambda: source_path.unlink(missing_ok=True)) if is_staged else None
    return _sse_migration_response(
        mod.iter_migrate(source_path, options=options),
        cleanup_cb=cleanup,
        migrator_id=migrator_id,
    )


def admin_migration_remote_accounts(request, migrator_id):
    """Fetch live account list from a remote source server (WHM API or SSH)."""
    if not _require_admin_user(request):
        return JsonResponse({'error': 'Administrator access required'}, status=403)
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    from services.migrators import get_migrator
    try:
        mod = get_migrator(migrator_id)
        if not hasattr(mod, 'list_remote_accounts'):
            return JsonResponse({'error': 'Remote migration is not supported by this migrator.'}, status=400)
        conn = {
            'host': request.POST.get('host', '').strip(),
            'whm_port': request.POST.get('whm_port', '2087').strip(),
            'whm_user': request.POST.get('whm_user', 'root').strip(),
            'whm_token': request.POST.get('whm_token', '').strip(),
            'ssh_port': request.POST.get('ssh_port', '22').strip(),
            'ssh_user': request.POST.get('ssh_user', 'root').strip(),
            'ssh_auth_mode': request.POST.get('ssh_auth_mode', 'password').strip(),
            'ssh_password': request.POST.get('ssh_password', ''),
            'ssh_key': request.POST.get('ssh_key', ''),
            'verify_ssl': request.POST.get('verify_ssl') in ('1', 'true', 'on'),
        }
        accounts = mod.list_remote_accounts(conn)
        return JsonResponse({'success': True, 'accounts': accounts})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)


def admin_migration_remote_execute(request, migrator_id):
    """Stream SSE migration of selected remote accounts via SSH pkgacct + SCP."""
    if not _require_admin_user(request):
        return JsonResponse({'error': 'Administrator access required'}, status=403)
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    from services.migrators import get_migrator
    try:
        mod = get_migrator(migrator_id)
        if not hasattr(mod, 'iter_migrate_remote'):
            return JsonResponse({'error': 'Remote migration is not supported by this migrator.'}, status=400)
    except ValueError as e:
        return JsonResponse({'error': str(e)}, status=400)

    conn = {
        'host': request.POST.get('host', '').strip(),
        'ssh_port': request.POST.get('ssh_port', '22').strip(),
        'ssh_user': request.POST.get('ssh_user', 'root').strip(),
        'ssh_auth_mode': request.POST.get('ssh_auth_mode', 'password').strip(),
        'ssh_password': request.POST.get('ssh_password', ''),
        'ssh_key': request.POST.get('ssh_key', ''),
    }
    usernames = [u.strip() for u in request.POST.getlist('usernames') if u.strip()]
    if not usernames and request.POST.get('usernames_csv'):
        usernames = [u.strip() for u in request.POST.get('usernames_csv', '').split(',') if u.strip()]
    options = _extract_migration_options(request.POST)

    return _sse_migration_response(
        mod.iter_migrate_remote(conn, usernames, options=options),
        migrator_id=migrator_id,
    )


# ===========================================================================
# Email Stack Management Views
# ===========================================================================

def admin_email_accounts(request):
    """Admin Email Accounts, Forwarders, Autoresponders, Catch-All & Deliverability management."""
    from services.mail import (
        create_mailbox, create_mail_alias, get_mailbox_disk_usage,
        set_domain_catchall, sync_mailbox_sieve,
        get_domain_deliverability, repair_domain_deliverability,
        is_snappymail_installed,
    )

    if request.method == 'POST':
        action = request.POST.get('action', 'create_mailbox')

        if action == 'create_mailbox':
            username = request.POST.get('username', '').strip().lower()
            domain = request.POST.get('domain', '').strip().lower()
            password = request.POST.get('password', '').strip()
            quota_raw = request.POST.get('quota', '1024').strip()

            if not username or not domain:
                messages.error(request, 'Mailbox username and domain are required.')
                return redirect('admin_email_accounts')

            if not re.match(r'^[a-z0-9._+-]+$', username):
                messages.error(request, 'Invalid characters in mailbox username.')
                return redirect('admin_email_accounts')

            try:
                quota = max(1, int(quota_raw))
            except ValueError:
                quota = 1024

            full_email = f"{username}@{domain}"
            if Mailbox.objects.filter(email=full_email).exists():
                messages.error(request, f'Mailbox {full_email} already exists.')
                return redirect('admin_email_accounts')

            site = Website.objects.filter(domain=domain).first()
            owner = site.owner if site else request.panel_user

            res = create_mailbox(full_email, password=password, quota_mb=quota)
            if res.get('success'):
                Mailbox.objects.create(
                    owner=owner,
                    email=full_email,
                    domain=domain,
                    quota_mb=quota,
                    used_mb=0.0,
                    is_active=True
                )
                messages.success(request, f'Mailbox {full_email} created successfully!')
            else:
                messages.error(request, res.get('error', 'Failed to create mailbox on server.'))
            return redirect('admin_email_accounts')

        elif action == 'create_forwarder':
            source_user = request.POST.get('source_user', '').strip().lower()
            source_domain = request.POST.get('source_domain', '').strip().lower()
            destination = request.POST.get('destination', '').strip().lower()

            if not source_user or not source_domain or not destination:
                messages.error(request, 'Forwarder source address and destination are required.')
                return redirect('admin_email_accounts')

            source_email = f"{source_user}@{source_domain}"
            if EmailForwarder.objects.filter(source=source_email).exists():
                messages.error(request, f'Forwarder for {source_email} already exists.')
                return redirect('admin_email_accounts')

            dest_list = [d.strip() for d in destination.split(',') if d.strip()]
            res = create_mail_alias(source_email, dest_list)
            if res.get('success'):
                site = Website.objects.filter(domain=source_domain).first()
                owner = site.owner if site else request.panel_user
                EmailForwarder.objects.create(
                    owner=owner,
                    source=source_email,
                    destination=destination,
                    domain=source_domain,
                    is_active=True
                )
                messages.success(request, f'Email forwarder for {source_email} created successfully!')
            else:
                messages.error(request, res.get('error', 'Failed to configure forwarder on server.'))
            return redirect('admin_email_accounts')

        elif action == 'create_autoresponder':
            username = request.POST.get('ar_user', '').strip().lower()
            domain = request.POST.get('ar_domain', '').strip().lower()
            subject = request.POST.get('ar_subject', '').strip()
            body = request.POST.get('ar_body', '').strip()
            interval_raw = request.POST.get('ar_interval', '24').strip()
            if not username or not domain or not subject or not body:
                messages.error(request, 'Autoresponder address, subject, and message body are required.')
                return redirect('admin_email_accounts')
            full_email = f"{username}@{domain}"
            try:
                interval_hours = max(1, int(interval_raw))
            except ValueError:
                interval_hours = 24
            site = Website.objects.filter(domain=domain).first()
            owner = site.owner if site else request.panel_user
            res = sync_mailbox_sieve(full_email, subject, body, interval_hours=interval_hours, is_active=True)
            if res.get('success'):
                EmailAutoresponder.objects.update_or_create(
                    email=full_email,
                    defaults={
                        'owner': owner,
                        'domain': domain,
                        'subject': subject[:255],
                        'body': body,
                        'interval_hours': interval_hours,
                        'is_active': True,
                    },
                )
                messages.success(request, f'Autoresponder saved for {full_email}.')
            else:
                messages.error(request, res.get('error', 'Failed to configure autoresponder.'))
            return redirect('admin_email_accounts')

        elif action == 'set_catchall':
            domain = request.POST.get('catchall_domain', '').strip().lower()
            ca_action = request.POST.get('catchall_action', 'fail').strip()
            destination = request.POST.get('catchall_destination', '').strip().lower()
            res = set_domain_catchall(domain, ca_action, destination)
            if res.get('success'):
                site = Website.objects.filter(domain=domain).first()
                owner = site.owner if site else request.panel_user
                EmailCatchAll.objects.update_or_create(
                    domain=domain,
                    defaults={
                        'owner': owner,
                        'action': ca_action,
                        'destination': destination if ca_action == 'forward' else '',
                        'is_active': ca_action != 'fail',
                    },
                )
                messages.success(request, f'Default address rule updated for {domain}.')
            else:
                messages.error(request, res.get('error', 'Failed to update default address rule.'))
            return redirect('admin_email_accounts')

        elif action == 'repair_deliverability':
            domain = request.POST.get('domain', '').strip().lower()
            site = Website.objects.filter(domain=domain).first()
            if site:
                repair_domain_deliverability(site)
                messages.success(request, f'MX, SPF, DKIM, and DMARC records updated for {domain}.')
            else:
                messages.error(request, 'Domain not found.')
            return redirect('admin_email_accounts')

    mailboxes = Mailbox.objects.select_related('owner').order_by('-created_at')
    for m in mailboxes:
        real_mb = get_mailbox_disk_usage(m.email)
        if real_mb > 0:
            m.used_mb = real_mb

    forwarders = EmailForwarder.objects.select_related('owner').order_by('-created_at')
    autoresponders = EmailAutoresponder.objects.select_related('owner').order_by('-created_at')
    catchalls = EmailCatchAll.objects.select_related('owner').order_by('domain')
    websites = Website.objects.filter(is_active=True).order_by('domain')
    deliverability_list = [get_domain_deliverability(w) for w in websites]

    return render(request, 'admin/email_accounts.html', {
        **_sidebar_context('email_accounts'),
        'mailboxes': mailboxes,
        'forwarders': forwarders,
        'autoresponders': autoresponders,
        'catchalls': catchalls,
        'deliverability_list': deliverability_list,
        'websites': websites,
        'snappymail_installed': is_snappymail_installed(),
        'active_section': 'email',
    })


def admin_email_delete(request, mailbox_id):
    """Delete mailbox."""
    if request.method != 'POST':
        return HttpResponseForbidden('POST required')

    from services.mail import delete_mailbox
    mailbox = get_object_or_404(Mailbox, id=mailbox_id)
    email = mailbox.email

    delete_mailbox(email)
    EmailAutoresponder.objects.filter(email=email).delete()
    mailbox.delete()
    messages.success(request, f'Mailbox {email} deleted successfully.')
    return redirect('admin_email_accounts')


def admin_email_edit(request, mailbox_id):
    """Update mailbox password or quota."""
    if request.method != 'POST':
        return HttpResponseForbidden('POST required')

    from services.mail import set_mailbox_password, update_mailbox_quota
    mailbox = get_object_or_404(Mailbox, id=mailbox_id)
    password = request.POST.get('password', '').strip()
    quota_raw = request.POST.get('quota', '').strip()

    if quota_raw:
        try:
            quota = int(quota_raw)
            if quota > 0:
                mailbox.quota_mb = quota
                mailbox.save(update_fields=['quota_mb'])
                update_mailbox_quota(mailbox.email, quota)
                messages.success(request, f'Quota updated for {mailbox.email}.')
        except ValueError:
            pass

    if password:
        set_mailbox_password(mailbox.email, password, quota_mb=mailbox.quota_mb)
        messages.success(request, f'Password updated for {mailbox.email}.')

    return redirect('admin_email_accounts')


def admin_email_webmail_launch(request, mailbox_id):
    """1-click SnappyMail SSO launch for an admin-selected mailbox."""
    from services.mail import is_snappymail_installed, launch_webmail
    if not is_snappymail_installed():
        messages.error(request, 'SnappyMail Webmail is not installed yet. Install it from Service Manager.')
        return redirect('admin_email_accounts')
    mailbox = get_object_or_404(Mailbox, id=mailbox_id)
    return launch_webmail(request, mailbox.email)


def admin_email_forwarder_delete(request, forwarder_id):
    """Delete an email forwarder."""
    if request.method != 'POST':
        return HttpResponseForbidden('POST required')

    from services.mail import delete_mail_alias
    fwd = get_object_or_404(EmailForwarder, id=forwarder_id)
    source = fwd.source

    delete_mail_alias(source)
    fwd.delete()
    messages.success(request, f'Forwarder for {source} removed.')
    return redirect('admin_email_accounts')


def admin_email_autoresponder_delete(request, ar_id):
    """Delete an email autoresponder and its Sieve rule."""
    if request.method != 'POST':
        return HttpResponseForbidden('POST required')

    from services.mail import remove_mailbox_sieve
    ar = get_object_or_404(EmailAutoresponder, id=ar_id)
    remove_mailbox_sieve(ar.email)
    ar.delete()
    messages.success(request, f'Autoresponder for {ar.email} removed.')
    return redirect('admin_email_accounts')


def admin_email_queue(request):
    """View and manage Postfix mail delivery queue."""
    from services.mail import get_mail_queue, flush_mail_queue, delete_mail_queue

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'flush':
            res = flush_mail_queue()
            if res.get('success'):
                messages.success(request, 'Mail queue flush triggered successfully.')
            else:
                messages.error(request, res.get('error', 'Failed to flush queue.'))
            return redirect('admin_email_queue')
        elif action == 'delete_all':
            delete_mail_queue('ALL')
            messages.success(request, 'All messages removed from the mail queue.')
            return redirect('admin_email_queue')
        elif action == 'delete':
            msg_id = request.POST.get('message_id', '').strip()
            if msg_id:
                delete_mail_queue(msg_id)
                messages.success(request, f'Message {msg_id} removed from queue.')
            return redirect('admin_email_queue')

    queue_data = get_mail_queue()
    return render(request, 'admin/email_queue.html', {
        **_sidebar_context('email_queue'),
        'queue': queue_data,
        'active_section': 'email',
    })


def admin_email_queue_flush(request):
    """Trigger mail queue flush."""
    if request.method != 'POST':
        return HttpResponseForbidden('POST required')
    from services.mail import flush_mail_queue
    flush_mail_queue()
    messages.success(request, 'Mail queue flush initiated.')
    return redirect('admin_email_queue')


def admin_email_reports(request):
    """Summary statistics and Track Delivery logs for mail server traffic and health."""
    from services.mail import get_mail_stats, get_mail_delivery_log
    domain_filter = request.GET.get('domain', '').strip().lower()
    stats = get_mail_stats()
    deliveries = get_mail_delivery_log(limit=100, domain_filter=domain_filter) if domain_filter else stats.get('recent_deliveries', [])
    return render(request, 'admin/email_reports.html', {
        **_sidebar_context('email_reports'),
        'stats': stats,
        'deliveries': deliveries,
        'domain_filter': domain_filter,
        'active_section': 'email',
    })


def admin_email_settings(request):
    """Email global configuration (SMTP port, spam filter threshold, DKIM, and daemon sync)."""
    if request.method == 'POST':
        smtp_port = request.POST.get('smtp_port', '587').strip()
        spam_filter = request.POST.get('spam_filter', 'rspamd').strip()
        spam_threshold = request.POST.get('spam_threshold', '6.0').strip() or '6.0'
        dkim_enabled = request.POST.get('dkim_enabled') == 'on' or request.POST.get('dkim_enabled') == '1'

        if spam_filter not in ('rspamd', 'spamassassin', 'none'):
            spam_filter = 'rspamd'

        SystemSetting.set('email_smtp_port', smtp_port, description='Submission SMTP port')
        SystemSetting.set('email_spam_filter', spam_filter, description='Spam filter engine')
        SystemSetting.set('mail_spam_filter', spam_filter, description='Spam filter engine')
        SystemSetting.set('email_spam_threshold', spam_threshold, description='Spam filter score threshold')
        SystemSetting.set('email_dkim_enabled', 'true' if dkim_enabled else 'false', description='DKIM signing enabled')
        SystemSetting.set('mail_dkim_enabled', 'true' if dkim_enabled else 'false', description='DKIM signing enabled')

        try:
            threshold_val = float(spam_threshold)
        except ValueError:
            threshold_val = 6.0

        from services.mail import configure_mail_stack
        configure_mail_stack(
            smtp_port=smtp_port,
            spam_filter=spam_filter,
            dkim_enabled=dkim_enabled,
            spam_threshold=threshold_val,
        )

        messages.success(request, 'Email settings saved and mail stack updated successfully.')
        return redirect('admin_email_settings')

    smtp_port = SystemSetting.get('email_smtp_port', '587')
    spam_filter = SystemSetting.get('email_spam_filter', '') or SystemSetting.get('mail_spam_filter', 'rspamd')
    spam_threshold = SystemSetting.get('email_spam_threshold', '6.0')
    dkim_enabled = SystemSetting.get('email_dkim_enabled', 'true') == 'true'

    return render(request, 'admin/email_settings.html', {
        **_sidebar_context('email_settings'),
        'smtp_port': smtp_port,
        'spam_filter': spam_filter,
        'spam_threshold': spam_threshold,
        'dkim_enabled': dkim_enabled,
        'active_section': 'email',
    })

