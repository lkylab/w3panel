"""
W3Panel v2 — W3Host Manager Admin URLs (Port 2087)
Dedicated URL routing for W3Host Manager administrator panel.
"""
from django.urls import include, path, re_path
from apps.user import views as user_views

urlpatterns = [
    # Direct SSO endpoint (1-click user autologin)
    path('sso/', user_views.user_sso, name='admin_sso_direct'),
    path('user/sso/', user_views.user_sso, name='admin_user_sso_direct'),

    # Same-origin Database Admin & Webmail Tool reverse proxies
    re_path(r'^phpmyadmin(?:/(?P<subpath>.*))?$', user_views.db_tool_proxy_view, {'tool': 'phpmyadmin'}, name='admin_proxy_phpmyadmin'),
    re_path(r'^pgadmin4(?:/(?P<subpath>.*))?$', user_views.db_tool_proxy_view, {'tool': 'pgadmin4'}, name='admin_proxy_pgadmin4'),
    re_path(r'^snappymail(?:/(?P<subpath>.*))?$', user_views.webmail_proxy_view, name='admin_proxy_snappymail'),

    # Top-level admin routes (W3Host standard)
    path('', include('apps.admin.urls')),
    
    # API endpoints
    path('api/v1/', include('apps.api.urls')),
]
