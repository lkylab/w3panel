"""
W3Panel v2 — W3Client Portal URLs (Port 2083)
Dedicated URL routing for end-user panel without '/user/' prefix.
"""
from django.urls import include, path, re_path
from apps.user import views

urlpatterns = [
    # Same-origin Database Admin Tool reverse proxies
    re_path(r'^phpmyadmin(?:/(?P<subpath>.*))?$', views.db_tool_proxy_view, {'tool': 'phpmyadmin'}, name='user_proxy_phpmyadmin'),
    re_path(r'^pgadmin4(?:/(?P<subpath>.*))?$', views.db_tool_proxy_view, {'tool': 'pgadmin4'}, name='user_proxy_pgadmin4'),

    # Backward compatibility alias
    path('user/', include('apps.user.urls')),

    # Top-level user routes (W3Client standard)
    path('', include('apps.user.urls')),
    
    # API endpoints
    path('api/v1/', include('apps.api.urls')),
]
