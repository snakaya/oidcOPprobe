"""oidcOPprobe URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls import include, url
from django.conf.urls.static import static
from rp import views as rp_views


urlpatterns = [
    url(r'^test/', rp_views.test),
    url(r'^$', rp_views.top),
    url(r'^OIDC/redirect/(.+)$', rp_views.oidc_redirect),
    url(r'^apis/OPSettings/(.+)$', rp_views.opSettings),
    url(r'^apis/OIDC/Authz/Request/(.+)$', rp_views.oidc_authz_req),
    url(r'^apis/OIDC/Authz/Response/(.+)$', rp_views.oidc_authz_res),
    url(r'^apis/OIDC/Token/(.+)$', rp_views.oidc_token),
    url(r'^apis/OIDC/Refresh/(.+)$', rp_views.oidc_refresh),
    url(r'^apis/OIDC/UserInfo/(.+)$', rp_views.oidc_userinfo),
    url(r'^apis/OIDC/Revocation/(.+)$', rp_views.oidc_revocation),
    url(r'^apis/OIDC/Introspection/(.+)$', rp_views.oidc_introspection),
    url(r'^apis/OIDC/Custom/(.+)$', rp_views.oidc_custom),
    url(r'^apis/OIDC/Verify/(.+)$', rp_views.oidc_verify),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)    # Hached Ref: https://stackoverflow.com/questions/39907281/django-uwsgi-static-files-not-being-served-even-after-collectstatic