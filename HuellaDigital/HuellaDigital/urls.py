"""
URL configuration for HuellaDigital project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from Login import views 

urlpatterns = [
    path('admin/', admin.site.urls),

    #Front-end 
    path('register/', views.register_web, name='register_fingerprint_page'),
    path('', views.login_web, name='webauthn_login_page'),

    #Back-end
    path('register/begin/', views.register_webauthn_begin, name='register_fingerprint_begin'),
    path('register/complete/', views.register_webauthn_complete, name='register_fingerprint_complete'),

    path('login/begin/', views.login_webauthn_begin, name='webauthn_login_begin'),
    path('login/complete/', views.login_webauthn_complete, name='webauthn_login_complete'),
]
