"""
URL configuration for edr_system project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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
from django.http import HttpResponse
from django.urls import path, include
from monitoring.views import endpoint_activity, dashboard, update_policy, register_device
from monitoring.views import device_activity, get_commands, confirm_command, debug_commands
from monitoring.views import device_list, incident_logs, isolate_device, unisolate_device, delete_device #, get_last_bruteforce_check



# Простой view для корневого маршрута
def home(request):
    return HttpResponse("Welcome to the Home Page!")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/endpoint', endpoint_activity, name='endpoint_activity'),
    path('monitoring/', include('monitoring.urls')),
    path('device/<int:device_id>/activity/', device_activity, name='device_activity'),
    path('devices/', device_list, name='device_list'),  # Страница списка устройств
    path('devices/<int:device_id>/logs/', incident_logs, name='incident_logs'),  # Логи инцидентов
    path('devices/<int:device_id>/isolate/', isolate_device, name='isolate_device'),  # Изоляция устройства
    path('devices/<int:device_id>/unisolate/', unisolate_device, name='unisolate_device'),  # Снятие изоляции
    path('delete_device/<str:hostname>/', delete_device, name='delete_device'),
    path('api/commands/<str:hostname>/', get_commands, name='get_commands'),
    path('api/commands/<int:command_id>/confirm/', confirm_command, name='confirm_command'),
    path('api/debug-commands/<str:hostname>/', debug_commands, name='debug_commands'),
    path('api/register/', register_device, name='register_device'),
    path('', dashboard, name='dashboard'),  # главная страница
    path('devices/<int:device_id>/update_policy/', update_policy, name='update_policy'),
]
