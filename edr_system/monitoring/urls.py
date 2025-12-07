from django.urls import path
from .views import device_list, incident_logs, isolate_device, unisolate_device, device_activity

urlpatterns = [
    path('devices/', device_list, name='device_list'),  # Страница списка устройств
    path('devices/<int:device_id>/logs/', incident_logs, name='incident_logs'),  # Логи инцидентов
    path('devices/<int:device_id>/isolate/', isolate_device, name='isolate_device'),  # Изоляция устройства
    path('devices/<int:device_id>/unisolate/', unisolate_device, name='unisolate_device'),  # Снятие изоляции
    path('devices/<int:device_id>/activity/', device_activity, name='device_activity'),

]
