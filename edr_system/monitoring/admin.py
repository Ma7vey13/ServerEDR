from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import EndpointActivity, Device, IncidentLog

admin.site.register(EndpointActivity)
admin.site.register(Device)
admin.site.register(IncidentLog)