# Create your models here.
from django.db import models
from django.utils import timezone

class EndpointActivity(models.Model):
    hostname = models.CharField(max_length=255)  # Имя устройства
    activity_data = models.TextField()  # Поле для хранения JSON данных о процессах
    timestamp = models.DateTimeField(auto_now_add=True)  # Время записи

    def __str__(self):
        return f"Activity from {self.hostname} at {self.timestamp}"

class Device(models.Model):
    hostname = models.CharField(max_length=100)
    auth_token = models.CharField(max_length=100, default='my_secret_token_123')
    status = models.CharField(max_length=50, default='Active')
    is_isolated = models.BooleanField(default=False)
    last_active = models.DateTimeField(default=timezone.now)
    isolation_reason = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    # === ПОЛИТИКИ БЕЗОПАСНОСТИ ===
    ddos_connection_threshold = models.IntegerField(default=100)
    ddos_traffic_threshold_mb = models.FloatField(default=50.0)
    enable_behavioral_analysis = models.BooleanField(default=True)
    enable_ransomware_trap = models.BooleanField(default=True)

    def update_last_active(self):
        """Метод для обновления времени последней активности"""
        self.last_active = timezone.now()
        self.save(update_fields=['last_active'])

    def get_status_display(self):
        """Метод для получения отображаемого статуса"""
        time_diff = timezone.now() - self.last_active
        if time_diff.total_seconds() > 180:  # 5 минут (300 секунд)
            return "Inactive"
        return "Active"

    def __str__(self):
        return self.hostname

class IncidentLog(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    description = models.TextField()

    def __str__(self):
        return f"{self.device.hostname} - {self.timestamp}"
    #    return f"Log for {self.device.hostname} at {self.timestamp}"

class Command(models.Model):
    COMMAND_TYPES = (
        ('ISOLATE', 'Isolate Device'),
        ('UNISOLATE', 'Unisolate Device'),
    )
    STATUS_TYPES = (
        ('PENDING', 'Pending'),
        ('SENT', 'Sent'),
        ('CONFIRMED', 'Confirmed'),
        ('FAILED', 'Failed'),
    )

    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    command_type = models.CharField(max_length=20, choices=COMMAND_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_TYPES, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)
    executed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.command_type} for {self.device.hostname} ({self.status})"