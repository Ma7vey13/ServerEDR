import json
import socket
from collections import Counter
from datetime import timedelta

from django.db.models import Count
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from .models import Device, IncidentLog, Command, EndpointActivity

# Вспомогательная функция для аутентификации агента
def authenticate_agent(request, hostname):
    """Проверяет токен из заголовка my_secret_token_123"""
    auth_header = request.headers.get('X-Agent-Token')
    if not auth_header:
        return JsonResponse({'error': 'Missing auth token'}, status=401)

    try:
        device = Device.objects.get(hostname__iexact=hostname)
        if device.auth_token != auth_header:
            return JsonResponse({'error': 'Invalid token'}, status=403)
        return device
    except Device.DoesNotExist:
        return JsonResponse({'error': 'Device not found'}, status=404)

# Панель управления устройствами
def device_list(request):
    devices = Device.objects.all()  # Получаем все устройства
    return render(request, 'monitoring/device_list.html', {'devices': devices})

# Просмотр журналов инцидентов для конкретного устройства
def incident_logs(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    logs = IncidentLog.objects.filter(device=device).order_by('-timestamp')
    return render(request, 'monitoring/incident_logs.html', {'device': device, 'logs': logs})

# Изоляция устройства
def isolate_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    device.is_isolated = True
    device.save()
    # Логируем создание инцидента
    log_entry = IncidentLog.objects.create(device=device, description="Device isolated due to suspicious activity.")
    print(f"Incident created: {log_entry.timestamp} - {log_entry.description}")
    Command.objects.create(
        device=device,
        command_type='ISOLATE',
        status='PENDING'
    )
    print(f"[SERVER] ✅ ISOLATE command created for {device.hostname}")
    return redirect('device_list')

# Разблокировка устройства
def unisolate_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    # Сбрасываем флаг изоляции и причину
    device.is_isolated = False
    device.isolation_reason = ""
    device.save()
    # УДАЛЯЕМ ВСЕ НЕПОДТВЕРЖДЕННЫЕ КОМАНДЫ ISOLATE ДЛЯ ЭТОГО УСТРОЙСТВА
    deleted_count, _ = Command.objects.filter(
        device=device,
        command_type='ISOLATE',
        status__in=['PENDING', 'SENT'] # Удаляем и PENDING, и SENT, но не CONFIRMED/FAILED
    ).delete()
    print(f"[SERVER] Deleted {deleted_count} pending/sent ISOLATE command(s) for {device.hostname}")
    # Создаём команду UNISOLATE
    unisolate_command = Command.objects.create(
        device=device,
        command_type='UNISOLATE',
        status='PENDING'
    )
    log_entry = IncidentLog.objects.create(device=device, description="Device unisolated by admin.")
    print(f"Incident created: {log_entry.timestamp} - {log_entry.description}")
    print(f"[SERVER] ✅ UNISOLATE command created for {device.hostname} (ID: {unisolate_command.id})")
    return redirect('device_list')

# Функция удаления устройства
def delete_device(request, hostname):
    if request.method == 'POST':
        device = get_object_or_404(Device, hostname=hostname)
        device.delete()
        return redirect('device_list')
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

def device_activity(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    activities = EndpointActivity.objects.filter(hostname=device.hostname).order_by('-timestamp')
    activities_list = []
    for activity in activities:
        try:
            activity_data = json.loads(activity.activity_data)  # Декодируем JSON
        except json.JSONDecodeError:
            continue  # Пропускаем записи с ошибкой
        for entry in activity_data:
            if isinstance(entry, dict):
                activities_list.append({
                    'timestamp': activity.timestamp.strftime('%Y-%m-%d %H:%M:%S'),  # Используйте форматированную дату
                    'name': entry.get('name', 'Unknown'),  # Имя процесса
                    'action': entry.get('action', 'Unknown'),  # Действие
                    'pid': entry.get('pid', 'Unknown'),  # PID процесса
                })

    # Статистика для отображения
    running_count = sum(1 for a in activities_list if a.get('action') == 'Running')
    suspicious_count = sum(1 for a in activities_list if any(
        word in a.get('name', '').lower() for word in ['malicious', 'suspicious']
    ) or a.get('pid') == 9999)
    return render(request, 'monitoring/device_activity.html', {
        'device': device,
        'activities': activities_list,
        'running_count': running_count,
        'suspicious_count': suspicious_count
    })

# Функция обновления политик
def update_policy(request, device_id):
    device = get_object_or_404(Device, id=device_id) # Получение данных устройства
    if request.method == 'POST':
        device.ddos_connection_threshold = int(request.POST.get('ddos_threshold', 100))
        device.ddos_traffic_threshold_mb = float(request.POST.get('traffic_threshold', 50.0))
        device.enable_behavioral_analysis = 'behavioral' in request.POST
        device.enable_ransomware_trap = 'ransomware' in request.POST
        device.save()
        return redirect('device_list')
    return redirect('device_list')

# Интерфейс
def dashboard(request):
    devices = Device.objects.all()
    incidents = IncidentLog.objects.select_related('device').order_by('-timestamp')[:10]

    # Статистика
    total_devices = devices.count()
    isolated_devices = devices.filter(is_isolated=True).count()
    total_incidents = IncidentLog.objects.count()

    # Подсчёт активных/неактивных устройств
    now = timezone.now()
    inactive_threshold = now - timedelta(minutes=5)  # Порог неактивности 5 минут
    inactive_devices = devices.filter(last_active__lt=inactive_threshold).exclude(
        is_isolated=True).count()  # Исключаем изолированные из "неактивных"
    active_devices = total_devices - isolated_devices - inactive_devices  # Остальные активные

    # Группировка инцидентов по дням за последние 7 дней
    last_7_days = [now.date() - timedelta(days=i) for i in range(7)]
    last_7_days_str = [day.strftime('%Y-%m-%d') for day in
                       reversed(last_7_days)]  # Отсортированы по возрастанию (старые -> новые)

    # Подсчёт инцидентов по дням
    incidents_by_date = (
        IncidentLog.objects
        .filter(timestamp__date__gte=last_7_days[-1])  # Фильтр по дате
        .values('timestamp__date')  # Группировка по дате
        .annotate(count=Count('id'))  # Подсчёт количества
        .order_by('timestamp__date')  # Сортировка по дате
    )
    # Создаём словарь {дата: количество}
    incident_counts_map = {item['timestamp__date'].strftime('%Y-%m-%d'): item['count'] for item in incidents_by_date}

    # Заполняем массив данных, учитывая дни без инцидентов
    incidents_over_time_data = [incident_counts_map.get(day, 0) for day in last_7_days_str]

    # Типы угроз для графика
    threat_types = []
    for inc in IncidentLog.objects.all():
        desc_lower = inc.description.lower()

        # Сопоставление с типами угроз из endpoint_activity
        if any(phrase in desc_lower for phrase in [
            'ddos detected', 'high outgoing traffic', 'malicious ip connection',
            'ddos activity', 'network traffic'
        ]):
            threat_types.append("Network Attacks")

        elif any(phrase in desc_lower for phrase in [
            'hosts modified', 'startup modified', 'hosts file', 'startup entry'
        ]):
            threat_types.append("Configuration Tampering")

        elif any(phrase in desc_lower for phrase in [
            'ransomware detected', 'suspicious temp exe', 'ransomware activity',
            'executable file detected in temp'
        ]):
            threat_types.append("Ransomware")

        elif any(phrase in desc_lower for phrase in [
            'malicious process', 'suspicious.exe', 'pid 9999', 'malicious pid',
            'malicious_process.exe'
        ]):
            threat_types.append("Malicious Process")

        elif any(phrase in desc_lower for phrase in [
            'user behavior anomaly', 'behavioral anomaly', 'process launch patterns'
        ]):
            threat_types.append("User/Process Behavior Anomaly")

        elif any(phrase in desc_lower for phrase in [
            'device isolated', 'device unisolated', 'isolated by admin'
        ]):
            threat_types.append("Administrative Actions")

    # 1. Активность устройств за последние 24 часа
    last_24h = [now - timedelta(hours=i) for i in range(24)]
    last_24h_str = [hour.strftime('%H:%M') for hour in reversed(last_24h)]
    device_activity_data = []
    for hour in last_24h:
        hour_start = hour.replace(minute=0, second=0, microsecond=0)
        hour_end = hour_start + timedelta(hours=1)
        active_count = Device.objects.filter(
            last_active__gte=hour_start,
            last_active__lt=hour_end
        ).count()
        device_activity_data.append(active_count)

    # 2. Топ устройств по количеству инцидентов
    top_devices = (
        IncidentLog.objects
        .values('device__hostname')
        .annotate(incident_count=Count('id'))
        .order_by('-incident_count')[:8]  # Топ 8 устройств
    )
    top_device_labels = [device['device__hostname'] for device in top_devices]
    top_device_data = [device['incident_count'] for device in top_devices]

    # 3. Распределение инцидентов по критичности
    incidents_all = IncidentLog.objects.all()
    critical_count = 0
    warning_count = 0
    info_count = 0
    for inc in incidents_all:
        desc_lower = inc.description.lower()
        if any(word in desc_lower for word in [
            'ransomware', 'ddos', 'malicious', 'isolated due to'
        ]):
            critical_count += 1
        elif any(word in desc_lower for word in [
            'hosts', 'startup', 'behavior', 'suspicious', 'anomaly'
        ]):
            warning_count += 1
        else:
            info_count += 1

    threat_counter = Counter(threat_types)
    threat_labels = list(threat_counter.keys())
    threat_data = list(threat_counter.values())

    context = {
        'total_devices': total_devices,
        'isolated_devices': isolated_devices,
        'total_incidents': total_incidents,
        'recent_incidents': incidents,
        'threat_labels': threat_labels,
        'threat_data': threat_data,
        'active_devices': active_devices,
        'inactive_devices': inactive_devices,
        'incidents_over_time_labels': last_7_days_str,
        'incidents_over_time_data': incidents_over_time_data,

        'device_activity_labels': last_24h_str,
        'device_activity_data': device_activity_data,
        'top_device_labels': top_device_labels,
        'top_device_data': top_device_data,
        'severity_labels': ['Critical', 'Warning', 'Info'],
        'severity_data': [critical_count, warning_count, info_count],
        'severity_colors': ['#c44536', '#d68c45', '#4a7b9d']
    }
    return render(request, 'monitoring/dashboard.html', context)

# Агент запрашивает команды для себя
@csrf_exempt
def get_commands(request, hostname):
    if request.method == 'GET':
        print(f"[SERVER] Command request received for hostname: '{hostname}'")

        # Аутентификация агента
        result = authenticate_agent(request, hostname)
        if isinstance(result, JsonResponse):
            return result  # вернёт ошибку 401/403/404
        device = result
        print(f"[SERVER] Device found: {device.hostname} (ID: {device.id})")
        device.update_last_active()

        # Ищем команды со статусом PENDING
        pending_commands = Command.objects.filter(device=device, status='PENDING')
        print(f"[SERVER] Found {pending_commands.count()} pending commands")
        command_list = []  # Список команд
        for cmd in pending_commands:
            command_data = {
                'id': cmd.id,
                'type': cmd.command_type
            }
            command_list.append(command_data) # Добавление в список
            print(f"[SERVER] Sending command: {cmd.command_type} (ID: {cmd.id})")
            cmd.status = 'SENT' # Помечаем как отправленную
            cmd.save()

        # Добавляем настраиваемые пороги для сетевых аномалий
        response_data = {
            'commands': command_list,
            'ddos_connection_threshold': device.ddos_connection_threshold,
            'ddos_traffic_threshold_mb': device.ddos_traffic_threshold_mb,
        }

        print(f"[SERVER] Sending JSON response with thresholds: {response_data}")
        return JsonResponse(response_data)

    return JsonResponse({'error': 'Method not allowed'}, status=405)

# Агент подтверждает выполнение команды
@csrf_exempt
def confirm_command(request, command_id):
    print(f"[SERVER] Confirm command request for ID: {command_id}")
    if request.method == 'POST':
        try:
            command = Command.objects.select_related('device').get(id=command_id)
            print(f"[SERVER] Command found: {command.command_type} for device {command.device.hostname}")
        except Command.DoesNotExist:
            print(f"[SERVER] Command with ID {command_id} NOT FOUND!")
            return JsonResponse({'error': 'Command not found'}, status=404)

        # Проверяем токен
        auth_header = request.headers.get('X-Agent-Token')
        if not auth_header:
            return JsonResponse({'error': 'Missing auth token'}, status=401)
        if command.device.auth_token != auth_header:
            return JsonResponse({'error': 'Invalid token'}, status=403)

        command.status = 'CONFIRMED'
        command.executed_at = timezone.now()
        command.save()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def debug_commands(request, hostname):
    """Эндпоинт для отладки - показывает все команды для устройства"""
    try:
        device = Device.objects.get(hostname=hostname)
        commands = Command.objects.filter(device=device).order_by('-created_at')
        result = {
            'device': device.hostname,
            'total_commands': commands.count(),
            'pending_commands': commands.filter(status='PENDING').count(),
            'commands': []
        }
        for cmd in commands:
            result['commands'].append({
                'id': cmd.id,
                'type': cmd.command_type,
                'status': cmd.status,
                'created': cmd.created_at.isoformat()
            })
        return JsonResponse(result)
    except Device.DoesNotExist:
        return JsonResponse({'error': 'Device not found'}, status=404)

@csrf_exempt
def register_device(request):
    """
    Регистрирует новое устройство.
    Ожидает POST-запрос с JSON: {"hostname": "...", "token": "..."}
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)

    hostname = data.get('hostname')
    token = data.get('token')

    if not hostname or not token:
        return JsonResponse({'error': 'Missing hostname or token in request body'}, status=400)

    # Проверяем, совпадает ли токен с ожидаемым (можно усложнить логику, например, использовать список токенов)
    expected_token = "my_secret_token_123" # Используйте константу или настройку
    if token != expected_token:
        print(f"[SERVER] Registration attempt with invalid token '{token}' for hostname '{hostname}'")
        return JsonResponse({'error': 'Invalid token for registration'}, status=403)

    # Проверяем, существует ли устройство уже
    device, created = Device.objects.get_or_create(
        hostname__iexact=hostname,
        defaults={
            'hostname': hostname,  # Явно указываем имя хоста
            'auth_token': token,  # Сохраняем токен
            # Остальные поля будут заполнены значениями по умолчанию из модели
        }
    )

    if created:
        print(f"[SERVER] Device '{hostname}' registered successfully via /api/register/. Token saved.")
        return JsonResponse({'message': f'Device {hostname} registered successfully'}, status=201)
    else:
        print(f"[SERVER] Device '{hostname}' already exists, registration skipped.")
        # Возвращаем 200 OK, если устройство уже зарегистрировано
        return JsonResponse({'message': f'Device {hostname} was already registered'}, status=200)

@csrf_exempt
def endpoint_activity(request):
    ## print("Request body:", request.body)

    if request.method == 'POST': # Принятие POST запроса
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError as e:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        hostname = data.get('hostname', 'unknown') # Имя хоста
        auth_header = request.headers.get('X-Agent-Token') # Токен аутентификации
        if not auth_header:
            return JsonResponse({'error': 'Missing auth token'}, status=401)

        activity_data = data.get('activity_data', [])
        threat_type = data.get('threat')
        threat_description = data.get('description')

        # Аутентификация агента
        result = authenticate_agent(request, hostname)
        if isinstance(result, JsonResponse):
            return result
        device = result

        # Обновление IP-адреса устройства при каждом запросе
        client_ip = request.META.get('REMOTE_ADDR')
        if device.ip_address != client_ip:
            device.ip_address = client_ip
            device.save(update_fields=['ip_address'])  # Сохраняем только это поле

        device.update_last_active()

        # Логика автоматической изоляции
        is_suspicious = False
        isolation_reason = ""

        if threat_type == "hosts_modified":
            is_suspicious = True
            isolation_reason = f"Malicious hosts file modification detected: {threat_description}"
        elif threat_type == "startup_modified":
            is_suspicious = True
            isolation_reason = f"Suspicious startup entry detected: {threat_description}"
        elif threat_type == "ddos_detected":
            is_suspicious = True
            isolation_reason = f"Possible DDoS activity detected: {threat_description}"
        elif threat_type == "high_outgoing_traffic":
            is_suspicious = True
            isolation_reason = f"Anomalously high outgoing network traffic detected: {threat_description}"
        elif threat_type == "ransomware_detected":
            is_suspicious = True
            isolation_reason = f"Ransomware activity detected: {threat_description}"
        elif threat_type == "process_from_temp":
            is_suspicious = True
            isolation_reason = f"Process executed from TEMP directory: {threat_description}"
        elif threat_type == "suspicious_temp_exe":
            is_suspicious = True
            isolation_reason = f"Suspicious executable file detected in TEMP directory: {threat_description}"
        elif threat_type == "malicious_ip_connection":
            is_suspicious = True
            isolation_reason = f"Malicious IP connection detected: {threat_description}"
        elif threat_type == "malicious_process":
            is_suspicious = True
            isolation_reason = f"Malicious process detected: {threat_description}"
        elif threat_type == "user_behavior_anomaly":
            is_suspicious = True
            isolation_reason = f"Behavioral anomaly detected based on process launch patterns: {threat_description}"

        # Проверка на подозрительные процессы
        for entry in activity_data:
            if entry.get('action') == 'Running' and entry.get('name') in ['malicious_process.exe', 'suspicious.exe']:
                is_suspicious = True
                isolation_reason = f"Detected suspicious process: {entry.get('name')}"
                break
            if entry.get('pid') in [9999]:
                is_suspicious = True
                isolation_reason = "Detected known malicious PID."
                break

        if isinstance(activity_data, list):
            activity_data = json.dumps(activity_data)  # Преобразуем в JSON-строку, если это список
        else:
            return JsonResponse({'error': 'Invalid activity data format'}, status=400)

        if is_suspicious:
            try:
                # Проверяем, есть ли уже неподтвержденная команда ISOLATE для этого устройства
                existing_pending_isolate = Command.objects.filter(
                    device=device,
                    command_type='ISOLATE',
                    status__in=['PENDING', 'SENT']  # Проверяем и PENDING, и SENT
                ).exists()

                if not existing_pending_isolate:
                    device.is_isolated = True
                    device.isolation_reason = isolation_reason  # Устанавливаем причину изоляции
                    device.save()
                    # Логируем инцидент
                    IncidentLog.objects.create(device=device, description=isolation_reason)
                    # СОЗДАЕМ КОМАНДУ ДЛЯ АГЕНТА ТОЛЬКО ЕСЛИ НЕТ СТАРЫХ НЕПОДТВЕРЖДЕННЫХ
                    Command.objects.create(
                        device=device,
                        command_type='ISOLATE',
                        status='PENDING'
                    )
                    print(
                        f"[SERVER] Threat detected. ISOLATE command queued for {hostname}. Reason: {isolation_reason}")
                else:
                    print(
                        f"[SERVER] Threat detected for {hostname}, but an ISOLATE command is already pending/sent. Skipping new command creation.")
            except Device.DoesNotExist:
                print(f"Device with hostname {hostname} does not exist.")


        activity_data = activity_data.replace('\\u0000', '')
        # Сохранение данных в базе (если это строка в базе)
        activity_entry = EndpointActivity.objects.create(
            hostname=hostname, activity_data=activity_data
        )
        #print(f"Activity saved: {activity_entry.hostname} - {activity_entry.activity_data}")
    return JsonResponse({'status': 'success'})
