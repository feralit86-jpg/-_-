"""
LAN Status Monitor  v0.3
Сканирует локальную сеть /24 и выводит все обнаруженные устройства
в виде таблицы. Использует только стандартную библиотеку Python
и системные утилиты Windows (ipconfig, route, ping, arp).
"""

import os
import re
import sys
import socket
import datetime
import threading
import subprocess
import concurrent.futures


# ═══════════════════════════════ Конфигурация ════════════════════════════════

PING_TIMEOUT_MS = 500        # таймаут одного ping-пакета
PING_WORKERS    = 60         # потоков для ping-скана
TCP_WORKERS     = 30         # потоков для tcp-скана
TCP_TIMEOUT     = 0.4        # таймаут подключения к одному порту
DNS_TIMEOUT     = 1.0        # таймаут reverse-DNS
TCP_PORTS       = (80, 443, 445, 22, 8080, 3389, 135, 139, 53, 8443)

CREATE_NO_WINDOW = 0x08000000 if sys.platform == 'win32' else 0
TIME_RE = re.compile(r'([=<])\s*(\d+)\s*(?:мс|ms)', re.IGNORECASE)

# Адаптеры, которые НЕ являются реальным подключением к LAN
VIRTUAL_ADAPTER_KEYWORDS = (
    'radmin', 'vpn', 'virtual', 'vmware', 'virtualbox', 'hyper-v',
    'vethernet', 'tap-windows', 'tap adapter', 'tailscale', 'zerotier',
    'wireguard', 'openvpn', 'hamachi', 'loopback', 'bluetooth',
    'isatap', 'teredo', 'pseudo-interface',
)
VIRTUAL_IP_PREFIXES = ('26.', '25.', '100.64.', '100.65.', '10.8.0.')

# OUI → производитель (первые 3 байта MAC). Небольшой справочник —
# для полного покрытия нужна база IEEE.
OUI_VENDORS = {
    'e4-aa-ea': 'Xiaomi',    'f0-a7-31': 'TP-Link',
    '38-d5-47': 'Intel',     'e0-d5-5e': 'Intel',
    '30-9c-23': 'Intel',     '00-e0-4c': 'Realtek',
    'b4-2e-99': 'GIGA-BYTE', '2c-4d-54': 'ASUS',
    '00-1d-7d': 'Intel',     '70-4d-7b': 'ASUS',
    'e4-9b-4f': 'Apple',     'a4-9b-4f': 'Apple',
    '98-59-7a': 'Apple',     '08-31-8b': 'Apple',
    'b0-95-75': 'TP-Link',   'dc-2c-6e': 'Xiaomi',
    'ac-15-a2': 'Xiaomi',    '0c-38-3e': 'Xiaomi',
    '0c-80-63': 'Xiaomi',    '00-66-be': 'Xiaomi',
    'a0-29-42': 'Intel',     'f8-fe-5e': 'Intel',
    '00-0b-0e': 'Xiaomi',    '4c-cc-6a': 'Xiaomi',
    '2c-7b-a0': 'Xiaomi',    '38-ea-3e': 'Huawei',
    'a4-f9-33': 'Xiaomi',    'b4-22-00': 'Xiaomi',
    '10-7b-44': 'Xiaomi',    'ec-8e-77': 'Xiaomi',
    'e8-5f-02': 'Huawei',
}


# ═══════════════════════════ Кодировка консоли ═══════════════════════════════

def setup_console():
    """UTF-8 для консоли — иначе Unicode-рамка развалится в кракозябры."""
    if sys.platform == 'win32':
        try:
            os.system('chcp 65001 >nul 2>&1')
        except Exception:
            pass
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


# ═══════════════════════════ Системные команды ══════════════════════════════

def run_cmd(args, timeout=10):
    """Запускает команду и возвращает stdout в cp866 (OEM русской Windows)."""
    try:
        r = subprocess.run(
            args, capture_output=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return r.stdout.decode('cp866', errors='replace') if r.stdout else ''
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ''


# ═══════════════════════ Определение основного адаптера ══════════════════════

def is_virtual_adapter(name):
    return any(k in name.lower() for k in VIRTUAL_ADAPTER_KEYWORDS)


def is_virtual_ip(ip):
    return any(ip.startswith(p) for p in VIRTUAL_IP_PREFIXES)


def _route_default_metrics():
    """{IP-интерфейса: метрика} из таблицы маршрутов по умолчанию."""
    metrics = {}
    for line in run_cmd(['route', 'print', '0.0.0.0']).splitlines():
        parts = line.split()
        if (len(parts) >= 5
                and parts[0] == '0.0.0.0'
                and parts[1] == '0.0.0.0'
                and re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', parts[3])):
            try:
                metrics[parts[3]] = int(parts[4])
            except ValueError:
                pass
    return metrics


def get_local_ip():
    """Возвращает (ip, имя_адаптера) основного физического интерфейса.

    Отбрасывает VPN и виртуальные адаптеры, а из оставшихся выбирает
    тот, у которого наименьшая метрика в таблице маршрутов по умолчанию.
    """
    out = run_cmd(['ipconfig', '/all'])
    candidates = []

    for block in re.split(r'(?m)^(?=\S)', out):
        lines = block.splitlines()
        if not lines:
            continue
        header = lines[0].rstrip()
        if not header.endswith(':') or not re.search(r'adapter|адаптер', header, re.I):
            continue

        name = header.rstrip(':').strip()
        text = '\n'.join(lines[1:])

        if re.search(r'Среда.*отключ[её]н|Media disconnected', text, re.I):
            continue

        ip_m = re.search(r'IPv4[^\d]*(\d{1,3}(?:\.\d{1,3}){3})', text)
        if not ip_m:
            continue
        ip = ip_m.group(1)
        if ip.startswith(('127.', '169.254.')):
            continue
        if is_virtual_adapter(name) or is_virtual_ip(ip):
            continue

        gw_ok = bool(re.search(
            r'(?:Основной шлюз|Default Gateway)[^\n]*\d+\.\d+\.\d+\.\d+'
            r'|(?:Основной шлюз|Default Gateway)\s*\n\s+\d+\.\d+\.\d+\.\d+',
            text,
        ))
        if not gw_ok:
            continue

        candidates.append((ip, name))

    if not candidates:
        return None, None

    if len(candidates) > 1:
        metrics = _route_default_metrics()
        candidates.sort(key=lambda c: metrics.get(c[0], 9999))

    return candidates[0]


# ═══════════════════════════ Проверка одного хоста ═══════════════════════════

def reverse_dns(ip, timeout=DNS_TIMEOUT):
    """IP → hostname с жёстким таймаутом (в отдельном daemon-потоке)."""
    result = [None]

    def worker():
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    return result[0]


def ping_host(ip):
    """(ip, online, ms_str|None, hostname|None).

    Без флага -a: reverse-DNS делаем сами с коротким таймаутом,
    иначе ping «висит» на медленном DNS и не успевает вывести TTL=.
    """
    out = run_cmd(
        ['ping', '-n', '1', '-w', str(PING_TIMEOUT_MS), ip],
        timeout=PING_TIMEOUT_MS // 1000 + 2,
    )
    if 'TTL=' not in out.upper():
        return ip, False, None, None

    m = TIME_RE.search(out)
    if m:
        ms = f'<{m.group(2)}' if m.group(1) == '<' else m.group(2)
    else:
        ms = '—'

    return ip, True, ms, reverse_dns(ip)


def tcp_check(ip):
    """Первый открытый TCP-порт из TCP_PORTS или None."""
    for port in TCP_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TCP_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except OSError:
            continue
    return None


def get_arp_table():
    """{ip: mac} из arp -a."""
    table = {}
    pat = r'(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})'
    for line in run_cmd(['arp', '-a']).splitlines():
        m = re.search(pat, line)
        if m:
            ip = m.group(1)
            mac = m.group(2).replace(':', '-').lower()
            if mac != 'ff-ff-ff-ff-ff-ff':
                table[ip] = mac
    return table


# ════════════════════════════ Сбор устройств ═════════════════════════════════

def collect_devices(prefix, local_ip):
    """Возвращает {ip: info} для всех найденных устройств в подсети prefix."""
    ips = [f'{prefix}.{i}' for i in range(1, 255)]
    devices = {}

    # 1. Ping-скан
    with concurrent.futures.ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futs = [ex.submit(ping_host, ip) for ip in ips]
        for f in concurrent.futures.as_completed(futs):
            try:
                ip, ok, ms, name = f.result()
            except Exception:
                continue
            if ok:
                devices[ip] = {'method': 'ping', 'ms': ms,
                               'name': name, 'mac': None}

    # 2. ARP-таблица — после ping-скана она уже наполнена
    arp = {ip: mac for ip, mac in get_arp_table().items()
           if ip.startswith(prefix + '.')}

    # 3. TCP-скан тех, кто есть в ARP, но не ответил на ping
    candidates = [ip for ip in arp if ip not in devices]
    with concurrent.futures.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        futs = {ex.submit(tcp_check, ip): ip for ip in candidates}
        for f in concurrent.futures.as_completed(futs):
            ip = futs[f]
            try:
                port = f.result()
            except Exception:
                port = None
            method = f'tcp:{port}' if port else 'arp'
            devices[ip] = {'method': method, 'ms': None,
                           'name': None, 'mac': arp[ip]}

    # Подставим MAC тем, кому он ещё не назначен
    for ip, d in devices.items():
        if d['mac'] is None and ip in arp:
            d['mac'] = arp[ip]

    # Свой ПК — принудительно: в своей ARP-таблице он не появляется
    if local_ip and local_ip.startswith(prefix + '.'):
        hostname = socket.gethostname()
        if local_ip in devices:
            devices[local_ip]['name'] = hostname
        else:
            devices[local_ip] = {'method': 'self', 'ms': '<1',
                                 'name': hostname, 'mac': None}

    return devices


# ════════════════════════════ Идентификация ══════════════════════════════════

def is_randomized_mac(mac):
    """Locally administered MAC (второй hex-символ 2/6/A/E) — обычно телефон."""
    if not mac or '-' not in mac:
        return False
    return mac.split('-')[0][1].lower() in '26ae'


def device_label(d):
    """Человекочитаемое имя для колонки «Устройство»."""
    if d.get('name'):
        return d['name']
    mac = d.get('mac')
    if not mac:
        return '—'
    if is_randomized_mac(mac):
        return '— (random MAC)'
    return OUI_VENDORS.get(mac[:8], mac)


def ip_key(ip):
    return tuple(int(p) for p in ip.split('.'))


# ══════════════════════════════ Отрисовка ════════════════════════════════════


INNER = 61

COLS_BASE = [(3, 'right'), (18, 'left'), (16, 'left'), (8, 'center'), (5, 'right')]

def _distribute(inner, cols):
    """Распределяет ширину с весами: маленькие колонки не раздуваются."""
    target = inner - 2 - (len(cols) - 1) - 2

    # Веса: сколько «жадности» у колонки к лишним символам.
    # 0 = фиксированная ширина
    WEIGHTS = [0, 2, 1, 0, 0]
    #       № Устр Адрес Стат мс

    base = [w for w, _ in cols]
    fixed = sum(b for b, wt in zip(base, WEIGHTS) if wt == 0)
    flex  = sum(b for b, wt in zip(base, WEIGHTS) if wt != 0)
    total_weight = sum(WEIGHTS)

    diff = target - sum(base)
    if diff == 0:
        return list(cols)
    if diff < 0:
        raise ValueError(f'INNER={inner} слишком мал: минимум {sum(base) + 8}')

    out = []
    leftover = diff
    for i, ((w, a), wt) in enumerate(zip(cols, WEIGHTS)):
        if wt == 0:
            out.append((w, a))                    # фиксированная
        else:
            add = diff * wt // total_weight       # пропорционально весу
            out.append((w + add, a))
            leftover -= add
    # остаток — первой гибкой колонке
    for i, wt in enumerate(WEIGHTS):
        if wt != 0:
            w, a = out[i]
            out[i] = (w + leftover, a)
            break
    return out

COLS = _distribute(INNER, COLS_BASE)

B_TOP = '╔' + '═' * INNER + '╗'
B_SEP = '╠' + '═' * INNER + '╣'
B_BOT = '╚' + '═' * INNER + '╝'


def text_row(text):
    return '║' + str(text).center(INNER)[:INNER] + '║'


def cells_row(values):
    parts = []
    for (w, align), v in zip(COLS, values):
        v = str(v)
        if len(v) > w:
            v = v[:w]
        parts.append(v.rjust(w) if align == 'right'
                     else v.center(w) if align == 'center'
                     else v.ljust(w))
    body = '  ' + ' '.join(parts) + '  '
    assert len(body) == INNER, f'row length {len(body)} != {INNER}'
    return '║' + body + '║'


def _status_of(d):
    """(status_str, ms_str, category) для строки таблицы."""
    method = d['method']
    if method == 'ping':
        return 'ONLINE', d['ms'] or '—', 'online'
    if method == 'self':
        return 'ONLINE', '<1', 'online'
    if method.startswith('tcp:'):
        return 'TCP:' + method.split(':')[1], '—', 'tcp'
    return 'ARP', '—', 'arp'


def render(devices):
    print(B_TOP)
    print(text_row('LAN Status Monitor  v0.3'))
    print(text_row('Проверка: ' + datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S')))
    print(B_SEP)
    print(cells_row(['#', 'Устройство', 'Адрес', 'Статус', 'мс']))
    print(B_SEP)

    if not devices:
        print(text_row('(устройства не найдены)'))
        print(B_SEP)
        print(text_row('Итого: 0 устройств'))
        print(B_BOT)
        return

    counters = {'online': 0, 'tcp': 0, 'arp': 0}
    for i, ip in enumerate(sorted(devices, key=ip_key), 1):
        d = devices[ip]
        status, ms, cat = _status_of(d)
        counters[cat] += 1
        print(cells_row([i, device_label(d), ip, status, ms]))

    print(B_SEP)
    summary = (f"Итого: {counters['online']} пинг, "
               f"{counters['tcp']} tcp, {counters['arp']} только ARP")
    print(text_row(summary))
    print(B_BOT)


# ══════════════════════════════ Точка входа ══════════════════════════════════

def main():
    setup_console()

    local_ip, adapter_name = get_local_ip()
    if not local_ip:
        print('Не удалось найти активное сетевое подключение (Wi-Fi/Ethernet).')
        print('Проверьте, что адаптер подключён и у него есть IP и шлюз.')
        return

    prefix = '.'.join(local_ip.split('.')[:3])
    print(f'Основной адаптер: {adapter_name}')
    print(f'Локальный IP:    {local_ip}')
    print(f'Сканирую:        {prefix}.0/24 ... (несколько секунд)\n')

    devices = collect_devices(prefix, local_ip)
    print()
    render(devices)



if __name__ == '__main__':
    main()