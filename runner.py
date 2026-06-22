#!/usr/bin/env python3
"""
VPN Config Runner
=================
Запускается раз в час:
  1. vpn_ping_test  — скачивает конфиги, пингует, сохраняет рабочие в working_configs.txt
  2. speed_test     — берёт working_configs.txt, мерит скорость, сохраняет в tested_configs.txt

Переменные окружения:
  CONFIG_URL     — URL списка конфигов (по умолчанию захардкожен ниже)
  XRAY_BIN       — путь к xray-бинарнику (default: xray)
  RUN_INTERVAL   — интервал в секундах (default: 3600)
  OUTPUT_DIR     — папка для файлов (default: /data)
"""

import asyncio
import base64
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from urllib.parse import unquote

try:
    import aiohttp
    from aiohttp_socks import ProxyConnector
except ImportError:
    print("[!] Установите зависимости: pip install aiohttp aiohttp-socks")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════════
#  НАСТРОЙКИ
# ═══════════════════════════════════════════════════════════════════════════════

API_PORT        = int(os.environ.get("API_PORT", "29000"))
CONFIG_URL      = os.environ.get("CONFIG_URL",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt")
XRAY_BIN        = os.environ.get("XRAY_BIN", "xray")
RUN_INTERVAL    = int(os.environ.get("RUN_INTERVAL", "3600"))
OUTPUT_DIR      = os.environ.get("OUTPUT_DIR", "/data")

WORKING_FILE    = os.path.join(OUTPUT_DIR, "working_configs.txt")
TESTED_FILE     = os.path.join(OUTPUT_DIR, "tested_configs.txt")

# Ping-тест
PING_TEST_URL   = "http://cp.cloudflare.com/"
PING_TIMEOUT    = 3
PING_MAX_WORKERS = 120
PING_TRIES      = 2
PING_SOCKS_BASE = 10800

# Speed-тест
SPEED_TIMEOUT   = 30          # таймаут на один конфиг (сек) — для 20 МБ по медленному VPN
SPEED_MIN_MBPS  = 5
SPEED_MAX_WORKERS = 70
SPEED_SOCKS_BASE = 12000
# 20 МБ = 20 * 1024 * 1024 = 20971520 байт
DOWNLOAD_BYTES  = 20 * 1024 * 1024   # 20 MB
DOWNLOAD_URLS   = [
    f"http://speed.cloudflare.com/__down?bytes={DOWNLOAD_BYTES}",
    f"https://speed.cloudflare.com/__down?bytes={DOWNLOAD_BYTES}",
]
UPLOAD_BYTES    = 20 * 1024 * 1024   # 20 MB
UPLOAD_URL      = "https://speed.cloudflare.com/__up"
IP_API          = "http://ip-api.com/json/"

# ═══════════════════════════════════════════════════════════════════════════════
#  BRIDGE — self-hosted VLESS → лучший конфиг
# ═══════════════════════════════════════════════════════════════════════════════
import uuid
BRIDGE_IP        = "95.165.137.180"
BRIDGE_PORT      = 8443
BRIDGE_UUID      = str(uuid.uuid5(uuid.NAMESPACE_DNS, "self-hosted-ru-bridge"))
BRIDGE_SOCKS_PORT = 15000   # локальный SOCKS лучшего конфига

# ═══════════════════════════════════════════════════════════════════════════════
#  ОБЩИЕ УТИЛИТЫ
# ═══════════════════════════════════════════════════════════════════════════════

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def find_free_port(base, offset):
    port = base + offset
    while port < base + 2000:
        try:
            with socket.socket() as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            port += 1
    return port


def get_flag(cc):
    if not cc or len(cc) != 2:
        return "🏳"
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)


def protocol_name(uri):
    for p in ("vless", "vmess", "trojan", "ss"):
        if uri.startswith(f"{p}://"):
            return p.upper()
    return "UNK"


def clean_url(uri):
    if '#' in uri:
        uri = uri.split('#')[0]
    if uri.startswith(("vless://", "vmess://")):
        if '?' in uri:
            base_part, params_part = uri.split('?', 1)
            clean_params = [
                p for p in params_part.split('&')
                if not any(x in p for x in ['%20', 't.me', '@', '#', '[', ']'])
            ]
            uri = base_part + ('?' + '&'.join(clean_params) if clean_params else '')
    try:
        if '%' in uri:
            decoded = urllib.parse.unquote(uri)
            if any(x in decoded for x in [' ', '[', ']', '(', ')']):
                decoded = re.sub(r'[\[\]\(\)].*$', '', decoded)
            uri = decoded
    except Exception:
        pass
    return uri.strip()


def get_label(uri):
    if "#" in uri:
        return unquote(uri.split("#", 1)[1]).strip()[:60]
    return uri[:60]


# ═══════════════════════════════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ XRAY-КОНФИГОВ  (общая для обоих тестов)
# ═══════════════════════════════════════════════════════════════════════════════

def _base_xray(socks_port, outbound):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        }],
        "outbounds": [outbound]
    }


def _vless_xray(uri, socks_port):
    m = re.match(r"vless://([^@]+)@([^:]+):(\d+)\??([^#]*)", uri)
    if not m:
        return None
    user_id, host, port = m.group(1), m.group(2), int(m.group(3))
    params = dict(urllib.parse.parse_qsl(m.group(4)))

    net      = params.get("type", "tcp")
    security = params.get("security", "none")
    flow     = params.get("flow", "")
    sni      = params.get("sni", host)
    fp       = params.get("fp", "chrome") or "chrome"
    pbk      = params.get("pbk", "")
    sid      = params.get("sid", "")
    path     = params.get("path", "/")
    host_h   = params.get("host", host)
    mode     = params.get("mode", "gun")

    stream = {"network": net}
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_h}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": params.get("serviceName", ""), "multiMode": False, "mode": mode}
    elif net == "xhttp":
        stream["xhttpSettings"] = {"path": path, "mode": mode or "auto"}
    else:
        stream["tcpSettings"] = {}

    if security == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp,
                                  "allowInsecure": params.get("insecure", "0") == "1"}
    elif security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {"serverName": sni, "fingerprint": fp,
                                      "publicKey": pbk, "shortId": sid, "spiderX": params.get("spx", "/")}
    else:
        stream["security"] = "none"

    outbound = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port,
                                 "users": [{"id": user_id, "encryption": "none", "flow": flow}]}]},
        "streamSettings": stream
    }
    return _base_xray(socks_port, outbound)


def _vmess_xray(uri, socks_port):
    b64 = uri[len("vmess://"):].split("#")[0]
    b64 += "=" * (4 - len(b64) % 4)
    try:
        data = json.loads(base64.b64decode(b64).decode())
    except Exception:
        return None

    host     = data.get("add", "")
    port     = int(data.get("port", 443))
    user_id  = data.get("id", "")
    alter_id = int(data.get("aid", 0))
    net      = data.get("net", "tcp")
    tls      = data.get("tls", "")
    sni      = data.get("sni", host)
    path     = data.get("path", "/")
    host_h   = data.get("host", host)

    stream = {"network": net}
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_h}}
    else:
        stream["tcpSettings"] = {}

    if tls == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "allowInsecure": True}
    else:
        stream["security"] = "none"

    outbound = {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port,
                                 "users": [{"id": user_id, "alterId": alter_id, "security": "auto"}]}]},
        "streamSettings": stream
    }
    return _base_xray(socks_port, outbound)


def _trojan_xray(uri, socks_port):
    m = re.match(r"trojan://([^@]+)@([^:]+):(\d+)\??([^#]*)", uri)
    if not m:
        return None
    password, host, port = m.group(1), m.group(2), int(m.group(3))
    params = dict(urllib.parse.parse_qsl(m.group(4)))
    sni    = params.get("sni", host)
    net    = params.get("type", "tcp")
    path   = params.get("path", "/")
    host_h = params.get("host", host)

    stream = {"network": net, "security": "tls",
               "tlsSettings": {"serverName": sni, "allowInsecure": True}}
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_h}}

    outbound = {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": stream
    }
    return _base_xray(socks_port, outbound)


def _ss_xray(uri, socks_port):
    raw = uri[len("ss://"):]
    if "#" in raw:
        raw = raw.rsplit("#", 1)[0]
    try:
        if "@" in raw:
            userinfo, hostport = raw.rsplit("@", 1)
            try:
                decoded = base64.b64decode(userinfo + "==").decode()
                method, password = decoded.split(":", 1)
            except Exception:
                method, password = userinfo.split(":", 1)
        else:
            decoded = base64.b64decode(raw + "==").decode()
            method_pass, hostport = decoded.split("@", 1)
            method, password = method_pass.split(":", 1)

        if ":" in hostport:
            host, port_s = hostport.rsplit(":", 1)
            port = int(port_s.strip("/").split("?")[0])
        else:
            return None
    except Exception:
        return None

    outbound = {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port,
                                   "method": method, "password": password}]}
    }
    return _base_xray(socks_port, outbound)


def make_xray_config(uri, socks_port):
    uri = uri.replace("&amp;", "&")
    try:
        if uri.startswith("vless://"):   return _vless_xray(uri, socks_port)
        if uri.startswith("vmess://"):   return _vmess_xray(uri, socks_port)
        if uri.startswith("trojan://"):  return _trojan_xray(uri, socks_port)
        if uri.startswith("ss://"):      return _ss_xray(uri, socks_port)
    except Exception:
        pass
    return None


def get_server_addr(xray_cfg):
    try:
        out = xray_cfg["outbounds"][0]["settings"]
        servers = out.get("vnext") or out.get("servers") or []
        if servers:
            return "{}:{}".format(servers[0].get("address", "?"), servers[0].get("port", "?"))
    except Exception:
        pass
    return "?"


async def start_xray(config, socks_port):
    try:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, prefix="xray_")
        json.dump(config, tmp)
        tmp.close()

        # Временно: пишем stderr в файл для диагностики
        log_path = tmp.name.replace(".json", ".log")
        log_file = open(log_path, "w")

        kwargs = {}
        if os.name != "nt":
            kwargs["preexec_fn"] = os.setsid

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", tmp.name],
            stdout=log_file,
            stderr=log_file,
            **kwargs
        )
        await asyncio.sleep(1.5)

        # Читаем лог и выводим
        log_file.flush()
        with open(log_path, "r") as f:
            output = f.read().strip()
        if output:
            log(f"[xray:{socks_port}] {output[:500]}")

        if proc.poll() is not None:
            log(f"[xray:{socks_port}] ❌ Процесс завершился (exit={proc.poll()})")
            os.unlink(tmp.name)
            return None

        proc._tmp = tmp.name
        return proc
    except FileNotFoundError:
        log(f"[!] xray не найден: '{XRAY_BIN}'. Скачайте: https://github.com/XTLS/Xray-core/releases")
        sys.exit(1)
    except Exception:
        return None


def stop_xray(proc):
    try:
        if os.name != "nt":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    tmp = getattr(proc, "_tmp", None)
    if tmp and os.path.exists(tmp):
        try:
            os.unlink(tmp)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
#  ШАГ 1 — PING-ТЕСТ (vpn_ping_test)
# ═══════════════════════════════════════════════════════════════════════════════

def extract_host_port(config):
    try:
        if '://' in config:
            protocol, rest = config.split('://', 1)
            if '@' in rest:
                host_part = rest.split('@')[1].split('?')[0]
                if ':' in host_part:
                    host, port = host_part.split(':')
                    return f"{host}:{port}"
            elif protocol == 'vmess':
                try:
                    decoded = base64.b64decode(rest).decode('utf-8')
                    vmess_data = json.loads(decoded)
                    if 'add' in vmess_data and 'port' in vmess_data:
                        return f"{vmess_data['add']}:{vmess_data['port']}"
                except Exception:
                    pass
    except Exception:
        pass
    return None


def fetch_configs(url):
    log(f"[ping] Загрузка конфигов: {url}")
    text = None
    while text is None:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            break
        except Exception as e:
            log(f"[ping] Ошибка загрузки: {e}, повтор через 5 сек...")
            time.sleep(5)

    configs = []
    seen_hosts = set()
    for line in text.splitlines():
        line = line.strip().replace("&#38;amp;", "&#38;")
        line = line.strip().replace("&" + "amp;", "&")
        if not line or line.startswith("#"):
            continue
        if re.match(r"^(vless|vmess|trojan|ss)://", line):
            cleaned = clean_url(line)
            if cleaned and len(cleaned) > 20:
                host_port = extract_host_port(cleaned)
                if host_port and host_port not in seen_hosts:
                    seen_hosts.add(host_port)
                    configs.append(cleaned)
                elif not host_port:
                    configs.append(cleaned)

    # Удаляем дубликаты сохраняя порядок
    configs = list(dict.fromkeys(configs))

    log(f"[ping] Найдено конфигов: {len(configs)} (уникальных хостов: {len(seen_hosts)})")
    return configs


async def measure_via_proxy(socks_port, test_url, timeout):
    connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            t0 = time.perf_counter()
            async with session.get(test_url,
                                   timeout=aiohttp.ClientTimeout(total=timeout),
                                   allow_redirects=False, ssl=False) as resp:
                await resp.read()
            return (time.perf_counter() - t0) * 1000
    except Exception:
        return None
    finally:
        await connector.close()


async def ping_one(uri, idx, total, port_offset):
    label = get_label(uri)
    result = {"label": label, "uri": uri, "ping": None, "error": None}

    socks_port = find_free_port(PING_SOCKS_BASE, port_offset * 3)
    xray_cfg = make_xray_config(uri, socks_port)

    if xray_cfg is None:
        result["error"] = "parse_error"
        return result

    proc = await start_xray(xray_cfg, socks_port)
    if proc is None:
        result["error"] = "xray_failed"
        return result

    try:
        pings = []
        for _ in range(PING_TRIES):
            ms = await measure_via_proxy(socks_port, PING_TEST_URL, PING_TIMEOUT)
            if ms is not None:
                pings.append(ms)

        if pings:
            result["ping"] = sum(pings) / len(pings)
            log(f"  [{idx:>4}/{total}] {result['ping']:>7.1f} ms  {label[:50]}")
        else:
            result["error"] = "timeout"
    finally:
        stop_xray(proc)

    return result


async def run_ping_test(configs):
    sem = asyncio.Semaphore(PING_MAX_WORKERS)
    total = len(configs)
    results = []
    counter = [0]

    async def bounded(uri, offset):
        async with sem:
            counter[0] += 1
            r = await ping_one(uri, counter[0], total, offset)
            results.append(r)

    await asyncio.gather(*[bounded(uri, i) for i, uri in enumerate(configs)])
    return results


def get_country_via_curl(socks_port, timeout=5):
    """Получить код страны через curl + ipinfo.io по SOCKS5 прокси"""
    try:
        import subprocess
        result = subprocess.run(
            [
                "curl", "--socks5", f"127.0.0.1:{socks_port}",
                "--max-time", str(timeout), "-s",
                "https://ipinfo.io/json"
            ],
            capture_output=True, text=True, timeout=timeout + 5
        )
        if result.returncode == 0 and result.stdout:
            import json
            data = json.loads(result.stdout)
            return data.get("country", "")
    except Exception:
        pass
    return ""


def get_country_by_ip(host, socks_port=None):
    """Получить флаг страны по IP через curl+ipinfo.io (если socks_port) или GeoIP fallback"""
    # Пытаемся через curl с прокси
    if socks_port:
        country_code = get_country_via_curl(socks_port)
        if country_code:
            return get_flag(country_code)
    
    # Fallback — GeoIP (для backward compatibility)
    try:
        import geoip2.database
        import socket
    except ImportError:
        return "🌍"
    
    try:
        h = host
        if '://' in h:
            h = h.split('://')[1]
        if '@' in h:
            h = h.split('@')[1]
        h = h.split(':')[0].split('?')[0]
        
        ip = socket.gethostbyname(h)
        
        db_path = '/usr/share/GeoIP/GeoLite2-Country.mmdb'
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip)
            return get_flag(response.country.iso_code)
    except Exception:
        pass
    return "🌍"


def save_working_configs(results):
    ok = sorted([r for r in results if r["ping"] is not None], key=lambda x: x["ping"])
    if not ok:
        log("[ping] Нет рабочих конфигов")
        return 0

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(WORKING_FILE, "w", encoding="utf-8") as f:
        f.write("#profile-title: Рабочие\n")
        f.write("#profile-update-interval: 1\n")
        f.write("#support-url: https://t.me/ine4eg\n")
        f.write("#announce: t.me/ine4eg\n")
        f.write("#subscription-userinfo: upload=0; download=0; total=0; expire=0\n\n")

        for r in ok:
            # Получаем протокол
            proto = protocol_name(r["uri"])
            
            # Получаем флаг страны по IP
            flag = get_country_by_ip(r["uri"])
            
            # Создаем красивую метку
            label = f"{flag} {proto} ping: {r['ping']:.0f}ms, t.me/ine4eg"
            
            # Пересобираем URI
            rebuilt_uri = rebuild_uri(r["uri"].strip(), label)
            f.write(rebuilt_uri + "\n")

    log(f"[ping] Сохранено {len(ok)} рабочих конфигов -> {WORKING_FILE}")
    return len(ok)


async def do_ping_stage():
    log("=" * 60)
    log("  ЭТАП 1: PING-ТЕСТ")
    log("=" * 60)

    configs = fetch_configs(CONFIG_URL)
    if not configs:
        log("[ping] Нет конфигов для проверки")
        return 0

    t0 = time.perf_counter()
    results = await run_ping_test(configs)
    elapsed = time.perf_counter() - t0

    ok = [r for r in results if r["ping"] is not None]
    timeout = [r for r in results if r.get("error") == "timeout"]
    log(f"[ping] Завершено за {elapsed:.0f} сек. OK={len(ok)} Таймаут={len(timeout)}")

    if ok:
        ok_sorted = sorted(ok, key=lambda x: x["ping"])
        log(f"[ping] Лучший: {ok_sorted[0]['ping']:.1f} ms — {ok_sorted[0]['label'][:50]}")

    return save_working_configs(results)


# ═══════════════════════════════════════════════════════════════════════════════
#  ШАГ 2 — SPEED-ТЕСТ (speed_test_configs)
# ═══════════════════════════════════════════════════════════════════════════════

def parse_configs_file(filepath):
    """Читает файл, пропускает заголовки (#profile-*), удаляет пустые строки и дубликаты"""
    configs = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Пропускаем комментарии кроме subscription-userinfo (Clash-заголовки)
            if line.startswith("#"):
                continue
            cleaned = clean_url(line)
            if cleaned and len(cleaned) > 20:
                configs.append(cleaned)
    return list(dict.fromkeys(configs))


def normalize_vmess_config(d):
    order = ["v","ps","add","port","id","aid","net","type","host","path","tls","sni","alpn","fp","security","scy"]
    norm = {k: d[k] for k in order if k in d}
    norm.update({k: v for k, v in d.items() if k not in norm})
    return norm


def rebuild_uri(uri, label):
    clean = uri.split('#')[0]
    quoted = urllib.parse.quote(label)
    if uri.startswith("vmess://"):
        try:
            b64 = clean[8:]
            while len(b64) % 4:
                b64 += '='
            cfg = json.loads(base64.b64decode(b64).decode())
            cfg['ps'] = label
            cfg = normalize_vmess_config(cfg)
            new_b64 = base64.b64encode(json.dumps(cfg, separators=(',', ':')).encode()).decode()
            return f"vmess://{new_b64}#{quoted}"
        except Exception:
            return f"{clean}#{quoted}"
    return f"{clean}#{quoted}"


async def speed_test_one(uri, idx):
    socks_port = SPEED_SOCKS_BASE + (idx % 1000)
    if socks_port > 65535:
        socks_port = 12000 + (idx % 1000)

    config = make_xray_config(uri, socks_port)
    if not config:
        return None

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f)
        tmp_file = f.name

    proc = subprocess.Popen(
        [XRAY_BIN, 'run', '-c', tmp_file],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    await asyncio.sleep(0.7)

    if proc.poll() is not None:
        os.unlink(tmp_file)
        return None

    try:
        result = await asyncio.wait_for(_measure_speed(uri, socks_port), timeout=SPEED_TIMEOUT)
    except asyncio.TimeoutError:
        log(f"[speed] TIMEOUT ({SPEED_TIMEOUT}s) конфиг #{idx}")
        result = None

    proc.terminate()
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.kill()
    try:
        os.unlink(tmp_file)
    except Exception:
        pass

    return result


async def _measure_speed(uri, port):
    """
    Измеряет download и upload скорость через SOCKS-прокси.
    Использует 20 МБ для каждого направления с пер-конфиг таймаут-лимитом,
    чтобы очень медленные конфиги не вешали тест бесконечно.
    """
    # Оставляем ~10 сек на handshake + IP-запрос, остальное — на dl + up
    _per_request_timeout = max(SPEED_TIMEOUT - 10, 60)

    try:
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        async with aiohttp.ClientSession(connector=connector) as session:
            down_mbps = 0
            up_mbps   = 0

            # ── DOWNLOAD ──────────────────────────────────────────────
            for url in DOWNLOAD_URLS:
                try:
                    start = time.time()
                    async with session.get(url,
                                           timeout=aiohttp.ClientTimeout(total=_per_request_timeout),
                                           ssl=False) as resp:
                        data = await resp.read()
                    elapsed = time.time() - start
                    if elapsed > 0:
                        down_mbps = (len(data) * 8) / elapsed / 1e6
                    if down_mbps > 0:
                        break
                except Exception:
                    continue

            if down_mbps == 0:
                return None

            # ── UPLOAD ────────────────────────────────────────────────
            try:
                payload = b'\x00' * UPLOAD_BYTES
                start = time.time()
                async with session.post(UPLOAD_URL, data=payload,
                                        timeout=aiohttp.ClientTimeout(total=_per_request_timeout)) as resp:
                    await resp.read()
                elapsed = time.time() - start
                if elapsed > 0:
                    up_mbps = (len(payload) * 8) / elapsed / 1e6
            except Exception:
                pass

            country = None
            try:
                async with session.get(IP_API, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    data = await resp.json()
                    country = data.get('countryCode')
            except Exception:
                pass

            if down_mbps >= SPEED_MIN_MBPS:
                proto = protocol_name(uri)
                flag  = get_flag(country) if country else "🏳"
                up_str = f"/{up_mbps:.0f}" if up_mbps > 0 else ""
                label = f"{proto} {flag} {down_mbps:.0f}{up_str}mbps t.me/ine4eg"
                new_uri = rebuild_uri(uri, label)
                log(f"[speed] OK ↓{down_mbps:.1f}/↑{up_mbps:.1f} Mbps  {proto} {flag}")
                return new_uri
            else:
                return None
    except Exception:
        return None


class SpeedTester:
    def __init__(self):
        self.semaphore = asyncio.Semaphore(SPEED_MAX_WORKERS)

    async def test_all(self, configs):
        log(f"[speed] Запуск тестирования {len(configs)} конфигов (workers={SPEED_MAX_WORKERS})")

        async def bounded(uri, idx):
            async with self.semaphore:
                return await speed_test_one(uri, idx)

        tasks = [asyncio.create_task(bounded(uri, i)) for i, uri in enumerate(configs)]
        results = []
        for i, task in enumerate(asyncio.as_completed(tasks)):
            r = await task
            if r:
                results.append(r)
            if (i + 1) % max(1, len(configs) // 10) == 0:
                pct = (i + 1) / len(configs) * 100
                log(f"[speed] Прогресс: {pct:.0f}% ({i+1}/{len(configs)}) — найдено {len(results)} рабочих")

        return results


# ═══════════════════════════════════════════════════════════════════════════════
#  BRIDGE — self-hosted Shadowsocks → ТРЕМ лучшим конфигам с health-check
# ═══════════════════════════════════════════════════════════════════════════════
import hashlib

SS_METHOD    = "chacha20-ietf-poly1305"
SS_PASSWORD  = hashlib.md5(b"self-hosted-ru-bridge").hexdigest()  # deterministic 32-char

BRIDGE_POOL_SIZE      = 3
HEALTH_CHECK_INTERVAL = 5  # секунд
BRIDGE_SOCKS_PORTS    = [BRIDGE_SOCKS_PORT, BRIDGE_SOCKS_PORT + 1, BRIDGE_SOCKS_PORT + 2]


def _extract_download_mbps(uri):
    """Извлечь download Mbps из лейбла URI (после #)"""
    try:
        label = uri.split("#", 1)[1]
        # URL-decode лейбла (пробелы могут быть %20)
        label = urllib.parse.unquote(label)
        # Ищем паттерн вроде "123mbps" или "123/45mbps"
        m = re.search(r"(\d+)\s*/\s*(?:\d+\s*)?mbps", label, re.IGNORECASE)
        if m:
            return int(m.group(1))
        # Попробуем просто число перед mbps
        m = re.search(r"(\d+)mbps", label, re.IGNORECASE)
        return int(m.group(1)) if m else 0
    except Exception:
        return 0

def _get_bridge_prefix():
    """Получить префикс bridge URI для фильтрации"""
    return f"ss://{base64.b64encode(f'{SS_METHOD}:{SS_PASSWORD}'.encode()).decode()}@"


def _is_non_ru_config(uri):
    """Проверить, что выходной IP конфига НЕ из РФ через GeoIP."""
    try:
        import geoip2.database
        import socket
        
        host = uri
        if '://' in host:
            host = host.split('://')[1]
        if '@' in host:
            host = host.split('@')[1]
        host = host.split(':')[0].split('?')[0]
        
        ip = socket.gethostbyname(host)
        
        db_path = '/usr/share/GeoIP/GeoLite2-Country.mmdb'
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip)
            return response.country.iso_code != 'RU'
    except Exception:
        pass
    # Если не определили — исключаем из bridge (better safe than sorry)
    return False


def _get_all_real_configs():
    """Получить все реальные конфиги (не bridge, не RU) из tested_configs.txt"""
    if not os.path.exists(TESTED_FILE):
        return []
    configs = parse_configs_file(TESTED_FILE)
    prefix = _get_bridge_prefix()
    real = [c for c in configs if not c.startswith(prefix) and _extract_download_mbps(c) > 0]
    # Фильтруем — только НЕ-РФ по GeoIP
    non_ru = [c for c in real if _is_non_ru_config(c)]
    if len(non_ru) < len(real):
        log(f"[bridge] GeoIP: {len(real)} рабочих → {len(non_ru)} без РФ")
    return non_ru


# ─── Глобальное состояние bridge-менеджера ─────────────────────────────
_bridge_state = {
    'upstream_procs': [None, None, None],
    'upstream_uris':  [None, None, None],
    'bridge_proc':    None,
    'active_idx':     0,
    'running':        False,
    'health_task':    None,
}


class BridgeManager:
    """Управляет ТРЕМЯ upstream-процессами с health-check и failover."""

    def __init__(self):
        self._bridge_state = {
            'running': False,
            'upstream_procs': [None, None, None],
            'upstream_uris': [None, None, None],
            'active_idx': 0,
            'bridge_proc': None,
            'health_task': None,
        }

    def _select_pool(self, top3):
        """Собрать пул из 3-х лучших конфигов, заполнив пустые слоты."""
        pool = [None, None, None]
        for i, uri in enumerate(top3[:3]):
            pool[i] = uri

        # Заполняем пустые слоты из доступных
        tested = _get_all_real_configs()
        used   = {u for u in pool if u is not None}
        available = [c for c in tested if c not in used]

        while None in pool and available:
            pos = pool.index(None)
            pool[pos] = available.pop(0)

        return pool

    async def _stop_process(self, proc):
        """Безопасно остановить процесс."""
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    async def _start_upstream(self, uri, port_idx):
        """Запустить один upstream xray на指定 SOCKS-порту."""
        socks_port = BRIDGE_SOCKS_PORTS[port_idx]
        cfg = make_xray_config(uri, socks_port)
        if not cfg:
            return None
        proc = await start_xray(cfg, socks_port)
        if proc:
            log(f"[bridge]   Upstream [{port_idx}] запущен (SOCKS :{socks_port})")
        return proc

    async def _restart_bridge(self, active_idx):
        """Перезапустить bridge xray с маршрутизацией на активный upstream."""
        if self._bridge_state['bridge_proc']:
            await self._stop_process(self._bridge_state['bridge_proc'])

        upstream_socks_port = BRIDGE_SOCKS_PORTS[active_idx]

        bridge_cfg = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "port": BRIDGE_PORT,
                "listen": "0.0.0.0",
                "protocol": "shadowsocks",
                "settings": {
                    "method": SS_METHOD,
                    "password": SS_PASSWORD,
                    "udp": True,
                    "network": "tcp,udp"
                }
            }],
            "outbounds": [{
                "tag": "proxy",
                "protocol": "socks",
                "settings": {
                    "servers": [{
                        "address": "127.0.0.1",
                        "port": upstream_socks_port
                    }]
                }
            }]
        }

        proc = await start_xray(bridge_cfg, BRIDGE_PORT)
        if proc:
            self._bridge_state['bridge_proc'] = proc
            log(f"[bridge]   Bridge → Shadowsocks :{BRIDGE_PORT} → SOCKS :{upstream_socks_port}")
        return proc

    async def _switch_to(self, new_idx):
        """Переключить активный upstream на new_idx."""
        if self._bridge_state['upstream_uris'][new_idx] is None:
            return False
        log(f"[bridge] ⚡ Переключение на upstream [{new_idx}]: {get_label(self._bridge_state['upstream_uris'][new_idx])[:50]}")
        self._bridge_state['active_idx'] = new_idx
        await self._restart_bridge(new_idx)
        return True

    async def _replenish_slot(self, slot_idx):
        """Пополнить слот новым рабочим конфигом."""
        tested = _get_all_real_configs()
        used   = set(self._bridge_state['upstream_uris']) - {None}
        available = [c for c in tested if c not in used]

        if not available:
            log("[bridge] Нет доступных конфигов для пополнения")
            return False

        # Берём лучший доступный
        new_uri = max(available, key=_extract_download_mbps)

        await self._stop_process(self._bridge_state['upstream_procs'][slot_idx])
        proc = await self._start_upstream(new_uri, slot_idx)
        if proc:
            self._bridge_state['upstream_procs'][slot_idx] = proc
            self._bridge_state['upstream_uris'][slot_idx]  = new_uri
            log(f"[bridge]   🔄 Слот [{slot_idx}] пополнен: {get_label(new_uri)[:50]}")
            return True

    async def _ping_socks(self, port_idx, timeout=3):
        """Проверить upstream через реальный запрос по SOCKS."""
        proc = self._bridge_state['upstream_procs'][port_idx]
        if proc is None or proc.poll() is not None:
            return False
        try:
            r = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    "curl", "-s", "--max-time", str(timeout),
                    "--socks5-hostname", f"127.0.0.1:{BRIDGE_SOCKS_PORTS[port_idx]}",
                    "http://cp.cloudflare.com/",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                ),
                timeout=timeout + 1
            )
            await r.communicate()
            return r.returncode == 0
        except Exception:
            return False

    async def health_check_loop(self):
        """Health-check каждые HEALTH_CHECK_INTERVAL секунд."""
        while self._bridge_state['running']:
            await asyncio.sleep(HEALTH_CHECK_INTERVAL)

            active = self._bridge_state['active_idx']

            # ── Проверяем все слоты ping-ом ──────────────────────────
            slot_health = {}
            for i in range(BRIDGE_POOL_SIZE):
                slot_health[i] = await self._ping_socks(i)

            # ── Логи статуса всех слотов ──────────────────────────────
            status_lines = []
            for i in range(BRIDGE_POOL_SIZE):
                uri  = self._bridge_state['upstream_uris'][i]
                proc = self._bridge_state['upstream_procs'][i]
                label_short = get_label(uri)[:40] if uri else "пусто"

                if i == active:
                    role = "ACTIVE"
                else:
                    role = "backup"

                if proc is None:
                    health = "✗ нет процесса"
                elif proc.poll() is not None:
                    health = "✗ упал"
                elif slot_health[i]:
                    health = "✓ жив (ping OK)"
                else:
                    health = "✗ ping FAIL"

                port = BRIDGE_SOCKS_PORTS[i]
                status_lines.append(f"  [{i}]({role}) port:{port} {health} | {label_short}")

            log("[bridge] 🩺 Health-Check:")
            for line in status_lines:
                log(line)
            # ── Конец логов статуса ────────────────────────────────────

            # ── Проверяем активный upstream ───────────────────────────
            active_proc = self._bridge_state['upstream_procs'][active]
            active_dead = (active_proc is None
                           or active_proc.poll() is not None
                           or not slot_health.get(active, False))

            if active_dead:
                log(f"[bridge] ⚠️ Active upstream [{active}] не отвечает!")

                # Ищем живой backup
                switched = False
                for i in range(BRIDGE_POOL_SIZE):
                    if i == active:
                        continue
                    if slot_health.get(i, False):
                        await self._switch_to(i)
                        switched = True
                        break

                # Восстанавливаем упавший слот
                await self._replenish_slot(active)

                # Если не переключились, пробуем после восстановления
                if not switched:
                    for i in range(BRIDGE_POOL_SIZE):
                        if slot_health.get(i, False):
                            await self._switch_to(i)
                            switched = True
                            break

                if not switched:
                    log("[bridge] ❌ Нет доступных upstream-процессов!")

            # Проверяем backup-слоты — восстанавливаем упавшие
            for i in range(BRIDGE_POOL_SIZE):
                if i == self._bridge_state['active_idx']:
                    continue
                if self._bridge_state['upstream_uris'][i]:
                    if not slot_health.get(i, False):
                        log(f"[bridge] ⚠️ Backup upstream [{i}] не отвечает, пополняю...")
                        await self._replenish_slot(i)

    def _save_bridge_uri(self, bridge_uri):
        """Сохранить bridge URI в начало tested_configs.txt."""
        prefix = _get_bridge_prefix()
        existing_lines = []
        header_lines = []
        if os.path.exists(TESTED_FILE):
            with open(TESTED_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        header_lines.append(line)
                    elif line:
                        existing_lines.append(line)

        existing_lines = [l for l in existing_lines if not l.startswith(prefix)]

        with open(TESTED_FILE, "w", encoding="utf-8") as f:
            for hl in header_lines:
                f.write(hl + "\n")
            f.write("\n")
            f.write(bridge_uri + "\n")
            for l in existing_lines:
                f.write(l + "\n")

        log(f"[bridge] ✅ Bridge-конфиг добавлен в {TESTED_FILE}")

    async def start(self, top3_uris):
        """Запустить bridge с ТРЕМЯ лучшими конфигами."""
        if not top3_uris:
            log("[bridge] Нет URI для bridge")
            return

        self._bridge_state['running'] = True

        log("=" * 60)
        log("  BRIDGE: self-hosted Shadowsocks мост (3 upstream + health-check)")
        log("=" * 60)

        # Остановить старые процессы
        for proc in self._bridge_state['upstream_procs']:
            await self._stop_process(proc)
        await self._stop_process(self._bridge_state['bridge_proc'])

        self._bridge_state['upstream_procs'] = [None, None, None]
        self._bridge_state['upstream_uris']  = [None, None, None]
        self._bridge_state['bridge_proc']    = None

        # Собрать пул из 3-х
        pool = self._select_pool(top3_uris)
        self._bridge_state['upstream_uris'] = pool

        # Запустить все 3 upstream
        for i in range(BRIDGE_POOL_SIZE):
            if pool[i]:
                dl = _extract_download_mbps(pool[i])
                log(f"[bridge]   [{i}] ↓{dl} Mbps — {get_label(pool[i])[:50]}")
                proc = await self._start_upstream(pool[i], i)
                self._bridge_state['upstream_procs'][i] = proc

        # Активный = слот 0 (лучший)
        self._bridge_state['active_idx'] = 0
        await self._restart_bridge(0)

        # Сгенерировать и сохранить bridge URI
        bridge_label = "self-hosted RU 🇷🇺"
        userinfo = base64.b64encode(f"{SS_METHOD}:{SS_PASSWORD}".encode()).decode()
        bridge_uri = f"ss://{userinfo}@{BRIDGE_IP}:{BRIDGE_PORT}#{urllib.parse.quote(bridge_label)}"
        log(f"[bridge] URI: {bridge_uri}")
        self._save_bridge_uri(bridge_uri)

        # Запустить health-check задачу
        if self._bridge_state['health_task']:
            self._bridge_state['health_task'].cancel()
        self._bridge_state['health_task'] = asyncio.create_task(self.health_check_loop())

        log(f"[bridge] ✅ Bridge запущен с {BRIDGE_POOL_SIZE} upstream, health-check каждые {HEALTH_CHECK_INTERVAL}с")


# Глобальный менеджер
_bridge_manager = BridgeManager()


async def create_bridge(top3_uris):
    """
    Создаёт мост с ТРЕМЯ лучшими конфигами:
      1. Запускает 3 upstream xray (по одному на конфиг)
      2. Запускает bridge xray (Shadowsocks → активный upstream)
      3. Health-check каждые 5с, failover при падении активного
      4. Динамическое пополнение пула при падении любого слота
      5. Вход: один порт 8443
    """
    await _bridge_manager.start(top3_uris)


async def do_speed_stage():
    log("=" * 60)
    log("  ЭТАП 2: SPEED-ТЕСТ")
    log("=" * 60)

    if not os.path.exists(WORKING_FILE):
        log(f"[speed] Файл {WORKING_FILE} не найден, пропускаем")
        return

    configs = parse_configs_file(WORKING_FILE)
    if not configs:
        log("[speed] Нет конфигураций для speed-теста")
        return

    log(f"[speed] Загружено {len(configs)} уникальных конфигов")

    tester = SpeedTester()
    t0 = time.time()
    results = await tester.test_all(configs)
    elapsed = time.time() - t0

    if results:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(TESTED_FILE, "w", encoding="utf-8") as f:
            f.write("#profile-title: С высокой скоростью\n")
            f.write("#profile-update-interval: 1\n")
            f.write("#support-url: https://t.me/ine4eg\n")
            f.write("#announce: t.me/ine4eg\n")
            f.write("#subscription-userinfo: upload=0; download=0; total=0; expire=0\n\n")
            for r in results:
                f.write(r + "\n")
        log(f"[speed] Готово! Найдено {len(results)} быстрых конфигов — {TESTED_FILE}")
        log(f"[speed] Время: {elapsed:.1f} сек, скорость: {len(configs)/elapsed:.1f} конфигов/сек")

        # ── Найти ТРЕХ лучших конфигов и создать bridge с failover ──
        top3 = sorted(results, key=_extract_download_mbps, reverse=True)[:3]
        await create_bridge(top3)
    else:
        log("[speed] Не найдено ни одного быстрого конфига")


# ═══════════════════════════════════════════════════════════════════════════════
#  API СЕРВЕР
# ═══════════════════════════════════════════════════════════════════════════════

from aiohttp import web

async def handle_working_configs(request):
    try:
        if os.path.exists(WORKING_FILE):
            with open(WORKING_FILE, "r", encoding="utf-8") as f:
                content = f.read()
            return web.Response(
                text=content,
                content_type="text/plain",
                charset="utf-8"
            )
        else:
            return web.Response(text="Нет доступных конфигов", status=404)
    except Exception as e:
        return web.Response(text=str(e), status=500)


async def handle_tested_configs(request):
    try:
        if os.path.exists(TESTED_FILE):
            with open(TESTED_FILE, "r", encoding="utf-8") as f:
                content = f.read()
            return web.Response(
                text=content,
                content_type="text/plain",
                charset="utf-8"
            )
        else:
            return web.Response(text="Нет доступных конфигов", status=404)
    except Exception as e:
        return web.Response(text=str(e), status=500)


async def start_api_server():
    """Запуск HTTP API сервера"""
    app = web.Application()
    app.router.add_get("/working_configs", handle_working_configs)
    app.router.add_get("/tested_configs", handle_tested_configs)
    
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(
        runner,
        "0.0.0.0",
        API_PORT
        # Убираем ssl_context - Cloudflare Tunnel сам предоставляет HTTPS
    )
    await site.start()
    log(f"[API] Сервер запущен на http://0.0.0.0:{API_PORT}")
    log(f"[API] Доступные эндпоинты: GET /working_configs, GET /tested_configs")


# ═══════════════════════════════════════════════════════════════════════════════
#  ПЛАНИРОВЩИК
# ═══════════════════════════════════════════════════════════════════════════════

async def run_cycle():
    """Один полный цикл: ping → speed."""
    log("▶▶▶ Запуск цикла")
    cycle_start = time.time()

    working_count = await do_ping_stage()

    if working_count > 0:
        await do_speed_stage()
    else:
        log("[!] Ping-тест не дал рабочих конфигов, speed-тест пропускается")

    elapsed = time.time() - cycle_start
    log(f"◀◀◀ Цикл завершён за {elapsed:.0f} сек.")


async def scheduler():
    log(f"Планировщик запущен. Интервал: {RUN_INTERVAL} сек ({RUN_INTERVAL//60} мин)")
    log(f"Output dir: {OUTPUT_DIR}")
    log(f"xray bin  : {XRAY_BIN}")

    while True:
        await run_cycle()
        next_run = time.time() + RUN_INTERVAL
        log(f"Следующий запуск: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(next_run))}")
        await asyncio.sleep(RUN_INTERVAL)


async def main():
    """Запуск API сервера и планировщика параллельно"""
    await asyncio.gather(
        start_api_server(),
        scheduler()
    )


if __name__ == "__main__":
    asyncio.run(main())
