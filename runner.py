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
SPEED_TIMEOUT   = 150
SPEED_MIN_MBPS  = 5
SPEED_MAX_WORKERS = 60
SPEED_SOCKS_BASE = 12000
DOWNLOAD_URLS   = [
    "http://speed.cloudflare.com/__down?bytes=3000000",
    "https://cachefly.cachefly.net/1mb.test",
]
UPLOAD_URL      = "https://speed.cloudflare.com/__up"
IP_API          = "http://ip-api.com/json/"

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

        kwargs = {}
        if os.name != "nt":
            kwargs["preexec_fn"] = os.setsid

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", tmp.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **kwargs
        )
        await asyncio.sleep(1.0)

        if proc.poll() is not None:
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
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        log(f"[ping] Ошибка загрузки: {e}")
        return []

    configs = []
    for line in text.splitlines():
        line = line.strip().replace("&amp;", "&")
        if not line or line.startswith("#"):
            continue
        if re.match(r"^(vless|vmess|trojan|ss)://", line):
            cleaned = clean_url(line)
            if cleaned and len(cleaned) > 20:
                configs.append(cleaned)
    
    # Удаляем дубликаты
    configs = list(dict.fromkeys(configs))
    
    log(f"[ping] Найдено конфигов: {len(configs)}")
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


def save_working_configs(results):
    ok = sorted([r for r in results if r["ping"] is not None], key=lambda x: x["ping"])
    if not ok:
        log("[ping] Нет рабочих конфигов")
        return 0

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(WORKING_FILE, "w") as f:
        f.write("#profile-title: С высокой скоростью\n")
        f.write("#profile-update-interval: 1\n")
        f.write("#support-url: https://t.me/ine4eg\n")
        f.write("#announce: t.me/ine4eg\n")
        f.write("#subscription-userinfo: upload=0; download=0; total=0; expire=0\n\n")

        for r in ok:
            f.write(r["uri"].strip() + "\n")

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
    configs = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
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
    try:
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        async with aiohttp.ClientSession(connector=connector) as session:
            down_mbps = 0
            up_mbps   = 0

            for url in DOWNLOAD_URLS:
                try:
                    start = time.time()
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=SPEED_TIMEOUT)) as resp:
                        data = await resp.read()
                    elapsed = time.time() - start
                    down_mbps = (len(data) * 8) / elapsed / 1e6
                    if down_mbps > 0:
                        break
                except Exception:
                    continue

            if down_mbps == 0:
                return None

            try:
                payload = b'x' * 500000
                start = time.time()
                async with session.post(UPLOAD_URL, data=payload,
                                        timeout=aiohttp.ClientTimeout(total=SPEED_TIMEOUT)) as resp:
                    await resp.read()
                elapsed = time.time() - start
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

            if down_mbps >= SPEED_MIN_MBPS and up_mbps >= SPEED_MIN_MBPS:
                proto = protocol_name(uri)
                flag  = get_flag(country) if country else "🏳"
                label = f"{proto} {flag} {down_mbps:.0f}/{up_mbps:.0f}mbps t.me/ine4eg"
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
