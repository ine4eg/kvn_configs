#!/usr/bin/env python3
"""
VPN Config Runner
=================
Запускается раз в час:
  1. vpn_ping_test  — скачивает конфиги, пингует, сохраняет рабочие в working_configs.txt
  2. speed_test     — берёт working_configs.txt, мерит скорость, сохраняет в tested_configs.txt

BRIDGE ARCHITECTURE:
  • 3 upstream xray (SOCKS) работают параллельно на портах 10801-10803
  • 1 bridge xray (SS) на порту 8443 слушает весь трафик клиентов
  • bridge маршрутизирует на лучший healthy upstream
  • health-check каждые 10 секунд пингует каждый upstream
  • failover = перезапуск bridge с routing на другой healthy upstream

Переменные окружения:
  CONFIG_URL     — URL списка конфигов
  XRAY_BIN       — путь к xray-бинарнику (default: xray)
  RUN_INTERVAL   — интервал в секундах (default: 3600)
  OUTPUT_DIR     — папка для файлов (default: /data)
"""

import asyncio
import base64
import hashlib
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
SPEED_TIMEOUT   = 60
SPEED_MIN_MBPS  = 5
SPEED_MAX_WORKERS = 70
SPEED_SOCKS_BASE = 12000
DOWNLOAD_BYTES  = 20 * 1024 * 1024
DOWNLOAD_URLS   = [
    f"http://speed.cloudflare.com/__down?bytes={DOWNLOAD_BYTES}",
    f"https://speed.cloudflare.com/__down?bytes={DOWNLOAD_BYTES}",
]
UPLOAD_BYTES    = 20 * 1024 * 1024
UPLOAD_URL      = "https://speed.cloudflare.com/__up"
IP_API          = "http://ip-api.com/json/"

# ═══════════════════════════════════════════════════════════════════════════════
#  BRIDGE — 3 upstream + 1 bridge (порт 8443) + health-check каждые 10с
# ═══════════════════════════════════════════════════════════════════════════════

BRIDGE_IP       = "95.165.137.180"
BRIDGE_PORT     = 8443               # ОДИН порт для клиентов (SS)
HEALTH_INTERVAL = 10                 # секунд между health-checkами
UPSTREAM_SOCKS_BASE = 19001          # SOCKS для upstream: 19001, 19002, 19003
FAILOVER_MAX_RETRIES = 5

# Shadowsocks credentials
SS_METHOD    = "chacha20-ietf-poly1305"
SS_PASSWORD  = hashlib.md5(b"self-hosted-ru-bridge").hexdigest()

_bridge_manager = None


class _BridgeSlot:
    """Слот для одного upstream-конфига"""
    def __init__(self):
        self.uri = None
        self.label = ""
        self.download_mbps = 0
        self.upload_mbps = 0
        self.healthy = False
        self.consecutive_failures = 0
        self.last_check = None
        self.upstream_proc = None
        self.upstream_socks_port = 0


class BridgeManager:
    """
    Архитектура:
      • 3 upstream xray (SOCKS) на внутренних портах 19001-19003
      • 1 bridge xray (SS) на BRIDGE_PORT=8443, маршрутизирует на активный upstream
      • health-check каждые 10с пингует каждый upstream
      • failover = перезапуск bridge с routing на healthy upstream
    """

    def __init__(self):
        self.slots = [_BridgeSlot() for _ in range(3)]
        self.backup_pool = []
        self.backup_cursor = 0
        self._health_task = None
        self._bridge_proc = None
        self._active_upstream_idx = 0
        self._lock = asyncio.Lock()

    # ── Публичный API ───────────────────────────────────────────────

    async def start_top3(self, tested_results):
        """Запустить 3 upstream + 1 bridge на BRIDGE_PORT"""
        await self._stop_all()

        real = [
            c for c in tested_results
            if not _is_bridge_uri(c) and _extract_download_mbps(c) > 0
        ]
        real.sort(key=_extract_download_mbps, reverse=True)

        if not real:
            log("[bridge] Нет рабочих конфигов")
            return

        top3 = real[:3]
        self.backup_pool = real[3:]
        self.backup_cursor = 0

        for i, uri in enumerate(top3):
            slot = self.slots[i]
            slot.uri = uri
            slot.label = get_label(uri)
            slot.download_mbps = _extract_download_mbps(uri)
            slot.upstream_socks_port = UPSTREAM_SOCKS_BASE + i
            slot.healthy = False
            slot.consecutive_failures = 0

        log("[bridge] Запуск 3 upstream процессов...")
        await asyncio.gather(*[self._start_upstream(i) for i in range(3)])

        self._active_upstream_idx = 0
        await self._restart_bridge()
        self._save_bridge_uri()

        self._health_task = asyncio.create_task(self._health_loop())
        log(f"[bridge] ✅ Bridge запущен SS:{BRIDGE_PORT}")
        log(f"[bridge] Active slot[{self._active_upstream_idx}] = {self.slots[self._active_upstream_idx].label[:50]}")

    # ── Health-check ────────────────────────────────────────────────

    async def _health_loop(self):
        while True:
            try:
                await self._do_health_check()
            except Exception as e:
                log(f"[bridge-health] Ошибка: {e}")
            await asyncio.sleep(HEALTH_INTERVAL)

    async def _do_health_check(self):
        now = time.time()
        for i, slot in enumerate(self.slots):
            if slot.upstream_proc is None or slot.upstream_proc.poll() is not None:
                slot.healthy = False
                slot.consecutive_failures += 1
                continue

            ms = await _ping_upstream(slot.upstream_socks_port)
            slot.last_check = now

            if ms is not None and ms < 5000:
                if not slot.healthy:
                    log(f"[bridge-health] ✅ slot[{i}] recovered  {slot.label[:40]}")
                slot.healthy = True
                slot.consecutive_failures = 0
            else:
                if slot.healthy:
                    log(f"[bridge-health] ❌ slot[{i}] down  {slot.label[:40]}")
                slot.healthy = False
                slot.consecutive_failures += 1

        if not self.slots[self._active_upstream_idx].healthy:
            log(f"[bridge-health] ⚠️  Active slot[{self._active_upstream_idx}] unhealthy → failover")
            await self._failover()

    # ── Failover ────────────────────────────────────────────────────

    async def _failover(self):
        """Переключить bridge на другой healthy upstream"""
        async with self._lock:
            healthy_slots = [(i, s) for i, s in enumerate(self.slots) if s.healthy]

            if healthy_slots:
                healthy_slots.sort(key=lambda x: x[0])
                new_idx = healthy_slots[0][0]
                self._active_upstream_idx = new_idx
                log(f"[bridge-failover] → slot[{new_idx}] = {self.slots[new_idx].label[:50]}")
                await self._restart_bridge()
                return

            # Ни один slot не healthy → пробовать backup
            for _ in range(FAILOVER_MAX_RETRIES):
                if self.backup_cursor >= len(self.backup_pool):
                    log("[bridge-failover] ❌ Backup pool исчерпан")
                    return
                candidate = self.backup_pool[self.backup_cursor]
                self.backup_cursor += 1
                log(f"[bridge-failover] Пробуем backup: {get_label(candidate)[:50]}")

                ms = await _quick_test(candidate)
                if ms is not None:
                    worst_idx = max(range(3), key=lambda i: self.slots[i].consecutive_failures)
                    self._stop_upstream(worst_idx)
                    slot = self.slots[worst_idx]
                    slot.uri = candidate
                    slot.label = get_label(candidate)
                    slot.download_mbps = _extract_download_mbps(candidate)
                    slot.consecutive_failures = 0
                    slot.healthy = True
                    await self._start_upstream(worst_idx)
                    self._active_upstream_idx = worst_idx
                    await self._restart_bridge()
                    log(f"[bridge-failover] ✅ Backup работает! slot[{worst_idx}]")
                    return

            log("[bridge-failover] ❌ Нет healthy upstream, backup исчерпан!")

    # ── Upstream management ─────────────────────────────────────────

    async def _start_upstream(self, idx):
        slot = self.slots[idx]
        if not slot.uri:
            return
        xray_cfg = make_xray_config(slot.uri, slot.upstream_socks_port)
        if not xray_cfg:
            log(f"[bridge] ❌ Не удалось распарсить slot[{idx}]")
            return
        proc = await start_xray(xray_cfg, slot.upstream_socks_port)
        if proc:
            slot.upstream_proc = proc
            slot.healthy = True
            log(f"[bridge] Upstream slot[{idx}] SOCKS:{slot.upstream_socks_port}  {slot.label[:40]}")
        else:
            log(f"[bridge] ❌ Не запустился slot[{idx}]")
            slot.healthy = False

    def _stop_upstream(self, idx):
        slot = self.slots[idx]
        if slot.upstream_proc:
            stop_xray(slot.upstream_proc)
            slot.upstream_proc = None

    # ── Bridge management ───────────────────────────────────────────

    async def _restart_bridge(self):
        """Перезапустить bridge: SS inbound → SOCKS outbound на активный upstream"""
        if self._bridge_proc:
            log("[bridge] Остановка старого bridge...")
            stop_xray(self._bridge_proc)
            self._bridge_proc = None

        active = self._active_upstream_idx
        slot = self.slots[active]
        upstream_socks_port = slot.upstream_socks_port

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
                    "servers": [{"address": "127.0.0.1", "port": upstream_socks_port}]
                }
            }]
        }

        try:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, prefix="bridge_")
            json.dump(bridge_cfg, tmp)
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
            proc._tmp = tmp.name
            await asyncio.sleep(1.5)

            if proc.poll() is not None:
                log(f"[bridge] ❌ Bridge xray упал (exit={proc.poll()})")
                try:
                    os.unlink(tmp.name)
                except Exception:
                    pass
                return

            self._bridge_proc = proc
            log(f"[bridge] ✅ Bridge: SS:{BRIDGE_PORT} → SOCKS:{upstream_socks_port} (slot[{active}])")
        except Exception as e:
            log(f"[bridge] ❌ Ошибка запуска bridge: {e}")

    # ── Save bridge URI ─────────────────────────────────────────────

    def _save_bridge_uri(self):
        userinfo = base64.b64encode(f"{SS_METHOD}:{SS_PASSWORD}".encode()).decode()
        bridge_uri = f"ss://{userinfo}@{BRIDGE_IP}:{BRIDGE_PORT}#{urllib.parse.quote('self-hosted RU 🇷🇺')}"

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

        existing_lines = [l for l in existing_lines if not _is_bridge_uri(l)]

        with open(TESTED_FILE, "w", encoding="utf-8") as f:
            for hl in header_lines:
                f.write(hl + "\n")
            f.write("\n")
            f.write(bridge_uri + "\n")
            for l in existing_lines:
                f.write(l + "\n")

        log(f"[bridge] ✅ Bridge URI сохранён в {TESTED_FILE}")

    # ── Status ──────────────────────────────────────────────────────

    def get_status(self):
        status = []
        for i, slot in enumerate(self.slots):
            status.append({
                "slot": i,
                "active": (i == self._active_upstream_idx),
                "healthy": slot.healthy,
                "label": (slot.label[:50] if slot.label else None),
                "download_mbps": slot.download_mbps,
                "upstream_socks_port": slot.upstream_socks_port,
                "consecutive_failures": slot.consecutive_failures,
                "last_check": slot.last_check,
            })
        return {
            "bridge_port": BRIDGE_PORT,
            "active_upstream_idx": self._active_upstream_idx,
            "slots": status,
            "backup_remaining": max(0, len(self.backup_pool) - self.backup_cursor),
        }

    async def _stop_all(self):
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
        if self._bridge_proc:
            stop_xray(self._bridge_proc)
            self._bridge_proc = None
        for i in range(3):
            self._stop_upstream(i)
        for slot in self.slots:
            slot.uri = None
            slot.healthy = False
            slot.consecutive_failures = 0


def _is_bridge_uri(uri):
    """Проверить, является ли URI нашим bridge-конфигом"""
    return uri.startswith(f"ss://{base64.b64encode(f'{SS_METHOD}:{SS_PASSWORD}'.encode()).decode()}@")


async def _ping_upstream(socks_port):
    """Измерить задержку upstream SOCKS-порта"""
    connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            t0 = time.perf_counter()
            async with session.get(
                PING_TEST_URL,
                timeout=aiohttp.ClientTimeout(total=3),
                allow_redirects=False, ssl=False
            ) as resp:
                await resp.read()
            return (time.perf_counter() - t0) * 1000
    except Exception:
        return None
    finally:
        await connector.close()


async def _quick_test(uri):
    """Быстрый тест: один HTTP-запрос через конфиг"""
    socks_port = find_free_port(20000, 0)
    xray_cfg = make_xray_config(uri, socks_port)
    if not xray_cfg:
        return None
    proc = await start_xray(xray_cfg, socks_port)
    if not proc:
        return None
    try:
        return await _ping_upstream(socks_port)
    finally:
        stop_xray(proc)


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


def _extract_download_mbps(uri):
    """Извлечь download Mbps из лейбла URI"""
    try:
        label = uri.split("#", 1)[1]
        label = urllib.parse.unquote(label)
        m = re.search(r"(\d+)\s*/\s*(?:\d+\s*)?mbps", label, re.IGNORECASE)
        if m:
            return int(m.group(1))
        m = re.search(r"(\d+)mbps", label, re.IGNORECASE)
        return int(m.group(1)) if m else 0
    except Exception:
        return 0


# ═══════════════════════════════════════════════════════════════════════════════
#  ГЕНЕРАЦИЯ XRAY-КОНФИГОВ
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
        stream["security"] = security

    return _base_xray(socks_port, {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port,
                                 "users": [{"id": user_id, "flow": flow, "encryption": "none"}]}]},
        "streamSettings": stream
    })


def _vmess_xray(uri, socks_port):
    try:
        payload = base64.b64decode(uri[len("vmess://"):]).decode("utf-8")
        info = json.loads(payload)
    except Exception:
        return None
    host = info.get("add", "")
    port = int(info.get("port", 443))
    user_id = info.get("id", "")
    alter_id = int(info.get("aid", 0))
    net = info.get("net", info.get("type", "tcp"))
    security = info.get("tls", "none")
    sni = info.get("sni", host)
    path = info.get("path", "/")
    host_h = info.get("host", host)
    svc = info.get("path", "")

    stream = {"network": net}
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_h}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": svc, "multiMode": False, "mode": "gun"}
    else:
        stream["tcpSettings"] = {}

    if security in ("tls", "xtls"):
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "fingerprint": "chrome"}

    return _base_xray(socks_port, {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port,
                                 "users": [{"id": user_id, "alterId": alter_id}]}]},
        "streamSettings": stream
    })


def _trojan_xray(uri, socks_port):
    m = re.match(r"trojan://([^@]+)@([^:]+):(\d+)\??([^#]*)", uri)
    if not m:
        return None
    pwd, host, port = m.group(1), m.group(2), int(m.group(3))
    params = dict(urllib.parse.parse_qsl(m.group(4)))
    net = params.get("type", "tcp")
    security = params.get("security", "none")
    sni = params.get("sni", host)
    fp = params.get("fp", "chrome") or "chrome"
    path = params.get("path", "/")
    host_h = params.get("host", host)
    svc = params.get("serviceName", "")

    stream = {"network": net}
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_h}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": svc, "multiMode": False, "mode": "gun"}
    else:
        stream["tcpSettings"] = {}

    if security == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp}

    return _base_xray(socks_port, {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": pwd}]},
        "streamSettings": stream
    })


def _ss_xray(uri, socks_port):
    m = re.match(r"ss://([^@]+)@([^:]+):(\d+)", uri)
    if not m:
        return None
    encoded = m.group(1)
    # URL-decode first (may contain %XX encoded chars including base64 padding)
    encoded = urllib.parse.unquote(encoded)
    # Convert URL-safe base64 to standard base64
    encoded = encoded.replace("-", "+").replace("_", "/")
    # Add base64 padding if missing
    pad = len(encoded) % 4
    if pad:
        encoded += "=" * (4 - pad)
    try:
        creds = base64.b64decode(encoded).decode("utf-8")
    except Exception:
        return None
    if ":" not in creds:
        return None
    method, password = creds.split(":", 1)
    host, port = m.group(2), int(m.group(3))

    return _base_xray(socks_port, {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port,
                                   "method": method, "password": password}]},
        "streamSettings": {"network": "tcp"}
    })


def make_xray_config(uri, socks_port):
    uri = clean_url(uri)
    if uri.startswith("vless://"):
        return _vless_xray(uri, socks_port)
    elif uri.startswith("vmess://"):
        return _vmess_xray(uri, socks_port)
    elif uri.startswith("trojan://"):
        return _trojan_xray(uri, socks_port)
    elif uri.startswith("ss://"):
        return _ss_xray(uri, socks_port)
    return None


async def start_xray(config_json, socks_port):
    try:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, prefix="xray_")
        json.dump(config_json, tmp)
        tmp.close()
        kwargs = {}
        if os.name != "nt":
            kwargs["preexec_fn"] = os.setsid
        proc = subprocess.Popen([XRAY_BIN, "run", "-c", tmp.name],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
        proc._tmp = tmp.name
        await asyncio.sleep(1)
        if proc.poll() is not None:
            log(f"[!] xray упал на порту {socks_port} (exit={proc.poll()})")
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
            return None
        return proc
    except Exception as e:
        log(f"[!] Ошибка запуска xray: {e}")
        return None


def stop_xray(proc):
    try:
        if proc.poll() is None:
            try:
                os.kill(proc.pid, signal.SIGTERM)
            except Exception:
                proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
    except Exception:
        pass
    finally:
        try:
            if hasattr(proc, "_tmp") and os.path.exists(proc._tmp):
                os.unlink(proc._tmp)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
#  ПИНГ-ТЕСТ
# ═══════════════════════════════════════════════════════════════════════════════

async def ping_one(uri):
    port = find_free_port(PING_SOCKS_BASE, 0)
    xray_cfg = make_xray_config(uri, port)
    if not xray_cfg:
        return None, uri
    proc = await start_xray(xray_cfg, port)
    if not proc:
        return None, uri
    best = None
    for _ in range(PING_TRIES):
        try:
            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
            try:
                async with aiohttp.ClientSession(connector=connector) as session:
                    t0 = time.perf_counter()
                    async with session.get(PING_TEST_URL, timeout=aiohttp.ClientTimeout(total=PING_TIMEOUT)) as resp:
                        await resp.read()
                    elapsed = (time.perf_counter() - t0) * 1000
                    if best is None or elapsed < best:
                        best = elapsed
            finally:
                await connector.close()
        except Exception:
            pass
        finally:
            await asyncio.sleep(0.2)
    stop_xray(proc)
    return best, uri


async def vpn_ping_test():
    log("── Загрузка конфигов ──")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(CONFIG_URL, ssl=False) as resp:
                text = await resp.text()
    except Exception as e:
        log(f"[!] Не удалось скачать конфиги: {e}")
        return []

    raw = []
    for line in text.splitlines():
        line = line.strip()
        for part in line.split():
            part = part.strip()
            if part.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                raw.append(part)
    log(f"[ping] Всего сырых строк: {len(raw)}")

    cleaned = []
    seen = set()
    for u in raw:
        u = clean_url(u)
        h = hashlib.md5(u.encode()).hexdigest()[:12]
        if h not in seen:
            seen.add(h)
            cleaned.append(u)
    log(f"[ping] Уникальных после очистки: {len(cleaned)}")

    total = len(cleaned)
    tested = 0
    working_count = 0
    failed_count = 0
    best_results = []  # (ms, label) для лучших результатов
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(PING_MAX_WORKERS)
    last_log_time = 0

    async def limited(uri):
        nonlocal tested, working_count, failed_count, last_log_time
        async with sem:
            ms, _ = await ping_one(uri)
        async with lock:
            tested += 1
            label = get_label(uri)[:40]
            proto = protocol_name(uri)
            now = time.time()
            if ms is not None:
                working_count += 1
                best_results.append((ms, label, proto))
                # Логируем каждый рабочий + периодический прогресс
                if ms < 300 or (tested % 25 == 0) or tested == total or (now - last_log_time) > 2:
                    best_results.sort(key=lambda x: x[0])
                    top3 = best_results[:3]
                    top_str = "; ".join(f"{ms:.0f}ms {lbl}" for ms, lbl, _ in top3)
                    log(f"[ping] {working_count}/{tested} ✅ {ms:.0f}ms {proto} {label}  |  TOP3: {top_str}")
                    last_log_time = now
            else:
                failed_count += 1
                if (tested % 25 == 0) or tested == total or (now - last_log_time) > 2:
                    log(f"[ping] {working_count}/{tested} ❌ {proto} {label}  |  Нерабочих: {failed_count}")
                    last_log_time = now
        return ms, uri

    coros = [limited(u) for u in cleaned]
    results = await asyncio.gather(*coros)

    working = []
    for ms, uri in results:
        if ms is not None:
            working.append(uri)

    working.sort(key=lambda u: _extract_download_mbps(u) if _extract_download_mbps(u) > 0 else float('inf'))

    # Итоговая сводка пинг-теста
    log(f"\n{'═'*70}")
    log(f"[ping] 📊 ИТОГИ ПИНГ-ТЕСТА")
    log(f"  Всего тестировано: {total}")
    log(f"  Рабочих: {working_count}  |  Нерабочих: {failed_count}")
    if best_results:
        best_results.sort(key=lambda x: x[0])
        log(f"  🏆 Лучшие по пингу:")
        for i, (ms, label, proto) in enumerate(best_results[:10], 1):
            medal = ["🥇", "🥈", "🥉"][i-1] if i <= 3 else f" {i}."
            log(f"    {medal} {ms:.0f}ms  {proto}  {label}")
    log(f"{'═'*70}\n")
    return working


# ═══════════════════════════════════════════════════════════════════════════════
#  СПИД-ТЕСТ
# ═══════════════════════════════════════════════════════════════════════════════

async def speed_one(uri):
    port = find_free_port(SPEED_SOCKS_BASE, 0)
    xray_cfg = make_xray_config(uri, port)
    if not xray_cfg:
        return None
    proc = await start_xray(xray_cfg, port)
    if not proc:
        return None

    connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
    result = None

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            # IP
            try:
                async with session.get(IP_API, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                    ip_info = await resp.json()
            except Exception:
                ip_info = {"country": "??", "query": "???"}

            # Download
            dl_speeds = []
            for url in DOWNLOAD_URLS:
                try:
                    t0 = time.perf_counter()
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=SPEED_TIMEOUT)) as resp:
                        while True:
                            chunk = await resp.content.read(1024 * 1024)
                            if not chunk:
                                break
                    elapsed = time.perf_counter() - t0
                    if elapsed > 0:
                        dl_speeds.append(resp.content.length / elapsed * 8 / 1_000_000)
                except Exception:
                    pass

            # Upload
            try:
                t0 = time.perf_counter()
                payload = bytearray(os.urandom(min(UPLOAD_BYTES, 5 * 1024 * 1024)))
                async with session.post(UPLOAD_URL, data=payload,
                                        timeout=aiohttp.ClientTimeout(total=SPEED_TIMEOUT), ssl=False) as resp:
                    await resp.read()
                elapsed = time.perf_counter() - t0
                if elapsed > 0:
                    ul_mbps = len(payload) / elapsed * 8 / 1_000_000
                else:
                    ul_mbps = 0
            except Exception:
                ul_mbps = 0

            dl_avg = sum(dl_speeds) / len(dl_speeds) if dl_speeds else 0

            label = get_label(uri)
            flag = get_flag(ip_info.get("country", "??"))
            proto = protocol_name(uri)
            ip = ip_info.get("query", "???")

            enriched = f"{uri}  {flag} {proto}  {ip}  ↓{dl_avg:.0f} / ↑{ul_mbps:.0f} mbps"
            return enriched
    finally:
        await connector.close()
        stop_xray(proc)


async def speed_test():
    if not os.path.exists(WORKING_FILE):
        log("[!] working_configs.txt не найден — пропускаем speed-test")
        return []

    with open(WORKING_FILE, "r", encoding="utf-8") as f:
        uris = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    total = len(uris)
    log(f"[speed] Тестирование скорости {total} конфигов...")

    tested = 0
    failed_count = 0
    results = []
    best_speeds = []  # (dl_mbps, result_line)
    lock = asyncio.Lock()
    sem = asyncio.Semaphore(SPEED_MAX_WORKERS)
    last_log_time = 0

    async def limited(uri):
        nonlocal tested, failed_count, last_log_time
        async with sem:
            r = await speed_one(uri)
        async with lock:
            tested += 1
            now = time.time()
            if r is not None:
                dl = _extract_download_mbps(r)
                results.append(r)
                label = get_label(r)[:50]
                best_speeds.append((dl, r))
                best_speeds.sort(key=lambda x: x[0], reverse=True)
                top3 = best_speeds[:3]
                top_str = "; ".join(f"↓{dl:.0f}Mbps {get_label(l)[:30]}" for dl, l in top3)
                if dl >= SPEED_MIN_MBPS or (tested % 15 == 0) or tested == total or (now - last_log_time) > 3:
                    log(f"[speed] {tested}/{total} ↓{dl:.0f}Mbps {label}  |  TOP3: {top_str}")
                    last_log_time = now
            else:
                failed_count += 1
                if (tested % 15 == 0) or tested == total or (now - last_log_time) > 3:
                    log(f"[speed] {tested}/{total} ... (нерабочих: {failed_count})")
                    last_log_time = now
        return r

    coros = [limited(u) for u in uris]
    await asyncio.gather(*coros)

    good = [r for r in results if _extract_download_mbps(r) >= SPEED_MIN_MBPS]
    good.sort(key=lambda r: _extract_download_mbps(r), reverse=True)

    # Итоговая сводка спид-теста
    log(f"\n{'═'*70}")
    log(f"[speed] 📊 ИТОГИ СПИД-ТЕСТА")
    log(f"  Всего тестировано: {total}")
    log(f"  Получено результатов: {len(results)}  |  Ошибок: {failed_count}")
    log(f"  Прошли порог ≥{SPEED_MIN_MBPS}Mbps: {len(good)}")
    if best_speeds:
        best_speeds.sort(key=lambda x: x[0], reverse=True)
        log(f"  🏆 Лучшие по скорости:")
        for i, (dl, line) in enumerate(best_speeds[:10], 1):
            medal = ["🥇", "🥈", "🥉"][i-1] if i <= 3 else f" {i}."
            label = get_label(line)[:60]
            # Извлечь upload из строки
            ul_match = re.search(r"↑(\d+)", line)
            ul = int(ul_match.group(1)) if ul_match else 0
            log(f"    {medal} ↓{dl:.0f} / ↑{ul:.0f} Mbps  {label}")
    log(f"{'═'*70}\n")

    if results:
        with open(TESTED_FILE, "w", encoding="utf-8") as f:
            f.write(f"# Total: {len(results)} configs  |  Good(>={SPEED_MIN_MBPS} Mbps): {len(good)}\n")
            f.write(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Bridge: SS {BRIDGE_IP}:{BRIDGE_PORT}  |  Method: {SS_METHOD}  |  Pass: {SS_PASSWORD}\n")
            f.write("\n")
            for r in results:
                f.write(r + "\n")
        log(f"[speed] Сохранено в {TESTED_FILE}")

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  REST API
# ═══════════════════════════════════════════════════════════════════════════════

async def handle_api_request(reader, writer):
    try:
        header = await asyncio.wait_for(reader.read(8192), timeout=10)
        request = header.decode("utf-8", errors="replace")
        method, path, _ = request.split("\r\n")[0].split(" ")

        if path == "/status":
            status = _build_status()
            body = json.dumps(status, ensure_ascii=False, indent=2)
            resp = (f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
        elif path == "/configs":
            body = ""
            for fname in (TESTED_FILE, WORKING_FILE):
                if os.path.exists(fname):
                    with open(fname, "r", encoding="utf-8") as f:
                        body += f.read() + "\n"
            resp = (f"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
        elif path == "/ping" and method in ("POST", "GET"):
            result = await _api_ping()
            body = json.dumps(result, ensure_ascii=False, indent=2)
            code = 200
            resp = (f"HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
        elif path == "/speed" and method == "POST":
            result = await _api_speed()
            body = json.dumps(result, ensure_ascii=False, indent=2)
            code = 200
            resp = (f"HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
        else:
            body = json.dumps({"error": "not found"}, ensure_ascii=False)
            resp = (f"HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")

        writer.write(resp.encode("utf-8"))
    except Exception as e:
        try:
            err = json.dumps({"error": str(e)}, ensure_ascii=False)
            resp = (f"HTTP/1.1 500 Error\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(err)}\r\nConnection: close\r\n\r\n{err}")
            writer.write(resp.encode("utf-8"))
        except Exception:
            pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _build_status():
    last_ping = None
    if os.path.exists(WORKING_FILE):
        last_ping = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(WORKING_FILE)))
    last_speed = None
    if os.path.exists(TESTED_FILE):
        last_speed = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(TESTED_FILE)))

    bridge = None
    if _bridge_manager:
        bridge = _bridge_manager.get_status()

    return {
        "uptime_seconds": time.time() - START_TIME,
        "last_ping": last_ping,
        "last_speedtest": last_speed,
        "config_url": CONFIG_URL,
        "working_file": WORKING_FILE,
        "tested_file": TESTED_FILE,
        "bridge": bridge,
    }


async def _api_ping():
    working = await vpn_ping_test()
    if working:
        with open(WORKING_FILE, "w", encoding="utf-8") as f:
            for u in working:
                f.write(u + "\n")
    return {"status": "ok", "working": len(working)}


async def _api_speed():
    results = await speed_test()
    good = [r for r in results if _extract_download_mbps(r) >= SPEED_MIN_MBPS]
    return {"status": "ok", "tested": len(results), "good": len(good)}


# ═══════════════════════════════════════════════════════════════════════════════
#  ОСНОВНОЙ ЦИКЛ
# ═══════════════════════════════════════════════════════════════════════════════

START_TIME = time.time()


async def main():
    global _bridge_manager
    _bridge_manager = BridgeManager()

    log("=" * 60)
    log(" VPN Config Runner — BRIDGE mode")
    log(f" API: http://0.0.0.0:{API_PORT}")
    log(f" Config URL: {CONFIG_URL}")
    log("=" * 60)

    # Запуск REST API
    server = await asyncio.start_server(handle_api_request, "0.0.0.0", API_PORT)
    log(f"[api] HTTP API запущен на порту {API_PORT}")

    # Основной цикл
    cycle = 0
    while True:
        cycle += 1
        log(f"\n── Цикл #{cycle} ──")

        working = await vpn_ping_test()

        if working:
            with open(WORKING_FILE, "w", encoding="utf-8") as f:
                for u in working:
                    f.write(u + "\n")
            log(f"[main] Сохранено {len(working)} рабочих конфигов в {WORKING_FILE}")

            results = await speed_test()
            good = [r for r in results if _extract_download_mbps(r) >= SPEED_MIN_MBPS]

            if good:
                await _bridge_manager.start_top3(good)
                log(f"[main] Bridge работает на SS:{BRIDGE_PORT} с top-3 конфигами")
            else:
                log("[main] Нет конфигов со скоростью >= 5 Mbps — bridge не запущен")
        else:
            log("[main] Нет рабочих конфигов")

        log(f"[main] Жду {RUN_INTERVAL}с до следующего цикла...")
        await asyncio.sleep(RUN_INTERVAL)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log("\n[main] Остановлено")
        if _bridge_manager:
            asyncio.run(_bridge_manager._stop_all())
        sys.exit(0)
