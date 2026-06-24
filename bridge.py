"""
Bridge — self-hosted Shadowsocks → ТРЁМ лучшим конфигам с health-check и failover.
"""

import asyncio
import base64
import hashlib
import os
import re
import socket
import time
import urllib.parse

try:
    import aiohttp
    from aiohttp_socks import ProxyConnector
except ImportError:
    pass  # will fail at runtime if needed


# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

BRIDGE_IP          = "0.0.0.0"
BRIDGE_PORT        = 8443
BRIDGE_POOL_SIZE   = 3
BRIDGE_SOCKS_PORTS = [11080, 11081, 11082]

SS_METHOD          = "chacha20-ietf-poly1305"
SS_PASSWORD        = hashlib.md5(b"self-hosted-ru-bridge").hexdigest()  # deterministic 32-char

HEALTH_CHECK_INTERVAL = 5  # секунд
SPEED_RECHECK_INTERVAL = 60  # секунд — перетестировать скорость


# ═══════════════════════════════════════════════════════════════════════════════
#  STUBS — will be injected by runner.py at import time
# ═══════════════════════════════════════════════════════════════════════════════

_log = None
_make_xray_config = None
_start_xray = None
_parse_configs_file = None
_get_label = None
_TESTED_FILE = None


def inject_runner_deps(log, make_xray_config, start_xray, parse_configs_file, get_label, tested_file):
    """Inject references to runner functions so bridge can call them."""
    global _log, _make_xray_config, _start_xray, _parse_configs_file, _get_label, _TESTED_FILE
    _log = log
    _make_xray_config = make_xray_config
    _start_xray = start_xray
    _parse_configs_file = parse_configs_file
    _get_label = get_label
    _TESTED_FILE = tested_file


def _l(msg):
    """Logging wrapper."""
    if _log:
        _log(msg)
    else:
        print(msg)


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════


def _extract_download_mbps(uri):
    """Извлечь download Mbps из лейбла URI (после #)"""
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


def _get_bridge_prefix():
    """Получить префикс bridge URI для фильтрации"""
    return f"ss://{base64.b64encode(f'{SS_METHOD}:{SS_PASSWORD}'.encode()).decode()}@"


_RU_FLAG = "\U0001F1F7\U0001F1FA"  # 🇷🇺


def _label_from_uri(uri):
    """Извлечь лейбл из URI (часть после #)."""
    try:
        label = uri.split("#", 1)[1]
        return urllib.parse.unquote(label)
    except Exception:
        return ""


def _is_non_ru_config(uri):
    """Проверить, что конфиг НЕ из РФ.

    Проверка по 3 методам (достаточно одного):
    1. Лейбл содержит флаг 🇷🇺
    2. GeoIP lookup выходного IP
    """
    label = _label_from_uri(uri)

    # Быстрая проверка: флаг в лейбле
    if _RU_FLAG in label:
        return False

    # GeoIP fallback
    try:
        import geoip2.database

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
    return False


def _get_all_real_configs():
    """Получить все реальные конфиги (не bridge, не RU) из tested_configs.txt.

    Лейблы парсятся из URI (часть после #) — формат из speed-теста:
      {proto} {flag} {down}mbps/{up}mbps t.me/ine4eg
    """
    if _TESTED_FILE is None or not os.path.exists(_TESTED_FILE):
        return []
    if _parse_configs_file is None:
        return []
    configs = _parse_configs_file(_TESTED_FILE)
    prefix = _get_bridge_prefix()
    real = [c for c in configs if not c.startswith(prefix) and _extract_download_mbps(c) > 0]
    non_ru = [c for c in real if _is_non_ru_config(c)]
    excluded = len(real) - len(non_ru)
    if excluded > 0:
        _l(f"[bridge] Фильтр РФ: {len(real)} рабочих → {len(non_ru)} без РФ (исключено {excluded})")
    return non_ru


# ═══════════════════════════════════════════════════════════════════════════════
#  BridgeManager
# ═══════════════════════════════════════════════════════════════════════════════


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
        self._last_ping_ms = [None, None, None]
        self._speed_mbps = [0, 0, 0]

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
        """Запустить один upstream xray на указанном SOCKS-порту."""
        socks_port = BRIDGE_SOCKS_PORTS[port_idx]
        cfg = _make_xray_config(uri, socks_port)
        if not cfg:
            return None
        proc = await _start_xray(cfg, socks_port)
        if proc:
            _l(f"[bridge]   Upstream [{port_idx}] запущен (SOCKS :{socks_port})")
        return proc

    def _select_pool(self, top3):
        """Собрать пул из 3-х лучших конфигов, заполнив пустые слоты."""
        pool = [None, None, None]
        for i, uri in enumerate(top3[:3]):
            pool[i] = uri

        tested = _get_all_real_configs()
        used   = {u for u in pool if u is not None}
        available = [c for c in tested if c not in used]

        while None in pool and available:
            pos = pool.index(None)
            pool[pos] = available.pop(0)

        return pool

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

        proc = await _start_xray(bridge_cfg, BRIDGE_PORT)
        if proc:
            self._bridge_state['bridge_proc'] = proc
            _l(f"[bridge]   Bridge → Shadowsocks :{BRIDGE_PORT} → SOCKS :{upstream_socks_port}")
        return proc

    async def _switch_to(self, new_idx):
        """Переключить активный upstream на new_idx."""
        if self._bridge_state['upstream_uris'][new_idx] is None:
            return False
        label = _get_label(self._bridge_state['upstream_uris'][new_idx]) if _get_label else ""
        _l(f"[bridge] ⚡ Переключение на upstream [{new_idx}]: {str(label)[:50]}")
        self._bridge_state['active_idx'] = new_idx
        await self._restart_bridge(new_idx)
        return True

    async def _replenish_slot(self, slot_idx):
        """Пополнить слот новым рабочим конфигом."""
        tested = _get_all_real_configs()
        used   = set(self._bridge_state['upstream_uris'])
        available = [c for c in tested if c not in used]

        if not available:
            _l(f"[bridge] ⚠ Слот [{slot_idx}] — нет конфигов для пополнения")
            return False

        uri = available[0]
        await self._stop_process(self._bridge_state['upstream_procs'][slot_idx])
        proc = await self._start_upstream(uri, slot_idx)
        if proc:
            self._bridge_state['upstream_uris'][slot_idx]  = uri
            self._bridge_state['upstream_procs'][slot_idx] = proc
            label = _get_label(uri) if _get_label else ""
            _l(f"[bridge]   Слот [{slot_idx}] пополнен: {str(label)[:50]}")
            return True
        return False

    async def _check_upstream_health(self, port_idx, timeout=3):
        """Проверить здоровье upstream-процесса."""
        proc  = self._bridge_state['upstream_procs'][port_idx]
        port  = BRIDGE_SOCKS_PORTS[port_idx]

        if proc is None:
            return False
        ret = proc.poll()
        if ret is not None:
            _l(f"[bridge-hc] Upstream [{port_idx}] умер (code={ret})")
            return False

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
        except Exception:
            _l(f"[bridge-hc] Upstream [{port_idx}] порт :{port} недоступен")
            return False

        return True

    async def _ping_upstream(self, port_idx, timeout=4):
        """Ping upstream — HTTP-запрос ЧЕРЕЗ VPN-туннель (SOCKS-прокси → удалённый сервер)."""
        proc = self._bridge_state['upstream_procs'][port_idx]
        if proc is None or proc.poll() is not None:
            return None

        socks_port = BRIDGE_SOCKS_PORTS[port_idx]
        connector = None
        try:
            connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
            async with aiohttp.ClientSession(connector=connector) as session:
                start = time.perf_counter()
                async with session.get(
                    "http://cp.cloudflare.com/",
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=False,
                    ssl=False
                ) as resp:
                    await resp.read()
                elapsed_ms = (time.perf_counter() - start) * 1000
                return round(elapsed_ms, 1)
        except Exception:
            return None
        finally:
            if connector:
                await connector.close()

    async def health_check_loop(self):
        """Основной цикл health-check: ping 5с, speed 60с, лог 5с."""
        slot_health = {0: False, 1: False, 2: False}
        speed_tester = None
        last_speed_check = time.time()

        _l("[bridge-hc] Health-check цикл запущен")
        _l("[bridge-hc] Ping: каждые 5с | Speed: каждые 60с | Log: каждые 5с")

        while self._bridge_state['running']:
            try:
                # ── ping по каждому upstream слоту ───────────────────────
                for idx in range(BRIDGE_POOL_SIZE):
                    if self._bridge_state['upstream_uris'][idx] is None:
                        self._last_ping_ms[idx] = None
                        continue
                    self._last_ping_ms[idx] = await self._ping_upstream(idx)

                # ── здоровье 3 upstream ───────────────────────────────────
                for idx in range(BRIDGE_POOL_SIZE):
                    if self._bridge_state['upstream_uris'][idx] is None:
                        slot_health[idx] = False
                        continue

                    healthy = await self._check_upstream_health(idx)
                    slot_health[idx] = healthy

                # ── bridge процесс жив? ───────────────────────────────────
                bridge_proc = self._bridge_state['bridge_proc']
                if bridge_proc and bridge_proc.poll() is not None:
                    _l("[bridge-hc] Bridge процесс умер → перезапуск")
                    await self._restart_bridge(self._bridge_state['active_idx'])

                # ── ре-тест скоростей каждые 60с ─────────────────────────
                now = time.time()
                if now - last_speed_check >= SPEED_RECHECK_INTERVAL:
                    last_speed_check = now
                    for idx in range(BRIDGE_POOL_SIZE):
                        uri = self._bridge_state['upstream_uris'][idx]
                        if uri is None:
                            continue
                        try:
                            if speed_tester is None:
                                from runner import SpeedTester
                                speed_tester = SpeedTester()
                            results = await speed_tester.test_all([uri])
                            if results:
                                new_uri = results[0]
                                self._bridge_state['upstream_uris'][idx] = new_uri
                                label = _get_label(new_uri) if _get_label else ""
                                _l(f"[bridge-hc] Upstream [{idx}] перетестирован: {str(label)[:60]}")
                                self._speed_mbps[idx] = _extract_download_mbps(new_uri)
                            else:
                                _l(f"[bridge-hc] Upstream [{idx}] не прошёл speed-test → пополняем")
                                replenished = await self._replenish_slot(idx)
                                if not replenished:
                                    _l(f"[bridge-hc] Не удалось пополнить слот [{idx}]")
                        except Exception as e:
                            _l(f"[bridge-hc] Ошибка ре-теста upstream [{idx}]: {e}")

                # ── failover: если активный упал, переключаемся ───────────
                active = self._bridge_state['active_idx']
                active_proc = self._bridge_state['upstream_procs'][active]
                active_dead = (active_proc is None
                               or active_proc.poll() is not None
                               or not slot_health.get(active, False))

                if active_dead:
                    _l(f"[bridge] ⚠️ Active upstream [{active}] не отвечает!")

                    switched = False
                    for i in range(BRIDGE_POOL_SIZE):
                        if i == active:
                            continue
                        if slot_health.get(i, False):
                            await self._switch_to(i)
                            switched = True
                            break

                    await self._replenish_slot(active)

                    if not switched:
                        for i in range(BRIDGE_POOL_SIZE):
                            if slot_health.get(i, False):
                                await self._switch_to(i)
                                switched = True
                                break

                    if not switched:
                        _l("[bridge] ❌ Нет доступных upstream-процессов!")

                for i in range(BRIDGE_POOL_SIZE):
                    if i == self._bridge_state['active_idx']:
                        continue
                    if self._bridge_state['upstream_uris'][i]:
                        if not slot_health.get(i, False):
                            _l(f"[bridge] ⚠️ Backup upstream [{i}] не отвечает, пополняю...")
                            await self._replenish_slot(i)

                # ── ЛОГ СТАТУСА каждые 5с ────────────────────────────────
                active = self._bridge_state['active_idx']
                active_uri = self._bridge_state['upstream_uris'][active]
                active_label = _label_from_uri(active_uri) if active_uri else "N/A"
                active_ping = self._last_ping_ms[active]
                active_speed = self._speed_mbps[active]

                ping_str = f"{active_ping}мс" if active_ping is not None else "N/A"
                speed_str = f"↓{active_speed} Mbps" if active_speed > 0 else "N/A"

                _l(
                    f"[bridge-status] Конфиг: [{active}] {str(active_label)[:50]}  |  "
                    f"Ping: {ping_str}  |  Скорость: {speed_str}"
                )

            except asyncio.CancelledError:
                break
            except Exception as e:
                _l(f"[bridge-hc] Ошибка: {e}")

            await asyncio.sleep(HEALTH_CHECK_INTERVAL)

    def _save_bridge_uri(self, bridge_uri):
        """Сохранить bridge URI в начало tested_configs.txt."""
        prefix = _get_bridge_prefix()
        existing_lines = []
        header_lines = []
        if os.path.exists(_TESTED_FILE):
            with open(_TESTED_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        header_lines.append(line)
                    elif line:
                        existing_lines.append(line)

        existing_lines = [l for l in existing_lines if not l.startswith(prefix)]

        with open(_TESTED_FILE, "w", encoding="utf-8") as f:
            for hl in header_lines:
                f.write(hl + "\n")
            f.write("\n")
            f.write(bridge_uri + "\n")
            for l in existing_lines:
                f.write(l + "\n")

        _l(f"[bridge] ✅ Bridge-конфиг добавлен в {_TESTED_FILE}")

    async def start(self, top3_uris):
        """Запустить bridge с ТРЕМЯ лучшими конфигами."""
        if not top3_uris:
            _l("[bridge] Нет URI для bridge")
            return

        self._bridge_state['running'] = True

        _l("=" * 60)
        _l("  BRIDGE: self-hosted Shadowsocks мост (3 upstream + health-check)")
        _l("=" * 60)

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
                label = _label_from_uri(pool[i])
                _l(f"[bridge]   [{i}] ↓{dl} Mbps — {label[:60]}")
                proc = await self._start_upstream(pool[i], i)
                self._bridge_state['upstream_procs'][i] = proc

        # Активный = слот 0 (лучший)
        self._bridge_state['active_idx'] = 0
        await self._restart_bridge(0)

        # Сгенерировать и сохранить bridge URI
        bridge_label = "self-hosted RU 🇷🇺"
        userinfo = base64.b64encode(f"{SS_METHOD}:{SS_PASSWORD}".encode()).decode()
        bridge_uri = f"ss://{userinfo}@{BRIDGE_IP}:{BRIDGE_PORT}#{urllib.parse.quote(bridge_label)}"
        _l(f"[bridge] URI: {bridge_uri}")
        self._save_bridge_uri(bridge_uri)

        # Запустить health-check задачу
        if self._bridge_state['health_task']:
            self._bridge_state['health_task'].cancel()
        self._bridge_state['health_task'] = asyncio.create_task(self.health_check_loop())

        _l(f"[bridge] ✅ Bridge запущен с {BRIDGE_POOL_SIZE} upstream, health-check каждые {HEALTH_CHECK_INTERVAL}с")


# ═══════════════════════════════════════════════════════════════════════════════
#  GLOBAL INSTANCE + ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

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