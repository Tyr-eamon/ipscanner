import csv
import io
import ipaddress
import json
import platform
import queue
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, unquote, urlparse

from flask import Flask, Response, jsonify, render_template, request

app = Flask(__name__)

WEB_PORTS = {
    80: 'HTTP',
    443: 'HTTPS',
    8000: 'HTTP-Alt',
    8080: 'HTTP-Proxy',
    5000: 'Flask Default',
    9000: 'Custom Web',
    8081: 'HTTP-Alt2'
}

DEFAULT_SOCKS_PORTS = {1080, 10000, 11300}
DEFAULT_TIMEOUT_MS = 1500
DEFAULT_MAX_CONCURRENCY = 8
DEFAULT_CONNECT_TARGET = ("1.1.1.1", 53)

stop_scan = False
scan_lock = threading.Lock()
progress_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
scan_thread: Optional[threading.Thread] = None


def parse_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    str_value = str(value).strip().lower()
    if str_value in {"1", "true", "yes", "on"}:
        return True
    if str_value in {"0", "false", "no", "off"}:
        return False
    return default


def parse_int(value: Any, default: int) -> int:
    try:
        result = int(value)
        return result
    except (TypeError, ValueError):
        return default


def parse_port_list(port_text: str, fallback: Optional[set] = None) -> set:
    if not port_text:
        return set(fallback or [])
    result = set()
    for token in port_text.replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            result.add(port)
    return result or set(fallback or [])


def parse_connect_target(value: str, fallback: Tuple[str, int] = DEFAULT_CONNECT_TARGET) -> Tuple[str, int]:
    if not value:
        return fallback
    if ":" not in value:
        return fallback
    host_part, port_part = value.rsplit(":", 1)
    host_part = host_part.strip()
    if not host_part:
        return fallback
    try:
        port = int(port_part)
    except ValueError:
        return fallback
    if not (0 < port < 65536):
        return fallback
    return host_part, port


def split_tokens(value: str) -> set:
    tokens: set = set()
    if not value:
        return tokens
    for line in value.replace('\r', '\n').split('\n'):
        if not line:
            continue
        for chunk in line.split(','):
            chunk = chunk.strip()
            if chunk:
                tokens.add(chunk)
    return tokens


def is_stop_requested() -> bool:
    with scan_lock:
        return stop_scan


def recv_exact(sock: socket.socket, expected_size: int) -> bytes:
    data = b""
    while len(data) < expected_size:
        chunk = sock.recv(expected_size - len(data))
        if not chunk:
            break
        data += chunk
    return data


def parse_socks_url(url: str) -> Dict[str, Any]:
    raw = url.strip()
    if not raw:
        raise ValueError("Empty URL")
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"socks5", "socks5h"}:
        raise ValueError("Unsupported scheme; use socks5 or socks5h")
    if not parsed.hostname:
        raise ValueError("Missing host in URL")
    host = parsed.hostname
    if host.startswith("[") and host.endswith("]"):
        raise ValueError("IPv6 addresses are not supported")
    if host.count(":") >= 2:
        # urlparse removes brackets for IPv6, but we skip IPv6 for now
        raise ValueError("IPv6 addresses are not supported")
    if parsed.port is None:
        raise ValueError("Missing port in URL")
    username = parsed.username
    password = parsed.password
    if username is not None:
        username = unquote(username)
        if len(username.encode("utf-8")) > 255:
            raise ValueError("Username exceeds 255 bytes")
    if password is not None:
        password = unquote(password)
        if len(password.encode("utf-8")) > 255:
            raise ValueError("Password exceeds 255 bytes")
    return {
        "original": raw,
        "scheme": scheme,
        "host": host,
        "port": parsed.port,
        "username": username,
        "password": password,
    }


def normalize_socks_url(entry: Dict[str, Any]) -> str:
    credentials = ""
    username = entry.get("username")
    password = entry.get("password")
    if username is not None:
        credentials = quote(username, safe="~")
        if password is not None:
            credentials += ":" + quote(password, safe="~")
        credentials += "@"
    return f"{entry['scheme']}://{credentials}{entry['host']}:{entry['port']}"


def _build_connect_request(target_host: str, target_port: int) -> bytes:
    if not (0 < target_port < 65536):
        raise ValueError("CONNECT target port out of range")
    try:
        addr_bytes = socket.inet_aton(target_host)
        atyp = 0x01
        payload = addr_bytes
    except OSError:
        host_bytes = target_host.encode("idna")
        if len(host_bytes) > 255:
            raise ValueError("CONNECT target host too long")
        atyp = 0x03
        payload = bytes([len(host_bytes)]) + host_bytes
    return bytes([0x05, 0x01, 0x00, atyp]) + payload + target_port.to_bytes(2, "big")


def _parse_connect_reply(sock: socket.socket) -> int:
    header = recv_exact(sock, 4)
    if len(header) < 4:
        raise OSError("Incomplete CONNECT reply header")
    if header[0] != 0x05:
        raise OSError("Invalid CONNECT reply version")
    rep = header[1]
    atyp = header[3]
    if atyp == 0x01:  # IPv4
        addr_len = 4
        _ = recv_exact(sock, addr_len)
    elif atyp == 0x04:  # IPv6
        addr_len = 16
        _ = recv_exact(sock, addr_len)
    elif atyp == 0x03:  # Domain
        length_bytes = recv_exact(sock, 1)
        if len(length_bytes) != 1:
            raise OSError("Incomplete domain length in reply")
        addr_len = length_bytes[0]
        _ = recv_exact(sock, addr_len)
    else:
        raise OSError(f"Unsupported ATYP 0x{atyp:02x} in reply")
    port_bytes = recv_exact(sock, 2)
    if len(port_bytes) < 2:
        raise OSError("Incomplete port in CONNECT reply")
    return rep


def verify_socks5_proxy(
    host: str,
    port: int,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    read_timeout_ms: Optional[int] = None,
    validate_connect: bool = True,
    connect_target: Tuple[str, int] = DEFAULT_CONNECT_TARGET,
) -> Dict[str, Any]:
    start_ts = time.time()
    classification = "connect-failed"
    auth_type = "none"
    auth_result = "not-attempted"
    connect_result = "skipped"
    notes = ""
    stage = "connect"
    connect_attempted = False

    if read_timeout_ms is None:
        read_timeout_ms = timeout_ms

    def finalize() -> Dict[str, Any]:
        duration = int(max(0, (time.time() - start_ts) * 1000))
        return {
            "auth_type": auth_type,
            "auth_result": auth_result,
            "connect_result": connect_result,
            "classification": classification,
            "latency_ms": duration,
            "notes": notes.strip(),
        }

    try:
        with socket.create_connection((host, port), timeout=timeout_ms / 1000.0) as sock:
            sock.settimeout(read_timeout_ms / 1000.0)
            stage = "handshake"
            sock.sendall(b"\x05\x02\x00\x02")
            selection = recv_exact(sock, 2)
            if len(selection) < 2:
                classification = "connect-failed"
                notes = "Incomplete method selection"
                return finalize()
            if selection[0] != 0x05:
                auth_type = "unknown"
                classification = "not-socks5"
                notes = f"Unexpected SOCKS version 0x{selection[0]:02x}"
                return finalize()
            method = selection[1]
            if method == 0x00:
                auth_type = "none"
                auth_result = "not-required"
                classification = "socks5-no-auth"
            elif method == 0x02:
                auth_type = "userpass"
                if username is None:
                    auth_result = "required"
                    classification = "socks5-auth-required"
                    return finalize()
                uname_bytes = username.encode("utf-8")
                passwd_bytes = (password or "").encode("utf-8")
                if len(uname_bytes) > 255 or len(passwd_bytes) > 255:
                    raise ValueError("Credentials exceed 255 bytes")
                stage = "authenticate"
                payload = bytes([0x01, len(uname_bytes)]) + uname_bytes + bytes([len(passwd_bytes)]) + passwd_bytes
                sock.sendall(payload)
                auth_reply = recv_exact(sock, 2)
                if len(auth_reply) < 2 or auth_reply[0] != 0x01:
                    auth_result = "failed"
                    classification = "socks5-auth-failed"
                    notes = "Invalid auth reply"
                    return finalize()
                if auth_reply[1] != 0x00:
                    auth_result = "failed"
                    classification = "socks5-auth-failed"
                    notes = f"Auth status 0x{auth_reply[1]:02x}"
                    return finalize()
                auth_result = "success"
                classification = "socks5-auth-success"
            else:
                auth_type = "unknown"
                classification = "not-socks5"
                notes = f"Unsupported auth method 0x{method:02x}"
                return finalize()

            if validate_connect and classification in {"socks5-no-auth", "socks5-auth-success"}:
                connect_attempted = True
                stage = "connect-request"
                request_bytes = _build_connect_request(*connect_target)
                sock.sendall(request_bytes)
                stage = "connect-reply"
                rep = _parse_connect_reply(sock)
                if rep == 0x00:
                    connect_result = "success"
                    classification = "connect-success"
                else:
                    connect_result = "failed"
                    classification = "connect-failed"
                    notes = f"CONNECT reply status 0x{rep:02x}"
            return finalize()
    except socket.timeout:
        if connect_attempted:
            connect_result = "timeout"
            classification = "connect-timeout"
        else:
            classification = "connect-timeout"
        notes = f"{stage} timed out"
        return finalize()
    except ValueError as exc:
        classification = "connect-failed"
        notes = str(exc)
        return finalize()
    except OSError as exc:
        if connect_attempted:
            connect_result = "failed"
        classification = "connect-failed"
        notes = exc.strerror or str(exc)
        return finalize()
    except Exception as exc:  # defensive
        classification = "connect-failed"
        notes = str(exc)
        return finalize()


def ping_ip(ip: str) -> bool:
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    try:
        return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False


def scan_port(ip: str, port: int, timeout: int = 1) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except Exception:
        return False
    finally:
        sock.close()


def scan_web_ports(ip: str) -> Optional[List[Tuple[int, str]]]:
    open_ports: List[Tuple[int, str]] = []
    for port, description in WEB_PORTS.items():
        if is_stop_requested():
            return None
        if scan_port(ip, port):
            open_ports.append((port, description))
    return open_ports


def parse_ip_file(file_obj: io.StringIO) -> Tuple[set, set]:
    subnets: set = set()
    ips: set = set()
    if not file_obj:
        return subnets, ips
    file_obj.seek(0)
    content = file_obj.read()
    file_obj.seek(0)
    sniffer = csv.Sniffer()
    try:
        dialect = sniffer.sniff(content)
        reader = csv.reader(io.StringIO(content), dialect)
    except Exception:
        lines = content.splitlines()
        for line in lines:
            entries = line.strip().split()
            if len(entries) == 2:
                subnets.add(entries[0].strip())
                ips.add(entries[1].strip())
            elif len(entries) == 1:
                value = entries[0].strip()
                if '/' in value or '-' in value:
                    subnets.add(value)
                else:
                    ips.add(value)
        return subnets, ips
    for row in reader:
        if len(row) == 2:
            subnets.add(row[0].strip())
            ips.add(row[1].strip())
        elif len(row) == 1:
            value = row[0].strip()
            if '/' in value or '-' in value:
                subnets.add(value)
            else:
                ips.add(value)
    return subnets, ips


def _prepare_hosts(subnets: set, ips: set) -> Tuple[List[str], List[str]]:
    all_hosts: set = set()
    invalid_subnets: List[str] = []
    for subnet in subnets:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            all_hosts.update(str(ip) for ip in net.hosts())
        except Exception:
            invalid_subnets.append(subnet)
    for ip_str in ips:
        try:
            ipaddress.ip_address(ip_str)
            all_hosts.add(ip_str)
        except Exception:
            continue
    return sorted(all_hosts), invalid_subnets


def _emit_stop(context: Optional[str] = None) -> None:
    payload: Dict[str, Any] = {}
    if context:
        payload['context'] = context
    progress_queue.put(('stopped', payload))


def _emit_progress(context: str, current: Optional[str], completed: int, total: int, start_ts: float) -> None:
    progress_queue.put(('progress', {
        'context': context,
        'current': current,
        'completed': completed,
        'total': total,
        'start': start_ts
    }))


def _process_socks_urls(raw_urls: List[str], options: Dict[str, Any]) -> bool:
    if not raw_urls:
        return True
    total = len(raw_urls)
    completed = 0
    start_ts = time.time()
    _emit_progress('socks_verify', None, completed, total, start_ts)

    valid_entries: List[Dict[str, Any]] = []
    for raw in raw_urls:
        if is_stop_requested():
            _emit_stop('socks_verify')
            return False
        try:
            entry = parse_socks_url(raw)
            entry['normalized'] = normalize_socks_url(entry)
            valid_entries.append(entry)
        except ValueError as exc:
            result = {
                'source': 'url_list',
                'input_url': raw.strip(),
                'normalized_url': raw.strip(),
                'host': None,
                'port': None,
                'scheme': None,
                'auth_type': None,
                'auth_result': 'invalid',
                'connect_result': 'skipped',
                'classification': 'invalid-url',
                'latency_ms': 0,
                'notes': str(exc)
            }
            progress_queue.put(('socks_result', result))
            completed += 1
            _emit_progress('socks_verify', raw.strip(), completed, total, start_ts)

    if is_stop_requested():
        _emit_stop('socks_verify')
        return False

    if not valid_entries:
        progress_queue.put(('phase_complete', {'context': 'socks_verify'}))
        return True

    timeout_ms = options.get('timeout_ms', DEFAULT_TIMEOUT_MS)
    read_timeout_ms = options.get('read_timeout_ms', timeout_ms)
    validate_connect = options.get('validate_connect', True)
    connect_target = options.get('connect_target', DEFAULT_CONNECT_TARGET)
    max_concurrency = options.get('max_concurrency', DEFAULT_MAX_CONCURRENCY)
    max_workers = max(1, min(max_concurrency, len(valid_entries)))

    def worker(entry: Dict[str, Any]) -> Dict[str, Any]:
        result = verify_socks5_proxy(
            entry['host'],
            entry['port'],
            username=entry.get('username'),
            password=entry.get('password'),
            timeout_ms=timeout_ms,
            read_timeout_ms=read_timeout_ms,
            validate_connect=validate_connect,
            connect_target=connect_target,
        )
        result.update({
            'source': 'url_list',
            'input_url': entry['original'],
            'normalized_url': entry['normalized'],
            'host': entry['host'],
            'port': entry['port'],
            'scheme': entry['scheme'],
        })
        return result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(worker, entry): entry for entry in valid_entries}
        for future in as_completed(future_map):
            if is_stop_requested():
                _emit_stop('socks_verify')
                for pending in future_map:
                    pending.cancel()
                return False
            entry = future_map[future]
            try:
                result_payload = future.result()
            except Exception as exc:  # pragma: no cover - safety net
                result_payload = {
                    'source': 'url_list',
                    'input_url': entry['original'],
                    'normalized_url': entry['normalized'],
                    'host': entry['host'],
                    'port': entry['port'],
                    'scheme': entry['scheme'],
                    'auth_type': None,
                    'auth_result': 'error',
                    'connect_result': 'error',
                    'classification': 'error',
                    'latency_ms': 0,
                    'notes': str(exc)
                }
            progress_queue.put(('socks_result', result_payload))
            completed += 1
            _emit_progress('socks_verify', entry['original'], completed, total, start_ts)

    progress_queue.put(('phase_complete', {'context': 'socks_verify'}))
    return True


def do_scan(subnets: set, ips: set, socks_urls: List[str], options: Dict[str, Any]) -> None:
    global stop_scan
    with scan_lock:
        stop_scan = False

    hosts, invalid_subnets = _prepare_hosts(subnets, ips)
    if not hosts and not socks_urls:
        message = 'No valid IPs or SOCKS URLs to process.'
        if invalid_subnets:
            message += f" Invalid subnets: {', '.join(invalid_subnets)}"
        progress_queue.put(('error', message))
        return

    detect_socks5 = options.get('detect_socks5', True)
    candidate_ports = set(options.get('candidate_ports', DEFAULT_SOCKS_PORTS))
    timeout_ms = options.get('timeout_ms', DEFAULT_TIMEOUT_MS)
    read_timeout_ms = options.get('read_timeout_ms', timeout_ms)
    validate_connect = options.get('validate_connect', True)
    connect_target = options.get('connect_target', DEFAULT_CONNECT_TARGET)

    host_total = len(hosts)
    host_start_ts = time.time()
    scanned_count = 0
    if host_total:
        for ip in hosts:
            if is_stop_requested():
                _emit_stop('host_scan')
                return
            _emit_progress('host_scan', ip, scanned_count, host_total, host_start_ts)
            scanned_count += 1
            if not ping_ip(ip):
                continue
            open_ports = scan_web_ports(ip)
            if open_ports is None:
                _emit_stop('host_scan')
                return
            filtered_ports = []
            port_numbers = [p[0] for p in open_ports]
            if 443 in port_numbers:
                filtered_ports = [(p, s) for p, s in open_ports if p != 80]
            else:
                filtered_ports = open_ports
            if filtered_ports:
                port_list_str = ', '.join(f"{p[0]} ({p[1]})" for p in filtered_ports)
                progress_queue.put(('live', {
                    'context': 'host_scan',
                    'ip': ip,
                    'ports': port_list_str,
                    'open_ports': filtered_ports
                }))
            if not detect_socks5:
                continue
            for port_value, _label in open_ports:
                if port_value not in candidate_ports:
                    continue
                if is_stop_requested():
                    _emit_stop('host_scan')
                    return
                result = verify_socks5_proxy(
                    ip,
                    port_value,
                    timeout_ms=timeout_ms,
                    read_timeout_ms=read_timeout_ms,
                    validate_connect=validate_connect,
                    connect_target=connect_target,
                )
                entry = {
                    'scheme': 'socks5',
                    'host': ip,
                    'port': port_value,
                    'username': None,
                    'password': None,
                }
                result.update({
                    'source': 'port-scan',
                    'input_url': f"socks5://{ip}:{port_value}",
                    'normalized_url': normalize_socks_url(entry),
                    'host': ip,
                    'port': port_value,
                    'scheme': 'socks5'
                })
                progress_queue.put(('socks_result', result))
        progress_queue.put(('phase_complete', {
            'context': 'host_scan',
            'invalid_subnets': invalid_subnets
        }))

    if is_stop_requested():
        return

    socks_success = _process_socks_urls(socks_urls, options)
    if not socks_success:
        return

    progress_queue.put(('complete', {'context': 'job'}))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/start_scan', methods=['POST'])
def start_scan():
    global scan_thread, stop_scan, progress_queue
    file = request.files.get('ipfile')
    subnets_raw = request.form.get('subnets', '')
    ips_raw = request.form.get('ips', '')
    socks_urls_raw = request.form.get('socks_urls', '')

    file_subnets, file_ips = set(), set()
    if file:
        file_content = file.read().decode(errors='ignore')
        file_subnets, file_ips = parse_ip_file(io.StringIO(file_content))

    manual_subnets = split_tokens(subnets_raw)

    manual_ips = split_tokens(ips_raw)

    all_subnets = manual_subnets | file_subnets
    all_ips = manual_ips | file_ips

    socks_urls = [line.strip() for line in socks_urls_raw.splitlines() if line.strip()]

    detect_socks5 = parse_bool(request.form.get('detect_socks5', '1'), True)
    validate_connect = parse_bool(request.form.get('validate_connect', '1'), True)
    timeout_ms = parse_int(request.form.get('timeout_ms'), DEFAULT_TIMEOUT_MS)
    read_timeout_ms = request.form.get('read_timeout_ms')
    read_timeout_ms = parse_int(read_timeout_ms, timeout_ms) if read_timeout_ms else timeout_ms
    max_concurrency = parse_int(request.form.get('max_concurrency'), DEFAULT_MAX_CONCURRENCY)
    candidate_ports = parse_port_list(request.form.get('socks_ports', ''), DEFAULT_SOCKS_PORTS)
    connect_target = parse_connect_target(request.form.get('connect_target', ''), DEFAULT_CONNECT_TARGET)

    options = {
        'detect_socks5': detect_socks5,
        'validate_connect': validate_connect,
        'timeout_ms': max(timeout_ms, 250),
        'read_timeout_ms': max(read_timeout_ms, 250),
        'candidate_ports': candidate_ports,
        'connect_target': connect_target,
        'max_concurrency': max(1, min(max_concurrency, 64)),
    }

    progress_queue = queue.Queue()
    scan_thread = threading.Thread(target=do_scan, args=(all_subnets, all_ips, socks_urls, options), daemon=True)
    scan_thread.start()
    with scan_lock:
        stop_scan = False

    return jsonify({'started': True})


@app.route('/stop', methods=['POST'])
def stop():
    global stop_scan
    with scan_lock:
        stop_scan = True
    return jsonify({'stopped': True})


@app.route('/progress')
def progress():
    def event_stream():
        while True:
            try:
                event, data = progress_queue.get(timeout=1)
            except queue.Empty:
                if is_stop_requested():
                    continue
                continue
            if event == 'progress':
                elapsed = 0.0
                if isinstance(data, dict) and 'start' in data:
                    elapsed = time.time() - data['start']
                payload = {
                    'type': 'progress',
                    'context': data.get('context'),
                    'current': data.get('current'),
                    'completed': data.get('completed'),
                    'total': data.get('total'),
                    'elapsed': elapsed
                }
            elif event == 'live':
                payload = {'type': 'live', **data}
            elif event == 'socks_result':
                payload = {'type': 'socks_result', **data}
            elif event == 'phase_complete':
                payload = {'type': 'phase_complete', **data}
            elif event == 'complete':
                payload = {'type': 'complete', **(data or {})}
                yield f"data: {json.dumps(payload)}\n\n"
                break
            elif event == 'stopped':
                payload = {'type': 'stopped', **(data or {})}
                yield f"data: {json.dumps(payload)}\n\n"
                break
            elif event == 'error':
                payload = {'type': 'error', 'message': data}
                yield f"data: {json.dumps(payload)}\n\n"
                break
            else:
                continue
            yield f"data: {json.dumps(payload)}\n\n"
    return Response(event_stream(), mimetype='text/event-stream')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
