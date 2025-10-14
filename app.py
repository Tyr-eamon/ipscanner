import socket
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, request, jsonify, render_template, Response
import ipaddress
import platform
import subprocess
import threading
import time
import queue
import json
import io
import csv

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

stop_scan = False
scan_lock = threading.Lock()
progress_queue = queue.Queue()
scan_thread = None

def ping_ip(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    try:
        return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False

def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return result == 0
    except:
        return False
    finally:
        sock.close()

def scan_web_ports(ip):
    open_ports = []
    for port in WEB_PORTS:
        with scan_lock:
            if stop_scan:
                return None
        if scan_port(ip, port):
            open_ports.append((port, WEB_PORTS[port]))
    return open_ports

def parse_ip_file(file):
    """
    Expects a file-like object with two columns:
    Column 0: IP segments (CIDR or dash form)
    Column 1: Individual IPs
    Both columns optional. Returns tuple (set of subnets, set of ips)
    """
    subnets = set()
    ips = set()
    if not file:
        return subnets, ips
    file.seek(0)
    # Detect CSV or whitespace
    content = file.read()
    file.seek(0)
    sniffer = csv.Sniffer()
    try:
        dialect = sniffer.sniff(content)
        reader = csv.reader(io.StringIO(content), dialect)
    except Exception:
        # fallback: whitespace split
        lines = content.splitlines()
        for line in lines:
            entries = line.strip().split()
            if len(entries) == 2:
                subnets.add(entries[0].strip())
                ips.add(entries[1].strip())
            elif len(entries) == 1:
                value = entries[0].strip()
                # Basic guess: if / in string or – it's likely a subnet, else an IP
                if '/' in value or '-' in value:
                    subnets.add(value)
                else:
                    ips.add(value)
            # Ignore empty/invalid rows
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

def do_scan(subnets, ips):
    global stop_scan
    stop_scan = False

    all_hosts = set()
    invalid_subnets = []
    # Add subnet hosts
    for subnet in subnets:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            all_hosts.update(str(ip) for ip in net.hosts())
        except Exception:
            invalid_subnets.append(subnet)
    # Add individual IPs (filter bad)
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            all_hosts.add(ip)
        except Exception:
            pass

    if not all_hosts:
        progress_queue.put(('error', f'No valid IPs to scan. Invalid subnets: {", ".join(invalid_subnets)}'))
        return

    total_hosts = len(all_hosts)
    start_time = time.time()
    scanned_count = 0

    # Progress and live discovery per IP
    for ip in all_hosts:
        with scan_lock:
            if stop_scan:
                progress_queue.put(('stopped', None))
                return
        progress_queue.put(('progress', {'current_ip': ip, 'scanned': scanned_count, 'total': total_hosts, 'start': start_time}))
        if ping_ip(ip):
            # Immediately scan and stream each ALIVE host
            open_ports = scan_web_ports(ip)
            if open_ports is None:
                progress_queue.put(('stopped', None))
                return
            # Live open port event for each IP found
            filtered_ports = []
            port_numbers = [p[0] for p in open_ports]
            if 443 in port_numbers:
                filtered_ports = [(p, s) for p, s in open_ports if p != 80]
            else:
                filtered_ports = open_ports
            if filtered_ports:
                port_list_str = ', '.join(f"{p[0]} ({p[1]})" for p in filtered_ports)
                progress_queue.put(('live', {
                    'ip': ip,
                    'ports': port_list_str,
                    'open_ports': filtered_ports
                }))
        scanned_count += 1

    progress_queue.put(('complete', {}))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    global scan_thread, stop_scan
    file = request.files.get('ipfile')
    subnets = request.form.get('subnets', '')
    ips = request.form.get('ips', '')

    file_subnets, file_ips = set(), set()
    if file:
        file_content = file.read().decode()
        file_subnets, file_ips = parse_ip_file(io.StringIO(file_content))
    # Merge file and manual input
    all_subnets = set([s.strip() for s in subnets.split(",") if s.strip()]) | file_subnets
    all_ips = set([i.strip() for i in ips.split(",") if i.strip()]) | file_ips

    scan_thread = threading.Thread(target=do_scan, args=(all_subnets, all_ips))
    scan_thread.start()
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
                if event == 'progress':
                    elapsed = time.time() - data['start']
                    payload = json.dumps({
                        'type': 'progress',
                        'current_ip': data['current_ip'],
                        'scanned': data['scanned'],
                        'total': data['total'],
                        'elapsed': elapsed
                    })
                    yield f"data: {payload}\n\n"
                elif event == 'live':
                    payload = json.dumps({'type': 'live', **data})
                    yield f"data: {payload}\n\n"
                elif event == 'complete':
                    payload = json.dumps({'type': 'complete'})
                    yield f"data: {payload}\n\n"
                    break
                elif event == 'stopped':
                    payload = json.dumps({'type': 'stopped'})
                    yield f"data: {payload}\n\n"
                    break
                elif event == 'error':
                    payload = json.dumps({'type': 'error', 'message': data})
                    yield f"data: {payload}\n\n"
                    break
            except queue.Empty:
                continue
            except GeneratorExit:
                break
    return Response(event_stream(), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
