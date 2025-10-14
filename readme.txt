Project Name:
IP Scanner / Subnet & IP Network Port Scanner (Flask)

Description:
A highly scalable Flask-based web application for scanning open web ports (e.g., HTTP/HTTPS/proxy ports or custom) on IP addresses and subnets.

Features:
Upload file with subnets (CIDR) and IPs (two columns, supports large lists)

Manual bulk entry for subnets and IPs (comma separated)

Scans popular web ports, extendable for all 1–65535 ports

Real-time progress bar and open port updates

Displays results in interactive tables and clickable URLs

Stop scan anytime and handle large datasets efficiently

Usage Instructions:
Run the backend:
python app.py

Access the web interface:
→ http://localhost:5000

On the UI:

Upload a file OR manually enter subnets/IPs.

Click Start Scan.

Watch live results appear instantly as ports open.

File Format:
Supported File Types: .csv, .txt
Format:
192.168.1.0/24,192.168.1.10
10.0.0.0/24,
,10.0.0.5

Column 1 → Subnet range in CIDR or dash.
Column 2 → Specific IPs.

Technologies Used:
Python (Flask)

HTML, CSS, JavaScript

ThreadPoolExecutor for concurrent scans

Server-Sent Events (SSE) for real-time updates

Workflow Overview:
Extracts unique IPs from uploaded files and input text.

Pings each host and scans reachable ones.

Streams results (open ports found) live to frontend.

Frontend shows clickable open port URLs instantly.

Recommended Future Enhancements:
Support for custom user port ranges.

Asynchronous scanning (Quart + asyncio).

Optional authentication for shared deployment.

License:
MIT License recommended or any preferred open-source license.

Author:
Developed for professional and educational use.