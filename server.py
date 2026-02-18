#!/usr/bin/env python3
"""
NetControl Backend - Network Scanner API
Handles real network scanning for PC discovery
"""

import asyncio
import json
import socket
import subprocess
import struct
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading
import time
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.hosts = {}
        self.known_hosts = {
            '192.168.227.1': {'name': 'Router Gateway', 'os': 'linux', 'type': 'router', 'mac': '00:11:22:33:44:55'},
            '192.168.227.2': {'name': 'NAS Server', 'os': 'linux', 'type': 'server', 'mac': '00:11:22:33:44:56'},
        }
    
    async def ping_host(self, ip, timeout=1):
        """Check if host responds to ping"""
        try:
            param = '-n' if subprocess.os.name == 'nt' else '-c'
            result = subprocess.run(
                ['ping', param, '1', '-W', str(timeout), ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except:
            return False
    
    async def check_port(self, ip, port, timeout=1):
        """Check if a port is open"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def get_mac_vendor(self, mac):
        """Get vendor from MAC address (simplified)"""
        # In production, use a MAC vendor database
        vendors = {
            '00:11:22': 'Cisco',
            '00:1A:2B': 'Dell',
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            'B8:27:EB': 'Raspberry Pi',
            'DC:A6:32': 'Raspberry Pi',
        }
        prefix = ':'.join(mac.split(':')[:3]).upper()
        return vendors.get(prefix, 'Unknown')
    
    async def detect_os(self, ip):
        """Detect OS based on open ports"""
        common_ports = [22, 80, 135, 139, 443, 445, 3389, 8080]
        open_ports = []
        
        for port in common_ports:
            if await self.check_port(ip, port, timeout=0.5):
                open_ports.append(port)
        
        # Windows typically has 135, 139, 445, 3389
        # Linux typically has 22, 80, 443
        windows_ports = {135, 139, 445, 3389}
        linux_ports = {22, 80, 443}
        
        if windows_ports & set(open_ports):
            return 'windows'
        elif linux_ports & set(open_ports):
            return 'linux'
        
        return 'unknown'
    
    async def scan_host(self, ip, detect_os_flag=False):
        """Scan a single host"""
        start_time = time.time()
        is_online = await self.ping_host(ip)
        
        host = {
            'ip': ip,
            'status': 'online' if is_online else 'offline',
            'lastSeen': datetime.now().isoformat() if is_online else None,
            'responseTime': None,
            'openPorts': [],
            'os': 'unknown',
            'mac': None,
            'vendor': None,
        }
        
        if is_online:
            host['responseTime'] = int((time.time() - start_time) * 1000)
            
            # Check common ports
            for port in [22, 80, 139, 443, 445, 3389, 8080]:
                if await self.check_port(ip, port):
                    host['openPorts'].append(port)
            
            # Detect OS if requested
            if detect_os_flag:
                host['os'] = await self.detect_os(ip)
            
            # Check known hosts
            if ip in self.known_hosts:
                known = self.known_hosts[ip]
                host['name'] = known['name']
                host['os'] = known['os']
                host['type'] = known['type']
                host['mac'] = known['mac']
            else:
                host['name'] = f'Host-{ip.split(".")[-1]}'
                host['type'] = 'unknown'
                host['mac'] = self._generate_mac()
        else:
            host['name'] = f'Host-{ip.split(".")[-1]}'
            host['type'] = 'unknown'
        
        self.hosts[ip] = host
        return host
    
    def _generate_mac(self):
        """Generate a random MAC for demo"""
        return ':'.join([f'{(hash(ip) >> i*8 & 0xFF):02x}' for i in range(6)])
    
    async def scan_range(self, start_ip, end_ip, detect_os=False):
        """Scan a range of IPs"""
        # Extract base IP and range
        base = '.'.join(start_ip.split('.')[:-1])
        start = int(start_ip.split('.')[-1])
        end = int(end_ip.split('.')[-1])
        
        tasks = []
        for i in range(start, end + 1):
            ip = f'{base}.{i}'
            tasks.append(self.scan_host(ip, detect_os))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]

# Global scanner
scanner = NetworkScanner()

class APIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        # CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Content-Type', 'application/json')
        
        if path == '/api/scan':
            self.handle_scan(params)
        elif path == '/api/hosts':
            self.handle_hosts(params)
        elif path == '/api/host':
            self.handle_host(params)
        elif path == '/api/ping':
            self.handle_ping(params)
        else:
            self.send_error(404)
    
    def do_POST(self):
        self.send_header('Content-Type', 'application/json')
        
        if self.path == '/api/scan':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
                self.handle_scan_post(data)
            except:
                self.send_error(400)
        else:
            self.send_error(404)
    
    def handle_scan(self, params):
        start_ip = params.get('start', ['192.168.227.1'])[0]
        end_ip = params.get('end', ['192.168.227.254'])[0]
        detect_os = params.get('os', ['false'])[0].lower() == 'true'
        
        # Run async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            scanner.scan_range(start_ip, end_ip, detect_os)
        )
        loop.close()
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({
            'success': True,
            'count': len(results),
            'hosts': results
        }).encode())
    
    def handle_scan_post(self, data):
        start = data.get('start', '192.168.227.1')
        end = data.get('end', '192.168.227.254')
        detect_os = data.get('detectOS', False)
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            scanner.scan_range(start, end, detect_os)
        )
        loop.close()
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({
            'success': True,
            'count': len(results),
            'hosts': results
        }).encode())
    
    def handle_hosts(self, params):
        hosts = list(scanner.hosts.values())
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(hosts).encode())
    
    def handle_host(self, params):
        ip = params.get('ip', [None])[0]
        if ip and ip in scanner.hosts:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(scanner.hosts[ip]).encode())
        else:
            self.send_error(404)
    
    def handle_ping(self, params):
        ip = params.get('ip', [None])[0]
        if ip:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(scanner.ping_host(ip))
            loop.close()
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({'ip': ip, 'online': result}).encode())
        else:
            self.send_error(400)
    
    def log_message(self, format, *args):
        print(f"[API] {format % args}")

def run_server(port=3001):
    server = HTTPServer(('0.0.0.0', port), APIHandler)
    print(f"NetControl API running on http://localhost:{port}")
    server.serve_forever()

if __name__ == '__main__':
    run_server()
