const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');
const dns = require('dns').promises;
const { WebSocketServer } = require('ws');
const { Client } = require('ssh2');
const { AnsiUp } = require('ansi_up');

const PORT = 3000;

// ============ NETWORK SCANNER ============

async function ping(ip) {
  return new Promise((resolve) => {
    const cmd = process.platform === 'win32' 
      ? `ping -n 1 -w 800 ${ip}`
      : `ping -c 1 -W 1 ${ip}`;
    
    exec(cmd, { timeout: 2000 }, (err) => {
      resolve(!err);
    });
  });
}

async function checkPort(ip, port) {
  return new Promise((resolve) => {
    const net = require('net');
    const socket = new net.Socket();
    socket.setTimeout(1500);
    
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.on('error', () => {
      resolve(false);
    });
    
    socket.connect(port, ip);
  });
}

async function getHostname(ip) {
  try {
    const hosts = await dns.reverse(ip);
    return hosts[0] || null;
  } catch {
    return null;
  }
}

async function scanHost(ip) {
  const start = Date.now();
  const online = await ping(ip);
  const responseTime = Date.now() - start;
  
  const host = {
    ip,
    status: online ? 'online' : 'offline',
    responseTime: online ? responseTime : null,
    hostname: null,
    mac: null,
    os: 'unknown',
    openPorts: [],
    lastSeen: online ? new Date().toISOString() : null
  };
  
  if (online) {
    host.hostname = await getHostname(ip);
    
    const ports = [22, 80, 135, 139, 443, 445, 3389, 8080, 8443, 5900, 5000, 88, 548];
    const results = await Promise.allSettled(ports.map(p => checkPort(ip, p)));
    
    results.forEach((result, i) => {
      if (result.status === 'fulfilled' && result.value) {
        host.openPorts.push(ports[i]);
      }
    });
    
    // Detect OS based on open ports
    if (host.openPorts.includes(5000) || host.openPorts.includes(548) || host.openPorts.includes(88)) {
      // Apple ports - MacOS
      host.os = 'macos';
    } else if (host.openPorts.includes(22)) {
      // Has SSH - could be Linux or Mac without AirPlay
      host.os = 'linux';
    } else if (host.openPorts.includes(3389) || host.openPorts.includes(135)) {
      host.os = 'windows';
    } else if (host.openPorts.includes(445)) {
      host.os = 'unknown';
    }
  }
  
  return host;
}

async function scanRange(startIP, endIP) {
  const base = startIP.split('.').slice(0, 3).join('.');
  const start = parseInt(startIP.split('.')[3]);
  const end = parseInt(endIP.split('.')[3]);
  
  const ips = [];
  for (let i = start; i <= end; i++) {
    ips.push(`${base}.${i}`);
  }
  
  console.log(`[SCANNER] Scanning ${ips.length} IPs...`);
  
  const results = [];
  const batchSize = 30;
  
  for (let i = 0; i < ips.length; i += batchSize) {
    const batch = ips.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map(ip => scanHost(ip)));
    results.push(...batchResults);
    
    const progress = Math.round(((i + batchSize) / ips.length) * 100);
    console.log(`[SCANNER] Progress: ${progress}%`);
  }
  
  const online = results.filter(r => r.status === 'online').length;
  console.log(`[SCANNER] Complete! ${online} hosts online.`);
  
  return results;
}

// ============ SSH TERMINAL WITH SSH2 ============

const HTML_DIR = __dirname;

function serveStatic(res, filePath, contentType) {
  fs.readFile(path.join(HTML_DIR, filePath), (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;
  
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Content-Type', 'application/json');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }
  
  // Static files
  if (pathname === '/' || pathname === '/index.html') {
    serveStatic(res, 'index.html', 'text/html');
    return;
  }
  
  if (pathname === '/terminal.html') {
    serveStatic(res, 'terminal.html', 'text/html');
    return;
  }
  
  if (pathname === '/rdp.html') {
    serveStatic(res, 'rdp.html', 'text/html');
    return;
  }
  
  // Serve noVNC static files
  if (pathname.startsWith('/noVNC/')) {
    const noVNCPath = pathname.slice(7);
    const contentTypes = {
      '.html': 'text/html',
      '.js': 'application/javascript',
      '.css': 'text/css',
      '.json': 'application/json',
      '.png': 'image/png',
      '.svg': 'image/svg+xml'
    };
    const ext = path.extname(noVNCPath);
    serveStatic(res, 'noVNC/' + (noVNCPath || 'vnc.html'), contentTypes[ext] || 'text/plain');
    return;
  }
  
  // API endpoints
  if (pathname === '/api/scan' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const startIP = data.start || '192.168.227.1';
        const endIP = data.end || '192.168.227.254';
        
        console.log(`[API] Scan: ${startIP} - ${endIP}`);
        const hosts = await scanRange(startIP, endIP);
        
        res.writeHead(200);
        res.end(JSON.stringify({
          success: true,
          count: hosts.length,
          online: hosts.filter(h => h.status === 'online').length,
          hosts: hosts
        }));
      } catch (e) {
        console.error('[API] Error:', e.message);
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }
  
  if (pathname === '/api/ping' && req.method === 'GET') {
    const ip = url.searchParams.get('ip');
    if (ip) {
      const start = Date.now();
      const online = await ping(ip);
      const responseTime = Date.now() - start;
      res.writeHead(200);
      res.end(JSON.stringify({ ip, online, responseTime }));
    } else {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Missing ip param' }));
    }
    return;
  }
  
  if (pathname === '/api/host' && req.method === 'GET') {
    const ip = url.searchParams.get('ip');
    if (ip) {
      const host = await scanHost(ip);
      res.writeHead(200);
      res.end(JSON.stringify(host));
    } else {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Missing ip param' }));
    }
    return;
  }
  
  if (pathname === '/api/ssh/check' && req.method === 'GET') {
    const ip = url.searchParams.get('ip');
    if (ip) {
      const hasSSH = await checkPort(ip, 22);
      res.writeHead(200);
      res.end(JSON.stringify({ ip, ssh: hasSSH }));
    } else {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Missing ip param' }));
    }
    return;
  }
  
  // 404
  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
});

// WebSocket for SSH terminal using ssh2
const wss = new WebSocketServer({ server, path: '/ws/terminal' });
const ansiUp = new AnsiUp();

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const ip = url.searchParams.get('ip');
  const username = url.searchParams.get('user') || 'manolo';
  const password = url.searchParams.get('pass') || '';
  
  if (!ip) {
    ws.send(JSON.stringify({ type: 'error', data: 'Missing IP address' }));
    ws.close();
    return;
  }
  
  console.log(`[TERM] SSH connection request: ${username}@${ip}`);
  
  const conn = new Client();
  let shell = null;
  
  conn.on('ready', () => {
    console.log(`[TERM] SSH connected to ${ip}`);
    
    // Send ready message first
    ws.send(JSON.stringify({ type: 'ready' }));
    
    conn.shell({ term: 'xterm-256color', cols: 120, rows: 30 }, (err, stream) => {
      if (err) {
        ws.send(JSON.stringify({ type: 'error', data: 'Error opening shell: ' + err.message }));
        return;
      }
      
      shell = stream;
      
      stream.on('data', (data) => {
        // Send raw data - xterm handles ANSI
        ws.send(JSON.stringify({ type: 'data', data: data.toString('utf-8') }));
      });
      
      stream.on('close', () => {
        ws.send(JSON.stringify({ type: 'close' }));
        conn.end();
      });
    });
  });
  
  conn.on('error', (err) => {
    console.error(`[TERM] SSH error: ${err.message}`);
    ws.send(JSON.stringify({ type: 'error', data: 'Error de conexión: ' + err.message }));
  });
  
  conn.on('close', () => {
    ws.send(JSON.stringify({ type: 'close' }));
    ws.close();
  });
  
  // Connect with password or try key-based
  conn.connect({
    host: ip,
    port: 22,
    username: username,
    password: password || undefined,
    privateKey: password ? undefined : require('fs').readFileSync(process.env.HOME + '/.ssh/id_rsa'),
    readyTimeout: 10000,
    algorithms: {
      kex: [
        'ecdh-sha2-nistp256',
        'ecdh-sha2-nistp384',
        'ecdh-sha2-nistp521',
        'diffie-hellman-group-exchange-sha256',
        'diffie-hellman-group14-sha256',
        'diffie-hellman-group14-sha1'
      ],
      cipher: [
        'aes128-ctr',
        'aes192-ctr',
        'aes256-ctr',
        'aes128-gcm@openssh.com',
        'aes256-gcm@openssh.com'
      ],
      serverHostKey: [
        'ssh-rsa',
        'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521',
        'ssh-ed25519',
        'rsa-sha2-256',
        'rsa-sha2-512'
      ],
      hmac: [
        'hmac-sha2-256',
        'hmac-sha2-512',
        'hmac-sha1'
      ]
    }
  });
  
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'input' && shell) {
        shell.write(data.data);
      } else if (data.type === 'password' && !password) {
        // Reconnect with password
        conn.end();
        conn.connect({
          host: ip,
          port: 22,
          username: username,
          password: data.password,
          readyTimeout: 10000
        });
      }
    } catch (e) {
      if (shell) shell.write(msg.toString());
    }
  });
  
  ws.on('close', () => {
    if (conn) conn.end();
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔═══════════════════════════════════════════╗
║     NetControl - Network Scanner           ║
║     http://localhost:${PORT}                   ║
╚═══════════════════════════════════════════╝

📡 API Endpoints:
   POST /api/scan      - Scan IP range {start, end}
   GET  /api/ping?ip=  - Ping single host
   GET  /api/host?ip=  - Full host scan
   GET  /api/ssh/check?ip= - Check SSH availability

🖥️ Terminal: http://localhost:${PORT}/terminal.html?ip=&user=&pass=
`);
});
