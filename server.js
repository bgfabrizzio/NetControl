const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { dns } = require('dns').promises;
const { WebSocketServer } = require('ws');
const { Client } = require('ssh2');
const { AnsiUp } = require('ansi_up');

const PORT = 3000;

// ============ DATA PERSISTENCE ============
const DATA_FILE = path.join(__dirname, 'data.json');

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('[DATA] Error loading:', e.message);
  }
  return { whitelist: [], devices: {} };
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

let appData = loadData();

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

async function getMacAddress(ip) {
  // Check if it's the local machine
  const localIP = require('os').networkInterfaces();
  for (const name in localIP) {
    for (const iface of localIP[name]) {
      if (iface.address === ip) {
        // This is a local interface, get its MAC
        if (iface.mac && iface.mac !== '00:00:00:00:00:00') {
          console.log(`[MAC] Local interface: ${ip} -> ${iface.mac}`);
          return iface.mac.toUpperCase();
        }
      }
    }
  }
  
  return new Promise((resolve) => {
    // Read /proc/net/arp directly first (might already have the MAC)
    try {
      const arpTable = require('fs').readFileSync('/proc/net/arp', 'utf8');
      const lines = arpTable.split('\n');
      for (const line of lines) {
        if (line.startsWith(ip + ' ')) {
          const parts = line.split(/\s+/);
          const mac = parts[3];
          if (mac && mac !== '00:00:00:00:00:00') {
            console.log(`[MAC] Found in cache: ${ip} -> ${mac}`);
            resolve(mac.toUpperCase());
            return;
          }
        }
      }
    } catch (e) {
      console.log('[MAC] Error reading /proc/net/arp:', e.message);
    }
    
    // If not in cache, ping and check again
    const pingCmd = process.platform === 'win32' ? `ping -n 1 -w 500 ${ip}` : `ping -c 1 -W 1 ${ip}`;
    
    exec(pingCmd, { timeout: 3000 }, (err) => {
      if (err) {
        resolve(null);
        return;
      }
      
      // Try reading /proc/net/arp again after ping
      try {
        const arpTable = require('fs').readFileSync('/proc/net/arp', 'utf8');
        const lines = arpTable.split('\n');
        for (const line of lines) {
          if (line.startsWith(ip + ' ')) {
            const parts = line.split(/\s+/);
            const mac = parts[3];
            if (mac && mac !== '00:00:00:00:00:00') {
              console.log(`[MAC] Found after ping: ${ip} -> ${mac}`);
              resolve(mac.toUpperCase());
              return;
            }
          }
        }
      } catch (e) {}
      
      console.log(`[MAC] Not found for ${ip}`);
      resolve(null);
    });
  });
}

async function scanHost(ip) {
  const start = Date.now();
  const online = await ping(ip);
  const responseTime = Date.now() - start;
  
  const isWhitelisted = appData.whitelist.includes(ip);
  const customName = appData.devices[ip]?.name;
  
  const host = {
    ip,
    status: online ? 'online' : 'offline',
    responseTime: online ? responseTime : null,
    hostname: null,
    mac: null,
    os: 'unknown',
    openPorts: [],
    lastSeen: online ? new Date().toISOString() : null,
    isWhitelisted,
    customName: customName || null,
    type: appData.devices[ip]?.type || 'unknown'
  };
  
  if (online) {
    host.hostname = await getHostname(ip);
    host.mac = await getMacAddress(ip);
    
    // Get device type from saved data
    if (appData.devices[ip]) {
      host.type = appData.devices[ip].type || 'unknown';
      host.customName = appData.devices[ip].name || null;
    }
    
    const ports = [22, 80, 135, 139, 443, 445, 3389, 8080, 8443, 5900, 5000, 88, 548, 631, 9100];
    const results = await Promise.allSettled(ports.map(p => checkPort(ip, p)));
    
    results.forEach((result, i) => {
      if (result.status === 'fulfilled' && result.value) {
        host.openPorts.push(ports[i]);
      }
    });
    
    // Detect OS based on open ports
    if (host.openPorts.includes(5000) || host.openPorts.includes(548) || host.openPorts.includes(88)) {
      host.os = 'macos';
      if (host.type === 'unknown') host.type = 'mac';
    } else if (host.openPorts.includes(22)) {
      host.os = 'linux';
      if (host.type === 'unknown') host.type = 'linux';
    } else if (host.openPorts.includes(3389) || host.openPorts.includes(135)) {
      host.os = 'windows';
      if (host.type === 'unknown') host.type = 'pc';
    } else if (host.openPorts.includes(631)) {
      host.type = 'impresora';
    } else if (host.openPorts.includes(9100)) {
      host.type = 'impresora';
    } else if (host.openPorts.includes(445)) {
      host.os = 'unknown';
      if (host.type === 'unknown') host.type = 'pc';
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

// ============ STATIC FILES ============
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

// ============ HTTP SERVER ============
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
  
  // Static files - relative paths
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
  
  // ============ API ENDPOINTS ============
  
  // Scan network
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
  
  // Get data (whitelist + devices)
  if (pathname === '/api/data' && req.method === 'GET') {
    res.writeHead(200);
    res.end(JSON.stringify({
      success: true,
      whitelist: appData.whitelist,
      devices: appData.devices
    }));
    return;
  }
  
  // Update whitelist
  if (pathname === '/api/whitelist' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        appData.whitelist = data.whitelist || [];
        saveData(appData);
        
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, whitelist: appData.whitelist }));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }
  
  // Add single IP to whitelist
  if (pathname === '/api/whitelist/add' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const ip = data.ip;
        
        if (ip && !appData.whitelist.includes(ip)) {
          appData.whitelist.push(ip);
          saveData(appData);
        }
        
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, whitelist: appData.whitelist }));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }
  
  // Remove IP from whitelist
  if (pathname === '/api/whitelist/remove' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const ip = data.ip;
        
        appData.whitelist = appData.whitelist.filter(i => i !== ip);
        saveData(appData);
        
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, whitelist: appData.whitelist }));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }
  
  // Update device (name, type)
  if (pathname === '/api/device' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const ip = data.ip;
        const name = data.name;
        const type = data.type;
        
        if (ip) {
          if (!appData.devices[ip]) {
            appData.devices[ip] = {};
          }
          if (name !== undefined) appData.devices[ip].name = name;
          if (type !== undefined) appData.devices[ip].type = type;
          saveData(appData);
        }
        
        res.writeHead(200);
        res.end(JSON.stringify({ success: true, device: appData.devices[ip] }));
      } catch (e) {
        res.writeHead(500);
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }
  
  // Single ping
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
  
  // Single host scan
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
  
  // SSH check
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

// ============ WEBSOCKET FOR SSH ============
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
    ws.send(JSON.stringify({ type: 'ready' }));
    
    conn.shell({ term: 'xterm-256color', cols: 120, rows: 30 }, (err, stream) => {
      if (err) {
        ws.send(JSON.stringify({ type: 'error', data: 'Error opening shell: ' + err.message }));
        return;
      }
      
      shell = stream;
      
      stream.on('data', (data) => {
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
  
  conn.connect({
    host: ip,
    port: 22,
    username: username,
    password: password || undefined,
    readyTimeout: 10000
  });
  
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'input' && shell) {
        shell.write(data.data);
      }
    } catch (e) {
      if (shell) shell.write(msg.toString());
    }
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`🚀 NetControl running on http://localhost:${PORT}`);
  console.log(`📡 Data file: ${DATA_FILE}`);
});
