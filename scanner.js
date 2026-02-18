const http = require('http');
const { exec } = require('child_process');
const dns = require('dns').promises;

const PORT = 3002;

// Real network scanner
async function ping(ip) {
  return new Promise((resolve) => {
    const cmd = process.platform === 'win32' 
      ? `ping -n 1 -w 500 ${ip}`
      : `ping -c 1 -W 1 ${ip}`;
    
    exec(cmd, { timeout: 2000 }, (err) => {
      resolve(!err);
    });
  });
}

async function checkPort(ip, port) {
  return new Promise((resolve) => {
    const client = require('net');
    const socket = new socket();
    socket.setTimeout(1000);
    
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
    return await dns.reverse(ip);
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
    // Try to get hostname
    host.hostname = await getHostname(ip);
    
    // Check common ports to detect OS
    const ports = [22, 80, 135, 139, 443, 445, 3389, 8080];
    const portResults = await Promise.allSettled(
      ports.map(p => checkPort(ip, p))
    );
    
    portResults.forEach((result, i) => {
      if (result.status === 'fulfilled' && result.value) {
        host.openPorts.push(ports[i]);
      }
    });
    
    // Detect OS based on open ports
    if (host.openPorts.includes(22)) host.os = 'linux';
    else if (host.openPorts.includes(3389) || host.openPorts.includes(135) || host.openPorts.includes(445)) {
      host.os = 'windows';
    }
  }
  
  return host;
}

async function scanRange(startIP, endIP) {
  // Parse IP range
  const base = startIP.split('.').slice(0, 3).join('.');
  const start = parseInt(startIP.split('.')[3]);
  const end = parseInt(endIP.split('.')[3]);
  
  const ips = [];
  for (let i = start; i <= end; i++) {
    ips.push(`${base}.${i}`);
  }
  
  console.log(`[SCANNER] Scanning ${ips.length} IPs...`);
  
  // Scan in batches of 50 for performance
  const results = [];
  const batchSize = 50;
  
  for (let i = 0; i < ips.length; i += batchSize) {
    const batch = ips.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map(ip => scanHost(ip)));
    results.push(...batchResults);
    
    const progress = Math.round(((i + batchSize) / ips.length) * 100);
    console.log(`[SCANNER] Progress: ${progress}%`);
  }
  
  console.log(`[SCANNER] Scan complete. Found ${results.filter(r => r.status === 'online').length} online hosts.`);
  return results;
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Content-Type', 'application/json');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }
  
  const url = new URL(req.url, `http://localhost:${PORT}`);
  
  if (url.pathname === '/api/scan' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const startIP = data.start || '192.168.227.1';
        const endIP = data.end || '192.168.227.254';
        
        console.log(`[API] Starting scan: ${startIP} - ${endIP}`);
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
  } else if (url.pathname === '/api/ping' && req.method === 'GET') {
    const ip = url.searchParams.get('ip');
    if (ip) {
      const online = await ping(ip);
      res.writeHead(200);
      res.end(JSON.stringify({ ip, online }));
    } else {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Missing ip parameter' }));
    }
  } else if (url.pathname === '/api/host' && req.method === 'GET') {
    const ip = url.searchParams.get('ip');
    if (ip) {
      const host = await scanHost(ip);
      res.writeHead(200);
      res.end(JSON.stringify(host));
    } else {
      res.writeHead(400);
      res.end(JSON.stringify({ error: 'Missing ip parameter' }));
    }
  } else {
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not found' }));
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 NetControl Scanner API running on http://localhost:${PORT}`);
  console.log(`📡 Endpoints:`);
  console.log(`   POST /api/scan - Scan IP range {start, end}`);
  console.log(`   GET  /api/ping?ip= - Ping single host`);
  console.log(`   GET  /api/host?ip= - Scan single host details`);
});
