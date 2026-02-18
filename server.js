const express = require('express');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const { dns } = require('dns').promises;
const { WebSocketServer } = require('ws');
const { Client } = require('ssh2');
const { AnsiUp } = require('ansi_up');
const session = require('express-session');
const db = require('./db');

const PORT = 3000;
const app = express();

// Session config
app.use(session({
  secret: 'netcontrol-' + Math.random().toString(36).substr(2),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(express.json());
app.use(express.static(__dirname));

// ============ AUTH MIDDLEWARE ============
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.status(401).json({ success: false, error: 'No autorizado' });
}

// ============ AUTH ROUTES ============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.json({ success: false, error: 'Usuario y contraseña requeridos' });
    }
    if (password.length < 3) {
      return res.json({ success: false, error: 'Contraseña muy corta' });
    }
    const userId = await db.createUser(username, password);
    req.session.userId = userId;
    req.session.username = username;
    res.json({ success: true, username });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      res.json({ success: false, error: 'Usuario ya existe' });
    } else {
      res.json({ success: false, error: err.message });
    }
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await db.getUser(username);
    if (!user || !db.checkPassword(user, password)) {
      return res.json({ success: false, error: 'Usuario o contraseña incorrectos' });
    }
    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ success: true, username: user.username });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Check session
app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ success: true, username: req.session.username });
  } else {
    res.json({ success: false });
  }
});

// ============ USER DEVICES ROUTES ============

// Get user's devices
app.get('/api/devices', requireAuth, async (req, res) => {
  try {
    const devices = await db.getDevices(req.session.userId);
    res.json({ success: true, devices });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// Add device
app.post('/api/devices', requireAuth, async (req, res) => {
  try {
    const { ip, name, type, ports } = req.body;
    if (!ip) {
      return res.json({ success: false, error: 'IP requerida' });
    }
    const id = await db.addDevice(req.session.userId, ip, name || '', type || 'PC', ports || '');
    res.json({ success: true, id });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// Update device
app.put('/api/devices/:id', requireAuth, async (req, res) => {
  try {
    const { name, type, ports } = req.body;
    const changes = await db.updateDevice(req.params.id, req.session.userId, name, type, ports);
    res.json({ success: changes > 0 });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// Delete device
app.delete('/api/devices/:id', requireAuth, async (req, res) => {
  try {
    const changes = await db.deleteDevice(req.params.id, req.session.userId);
    res.json({ success: changes > 0 });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// ============ NETWORK SCANNER (原有的) ============

async function ping(ip) {
  return new Promise((resolve) => {
    const cmd = process.platform === 'win32' 
      ? `ping -n 1 -w 800 ${ip}`
      : `ping -c 1 -W 1 ${ip}`;
    exec(cmd, { timeout: 2000 }, (err) => resolve(!err));
  });
}

async function checkPort(ip, port) {
  return new Promise((resolve) => {
    const net = require('net');
    const socket = new net.Socket();
    socket.setTimeout(1500);
    socket.on('connect', () => { socket.destroy(); resolve(true); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('error', () => resolve(false));
    socket.connect(port, ip);
  });
}

async function getHostname(ip) {
  try { const hosts = await dns.reverse(ip); return hosts[0] || null; } catch { return null; }
}

async function getMacAddress(ip) {
  const localIP = require('os').networkInterfaces();
  for (const name in localIP) {
    for (const iface of localIP[name]) {
      if (iface.address === ip && iface.mac && iface.mac !== '00:00:00:00:00:00') {
        return iface.mac.toUpperCase();
      }
    }
  }
  return new Promise((resolve) => {
    try {
      const arpTable = require('fs').readFileSync('/proc/net/arp', 'utf8');
      for (const line of arpTable.split('\n')) {
        if (line.startsWith(ip + ' ')) {
          const mac = line.split(/\s+/)[3];
          if (mac && mac !== '00:00:00:00:00:00') { resolve(mac.toUpperCase()); return; }
        }
      }
    } catch (e) {}
    resolve(null);
  });
}

async function scanHost(ip) {
  const start = Date.now();
  const online = await ping(ip);
  const responseTime = Date.now() - start;
  const mac = online ? await getMacAddress(ip) : null;
  const hostname = await getHostname(ip).catch(() => null);
  
  let os = 'unknown';
  let ports = [];
  
  if (online) {
    const [rdp, ssh, vnc, https] = await Promise.all([
      checkPort(ip, 3389),
      checkPort(ip, 22),
      checkPort(ip, 5900),
      checkPort(ip, 443)
    ]);
    
    if (rdp) ports.push(3389);
    if (ssh) ports.push(22);
    if (vnc) ports.push(5900);
    if (https) ports.push(443);
    
    if (ports.length > 0) {
      const [port1] = ports;
      if (port1 === 22) os = 'linux';
      else if (port1 === 3389) os = 'windows';
      else {
        const [http] = await Promise.all([checkPort(ip, 80)]);
        if (http) {
          os = await getHostname(ip).then(h => h ? 'linux' : 'unknown').catch(() => 'unknown');
        }
      }
    }
  }
  
  return { ip, status: online ? 'online' : 'offline', responseTime: online ? responseTime : null, mac, os, ports, hostname };
}

async function scanRange(startIP, endIP) {
  const start = parseInt(startIP.split('.').pop());
  const end = parseInt(endIP.split('.').pop());
  const base = startIP.substring(0, startIP.lastIndexOf('.'));
  
  const hosts = [];
  const promises = [];
  
  for (let i = start; i <= end; i++) {
    const ip = `${base}.${i}`;
    promises.push(scanHost(ip).then(h => hosts.push(h)));
  }
  
  await Promise.all(promises);
  return hosts.sort((a, b) => {
    if (a.status !== b.status) return a.status === 'online' ? -1 : 1;
    return parseInt(a.ip.split('.').pop()) - parseInt(b.ip.split('.').pop());
  });
}

// ============ SCAN API (公开) ============
app.post('/api/scan', async (req, res) => {
  try {
    const { start, end } = req.body;
    const startIP = start || '192.168.227.1';
    const endIP = end || '192.168.227.254';
    console.log(`[API] Scan: ${startIP} - ${endIP}`);
    const hosts = await scanRange(startIP, endIP);
    res.json({ success: true, count: hosts.length, online: hosts.filter(h => h.status === 'online').length, hosts });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ============ ACTIONS API (需要认证) ============
app.post('/api/ping', requireAuth, async (req, res) => {
  const { ip } = req.body;
  const result = await ping(ip);
  res.json({ success: true, online: result });
});

app.post('/api/rdp', requireAuth, (req, res) => {
  const { ip } = req.body;
  if (process.platform === 'win32') {
    exec(`start mstsc /v:${ip}`);
  }
  res.json({ success: true });
});

app.post('/api/ssh', requireAuth, (req, res) => {
  const { ip } = req.body;
  res.json({ success: true, url: `/terminal.html?ip=${ip}` });
});

// ============ WEBSOCKET FOR TERMINAL ============
const server = app.listen(PORT, () => {
  console.log(`🚀 NetControl running on http://localhost:${PORT}`);
});

const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const ip = url.searchParams.get('ip');
  const username = url.searchParams.get('user') || 'root';
  const password = url.searchParams.get('pass');
  
  if (!ip) { ws.close(); return; }
  
  const conn = new Client();
  let shell = null;
  const ansiUp = new AnsiUp();
  
  conn.on('ready', () => {
    conn.shell((err, stream) => {
      if (err) { ws.send(JSON.stringify({ type: 'error', data: err.message })); return; }
      shell = stream;
      ws.send(JSON.stringify({ type: 'ready' }));
      
      stream.on('data', (data) => {
        const html = ansiUp.ansi_to_html(data.toString());
        ws.send(JSON.stringify({ type: 'data', data: html }));
      });
      
      stream.on('close', () => {
        ws.send(JSON.stringify({ type: 'close' }));
        conn.end();
      });
    });
  });
  
  conn.on('error', (err) => {
    ws.send(JSON.stringify({ type: 'error', data: err.message }));
  });
  
  conn.connect({ host: ip, port: 22, username, password, readyTimeout: 10000 });
  
  ws.on('message', (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === 'input' && shell) shell.write(data.data);
    } catch (e) {
      if (shell) shell.write(msg.toString());
    }
  });
});

console.log(`📡 WebSocket terminal ready`);
