const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, 'netcontrol.db');
const db = new sqlite3.Database(dbPath);

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    name TEXT,
    type TEXT DEFAULT 'PC',
    ports TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
});

module.exports = {
  db,
  bcrypt,
  
  // User functions
  createUser: (username, password) => {
    return new Promise((resolve, reject) => {
      const hash = bcrypt.hashSync(password, 10);
      db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, 
        [username, hash], 
        function(err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });
  },

  getUser: (username) => {
    return new Promise((resolve, reject) => {
      db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  },

  getUserById: (id) => {
    return new Promise((resolve, reject) => {
      db.get(`SELECT id, username, created_at FROM users WHERE id = ?`, [id], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  },

  checkPassword: (user, password) => {
    return bcrypt.compareSync(password, user.password);
  },

  // Device functions
  addDevice: (userId, ip, name, type, ports) => {
    return new Promise((resolve, reject) => {
      db.run(`INSERT INTO devices (user_id, ip, name, type, ports) VALUES (?, ?, ?, ?, ?)`,
        [userId, ip, name, type, ports || ''],
        function(err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });
  },

  getDevices: (userId) => {
    return new Promise((resolve, reject) => {
      db.all(`SELECT * FROM devices WHERE user_id = ? ORDER BY name, ip`, [userId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  },

  updateDevice: (id, userId, name, type, ports) => {
    return new Promise((resolve, reject) => {
      db.run(`UPDATE devices SET name = ?, type = ?, ports = ? WHERE id = ? AND user_id = ?`,
        [name, type, ports, id, userId],
        function(err) {
          if (err) reject(err);
          else resolve(this.changes);
        }
      );
    });
  },

  deleteDevice: (id, userId) => {
    return new Promise((resolve, reject) => {
      db.run(`DELETE FROM devices WHERE id = ? AND user_id = ?`, [id, userId], function(err) {
        if (err) reject(err);
        else resolve(this.changes);
      });
    });
  }
};
