const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../public')));

// Path to persistent DB file
const DB_FILE = path.join(__dirname, '../data/db.json');
const LICENSES_SEED_FILE = path.join(__dirname, '../data/licenses.json');

// Session store for logged-in admins
const adminSessions = new Map();

// Helper to hash passwords
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Initial Database State
let db = {
  admin: {
    username: process.env.ADMIN_USERNAME || 'admin',
    passwordHash: hashPassword(process.env.ADMIN_PASSWORD || 'admin1234')
  },
  masterApiKey: process.env.MASTER_API_KEY || "ME9D3V19XU0",
  users: [],
  ranges: [
    "88017XXXXXX",
    "88018XXXXXX",
    "88019XXXXXX",
    "1201555XXXX",
    "447911XXXXXX",
    "62812XXXXXXXX",
    "26134XXXXXX"
  ],
  allocatedNumbers: [], // Clean: No demo/fake numbers
  otps: [],             // Clean: No demo/fake OTPs
  logs: []
};

// Load or Initialize DB
function loadDb() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, 'utf-8');
      db = JSON.parse(data);
    } else {
      // Seed initial users from licenses.json if available
      if (fs.existsSync(LICENSES_SEED_FILE)) {
        const seedLicenses = JSON.parse(fs.readFileSync(LICENSES_SEED_FILE, 'utf-8'));
        db.users = seedLicenses.map((item, idx) => ({
          id: `usr_${Date.now()}_${idx}`,
          username: item.user || `Client #${idx + 1}`,
          licenseKey: item.key,
          status: item.status || "active",
          createdAt: item.createdAt || new Date().toISOString(),
          lastActive: null,
          lastIp: null,
          lastDevice: null,
          allocatedCount: 0,
          otpCount: 0
        }));
      }
      saveDb();
    }
  } catch (err) {
    console.error("DB Load Error:", err.message);
  }
}

function saveDb() {
  try {
    const dir = path.dirname(DB_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
  } catch (err) {
    // In serverless read-only filesystem environments, state remains in memory
  }
}

// Initial DB Load
loadDb();

// Activity Logger
function addLog(action, details, ip = 'system') {
  const logItem = {
    id: Date.now().toString(),
    timestamp: new Date().toLocaleTimeString(),
    action,
    details,
    ip
  };
  db.logs.unshift(logItem);
  if (db.logs.length > 100) db.logs.pop();
  saveDb();
}

// ==========================================
// 1. ADMIN AUTHENTICATION MIDDLEWARE & APIS
// ==========================================

function verifyAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || 
                (req.headers.authorization && req.headers.authorization.replace('Bearer ', '')) ||
                req.query.token;

  if (!token || !adminSessions.has(token)) {
    return res.status(401).json({ success: false, error: "Unauthorized: Admin login required" });
  }

  const session = adminSessions.get(token);
  // Session timeout: 24 hours
  if (Date.now() - session.createdAt > 24 * 60 * 60 * 1000) {
    adminSessions.delete(token);
    return res.status(401).json({ success: false, error: "Session expired. Please log in again." });
  }

  req.adminUser = session.username;
  next();
}

// POST /api/admin/login
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, error: "Username and password are required" });
  }

  const inputHash = hashPassword(password);
  if (username.trim() === db.admin.username && inputHash === db.admin.passwordHash) {
    const token = crypto.randomBytes(32).toString('hex');
    adminSessions.set(token, {
      username: db.admin.username,
      createdAt: Date.now()
    });

    addLog("ADMIN_LOGIN", `Admin '${username}' logged in successfully`, req.ip);
    return res.json({
      success: true,
      token,
      username: db.admin.username,
      message: "Login successful"
    });
  }

  addLog("ADMIN_LOGIN_FAILED", `Failed login attempt for username '${username}'`, req.ip);
  return res.status(401).json({ success: false, error: "Invalid admin username or password" });
});

// GET /api/admin/verify-token
app.get('/api/admin/verify-token', (req, res) => {
  const token = req.headers['x-admin-token'] || 
                (req.headers.authorization && req.headers.authorization.replace('Bearer ', ''));

  if (token && adminSessions.has(token)) {
    return res.json({ success: true, authenticated: true });
  }
  return res.json({ success: false, authenticated: false });
});

// POST /api/admin/logout
app.post('/api/admin/logout', (req, res) => {
  const token = req.headers['x-admin-token'] || 
                (req.headers.authorization && req.headers.authorization.replace('Bearer ', ''));
  if (token) adminSessions.delete(token);
  res.json({ success: true, message: "Logged out" });
});

// POST /api/admin/change-password
app.post('/api/admin/change-password', verifyAdmin, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ success: false, error: "New password must be at least 6 characters" });
  }

  if (hashPassword(currentPassword) !== db.admin.passwordHash) {
    return res.status(400).json({ success: false, error: "Current password does not match" });
  }

  db.admin.passwordHash = hashPassword(newPassword);
  saveDb();
  addLog("PASSWORD_CHANGED", "Admin password changed successfully", req.ip);
  res.json({ success: true, message: "Password updated successfully" });
});

// ==========================================
// 2. REAL-TIME USER MANAGEMENT (PROTECTED)
// ==========================================

// GET /api/admin/dashboard
app.get('/api/admin/dashboard', verifyAdmin, (req, res) => {
  const now = Date.now();
  const onlineThreshold = 5 * 60 * 1000; // Active within last 5 minutes = Online

  const usersWithOnlineStatus = db.users.map(u => ({
    ...u,
    isOnline: u.lastActive ? (now - new Date(u.lastActive).getTime() < onlineThreshold) : false
  }));

  const activeCount = db.users.filter(u => u.status === 'active').length;
  const onlineCount = usersWithOnlineStatus.filter(u => u.isOnline).length;

  res.json({
    stats: {
      totalUsers: db.users.length,
      activeUsers: activeCount,
      onlineUsers: onlineCount,
      allocatedNumbers: db.allocatedNumbers.length,
      totalOtps: db.otps.length,
      activeRanges: db.ranges.length
    },
    users: usersWithOnlineStatus,
    ranges: db.ranges,
    allocatedNumbers: db.allocatedNumbers.slice(0, 30),
    otps: db.otps.slice(0, 30),
    logs: db.logs.slice(0, 40),
    settings: {
      masterApiKey: db.masterApiKey,
      adminUsername: db.admin.username
    }
  });
});

// POST /api/admin/users/add
app.post('/api/admin/users/add', verifyAdmin, (req, res) => {
  const { username, licenseKey, note } = req.body;
  if (!username) {
    return res.status(400).json({ success: false, error: "Username is required" });
  }

  // Generate clean RC-XXXXX-... key if not provided
  let key = licenseKey;
  if (!key || key.trim() === '') {
    const part = () => Math.random().toString(36).substring(2, 7).toUpperCase();
    key = `RC-${part()}-${part()}-${part()}-${part()}`;
  } else {
    key = key.trim();
  }

  // Check duplicate key
  if (db.users.some(u => u.licenseKey === key)) {
    return res.status(400).json({ success: false, error: "This license key already exists!" });
  }

  const newUser = {
    id: `usr_${Date.now()}_${Math.floor(Math.random() * 1000)}`,
    username: username.trim(),
    licenseKey: key,
    note: note || '',
    status: "active",
    createdAt: new Date().toISOString(),
    lastActive: null,
    lastIp: null,
    lastDevice: null,
    allocatedCount: 0,
    otpCount: 0
  };

  db.users.unshift(newUser);
  saveDb();
  addLog("USER_CREATED", `Created user '${newUser.username}' with Key: ${newUser.licenseKey}`, req.ip);

  res.json({ success: true, user: newUser });
});

// POST /api/admin/users/toggle-status
app.post('/api/admin/users/toggle-status', verifyAdmin, (req, res) => {
  const { id } = req.body;
  const user = db.users.find(u => u.id === id);
  if (!user) return res.status(404).json({ success: false, error: "User not found" });

  user.status = user.status === "active" ? "suspended" : "active";
  saveDb();
  addLog("USER_STATUS_CHANGE", `User '${user.username}' status set to ${user.status}`, req.ip);

  res.json({ success: true, user });
});

// POST /api/admin/users/delete
app.post('/api/admin/users/delete', verifyAdmin, (req, res) => {
  const { id } = req.body;
  const index = db.users.findIndex(u => u.id === id);
  if (index === -1) return res.status(404).json({ success: false, error: "User not found" });

  const deletedUser = db.users.splice(index, 1)[0];
  saveDb();
  addLog("USER_DELETED", `Deleted user '${deletedUser.username}' (Key: ${deletedUser.licenseKey})`, req.ip);

  res.json({ success: true, message: "User deleted" });
});

// POST /api/admin/send-otp
app.post('/api/admin/send-otp', verifyAdmin, (req, res) => {
  const { number, code, message } = req.body;
  if (!number) return res.status(400).json({ error: "Number is required" });

  const cleanNum = number.startsWith("+") ? number : "+" + number.trim();
  const finalCode = code || Math.floor(100000 + Math.random() * 900000).toString();
  const finalMessage = message || `Your Facebook confirmation code is ${finalCode}`;
  const otpId = Date.now().toString();

  const otpEntry = {
    otp_id: otpId,
    number: cleanNum,
    code: finalCode,
    message: finalMessage,
    createdAt: new Date().toISOString()
  };

  db.otps.unshift(otpEntry);

  // Increment user's OTP count if linked to allocated number
  const matchedAlloc = db.allocatedNumbers.find(a => a.fullNumber === cleanNum || a.noPlusNumber === cleanNum.replace('+', ''));
  if (matchedAlloc) {
    const user = db.users.find(u => u.licenseKey === matchedAlloc.allocatedToKey);
    if (user) user.otpCount = (user.otpCount || 0) + 1;
  }

  saveDb();
  addLog("OTP_DISPATCHED", `Live OTP code [${finalCode}] sent to ${cleanNum}`, req.ip);

  res.json({ success: true, otp: otpEntry });
});

// POST /api/admin/ranges/add
app.post('/api/admin/ranges/add', verifyAdmin, (req, res) => {
  const { range } = req.body;
  if (range && !db.ranges.includes(range.trim())) {
    db.ranges.push(range.trim());
    saveDb();
    addLog("RANGE_ADDED", `Added country range: ${range}`, req.ip);
  }
  res.json({ success: true, ranges: db.ranges });
});

// POST /api/admin/ranges/delete
app.post('/api/admin/ranges/delete', verifyAdmin, (req, res) => {
  const { range } = req.body;
  db.ranges = db.ranges.filter(r => r !== range);
  saveDb();
  addLog("RANGE_DELETED", `Removed country range: ${range}`, req.ip);
  res.json({ success: true, ranges: db.ranges });
});

// ==========================================
// 3. ANDROID APP COMPATIBLE API (REAL-TIME)
// ==========================================

// Authenticate app requests using license key
function verifyAppLicense(req, res, next) {
  const authHeader = req.headers['mauthapi'] || req.query.mauthapi || req.headers['authorization'];
  if (!authHeader) {
    addLog("APP_AUTH_DENIED", "Missing mauthapi license header", req.ip);
    return res.status(401).json({ error: "Unauthorized: Missing mauthapi header" });
  }

  const cleanKey = authHeader.replace("Bearer ", "").trim();
  const isMaster = cleanKey === db.masterApiKey;
  const user = db.users.find(u => u.licenseKey === cleanKey);

  if (!isMaster && !user) {
    addLog("APP_AUTH_DENIED", `Invalid License Key: ${cleanKey}`, req.ip);
    return res.status(403).json({ error: "Forbidden: Invalid License Key" });
  }

  if (user && user.status !== "active") {
    addLog("APP_ACCESS_BLOCKED", `Suspended user '${user.username}' attempted connection`, req.ip);
    return res.status(403).json({ error: `Forbidden: Account is ${user.status}. Contact administrator.` });
  }

  // Update real-time user activity
  if (user) {
    user.lastActive = new Date().toISOString();
    user.lastIp = req.ip || req.connection.remoteAddress;
    user.lastDevice = req.headers['user-agent'] || 'Android Client';
    saveDb();
  }

  req.authKey = cleanKey;
  req.authUser = user;
  next();
}

// GET /api/v1/license/verify
app.get('/api/v1/license/verify', (req, res) => {
  const key = (req.query.key || req.headers['mauthapi'] || '').trim();
  if (!key) return res.status(400).json({ valid: false, error: "License key parameter is required" });

  const user = db.users.find(u => u.licenseKey === key);
  const isMaster = key === db.masterApiKey;

  if (isMaster || (user && user.status === "active")) {
    return res.json({
      valid: true,
      status: "active",
      username: user ? user.username : "Master Admin",
      key: key
    });
  }

  return res.status(403).json({
    valid: false,
    status: user ? user.status : "invalid",
    error: user ? `License is ${user.status}` : "Invalid license key"
  });
});

// GET /api/v1/liveaccess
app.get('/api/v1/liveaccess', verifyAppLicense, (req, res) => {
  const username = req.authUser ? req.authUser.username : "Master";
  addLog("APP_LIVE_CONNECT", `User '${username}' connected to live access`, req.ip);

  res.json({
    status: "success",
    data: {
      services: [
        { sid: "fb", ranges: db.ranges },
        { sid: "facebook", ranges: db.ranges },
        { sid: "telegram", ranges: db.ranges }
      ]
    }
  });
});

// POST /api/v1/getnum
app.post('/api/v1/getnum', verifyAppLicense, (req, res) => {
  const { rid } = req.body;
  const prefix = (rid || "88017").replace(/[^0-9]/g, "");

  // Generate realistic virtual phone number with the prefix
  let remainingLen = 11 - prefix.length;
  if (remainingLen < 4) remainingLen = 6;
  let randomSuffix = "";
  for (let i = 0; i < remainingLen; i++) {
    randomSuffix += Math.floor(Math.random() * 10).toString();
  }

  const noPlusNumber = prefix + randomSuffix;
  const fullNumber = "+" + noPlusNumber;

  const numEntry = {
    id: Date.now().toString(),
    prefix,
    noPlusNumber,
    fullNumber,
    allocatedToKey: req.authKey,
    allocatedToUser: req.authUser ? req.authUser.username : "Master",
    createdAt: new Date().toISOString()
  };

  db.allocatedNumbers.unshift(numEntry);

  if (req.authUser) {
    req.authUser.allocatedCount = (req.authUser.allocatedCount || 0) + 1;
  }

  saveDb();
  addLog("APP_NUMBER_ALLOCATED", `User '${numEntry.allocatedToUser}' allocated number ${fullNumber}`, req.ip);

  res.json({
    meta: {
      code: 200,
      message: "Number allocated successfully"
    },
    data: {
      no_plus_number: noPlusNumber,
      full_number: fullNumber
    }
  });
});

// GET /api/v1/success-otp
app.get('/api/v1/success-otp', verifyAppLicense, (req, res) => {
  res.json({
    data: {
      otps: db.otps.map(o => ({
        otp_id: o.otp_id,
        number: o.number,
        message: o.message
      }))
    }
  });
});

// Fallback route for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Export app for Vercel
module.exports = app;

// Local development server listener
if (require.main === module || !process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`=======================================================`);
    console.log(`🚀 RC TOOLS Live Real-Time Server & Admin Panel`);
    console.log(`📡 URL: http://localhost:${PORT}`);
    console.log(`🔐 Admin Username: ${db.admin.username}`);
    console.log(`🔑 Master Key: ${db.masterApiKey}`);
    console.log(`👥 Registered Users: ${db.users.length}`);
    console.log(`=======================================================`);
  });
}
