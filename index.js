const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "100kb" }));

const DB_PATH = path.join(__dirname, "database.json");
const KEY_PATH = path.join(__dirname, "keylist.json");
const LOG_PATH = path.join(__dirname, "logUser.txt");
const VPS = require("./vps.json");
const KEYS = require("./keylist.json");

const readDB = () => JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
const writeDB = (d) => fs.writeFileSync(DB_PATH, JSON.stringify(d, null, 2));
const logUser = (msg) => fs.appendFileSync(LOG_PATH, `[${new Date().toISOString()}] ${msg}\n`);

const limiter = rateLimit({ windowMs: 60 * 1000, max: 30 });
app.use(limiter);

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Token wajib" });
  try {
    req.user = jwt.verify(token, KEYS.jwtSecret);
    next();
  } catch {
    return res.status(401).json({ message: "Token invalid/expired" });
  }
}

app.get("/health", (req, res) => res.json({ status: "ok", time: Date.now() }));

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  const db = readDB();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ message: "User tidak ditemukan" });
  const ok = await bcrypt.compare(password || "", user.password);
  if (!ok) return res.status(401).json({ message: "Password salah" });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, KEYS.jwtSecret, { expiresIn: "7d" });
  logUser(`LOGIN ${username} role=${user.role}`);
  return res.json({ token, role: user.role });
});

app.post("/feature/crash", auth, (req, res) => {
  const { target, sender } = req.body || {};
  if (!target) return res.status(400).json({ message: "Target wajib" });
  if (sender === "private") {
    const db = readDB();
    const pair = db.pairings.find(p => p.userId === req.user.id && p.active);
    if (!pair) return res.status(400).json({ message: "Sender private belum aktif. Tautkan perangkat WA dulu." });
  }
  logUser(`CRASH ${req.user.username} target=${target} sender=${sender}`);
  return res.json({ status: "ok", message: `Crash dikirim ke ${target} via sender ${sender}` });
});

app.post("/feature/otp", auth, (req, res) => {
  const { target, count, sender } = req.body || {};
  if (!target) return res.status(400).json({ message: "Target wajib" });
  const n = Math.min(parseInt(count) || 1, 100);
  if (sender === "private") {
    const db = readDB();
    const pair = db.pairings.find(p => p.userId === req.user.id && p.active);
    if (!pair) return res.status(400).json({ message: "Sender private belum aktif." });
  }
  logUser(`OTP ${req.user.username} target=${target} count=${n} sender=${sender}`);
  return res.json({ status: "ok", message: `Spam OTP ${n}x ke ${target} via sender ${sender}` });
});

app.post("/wa/pairing/request", auth, (req, res) => {
  const { phone } = req.body || {};
  if (!phone) return res.status(400).json({ message: "Nomor wajib" });
  const code = Math.floor(10000000 + Math.random() * 90000000).toString();
  const db = readDB();
  db.pairings = db.pairings.filter(p => p.userId !== req.user.id);
  db.pairings.push({ userId: req.user.id, phone, code, active: false });
  writeDB(db);
  logUser(`PAIR_REQ ${req.user.username} phone=${phone} code=${code}`);
  return res.json({ status: "ok", message: "Pairing code dibuat", code });
});

app.post("/wa/pairing/activate", auth, (req, res) => {
  const { phone, code } = req.body || {};
  const db = readDB();
  const p = db.pairings.find(x => x.userId === req.user.id && x.phone === phone);
  if (!p) return res.status(400).json({ message: "Pairing tidak ditemukan" });
  if (p.code !== code) return res.status(400).json({ message: "Kode salah" });
  p.active = true;
  writeDB(db);
  logUser(`PAIR_ACTIVE ${req.user.username} phone=${phone}`);
  return res.json({ status: "ok", message: "Sender private aktif untuk " + phone });
});

app.use((req, res) => res.status(404).json({ message: "Not found" }));

app.listen(VPS.port, VPS.host, () => console.log(`API running on ${VPS.host}:${VPS.port}`));