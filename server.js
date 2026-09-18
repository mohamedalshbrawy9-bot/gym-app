const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], states: {} }, null, 2));
}

function loadDB() {
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function defaultState() {
  return { days: [], currentDayIndex: 0, history: [] };
}
function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
}

const app = express();
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "please-change-this-secret-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 30,
      httpOnly: true,
    },
  })
);

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "مش مسجل دخول" });
  next();
}

app.post("/api/signup", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "لازم تدخل إيميل وباسورد" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "الباسورد لازم يكون 6 حروف/أرقام على الأقل" });
  }
  const cleanEmail = String(email).trim().toLowerCase();
  const db = loadDB();
  if (db.users.find((u) => u.email === cleanEmail)) {
    return res.status(400).json({ error: "الإيميل ده مسجل قبل كده" });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const id = genId();
  db.users.push({ id, email: cleanEmail, passwordHash, createdAt: new Date().toISOString() });
  db.states[id] = defaultState();
  saveDB(db);
  req.session.userId = id;
  res.json({ ok: true, email: cleanEmail });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  const cleanEmail = String(email || "").trim().toLowerCase();
  const db = loadDB();
  const user = db.users.find((u) => u.email === cleanEmail);
  if (!user) return res.status(400).json({ error: "بيانات الدخول غلط" });
  const ok = await bcrypt.compare(password || "", user.passwordHash);
  if (!ok) return res.status(400).json({ error: "بيانات الدخول غلط" });
  req.session.userId = user.id;
  res.json({ ok: true, email: user.email });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  const db = loadDB();
  const user = db.users.find((u) => u.id === req.session.userId);
  if (!user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, email: user.email });
});

app.get("/api/state", requireAuth, (req, res) => {
  const db = loadDB();
  res.json(db.states[req.session.userId] || defaultState());
});

app.put("/api/state", requireAuth, (req, res) => {
  const db = loadDB();
  db.states[req.session.userId] = req.body;
  saveDB(db);
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.redirect(req.session.userId ? "/app.html" : "/login.html");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
