const express   = require("express");
const cors      = require("cors");
const path      = require("path");
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const { Pool }  = require("pg");

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "killam-dev-secret-change-in-production";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── DB init ────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         TEXT PRIMARY KEY,
      username   TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS tasks (
      id          TEXT PRIMARY KEY,
      title       TEXT DEFAULT '',
      task        TEXT DEFAULT '',
      status      TEXT DEFAULT 'Not started',
      notes       TEXT DEFAULT '',
      deadline    TEXT DEFAULT '',
      contact     TEXT DEFAULT '',
      done        BOOLEAN DEFAULT FALSE,
      week_id     TEXT DEFAULT '',
      created_at  TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS archive (
      id              TEXT PRIMARY KEY,
      title           TEXT DEFAULT '',
      task            TEXT DEFAULT '',
      status          TEXT DEFAULT '',
      notes           TEXT DEFAULT '',
      deadline        TEXT DEFAULT '',
      contact         TEXT DEFAULT '',
      week_completed  TEXT DEFAULT '',
      archived_at     TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS meta (
      key   TEXT PRIMARY KEY,
      value TEXT
    );
    CREATE TABLE IF NOT EXISTS contacts (
      id         TEXT PRIMARY KEY,
      name       TEXT DEFAULT '',
      company    TEXT DEFAULT '',
      email      TEXT DEFAULT '',
      phone      TEXT DEFAULT '',
      notes      TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS projects (
      id           TEXT PRIMARY KEY,
      name         TEXT DEFAULT '',
      address      TEXT DEFAULT '',
      prospect     TEXT DEFAULT '',
      type         TEXT DEFAULT '',
      sf           TEXT DEFAULT '',
      price_per_sf TEXT DEFAULT '',
      status       TEXT DEFAULT '',
      notes        TEXT DEFAULT '',
      created_at   TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE contacts  ADD COLUMN IF NOT EXISTS notes      TEXT DEFAULT '';
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS notes      TEXT DEFAULT '';
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS sf         TEXT DEFAULT '';
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS price_per_sf TEXT DEFAULT '';
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS status     TEXT DEFAULT '';
  `);

  const weekRow = await pool.query("SELECT value FROM meta WHERE key = 'weekId'");
  if (weekRow.rows.length === 0) {
    await pool.query("INSERT INTO meta (key, value) VALUES ('weekId', $1)", [getCurrentWeekId()]);
  }
}

function getCurrentWeekId() {
  const d = new Date();
  const utc = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  utc.setUTCDate(utc.getUTCDate() + 4 - (utc.getUTCDay() || 7));
  const y = utc.getUTCFullYear();
  const start = new Date(Date.UTC(y, 0, 1));
  const w = Math.ceil((((utc - start) / 86400000) + 1) / 7);
  return `${y}-W${String(w).padStart(2, "0")}`;
}

// ── Middleware ─────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── Auth middleware ────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user = decoded;
    next();
  } catch(e) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ── Auth routes (public) ───────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  try {
    const existing = await pool.query("SELECT id FROM users WHERE username=$1", [username]);
    if (existing.rows.length > 0) return res.status(400).json({ error: "Username already exists" });
    const hash = await bcrypt.hash(password, 12);
    const id = Math.random().toString(36).slice(2,10);
    await pool.query("INSERT INTO users (id,username,password) VALUES ($1,$2,$3)", [id, username, hash]);
    const token = jwt.sign({ id, username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, username });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  try {
    const result = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid username or password" });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid username or password" });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, username: user.username });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/auth/check-users", async (req, res) => {
  const result = await pool.query("SELECT COUNT(*) FROM users");
  res.json({ hasUsers: parseInt(result.rows[0].count) > 0 });
});

// ── Protected API routes ───────────────────────────────────────
app.get("/api/state", requireAuth, async (req, res) => {
  try {
    const weekRes = await pool.query("SELECT value FROM meta WHERE key = 'weekId'");
    const weekId  = weekRes.rows[0]?.value || getCurrentWeekId();
    const taskRes = await pool.query("SELECT * FROM tasks ORDER BY created_at ASC");
    const archRes = await pool.query("SELECT * FROM archive ORDER BY archived_at DESC");
    const contRes = await pool.query("SELECT * FROM contacts ORDER BY name ASC");
    const projRes = await pool.query("SELECT * FROM projects ORDER BY name ASC");
    res.json({
      weekId,
      tasks: taskRes.rows.map(r => ({
        id: r.id, title: r.title, task: r.task, status: r.status,
        notes: r.notes, deadline: r.deadline, contact: r.contact, done: r.done
      })),
      archive: archRes.rows.map(r => ({
        id: r.id, title: r.title, task: r.task, status: r.status,
        notes: r.notes, deadline: r.deadline, contact: r.contact, weekCompleted: r.week_completed
      })),
      contacts: contRes.rows,
      projects: projRes.rows
    });
  } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});

app.post("/api/tasks", requireAuth, async (req, res) => {
  const { id, title, task, status, notes, deadline, contact, done, week_id } = req.body;
  await pool.query(
    "INSERT INTO tasks (id,title,task,status,notes,deadline,contact,done,week_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    [id, title||"", task||"", status||"Not started", notes||"", deadline||"", contact||"", done||false, week_id||""]
  );
  res.json({ ok: true });
});

app.put("/api/tasks/:id", requireAuth, async (req, res) => {
  const { title, task, status, notes, deadline, contact, done } = req.body;
  await pool.query(
    "UPDATE tasks SET title=$1,task=$2,status=$3,notes=$4,deadline=$5,contact=$6,done=$7 WHERE id=$8",
    [title||"", task||"", status||"Not started", notes||"", deadline||"", contact||"", done||false, req.params.id]
  );
  res.json({ ok: true });
});

app.delete("/api/tasks/:id", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM tasks WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

app.post("/api/newweek", requireAuth, async (req, res) => {
  const weekRes = await pool.query("SELECT value FROM meta WHERE key='weekId'");
  const currentWeekId = weekRes.rows[0]?.value;
  const doneTasks = await pool.query("SELECT * FROM tasks WHERE done=TRUE");
  for (const t of doneTasks.rows) {
    await pool.query(
      "INSERT INTO archive (id,title,task,status,notes,deadline,contact,week_completed) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
      [t.id, t.title, t.task, t.status, t.notes, t.deadline, t.contact, currentWeekId]
    );
  }
  await pool.query("DELETE FROM tasks WHERE done=TRUE");
  const newWeekId = getCurrentWeekId();
  await pool.query("UPDATE meta SET value=$1 WHERE key='weekId'", [newWeekId]);
  res.json({ ok: true, newWeekId });
});

app.put("/api/archive/:id", requireAuth, async (req, res) => {
  const { title, task, notes, contact } = req.body;
  await pool.query(
    "UPDATE archive SET title=$1,task=$2,notes=$3,contact=$4 WHERE id=$5",
    [title||"", task||"", notes||"", contact||"", req.params.id]
  );
  res.json({ ok: true });
});

app.post("/api/contacts", requireAuth, async (req, res) => {
  const { id, name, company, email, phone, notes } = req.body;
  await pool.query(
    "INSERT INTO contacts (id,name,company,email,phone,notes) VALUES ($1,$2,$3,$4,$5,$6)",
    [id, name||"", company||"", email||"", phone||"", notes||""]
  );
  res.json({ ok: true });
});

app.put("/api/contacts/:id", requireAuth, async (req, res) => {
  const { name, company, email, phone, notes } = req.body;
  await pool.query(
    "UPDATE contacts SET name=$1,company=$2,email=$3,phone=$4,notes=$5 WHERE id=$6",
    [name||"", company||"", email||"", phone||"", notes||"", req.params.id]
  );
  res.json({ ok: true });
});

app.delete("/api/contacts/:id", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM contacts WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

app.post("/api/projects", requireAuth, async (req, res) => {
  const { id, name, address, prospect, type, sf, price_per_sf, status, notes } = req.body;
  await pool.query(
    "INSERT INTO projects (id,name,address,prospect,type,sf,price_per_sf,status,notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    [id, name||"", address||"", prospect||"", type||"", sf||"", price_per_sf||"", status||"", notes||""]
  );
  res.json({ ok: true });
});

app.put("/api/projects/:id", requireAuth, async (req, res) => {
  const { name, address, prospect, type, sf, price_per_sf, status, notes } = req.body;
  await pool.query(
    "UPDATE projects SET name=$1,address=$2,prospect=$3,type=$4,sf=$5,price_per_sf=$6,status=$7,notes=$8 WHERE id=$9",
    [name||"", address||"", prospect||"", type||"", sf||"", price_per_sf||"", status||"", notes||"", req.params.id]
  );
  res.json({ ok: true });
});

app.patch("/api/projects/:id/status", requireAuth, async (req, res) => {
  const { status } = req.body;
  await pool.query("UPDATE projects SET status=$1 WHERE id=$2", [status||"", req.params.id]);
  res.json({ ok: true });
});

app.delete("/api/projects/:id", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM projects WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`Killam Tracker running on port ${PORT}`));
}).catch(err => { console.error("DB init failed:", err); process.exit(1); });
