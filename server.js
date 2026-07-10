const express  = require("express");
const cors     = require("cors");
const path     = require("path");
const { Pool } = require("pg");

const app  = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
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
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  const res = await pool.query("SELECT value FROM meta WHERE key = 'weekId'");
  if (res.rows.length === 0) {
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

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── State ──────────────────────────────────────────────────────
app.get("/api/state", async (req, res) => {
  try {
    const weekRes = await pool.query("SELECT value FROM meta WHERE key = 'weekId'");
    const weekId  = weekRes.rows[0]?.value || getCurrentWeekId();
    const taskRes = await pool.query("SELECT * FROM tasks ORDER BY created_at ASC");
    const archRes = await pool.query("SELECT * FROM archive ORDER BY archived_at DESC");
    const contRes = await pool.query("SELECT * FROM contacts ORDER BY name ASC");
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
      contacts: contRes.rows
    });
  } catch(e) { console.error(e); res.status(500).json({ error: e.message }); }
});

// ── Tasks ──────────────────────────────────────────────────────
app.post("/api/tasks", async (req, res) => {
  const { id, title, task, status, notes, deadline, contact, done, week_id } = req.body;
  await pool.query(
    "INSERT INTO tasks (id,title,task,status,notes,deadline,contact,done,week_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    [id, title||"", task||"", status||"Not started", notes||"", deadline||"", contact||"", done||false, week_id||""]
  );
  res.json({ ok: true });
});

app.put("/api/tasks/:id", async (req, res) => {
  const { title, task, status, notes, deadline, contact, done } = req.body;
  await pool.query(
    "UPDATE tasks SET title=$1,task=$2,status=$3,notes=$4,deadline=$5,contact=$6,done=$7 WHERE id=$8",
    [title||"", task||"", status||"Not started", notes||"", deadline||"", contact||"", done||false, req.params.id]
  );
  res.json({ ok: true });
});

app.delete("/api/tasks/:id", async (req, res) => {
  await pool.query("DELETE FROM tasks WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

// ── New week ───────────────────────────────────────────────────
app.post("/api/newweek", async (req, res) => {
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

// ── Archive ────────────────────────────────────────────────────
app.put("/api/archive/:id", async (req, res) => {
  const { title, task, notes, contact } = req.body;
  await pool.query(
    "UPDATE archive SET title=$1,task=$2,notes=$3,contact=$4 WHERE id=$5",
    [title||"", task||"", notes||"", contact||"", req.params.id]
  );
  res.json({ ok: true });
});

// ── Contacts ───────────────────────────────────────────────────
app.post("/api/contacts", async (req, res) => {
  const { id, name, company, email, phone } = req.body;
  await pool.query(
    "INSERT INTO contacts (id,name,company,email,phone) VALUES ($1,$2,$3,$4,$5)",
    [id, name||"", company||"", email||"", phone||""]
  );
  res.json({ ok: true });
});

app.put("/api/contacts/:id", async (req, res) => {
  const { name, company, email, phone } = req.body;
  await pool.query(
    "UPDATE contacts SET name=$1,company=$2,email=$3,phone=$4 WHERE id=$5",
    [name||"", company||"", email||"", phone||"", req.params.id]
  );
  res.json({ ok: true });
});

app.delete("/api/contacts/:id", async (req, res) => {
  await pool.query("DELETE FROM contacts WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

// ── Frontend ───────────────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`Killam Tracker running on port ${PORT}`));
}).catch(err => { console.error("DB init failed:", err); process.exit(1); });
