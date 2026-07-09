const express = require("express");
const cors    = require("cors");
const path    = require("path");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;

const db = new Database(path.join(__dirname, "tracker.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT PRIMARY KEY,
    title       TEXT DEFAULT '',
    task        TEXT DEFAULT '',
    status      TEXT DEFAULT 'Not started',
    notes       TEXT DEFAULT '',
    deadline    TEXT DEFAULT '',
    contact     TEXT DEFAULT '',
    done        INTEGER DEFAULT 0,
    week_id     TEXT DEFAULT '',
    created_at  TEXT DEFAULT (datetime('now'))
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
    archived_at     TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
  );
`);

function getCurrentWeekId() {
  const d = new Date();
  const utc = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  utc.setUTCDate(utc.getUTCDate() + 4 - (utc.getUTCDay() || 7));
  const y = utc.getUTCFullYear();
  const start = new Date(Date.UTC(y, 0, 1));
  const w = Math.ceil((((utc - start) / 86400000) + 1) / 7);
  return `${y}-W${String(w).padStart(2, "0")}`;
}

const weekRow = db.prepare("SELECT value FROM meta WHERE key = 'weekId'").get();
if (!weekRow) {
  db.prepare("INSERT INTO meta (key, value) VALUES ('weekId', ?)").run(getCurrentWeekId());
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/state", (req, res) => {
  const weekId = db.prepare("SELECT value FROM meta WHERE key = 'weekId'").get()?.value || getCurrentWeekId();
  const tasks = db.prepare("SELECT * FROM tasks ORDER BY created_at ASC").all().map(row => ({
    id: row.id, title: row.title, task: row.task, status: row.status,
    notes: row.notes, deadline: row.deadline, contact: row.contact, done: row.done === 1
  }));
  const archive = db.prepare("SELECT * FROM archive ORDER BY archived_at DESC").all().map(row => ({
    id: row.id, title: row.title, task: row.task, status: row.status,
    notes: row.notes, deadline: row.deadline, contact: row.contact, weekCompleted: row.week_completed
  }));
  res.json({ weekId, tasks, archive });
});

app.post("/api/tasks", (req, res) => {
  const { id, title, task, status, notes, deadline, contact, done, week_id } = req.body;
  db.prepare("INSERT INTO tasks (id, title, task, status, notes, deadline, contact, done, week_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .run(id, title||"", task||"", status||"Not started", notes||"", deadline||"", contact||"", done?1:0, week_id||"");
  res.json({ ok: true });
});

app.put("/api/tasks/:id", (req, res) => {
  const { title, task, status, notes, deadline, contact, done } = req.body;
  db.prepare("UPDATE tasks SET title=?, task=?, status=?, notes=?, deadline=?, contact=?, done=? WHERE id=?")
    .run(title||"", task||"", status||"Not started", notes||"", deadline||"", contact||"", done?1:0, req.params.id);
  res.json({ ok: true });
});

app.delete("/api/tasks/:id", (req, res) => {
  db.prepare("DELETE FROM tasks WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.post("/api/newweek", (req, res) => {
  const currentWeekId = db.prepare("SELECT value FROM meta WHERE key='weekId'").get()?.value;
  const doneTasks = db.prepare("SELECT * FROM tasks WHERE done=1").all();
  const insertArchive = db.prepare("INSERT INTO archive (id, title, task, status, notes, deadline, contact, week_completed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
  const newWeekId = getCurrentWeekId();
  db.transaction(() => {
    doneTasks.forEach(t => insertArchive.run(t.id, t.title, t.task, t.status, t.notes, t.deadline, t.contact, currentWeekId));
    db.prepare("DELETE FROM tasks WHERE done=1").run();
    db.prepare("UPDATE meta SET value=? WHERE key='weekId'").run(newWeekId);
  })();
  res.json({ ok: true, newWeekId });
});

app.put("/api/archive/:id", (req, res) => {
  const { title, task, notes, contact } = req.body;
  db.prepare("UPDATE archive SET title=?, task=?, notes=?, contact=? WHERE id=?")
    .run(title||"", task||"", notes||"", contact||"", req.params.id);
  res.json({ ok: true });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => console.log(`Killam Tracker running on port ${PORT}`));
