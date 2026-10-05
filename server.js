const express   = require("express");
const cors      = require("cors");
const path      = require("path");
const bcrypt    = require("bcryptjs");
const jwt       = require("jsonwebtoken");
const { Pool }  = require("pg");
const crypto    = require("crypto");
const multer    = require("multer");
const {
  S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand,
  DeleteObjectCommand, ListObjectsV2Command
} = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "killam-dev-secret-change-in-production";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});


// ── Cloudflare R2 (S3-compatible) file storage ─────────────────
// Needs four env vars on Railway: R2_ACCOUNT_ID, R2_ACCESS_KEY_ID,
// R2_SECRET_ACCESS_KEY, R2_BUCKET. Without them the app still runs;
// attachment endpoints just return a clear "not configured" error.
const R2_BUCKET = process.env.R2_BUCKET;
const r2Enabled = !!(process.env.R2_ACCOUNT_ID && process.env.R2_ACCESS_KEY_ID &&
                     process.env.R2_SECRET_ACCESS_KEY && R2_BUCKET);
const r2 = r2Enabled ? new S3Client({
  region: "auto",
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId:     process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
  },
  // Newer AWS SDK versions add checksum headers by default; only send them when required.
  requestChecksumCalculation:  "WHEN_REQUIRED",
  responseChecksumValidation:  "WHEN_REQUIRED"
}) : null;
if (!r2Enabled) console.warn("R2 not configured — file attachments are disabled.");

const MAX_ATTACH_BYTES = 15 * 1024 * 1024; // 15 MB per file
const uploadAttachment = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_ATTACH_BYTES, files: 1 }
}).single("file");

// ── Allowed attachment types ───────────────────────────────────
// "disposition" is how browsers should treat the file when opened: PDFs display in a tab,
// Word files can't be displayed by browsers, so they download instead.
// To allow another format later (e.g. Excel): add an entry here, a check in detectFileType(),
// and the extension to KEY_RE below.
const FILE_TYPES = {
  pdf:  { mime: "application/pdf",     disposition: "inline" },
  docx: { mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", disposition: "attachment" },
  doc:  { mime: "application/msword",  disposition: "attachment" }
};

// Decide what a file really is from its CONTENTS, never from the name/type the browser claims.
function detectFileType(buf) {
  // PDF: begins with "%PDF-"
  if (buf.subarray(0, 5).toString("latin1") === "%PDF-") return "pdf";
  // .docx: a ZIP archive ("PK\x03\x04"). .xlsx, .pptx and plain .zip files are ZIPs too,
  // so also require Word's own parts inside.
  if (buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04 &&
      buf.includes("[Content_Types].xml") && buf.includes("word/")) return "docx";
  // .doc (old Word format): an "OLE" container. .xls/.ppt use the same container,
  // so also require the "WordDocument" stream name (stored as UTF-16 inside the file).
  if (buf.length > 8 && buf.subarray(0, 8).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) &&
      buf.includes(Buffer.from("WordDocument", "utf16le"))) return "doc";
  return null;
}

const ID_RE  = /^[A-Za-z0-9_-]{1,64}$/;
// Every stored object must look exactly like: projects/<projectId>/<uuid>.<pdf|docx|doc>
const KEY_RE = /^projects\/([A-Za-z0-9_-]{1,64})\/[0-9a-f-]{36}\.(?:pdf|docx|doc)$/;

function requireR2(req, res, next) {
  if (!r2Enabled) return res.status(503).json({ error: "File storage is not configured on the server yet." });
  next();
}

// Make a user-supplied filename safe to put in a Content-Disposition header.
// `ext` comes from the stored file's key (i.e. the verified type), so the download name
// always ends in the right extension even if the saved name was wrong or missing one.
function safeFilename(name, ext) {
  let n = String(name || "document")
    .replace(/[\u0000-\u001f\u007f"\\\/]/g, "")  // control chars, quotes, slashes
    .trim()
    .replace(/\.(?:pdf|docx?)$/i, "")            // drop a known extension; the right one is added back below
    .slice(0, 150)
    .trim();
  if (!n) n = "document";
  return `${n}.${ext}`;
}

// Delete every file stored under a project (used when the project is deleted).
async function deleteProjectFiles(projectId) {
  if (!r2Enabled || !ID_RE.test(projectId)) return;
  let token;
  do {
    const list = await r2.send(new ListObjectsV2Command({
      Bucket: R2_BUCKET, Prefix: `projects/${projectId}/`, ContinuationToken: token
    }));
    await Promise.all((list.Contents || []).map(o =>
      r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: o.Key }))
    ));
    token = list.IsTruncated ? list.NextContinuationToken : undefined;
  } while (token);
}

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
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS contacts   TEXT DEFAULT '[]';
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS priority   TEXT DEFAULT '';
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS last_opened_at TIMESTAMP DEFAULT NOW();
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

// Archive a single task immediately
app.post("/api/newweek-single", requireAuth, async (req, res) => {
  const { taskId, weekId } = req.body;
  const task = await pool.query("SELECT * FROM tasks WHERE id=$1", [taskId]);
  if(!task.rows.length) return res.json({ ok: true });
  const t = task.rows[0];
  await pool.query(
    "INSERT INTO archive (id,title,task,status,notes,deadline,contact,week_completed) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (id) DO NOTHING",
    [t.id, t.title, t.task, t.status, t.notes, t.deadline, t.contact, weekId]
  );
  await pool.query("DELETE FROM tasks WHERE id=$1", [taskId]);
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
  const { id, name, address, prospect, type, sf, price_per_sf, status, notes, contacts, priority } = req.body;
  await pool.query(
    "INSERT INTO projects (id,name,address,prospect,type,sf,price_per_sf,status,notes,contacts,priority) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    [id, name||"", address||"", prospect||"", type||"", sf||"", price_per_sf||"", status||"", notes||"", contacts||"[]", priority||""]
  );
  res.json({ ok: true });
});

app.put("/api/projects/:id", requireAuth, async (req, res) => {
  const { name, address, prospect, type, sf, price_per_sf, status, notes, contacts, priority } = req.body;
  await pool.query(
    "UPDATE projects SET name=$1,address=$2,prospect=$3,type=$4,sf=$5,price_per_sf=$6,status=$7,notes=$8,contacts=$9,priority=$10 WHERE id=$11",
    [name||"", address||"", prospect||"", type||"", sf||"", price_per_sf||"", status||"", notes||"", contacts||"[]", priority||"", req.params.id]
  );
  res.json({ ok: true });
});

app.patch("/api/projects/:id/priority", requireAuth, async (req, res) => {
  const { priority } = req.body;
  await pool.query("UPDATE projects SET priority=$1 WHERE id=$2", [priority||"", req.params.id]);
  res.json({ ok: true });
});

app.patch("/api/projects/:id/status", requireAuth, async (req, res) => {
  const { status } = req.body;
  await pool.query("UPDATE projects SET status=$1 WHERE id=$2", [status||"", req.params.id]);
  res.json({ ok: true });
});

// Mark a project as viewed — resets its "idle" clock for the staleness glow
app.patch("/api/projects/:id/opened", requireAuth, async (req, res) => {
  const result = await pool.query(
    "UPDATE projects SET last_opened_at=NOW() WHERE id=$1 RETURNING last_opened_at",
    [req.params.id]
  );
  res.json({ ok: true, last_opened_at: result.rows[0]?.last_opened_at });
});

app.delete("/api/projects/:id", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM projects WHERE id=$1", [req.params.id]);
  // Clean up the project's files in the background; don't fail the request if R2 hiccups.
  deleteProjectFiles(req.params.id).catch(e => console.error("R2 cleanup failed:", e.message));
  res.json({ ok: true });
});

// ── File attachments: PDF and Word (stored in R2, referenced from journal entries) ──
// Upload: multipart form, field name "file". Returns the storage key to save in the note.
app.post("/api/projects/:id/attachments", requireAuth, requireR2, (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: "Invalid project id" });
  uploadAttachment(req, res, async (err) => {
    if (err) {
      if (err.code === "LIMIT_FILE_SIZE")
        return res.status(413).json({ error: `File too large (max ${MAX_ATTACH_BYTES / 1024 / 1024} MB)` });
      return res.status(400).json({ error: err.message });
    }
    const f = req.file;
    if (!f) return res.status(400).json({ error: "No file received" });
    // Check the file's real contents, not just its name/type.
    const type = detectFileType(f.buffer);
    if (!type)
      return res.status(400).json({ error: "Only PDF and Word (.docx, .doc) files are allowed" });
    try {
      const key = `projects/${req.params.id}/${crypto.randomUUID()}.${type}`;
      await r2.send(new PutObjectCommand({
        Bucket: R2_BUCKET, Key: key, Body: f.buffer, ContentType: FILE_TYPES[type].mime
      }));
      res.json({ ok: true, key, size: f.size, type });
    } catch (e) {
      console.error("R2 upload failed:", e);
      res.status(500).json({ error: "Upload failed" });
    }
  });
});

// Open: returns a signed link that works for 5 minutes. The bucket itself stays private.
app.get("/api/attachments/url", requireAuth, requireR2, async (req, res) => {
  const key = String(req.query.key || "");
  if (!KEY_RE.test(key)) return res.status(400).json({ error: "Invalid file key" });
  const ext  = key.slice(key.lastIndexOf(".") + 1);   // "pdf" | "docx" | "doc" (KEY_RE guarantees it)
  const ft   = FILE_TYPES[ext];
  const name = safeFilename(req.query.name, ext);
  const ascii = name.replace(/[^\x20-\x7e]/g, "_");
  try {
    await r2.send(new HeadObjectCommand({ Bucket: R2_BUCKET, Key: key })); // exists?
  } catch (e) {
    return res.status(404).json({ error: "File not found" });
  }
  try {
    const url = await getSignedUrl(r2, new GetObjectCommand({
      Bucket: R2_BUCKET, Key: key,
      ResponseContentType: ft.mime,
      ResponseContentDisposition: `${ft.disposition}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`
    }), { expiresIn: 300 });
    res.json({ url });
  } catch (e) {
    console.error("Signing failed:", e);
    res.status(500).json({ error: "Could not create download link" });
  }
});

// Delete one file. The key must belong to the project in the URL.
app.delete("/api/projects/:id/attachments", requireAuth, requireR2, async (req, res) => {
  const key = String(req.query.key || "");
  const m = KEY_RE.exec(key);
  if (!m || m[1] !== req.params.id) return res.status(400).json({ error: "Invalid file key" });
  try {
    await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key }));
    res.json({ ok: true });
  } catch (e) {
    console.error("R2 delete failed:", e);
    res.status(500).json({ error: "Delete failed" });
  }
});

// ── Generate brief (proxies Anthropic API) ────────────────────
app.post("/api/generate-brief", requireAuth, async (req, res) => {
  const { prompt } = req.body;
  if(!prompt) return res.status(400).json({ error: "No prompt provided" });

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if(!apiKey) return res.status(500).json({ error: "ANTHROPIC_API_KEY not configured on server" });

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-6",
        max_tokens: 2000,
        messages: [{ role: "user", content: prompt }]
      })
    });
    const data = await response.json();
    if(!response.ok) return res.status(response.status).json({ error: data.error?.message || "Anthropic API error" });
    const text = (data.content||[]).map(c=>c.text||"").join("").trim();
    res.json({ text });
  } catch(e) {
    console.error("Brief generation error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ── Change password ────────────────────────────────────────────
app.post("/api/auth/change-password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if(!currentPassword || !newPassword) return res.status(400).json({ error: "All fields required" });
  if(newPassword.length < 6) return res.status(400).json({ error: "New password must be at least 6 characters" });
  try {
    const result = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
    if(!result.rows.length) return res.status(404).json({ error: "User not found" });
    const user = result.rows[0];
    const match = await bcrypt.compare(currentPassword, user.password);
    if(!match) return res.status(401).json({ error: "Current password is incorrect" });
    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, req.user.id]);
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`Killam Tracker running on port ${PORT}`));
}).catch(err => { console.error("DB init failed:", err); process.exit(1); });
