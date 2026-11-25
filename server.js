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
app.set("trust proxy", 1);   // Railway sits behind a proxy; needed so invite links use https
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

// A project's own files (brochures etc., separate from journal-note attachments) are stored as a
// JSON list of {key, name, size} in projects.files. Check the list before saving it: it must be an
// array, and every key must be a real storage key belonging to THIS project.
// Returns the cleaned JSON string, or null if the list is invalid.
const MAX_PROJECT_FILES = 100;
function cleanProjectFiles(projectId, raw) {
  let arr = raw;
  if (typeof raw === "string") {
    try { arr = JSON.parse(raw); } catch (e) { return null; }
  }
  if (!Array.isArray(arr) || arr.length > MAX_PROJECT_FILES) return null;
  const out = [];
  for (const f of arr) {
    if (!f || typeof f.key !== "string") return null;
    const m = KEY_RE.exec(f.key);
    if (!m || m[1] !== projectId) return null;
    out.push({ key: f.key, name: String(f.name || "file").slice(0, 200), size: Number(f.size) || 0 });
  }
  return JSON.stringify(out);
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
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS files      TEXT DEFAULT '[]';

    -- Multi-user: who a user is, what they may do, and who owns each record
    ALTER TABLE users     ADD COLUMN IF NOT EXISTS theme      TEXT DEFAULT 'standard';
    ALTER TABLE users     ADD COLUMN IF NOT EXISTS email      TEXT;
    ALTER TABLE users     ADD COLUMN IF NOT EXISTS name       TEXT DEFAULT '';
    ALTER TABLE users     ADD COLUMN IF NOT EXISTS role       TEXT DEFAULT 'agent';
    ALTER TABLE users     ADD COLUMN IF NOT EXISTS active     BOOLEAN DEFAULT TRUE;
    ALTER TABLE users     ADD COLUMN IF NOT EXISTS invite_hash    TEXT;
    ALTER TABLE users     ADD COLUMN IF NOT EXISTS invite_expires TIMESTAMP;
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS owner_id   TEXT;
    ALTER TABLE tasks     ADD COLUMN IF NOT EXISTS owner_id   TEXT;
    ALTER TABLE archive   ADD COLUMN IF NOT EXISTS owner_id   TEXT;
    -- Supervisor layer: notes live in their own column so an agent saving their own journal can never overwrite
    -- them; supervisor-created tasks are flagged and remember who made them.
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS supervisor_notes TEXT DEFAULT '[]';
    -- "Unseen" flag: set when a supervisor assigns a project or leaves a note/task on it; cleared when its owner opens it.
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS sup_flag_at   TIMESTAMP;
    ALTER TABLE projects  ADD COLUMN IF NOT EXISTS sup_flag_text TEXT;
    ALTER TABLE tasks     ADD COLUMN IF NOT EXISTS supervisor BOOLEAN DEFAULT FALSE;
    ALTER TABLE tasks     ADD COLUMN IF NOT EXISTS created_by TEXT;
    ALTER TABLE tasks     ADD COLUMN IF NOT EXISTS created_by_name TEXT DEFAULT '';
    -- Lease Admin: a task can be assigned to the administrator from a project. Such a task belongs to her board
    -- (owner_id = her), remembers its project, who assigned it, and who finished it and when.
    ALTER TABLE tasks     ADD COLUMN IF NOT EXISTS project_id TEXT;
    ALTER TABLE tasks     ADD COLUMN IF NOT EXISTS assigned   BOOLEAN DEFAULT FALSE;
    ALTER TABLE tasks     ADD COLUMN IF NOT EXISTS completed_by_name TEXT DEFAULT '';
    ALTER TABLE tasks     ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP;
    ALTER TABLE archive   ADD COLUMN IF NOT EXISTS project_id TEXT;
    ALTER TABLE archive   ADD COLUMN IF NOT EXISTS created_by_name TEXT DEFAULT '';
    ALTER TABLE archive   ADD COLUMN IF NOT EXISTS completed_by_name TEXT DEFAULT '';
    ALTER TABLE archive   ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP;
    -- Leads: a contact can carry a Lead tag and be handed to an agent, who turns it into a project.
    ALTER TABLE contacts  ADD COLUMN IF NOT EXISTS is_lead    BOOLEAN DEFAULT FALSE;
    ALTER TABLE contacts  ADD COLUMN IF NOT EXISTS lead_to    TEXT;
    ALTER TABLE contacts  ADD COLUMN IF NOT EXISTS lead_by    TEXT;
    ALTER TABLE contacts  ADD COLUMN IF NOT EXISTS lead_by_name TEXT DEFAULT '';
    ALTER TABLE contacts  ADD COLUMN IF NOT EXISTS lead_at    TIMESTAMP;
    ALTER TABLE contacts  ADD COLUMN IF NOT EXISTS lead_project_id TEXT;
    CREATE INDEX IF NOT EXISTS tasks_project ON tasks (project_id);
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower ON users (lower(email)) WHERE email IS NOT NULL;
    CREATE INDEX IF NOT EXISTS projects_owner ON projects (owner_id);
    CREATE INDEX IF NOT EXISTS tasks_owner    ON tasks (owner_id);
    CREATE INDEX IF NOT EXISTS archive_owner  ON archive (owner_id);
  `);

  // One-time (and safe to repeat) migration: make sure there is an Owner, and that every
  // existing project/task/archive row belongs to someone. Anything unassigned goes to the Owner.
  const hasOwner = await pool.query("SELECT id FROM users WHERE role='owner' LIMIT 1");
  if (hasOwner.rows.length === 0) {
    const want = (process.env.OWNER_EMAIL || "").trim().toLowerCase();
    let pick = want
      ? await pool.query("SELECT id FROM users WHERE lower(username)=$1 OR lower(email)=$1 LIMIT 1", [want])
      : { rows: [] };
    if (!pick.rows.length) pick = await pool.query("SELECT id FROM users ORDER BY created_at ASC, id ASC LIMIT 1");
    if (pick.rows.length) {
      await pool.query("UPDATE users SET role='owner', active=TRUE WHERE id=$1", [pick.rows[0].id]);
      console.log("Migration: user", pick.rows[0].id, "is now the Owner");
    }
  }
  // Fill in email from the login name when the login name is an email address.
  await pool.query("UPDATE users SET email=lower(username) WHERE email IS NULL AND username LIKE '%@%' AND NOT EXISTS (SELECT 1 FROM users u2 WHERE lower(u2.email)=lower(users.username))");
  const ownerRow = await pool.query("SELECT id FROM users WHERE role='owner' LIMIT 1");
  if (ownerRow.rows.length) {
    const oid = ownerRow.rows[0].id;
    await pool.query("UPDATE projects SET owner_id=$1 WHERE owner_id IS NULL", [oid]);
    await pool.query("UPDATE tasks    SET owner_id=$1 WHERE owner_id IS NULL", [oid]);
    await pool.query("UPDATE archive  SET owner_id=$1 WHERE owner_id IS NULL", [oid]);
  }

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
// The token only proves WHO someone is. Their role and whether their account is still active are
// looked up from the database on every request, so deactivating a user or changing a role takes
// effect immediately instead of waiting for their 7-day token to expire.
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  let decoded;
  try { decoded = jwt.verify(auth.slice(7), JWT_SECRET); }
  catch(e) { return res.status(401).json({ error: "Invalid or expired token" }); }
  try {
    const r = await pool.query("SELECT id, username, email, name, role, active, theme FROM users WHERE id=$1", [decoded.id]);
    const u = r.rows[0];
    if (!u || u.active === false) return res.status(401).json({ error: "Account not found or deactivated" });
    req.user = u;
    next();
  } catch(e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
}

// Use after requireAuth: only let these roles through.
const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: "You don't have permission to do that" });

// Who may touch a project?
//   read  : the Owner and Supervisors can read every project; an Agent only their own
//   write : the Owner can change every project; everyone else only their own
//   A Lease Admin owns nothing: she can read only a project she has been given a task on (see canReadProjectDb).
const canReadProject  = (u, p) => u.role === "owner" || u.role === "supervisor" || p.owner_id === u.id;
const canWriteProject = (u, p) => u.role === "owner" || p.owner_id === u.id;

// Same as canReadProject, plus the Lease Admin rule (needs a look at the tasks table, so it is async).
async function canReadProjectDb(u, p) {
  if (u.role !== "admin") return canReadProject(u, p);
  const r = await pool.query("SELECT 1 FROM tasks WHERE owner_id=$1 AND project_id=$2 AND assigned=TRUE LIMIT 1", [u.id, p.id]);
  return r.rows.length > 0;
}

async function getProjectOwner(projectId) {
  const r = await pool.query("SELECT id, owner_id FROM projects WHERE id=$1", [projectId]);
  return r.rows[0] || null;
}

// Express middleware factory: loads :id, answers 404/403 itself, otherwise sets req.project.
// An agent asking about someone else's project gets "not found" so they can't even tell it exists.
const projectAccess = (mode) => async (req, res, next) => {
  try {
    const p = await getProjectOwner(req.params.id);
    if (!p || !(await canReadProjectDb(req.user, p))) return res.status(404).json({ error: "Project not found" });
    if (mode === "write" && !canWriteProject(req.user, p)) return res.status(403).json({ error: "You don't have permission to change this project" });
    req.project = p;
    next();
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
};

// For "UPDATE/DELETE ... WHERE id=$1 AND ($2 OR owner_id=$3)": the Owner may touch any row, others only their own.
const scopeParams = (u) => [u.role === "owner", u.id];

const ROLES = ["owner", "supervisor", "agent", "admin"];
const ROLE_LABEL = { owner: "Owner", supervisor: "Supervisor", agent: "Agent", admin: "Lease Admin" };
const ROLE_ORDER_SQL = "CASE role WHEN 'owner' THEN 0 WHEN 'supervisor' THEN 1 WHEN 'agent' THEN 2 ELSE 3 END";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
// Colour schemes. "starwars" is an Owner-only perk, so it is also filtered out when we read it back.
const THEMES = ["standard", "bright", "dark", "starwars"];
const themeFor = (u) => (THEMES.includes(u.theme) && (u.theme !== "starwars" || u.role === "owner")) ? u.theme : "standard";
const publicUser = (u) => ({ id: u.id, username: u.username, email: u.email, name: u.name || "", role: u.role, active: u.active !== false, theme: themeFor(u) });
const NO_PASSWORD = "!";   // not a valid bcrypt hash, so nobody can ever sign in with it (pending invites)

// ── Auth routes (public) ───────────────────────────────────────
// Public sign-up exists only to create the very first account (the Owner). After that, people
// join by invitation (see /api/users/invite).
app.post("/api/auth/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  try {
    const count = await pool.query("SELECT COUNT(*) FROM users");
    if (parseInt(count.rows[0].count) > 0)
      return res.status(403).json({ error: "Sign-up is by invitation only. Ask the owner for an invite." });
    const hash = await bcrypt.hash(password, 12);
    const id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
    const email = String(username).includes("@") ? String(username).trim().toLowerCase() : null;
    await pool.query("INSERT INTO users (id,username,password,email,role,active) VALUES ($1,$2,$3,$4,'owner',TRUE)",
      [id, String(username).trim(), hash, email]);
    const token = jwt.sign({ id, username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, username, role: "owner", id });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error: "Could not create account" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });
  try {
    const who = String(username).trim().toLowerCase();
    const result = await pool.query("SELECT * FROM users WHERE lower(username)=$1 OR lower(email)=$1 ORDER BY (lower(username)=$1) DESC LIMIT 1", [who]);
    if (result.rows.length === 0) return res.status(401).json({ error: "Invalid username or password" });
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid username or password" });
    if (user.active === false) return res.status(403).json({ error: "This account has been deactivated. Contact the owner." });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, username: user.username, role: user.role, id: user.id, name: user.name || "" });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/auth/check-users", async (req, res) => {
  const result = await pool.query("SELECT COUNT(*) FROM users");
  res.json({ hasUsers: parseInt(result.rows[0].count) > 0 });
});

// Invitation / password-setup links. A link carries a random token; only its SHA-256 hash is stored,
// so a copy of the database can't be used to sign in as someone.
app.get("/api/auth/invite/:token", async (req, res) => {
  try {
    const r = await pool.query(
      "SELECT name, email, password FROM users WHERE invite_hash=$1 AND invite_expires > NOW() AND active=TRUE",
      [sha256(String(req.params.token))]);
    if (!r.rows.length) return res.status(404).json({ error: "This link is invalid or has expired. Ask the owner for a new one." });
    res.json({ name: r.rows[0].name || "", email: r.rows[0].email || "", isNew: r.rows[0].password === NO_PASSWORD });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/auth/accept-invite", async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: "Token and password required" });
  if (String(password).length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  try {
    const hash = await bcrypt.hash(String(password), 12);
    // One atomic statement: the link works exactly once.
    const r = await pool.query(
      "UPDATE users SET password=$1, invite_hash=NULL, invite_expires=NULL WHERE invite_hash=$2 AND invite_expires > NOW() AND active=TRUE RETURNING id, username, role, name",
      [hash, sha256(String(token))]);
    if (!r.rows.length) return res.status(404).json({ error: "This link is invalid or has expired. Ask the owner for a new one." });
    const u = r.rows[0];
    const jwtToken = jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token: jwtToken, username: u.username, role: u.role, id: u.id, name: u.name || "" });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// ── Who am I ───────────────────────────────────────────────────
app.get("/api/me", requireAuth, (req, res) => res.json(publicUser(req.user)));

// Each person picks their own colour scheme; it is stored on their account so it follows them to any device.
app.put("/api/me/theme", requireAuth, async (req, res) => {
  const theme = String((req.body || {}).theme || "");
  if (!THEMES.includes(theme)) return res.status(400).json({ error: "Unknown colour scheme" });
  if (theme === "starwars" && req.user.role !== "owner") return res.status(403).json({ error: "That scheme is only available to the Owner" });
  try {
    await pool.query("UPDATE users SET theme=$1 WHERE id=$2", [theme, req.user.id]);
    res.json({ ok: true, theme });
  } catch (e) { console.error(e); res.status(500).json({ error: "Could not save" }); }
});

// ── Team management ────────────────────────────────────────────
// Owner and Supervisors can see the team list (needed to pick an agent to review);
// only the Owner can invite, change roles, or deactivate.
app.get("/api/users", requireAuth, requireRole("owner", "supervisor"), async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT u.id, u.username, u.email, u.name, u.role, u.active,
             (u.invite_hash IS NOT NULL AND u.invite_expires > NOW()) AS has_link,
             (u.password = $1) AS pending,
             (SELECT COUNT(*) FROM projects p WHERE p.owner_id = u.id)::int AS project_count
        FROM users u
       ORDER BY CASE u.role WHEN 'owner' THEN 0 WHEN 'supervisor' THEN 1 WHEN 'agent' THEN 2 ELSE 3 END, lower(u.name), lower(u.username)`,
      [NO_PASSWORD]);
    res.json({ users: r.rows.map(u => ({
      id: u.id, username: u.username, email: u.email, name: u.name || "", role: u.role,
      active: u.active !== false, pending: u.pending, projectCount: u.project_count
    })) });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

function makeLink(req, token) {
  const base = (process.env.APP_URL || `${req.protocol}://${req.get("host")}`).replace(/\/+$/, "");
  return `${base}/?invite=${token}`;
}
async function issueLink(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await pool.query("UPDATE users SET invite_hash=$1, invite_expires=NOW() + INTERVAL '7 days' WHERE id=$2", [sha256(token), userId]);
  return token;
}

app.post("/api/users/invite", requireAuth, requireRole("owner"), async (req, res) => {
  const name  = String(req.body.name || "").trim().slice(0, 100);
  const email = String(req.body.email || "").trim().toLowerCase();
  const role  = String(req.body.role || "");
  if (!name) return res.status(400).json({ error: "Name is required" });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: "Enter a valid email address" });
  if (!["supervisor", "agent", "admin"].includes(role)) return res.status(400).json({ error: "Role must be Supervisor, Agent or Lease Admin" });
  try {
    const dup = await pool.query("SELECT 1 FROM users WHERE lower(email)=$1 OR lower(username)=$1", [email]);
    if (dup.rows.length) return res.status(409).json({ error: "Someone with that email already exists" });
    const id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
    await pool.query("INSERT INTO users (id,username,password,email,name,role,active) VALUES ($1,$2,$3,$4,$5,$6,TRUE)",
      [id, email, NO_PASSWORD, email, name, role]);
    const token = await issueLink(id);
    res.json({ ok: true, user: { id, username: email, email, name, role, active: true, pending: true, projectCount: 0 }, inviteLink: makeLink(req, token) });
  } catch(e) { console.error(e); res.status(500).json({ error: "Could not create invitation" }); }
});

// New sign-in link for an existing person: re-sends a lapsed invite, or lets them set a new password.
app.post("/api/users/:id/link", requireAuth, requireRole("owner"), async (req, res) => {
  try {
    const r = await pool.query("SELECT id, active FROM users WHERE id=$1", [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: "User not found" });
    if (r.rows[0].active === false) return res.status(400).json({ error: "Reactivate this user first" });
    const token = await issueLink(req.params.id);
    res.json({ ok: true, inviteLink: makeLink(req, token) });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.patch("/api/users/:id", requireAuth, requireRole("owner"), async (req, res) => {
  const client = await pool.connect();
  try {
    const r = await client.query("SELECT * FROM users WHERE id=$1", [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: "User not found" });
    const target = r.rows[0];
    const { name, role, active, email } = req.body;
    const isOwnerAccount = target.role === "owner";
    if (role !== undefined) {
      if (!["supervisor", "agent", "admin"].includes(role)) return res.status(400).json({ error: "Role must be Supervisor, Agent or Lease Admin" });
      if (isOwnerAccount) return res.status(400).json({ error: "The owner's role can't be changed" });
      if (role === "admin") {
        const held = await client.query("SELECT COUNT(*)::int AS n FROM projects WHERE owner_id=$1", [req.params.id]);
        if (held.rows[0].n > 0) return res.status(400).json({ error: "This person still holds projects. Hand them off first; a Lease Admin can't own projects." });
      }
    }
    if (active === false && isOwnerAccount) return res.status(400).json({ error: "The owner can't be deactivated" });
    let newName = null, newEmail = null;
    if (name !== undefined) {
      newName = String(name).trim().slice(0, 100);
      if (!newName && !isOwnerAccount) return res.status(400).json({ error: "Name can't be empty" });
    }
    if (email !== undefined) {
      newEmail = String(email).trim().toLowerCase();
      if (!EMAIL_RE.test(newEmail)) return res.status(400).json({ error: "Enter a valid email address" });
      const dup = await client.query("SELECT 1 FROM users WHERE id<>$2 AND (lower(email)=$1 OR lower(username)=$1)", [newEmail, req.params.id]);
      if (dup.rows.length) return res.status(409).json({ error: "Someone else already uses that email" });
    }
    await client.query("BEGIN");
    await client.query(
      "UPDATE users SET name=COALESCE($1,name), role=COALESCE($2,role), active=COALESCE($3,active) WHERE id=$4",
      [newName, role === undefined ? null : role, active === undefined ? null : !!active, req.params.id]);
    if (newEmail !== null) {
      // The sign-in name follows the email when it was the email (invited people); a custom username is left alone.
      const followsEmail = String(target.username).toLowerCase() === String(target.email || "").toLowerCase();
      await client.query("UPDATE users SET email=$1, username=CASE WHEN $3 THEN $1 ELSE username END WHERE id=$2", [newEmail, req.params.id, followsEmail]);
    }
    // Keep the author label on supervisor notes and admin tasks in step with a corrected name.
    if (newName) {
      const label = newName || target.username;
      await client.query("UPDATE tasks SET created_by_name=$1 WHERE created_by=$2", [label, req.params.id]);
      const ps = await client.query("SELECT id, supervisor_notes FROM projects WHERE supervisor_notes LIKE $1", ['%"authorId":' + JSON.stringify(req.params.id) + '%']);
      for (const p of ps.rows) {
        let list = []; try { list = JSON.parse(p.supervisor_notes); } catch (e) { continue; }
        let changed = false;
        list.forEach(n => { if (n.authorId === req.params.id) { n.authorName = label; changed = true; } });
        if (changed) await client.query("UPDATE projects SET supervisor_notes=$1 WHERE id=$2", [JSON.stringify(list), p.id]);
      }
    }
    await client.query("COMMIT");
    res.json({ ok: true });
  } catch(e) {
    await client.query("ROLLBACK").catch(() => {});
    if (e.code === "23505") return res.status(409).json({ error: "Someone else already uses that email" });
    console.error(e); res.status(500).json({ error: "Server error" });
  } finally { client.release(); }
});

// ── Protected API routes ───────────────────────────────────────
// Each person's board is their own data. The Owner and Supervisors may look at another person's
// board read-only with ?as=<userId>. Contacts are one shared directory for everyone.
const weekKey = (userId) => `weekId:${userId}`;
async function getWeekId(userId) {
  const r = await pool.query("SELECT value FROM meta WHERE key=$1 OR key='weekId' ORDER BY (key='weekId') ASC LIMIT 1", [weekKey(userId)]);
  return r.rows[0]?.value || getCurrentWeekId();
}

const taskShape = (r) => ({
  id: r.id, title: r.title, task: r.task, status: r.status,
  notes: r.notes, deadline: r.deadline, contact: r.contact, done: r.done,
  supervisor: r.supervisor === true, createdBy: r.created_by || null, createdByName: r.created_by_name || "",
  assigned: r.assigned === true, projectId: r.project_id || null, completedByName: r.completed_by_name || ""
});

app.get("/api/state", requireAuth, async (req, res) => {
  try {
    let target = req.user;
    const as = req.query.as ? String(req.query.as) : "";
    if (as && as !== req.user.id) {
      if (!["owner", "supervisor"].includes(req.user.role)) return res.status(403).json({ error: "You don't have permission to do that" });
      const t = await pool.query("SELECT id, username, email, name, role, active FROM users WHERE id=$1", [as]);
      if (!t.rows.length) return res.status(404).json({ error: "User not found" });
      target = t.rows[0];
    }
    const isAdminBoard = target.role === "admin";
    const weekId  = await getWeekId(target.id);
    const taskRes = await pool.query("SELECT * FROM tasks WHERE owner_id=$1 ORDER BY created_at ASC", [target.id]);
    const archRes = await pool.query("SELECT * FROM archive WHERE owner_id=$1 ORDER BY archived_at DESC", [target.id]);
    const contRes = await pool.query(
      "SELECT c.*, COALESCE(NULLIF(u.name,''), u.username) AS lead_to_name, u.active AS lead_to_active FROM contacts c LEFT JOIN users u ON u.id=c.lead_to ORDER BY c.name ASC");
    // Who a lead can be handed to (only offered to the people allowed to hand them out).
    let leadTargets = [];
    if (["owner", "supervisor", "admin"].includes(req.user.role)) {
      const lt = await pool.query("SELECT id, name, username, role FROM users WHERE active=TRUE AND password <> $1 AND role IN ('agent','supervisor') ORDER BY lower(name), lower(username)", [NO_PASSWORD]);
      leadTargets = lt.rows.map(u => ({ id: u.id, name: u.name || u.username, role: u.role }));
    }
    // A Lease Admin's board holds only the projects she currently has an unfinished task on, and never the
    // supervisor-only layer. Everyone else sees the projects they hold.
    let projRows;
    if (isAdminBoard) {
      const pr = await pool.query(
        "SELECT * FROM projects WHERE id IN (SELECT project_id FROM tasks WHERE owner_id=$1 AND assigned=TRUE AND done=FALSE AND project_id IS NOT NULL) ORDER BY name ASC", [target.id]);
      // (A supervisor reviewing her board still sees everything; only she is kept out of the supervisor layer.)
      projRows = req.user.role === "admin" ? pr.rows.map(p => ({ ...p, supervisor_notes: "[]", sup_flag_at: null, sup_flag_text: null })) : pr.rows;
    } else {
      projRows = (await pool.query("SELECT * FROM projects WHERE owner_id=$1 ORDER BY name ASC", [target.id])).rows;
    }
    // Tasks handed to a Lease Admin from the projects on this board, and who can be asked.
    let assignedTasks = [], admins = [];
    if (!isAdminBoard) {
      if (projRows.length) {
        const at = await pool.query(
          `SELECT t.*, u.name AS assignee_name, u.username AS assignee_username FROM tasks t LEFT JOIN users u ON u.id=t.owner_id
           WHERE t.assigned=TRUE AND t.project_id = ANY($1) ORDER BY t.created_at ASC`, [projRows.map(p => p.id)]);
        assignedTasks = at.rows.map(r => ({ ...taskShape(r), assigneeId: r.owner_id, assigneeName: r.assignee_name || r.assignee_username || "" }));
        // Finished ones the assignee has already filed away stay visible on the project as history.
        const done = await pool.query(
          `SELECT a.*, u.name AS assignee_name, u.username AS assignee_username FROM archive a LEFT JOIN users u ON u.id=a.owner_id
           WHERE a.project_id = ANY($1) ORDER BY COALESCE(a.completed_at, a.archived_at) DESC LIMIT 200`, [projRows.map(p => p.id)]);
        assignedTasks = assignedTasks.concat(done.rows.map(r => ({
          id: r.id, projectId: r.project_id, task: r.task, status: r.status, notes: r.notes, deadline: r.deadline, done: true, archived: true,
          assigned: true, createdByName: r.created_by_name || "", completedByName: r.completed_by_name || "",
          completedAt: r.completed_at || r.archived_at, assigneeId: r.owner_id, assigneeName: r.assignee_name || r.assignee_username || ""
        })));
      }
      const ad = await pool.query("SELECT id, name, username FROM users WHERE role='admin' AND active=TRUE AND password <> $1 ORDER BY lower(name), lower(username)", [NO_PASSWORD]);
      admins = ad.rows.map(u => ({ id: u.id, name: u.name || u.username }));
    }
    res.json({
      weekId,
      me: publicUser(req.user),
      viewing: publicUser(target),
      readOnly: target.id !== req.user.id && req.user.role !== "owner",
      tasks: taskRes.rows.map(taskShape),
      archive: archRes.rows.map(r => ({
        id: r.id, title: r.title, task: r.task, status: r.status,
        notes: r.notes, deadline: r.deadline, contact: r.contact, weekCompleted: r.week_completed,
        createdByName: r.created_by_name || "", completedByName: r.completed_by_name || "", projectId: r.project_id || null
      })),
      contacts: contRes.rows,
      projects: projRows,
      assignedTasks, admins, leadTargets
    });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/tasks", requireAuth, async (req, res) => {
  const { id, title, task, status, notes, deadline, contact, done, week_id } = req.body;
  if (!id || !ID_RE.test(String(id))) return res.status(400).json({ error: "Invalid task id" });
  try {
    await pool.query(
      "INSERT INTO tasks (id,title,task,status,notes,deadline,contact,done,week_id,owner_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
      [id, title||"", task||"", status||"Not started", notes||"", deadline||"", contact||"", done||false, week_id||"", req.user.id]
    );
    res.json({ ok: true });
  } catch(e) {
    if (e.code === "23505") return res.status(409).json({ error: "That task already exists" });
    console.error(e); res.status(500).json({ error: "Server error" });
  }
});

// The project journal is a JSON list in projects.notes, newest first. These helpers change it safely (row lock)
// so the automatic "completed by" lines never collide with someone saving a note at the same moment.
async function mutateJournal(projectId, fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query("SELECT notes FROM projects WHERE id=$1 FOR UPDATE", [projectId]);
    if (!r.rows.length) { await client.query("ROLLBACK"); return null; }
    let list = [];
    const raw = r.rows[0].notes || "";
    try { const j = JSON.parse(raw); list = Array.isArray(j) ? j : []; if (!Array.isArray(j) && raw.trim()) list = [{ date: "Previous notes", text: raw.trim() }]; }
    catch (e) { if (raw.trim()) list = [{ date: "Previous notes", text: raw.trim() }]; }
    fn(list);
    await client.query("UPDATE projects SET notes=$1 WHERE id=$2", [JSON.stringify(list), projectId]);
    await client.query("COMMIT");
    return list;
  } catch (e) { await client.query("ROLLBACK").catch(() => {}); throw e; }
  finally { client.release(); }
}

// Done / not-done flips: remember when (for everyone) and, for tasks handed over by someone, who finished it,
// with a line in the project's journal ("Task completed by Lease Admin: ...") that is withdrawn if it is un-ticked.
async function recordCompletion(cur, nowDone, user) {
  if (!!cur.done === !!nowDone) return;
  if (!nowDone) await pool.query("UPDATE tasks SET completed_at=NULL, completed_by_name='' WHERE id=$1", [cur.id]);
  else await pool.query("UPDATE tasks SET completed_at=NOW(), completed_by_name=$2 WHERE id=$1", [cur.id, cur.assigned ? ROLE_LABEL[user.role] || "" : ""]);
  if (!cur.assigned || !cur.project_id) return;
  try {
    await mutateJournal(cur.project_id, list => {
      const keep = list.filter(e => !(e && e.system && e.taskId === cur.id));
      list.length = 0; list.push(...keep);
      if (nowDone) list.unshift({ date: new Date().toISOString(), text: `Task completed by ${ROLE_LABEL[user.role] || "team"}: ${cur.task}`, system: true, taskId: cur.id, by: ROLE_LABEL[user.role] || "" });
    });
  } catch (e) { console.error("journal log failed:", e.message); }
}

// A task handed over by someone else (to a Lease Admin) is the author's to word and date; its assignee updates
// progress: tick it done and change its status and notes.
const canEditAssignedTask = (u, t) => !t.assigned || u.role === "owner" || t.created_by === u.id;

// A task made by a supervisor ("admin task") belongs to the project's owner but is the supervisor's to edit:
// the owner may tick it done, nothing more. Only its author (or the Owner) can change or delete it.
const canEditSupervisorTask = (u, t) => !t.supervisor || u.role === "owner" || t.created_by === u.id;

app.put("/api/tasks/:id", requireAuth, async (req, res) => {
  const { title, task, status, notes, deadline, contact, done } = req.body;
  try {
    const cur = (await pool.query("SELECT id, owner_id, supervisor, created_by, assigned, project_id, done, task FROM tasks WHERE id=$1", [req.params.id])).rows[0];
    if (!cur || !(req.user.role === "owner" || cur.owner_id === req.user.id)) return res.status(404).json({ error: "Task not found" });
    if (!canEditSupervisorTask(req.user, cur)) {
      await pool.query("UPDATE tasks SET done=$1 WHERE id=$2", [done === true, req.params.id]);   // completing is all they may do
      await recordCompletion(cur, done === true, req.user);
      return res.json({ ok: true });
    }
    if (!canEditAssignedTask(req.user, cur)) {
      // The Lease Admin: progress only. What the task says and when it is due stay as assigned.
      await pool.query("UPDATE tasks SET status=$1, notes=$2, done=$3 WHERE id=$4",
        [status||"Not started", notes||"", done === true, req.params.id]);
      await recordCompletion(cur, done === true, req.user);
      return res.json({ ok: true });
    }
    await pool.query(
      "UPDATE tasks SET title=$1,task=$2,status=$3,notes=$4,deadline=$5,contact=$6,done=$7 WHERE id=$8",
      [title||"", task||"", status||"Not started", notes||"", deadline||"", contact||"", done||false, req.params.id]
    );
    await recordCompletion(cur, done === true, req.user);
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.delete("/api/tasks/:id", requireAuth, async (req, res) => {
  try {
    const cur = (await pool.query("SELECT id, owner_id, supervisor, created_by, assigned FROM tasks WHERE id=$1", [req.params.id])).rows[0];
    if (!cur || !(req.user.role === "owner" || cur.owner_id === req.user.id)) return res.json({ ok: true });
    if (!canEditSupervisorTask(req.user, cur)) return res.status(403).json({ error: "Only the supervisor who added this task can remove it" });
    if (!canEditAssignedTask(req.user, cur)) return res.status(403).json({ error: "Only the person who assigned this task can remove it" });
    await pool.query("DELETE FROM tasks WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// Archive a single task immediately
app.post("/api/newweek-single", requireAuth, async (req, res) => {
  const { taskId, weekId } = req.body;
  try {
    const task = await pool.query("SELECT * FROM tasks WHERE id=$1 AND ($2 OR owner_id=$3)", [taskId, ...scopeParams(req.user)]);
    if(!task.rows.length) return res.json({ ok: true });
    const t = task.rows[0];
    // An unfinished supervisor task can't be tucked away by its assignee.
    if (!t.done && !canEditSupervisorTask(req.user, t)) return res.status(403).json({ error: "That task was assigned by a supervisor" });
    if (!t.done && !canEditAssignedTask(req.user, t)) return res.status(403).json({ error: "That task was assigned to you. Finish it first." });
    await pool.query(
      "INSERT INTO archive (id,title,task,status,notes,deadline,contact,week_completed,owner_id,project_id,created_by_name,completed_by_name,completed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT (id) DO NOTHING",
      [t.id, t.title, t.task, t.status, t.notes, t.deadline, t.contact, weekId, t.owner_id, t.project_id, t.created_by_name || "", t.completed_by_name || "", t.completed_at]
    );
    await pool.query("DELETE FROM tasks WHERE id=$1", [taskId]);
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// "New week" archives the CALLER's finished tasks and moves the CALLER's week forward.
app.post("/api/newweek", requireAuth, async (req, res) => {
  try {
    const currentWeekId = await getWeekId(req.user.id);
    const doneTasks = await pool.query("SELECT * FROM tasks WHERE done=TRUE AND owner_id=$1", [req.user.id]);
    for (const t of doneTasks.rows) {
      await pool.query(
        "INSERT INTO archive (id,title,task,status,notes,deadline,contact,week_completed,owner_id,project_id,created_by_name,completed_by_name,completed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT (id) DO NOTHING",
        [t.id, t.title, t.task, t.status, t.notes, t.deadline, t.contact, currentWeekId, t.owner_id, t.project_id, t.created_by_name || "", t.completed_by_name || "", t.completed_at]
      );
    }
    await pool.query("DELETE FROM tasks WHERE done=TRUE AND owner_id=$1", [req.user.id]);
    const newWeekId = getCurrentWeekId();
    await pool.query("INSERT INTO meta (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", [weekKey(req.user.id), newWeekId]);
    res.json({ ok: true, newWeekId });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.put("/api/archive/:id", requireAuth, async (req, res) => {
  const { title, task, notes, contact } = req.body;
  try {
    await pool.query(
      "UPDATE archive SET title=$1,task=$2,notes=$3,contact=$4 WHERE id=$5 AND ($6 OR owner_id=$7)",
      [title||"", task||"", notes||"", contact||"", req.params.id, ...scopeParams(req.user)]
    );
    res.json({ ok: true });
  } catch(e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// Contacts are one directory shared by the whole team.
app.post("/api/contacts", requireAuth, async (req, res) => {
  const { id, name, company, email, phone, notes } = req.body;
  if (!id || !ID_RE.test(String(id))) return res.status(400).json({ error: "Invalid contact id" });
  try {
    await pool.query(
      "INSERT INTO contacts (id,name,company,email,phone,notes,is_lead) VALUES ($1,$2,$3,$4,$5,$6,$7)",
      [id, name||"", company||"", email||"", phone||"", notes||"", req.body.is_lead === true]
    );
    res.json({ ok: true });
  } catch(e) {
    if (e.code === "23505") return res.status(409).json({ error: "That contact already exists" });
    console.error(e); res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/contacts/:id", requireAuth, async (req, res) => {
  const { name, company, email, phone, notes } = req.body;
  const isLead = typeof req.body.is_lead === "boolean" ? req.body.is_lead : null;   // absent = leave the tag alone
  try {
    await pool.query(
      "UPDATE contacts SET name=$1,company=$2,email=$3,phone=$4,notes=$5,is_lead=COALESCE($6,is_lead) WHERE id=$7",
      [name||"", company||"", email||"", phone||"", notes||"", isLead, req.params.id]
    );
    // Taking the Lead tag off a lead that is waiting with an agent withdraws it from them.
    if (isLead === false) await pool.query("UPDATE contacts SET lead_to=NULL, lead_by=NULL, lead_by_name='', lead_at=NULL WHERE id=$1 AND lead_project_id IS NULL", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// ── Leads ──────────────────────────────────────────────────────
// The Lease Admin (and the Owner and Supervisors) can hand a lead to an agent. It then shows up on the agent's
// project board as a prompt to create a project from it; creating the project closes the lead out.
const leadGivers = requireRole("owner", "supervisor", "admin");
app.post("/api/contacts/:id/assign-lead", requireAuth, leadGivers, async (req, res) => {
  try {
    const c = (await pool.query("SELECT id, lead_project_id FROM contacts WHERE id=$1", [req.params.id])).rows[0];
    if (!c) return res.status(404).json({ error: "Contact not found" });
    if (c.lead_project_id) return res.status(409).json({ error: "A project has already been created from this lead" });
    const to = (await pool.query("SELECT id, name, username FROM users WHERE id=$1 AND active=TRUE AND password <> $2 AND role IN ('agent','supervisor')", [String(req.body.userId || ""), NO_PASSWORD])).rows[0];
    if (!to) return res.status(400).json({ error: "Choose an active agent" });
    await pool.query("UPDATE contacts SET is_lead=TRUE, lead_to=$1, lead_by=$2, lead_by_name=$3, lead_at=NOW() WHERE id=$4",
      [to.id, req.user.id, displayName(req.user), req.params.id]);
    res.json({ ok: true, lead: { lead_to: to.id, lead_to_name: to.name || to.username, lead_by: req.user.id, lead_by_name: displayName(req.user), lead_at: new Date().toISOString() } });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});
app.delete("/api/contacts/:id/assign-lead", requireAuth, leadGivers, async (req, res) => {
  try {
    await pool.query("UPDATE contacts SET lead_to=NULL, lead_by=NULL, lead_by_name='', lead_at=NULL WHERE id=$1 AND lead_project_id IS NULL", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.delete("/api/contacts/:id", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM contacts WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

app.post("/api/projects", requireAuth, requireRole("owner", "supervisor", "agent"), async (req, res) => {
  const { id, name, address, prospect, type, sf, price_per_sf, status, notes, contacts, priority, files } = req.body;
  if (!id || !ID_RE.test(String(id))) return res.status(400).json({ error: "Invalid project id" });
  // A new project may arrive with files already uploaded under its (pre-generated) id.
  const filesJson = files === undefined ? "[]" : cleanProjectFiles(id, files);
  if (filesJson === null) return res.status(400).json({ error: "Invalid files list" });
  try {
    await pool.query(
      "INSERT INTO projects (id,name,address,prospect,type,sf,price_per_sf,status,notes,contacts,priority,files,owner_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
      [id, name||"", address||"", prospect||"", type||"", sf||"", price_per_sf||"", status||"", notes||"", contacts||"[]", priority||"", filesJson, req.user.id]
    );
    // Created from a lead that was handed to this person: close the lead out and link it to the new project.
    if (req.body.leadContactId) {
      await pool.query("UPDATE contacts SET lead_project_id=$1 WHERE id=$2 AND lead_to=$3 AND lead_project_id IS NULL", [id, String(req.body.leadContactId), req.user.id]);
    }
    res.json({ ok: true });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "That project already exists" });
    console.error(e); res.status(500).json({ error: "Server error" });
  }
});

app.put("/api/projects/:id", requireAuth, projectAccess("write"), async (req, res) => {
  const { name, address, prospect, type, sf, price_per_sf, status, notes, contacts, priority, files } = req.body;
  // `files` is optional. Many parts of the app save a project without knowing about files
  // (e.g. adding a journal note), so when it's absent we keep what's already stored (COALESCE).
  let filesJson = null;
  if (files !== undefined) {
    filesJson = cleanProjectFiles(req.params.id, files);
    if (filesJson === null) return res.status(400).json({ error: "Invalid files list" });
  }
  try {
    await pool.query(
      "UPDATE projects SET name=$1,address=$2,prospect=$3,type=$4,sf=$5,price_per_sf=$6,status=$7,notes=$8,contacts=$9,priority=$10,files=COALESCE($11,files) WHERE id=$12",
      [name||"", address||"", prospect||"", type||"", sf||"", price_per_sf||"", status||"", notes||"", contacts||"[]", priority||"", filesJson, req.params.id]
    );
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.patch("/api/projects/:id/priority", requireAuth, projectAccess("write"), async (req, res) => {
  const { priority } = req.body;
  await pool.query("UPDATE projects SET priority=$1 WHERE id=$2", [priority||"", req.params.id]);
  res.json({ ok: true });
});

app.patch("/api/projects/:id/status", requireAuth, projectAccess("write"), async (req, res) => {
  const { status } = req.body;
  await pool.query("UPDATE projects SET status=$1 WHERE id=$2", [status||"", req.params.id]);
  res.json({ ok: true });
});

// Mark a project as viewed — resets its "idle" clock for the staleness glow.
// Only the project's own person resets the clock: a supervisor looking at an agent's project must not
// make a neglected project look fresh.
app.patch("/api/projects/:id/opened", requireAuth, projectAccess("read"), async (req, res) => {
  const result = await pool.query(
    "UPDATE projects SET last_opened_at=NOW(), sup_flag_at=NULL, sup_flag_text=NULL WHERE id=$1 AND owner_id=$2 RETURNING last_opened_at",
    [req.params.id, req.user.id]
  );
  res.json({ ok: true, last_opened_at: result.rows[0]?.last_opened_at });
});

// Replace a project's file list (used by the project view, which changes files on their own,
// without resending every other project field).
app.patch("/api/projects/:id/files", requireAuth, projectAccess("write"), async (req, res) => {
  const filesJson = cleanProjectFiles(req.params.id, req.body.files);
  if (filesJson === null) return res.status(400).json({ error: "Invalid files list" });
  try {
    const r = await pool.query("UPDATE projects SET files=$1 WHERE id=$2 RETURNING id", [filesJson, req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: "Project not found" });
    res.json({ ok: true, files: filesJson });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.delete("/api/projects/:id", requireAuth, projectAccess("write"), async (req, res) => {
  await pool.query("DELETE FROM projects WHERE id=$1", [req.params.id]);
  await pool.query("DELETE FROM tasks WHERE project_id=$1 AND assigned=TRUE", [req.params.id]);   // tasks handed to a Lease Admin go with it
  // Clean up the project's files in the background; don't fail the request if R2 hiccups.
  deleteProjectFiles(req.params.id).catch(e => console.error("R2 cleanup failed:", e.message));
  res.json({ ok: true });
});

// Hand projects to another person. Owner and Supervisors may do this. The project's journal and files
// travel with it automatically (they live on the project); its tasks — the ones titled "<name> — <address>"
// that currently belong to the old holder — move too.
app.post("/api/projects/reassign", requireAuth, requireRole("owner", "supervisor"), async (req, res) => {
  const ids = Array.isArray(req.body.projectIds) ? req.body.projectIds.map(String) : [];
  const toId = String(req.body.userId || "");
  if (!ids.length || ids.length > 500 || !ids.every(i => ID_RE.test(i))) return res.status(400).json({ error: "Choose at least one project" });
  const client = await pool.connect();
  try {
    const to = await client.query("SELECT id, active, role FROM users WHERE id=$1", [toId]);
    if (!to.rows.length || to.rows[0].active === false) return res.status(400).json({ error: "Choose an active user" });
    if (to.rows[0].role === "admin") return res.status(400).json({ error: "A Lease Admin can't hold projects. Assign her a task instead." });
    await client.query("BEGIN");
    let moved = 0, tasksMoved = 0;
    for (const pid of ids) {
      const p = await client.query("SELECT id, name, address, owner_id FROM projects WHERE id=$1 FOR UPDATE", [pid]);
      if (!p.rows.length || p.rows[0].owner_id === toId) continue;
      const row = p.rows[0];
      // Handing a project to someone else flags it for them; taking one yourself clears any flag.
      if (toId === req.user.id) await client.query("UPDATE projects SET owner_id=$1, sup_flag_at=NULL, sup_flag_text=NULL WHERE id=$2", [toId, pid]);
      else await client.query("UPDATE projects SET owner_id=$1, sup_flag_at=NOW(), sup_flag_text=$3 WHERE id=$2", [toId, pid, "Assigned by " + shortName(req.user)]);
      const t = await client.query(
        "UPDATE tasks SET owner_id=$1 WHERE owner_id=$2 AND btrim(title) = btrim($3)",
        [toId, row.owner_id, `${row.name || ""} — ${row.address || ""}`]);
      moved++; tasksMoved += t.rowCount;
    }
    await client.query("COMMIT");
    res.json({ ok: true, moved, tasksMoved });
  } catch(e) {
    await client.query("ROLLBACK").catch(() => {});
    console.error(e); res.status(500).json({ error: "Could not reassign" });
  } finally { client.release(); }
});

// ── Supervisor layer ───────────────────────────────────────────
// Owner and Supervisors can add notes and admin tasks to any project they can see. They are labelled with
// the author's name so the project's owner always knows who wrote them. The project's owner can read them
// (and tick admin tasks done) but cannot edit or delete them.
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const supervisorsOnly = requireRole("owner", "supervisor");
const displayName = (u) => (u.name && u.name.trim()) || u.username;
const shortName = (u) => ((u.name && u.name.trim()) ? u.name.trim().split(/\s+/)[0] : String(u.username).split("@")[0]);

async function mutateSupervisorNotes(projectId, fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const r = await client.query("SELECT supervisor_notes FROM projects WHERE id=$1 FOR UPDATE", [projectId]);
    let list = [];
    try { list = JSON.parse(r.rows[0]?.supervisor_notes || "[]"); } catch (e) {}
    if (!Array.isArray(list)) list = [];
    const out = fn(list);
    if (out && out.error) { await client.query("ROLLBACK"); return out; }
    await client.query("UPDATE projects SET supervisor_notes=$1 WHERE id=$2", [JSON.stringify(list), projectId]);
    await client.query("COMMIT");
    return { notes: list };
  } catch (e) { await client.query("ROLLBACK").catch(() => {}); throw e; }
  finally { client.release(); }
}
// Raise the "unseen" flag on a project for its owner. Labels pile up ("Assigned by Tano · New note") until the
// owner opens the project. A supervisor working on their own project flags nothing.
async function flagProject(db, project, actor, label) {
  if (!project || project.owner_id === actor.id) return;
  await db.query(
    `UPDATE projects SET sup_flag_at = NOW(),
       sup_flag_text = CASE WHEN COALESCE(sup_flag_text,'') = '' THEN $2
                            WHEN position($2 in sup_flag_text) > 0 THEN sup_flag_text
                            ELSE sup_flag_text || ' · ' || $2 END
     WHERE id = $1`, [project.id, label]);
}
const cleanText = (v, max) => String(v == null ? "" : v).trim().slice(0, max);

app.post("/api/projects/:id/supervisor-notes", requireAuth, supervisorsOnly, projectAccess("read"), async (req, res) => {
  const text = cleanText(req.body.text, 5000);
  if (!text) return res.status(400).json({ error: "Note can't be empty" });
  try {
    const out = await mutateSupervisorNotes(req.params.id, list => {
      list.unshift({ id: crypto.randomBytes(6).toString("hex"), date: new Date().toISOString(), text, authorId: req.user.id, authorName: displayName(req.user) });
    });
    await flagProject(pool, req.project, req.user, "New note");
    res.json({ ok: true, notes: out.notes });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.put("/api/projects/:id/supervisor-notes/:noteId", requireAuth, supervisorsOnly, projectAccess("read"), async (req, res) => {
  const text = cleanText(req.body.text, 5000);
  if (!text) return res.status(400).json({ error: "Note can't be empty" });
  try {
    const out = await mutateSupervisorNotes(req.params.id, list => {
      const n = list.find(x => x.id === req.params.noteId);
      if (!n) return { error: 404, msg: "Note not found" };
      if (n.authorId !== req.user.id && req.user.role !== "owner") return { error: 403, msg: "Only the author can edit this note" };
      n.text = text; n.edited = new Date().toISOString();
    });
    if (out.error) return res.status(out.error).json({ error: out.msg });
    res.json({ ok: true, notes: out.notes });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.delete("/api/projects/:id/supervisor-notes/:noteId", requireAuth, supervisorsOnly, projectAccess("read"), async (req, res) => {
  try {
    const out = await mutateSupervisorNotes(req.params.id, list => {
      const i = list.findIndex(x => x.id === req.params.noteId);
      if (i < 0) return { error: 404, msg: "Note not found" };
      if (list[i].authorId !== req.user.id && req.user.role !== "owner") return { error: 403, msg: "Only the author can delete this note" };
      list.splice(i, 1);
    });
    if (out.error) return res.status(out.error).json({ error: out.msg });
    res.json({ ok: true, notes: out.notes });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// Admin tasks: land on the project owner's list, filed under the project like any other task.
app.post("/api/projects/:id/supervisor-tasks", requireAuth, supervisorsOnly, projectAccess("read"), async (req, res) => {
  const id = String(req.body.id || "");
  const task = cleanText(req.body.task, 2000);
  const deadline = String(req.body.deadline || "");
  if (!ID_RE.test(id)) return res.status(400).json({ error: "Invalid task id" });
  if (!task) return res.status(400).json({ error: "Describe the task" });
  if (deadline && !DATE_RE.test(deadline)) return res.status(400).json({ error: "Invalid date" });
  try {
    const p = (await pool.query("SELECT name, address, owner_id FROM projects WHERE id=$1", [req.params.id])).rows[0];
    const title = `${p.name || ""} — ${p.address || ""}`.trim();
    const weekId = await getWeekId(p.owner_id);
    await pool.query(
      "INSERT INTO tasks (id,title,task,status,notes,deadline,contact,done,week_id,owner_id,supervisor,created_by,created_by_name) VALUES ($1,$2,$3,'Not started','',$4,'',FALSE,$5,$6,TRUE,$7,$8)",
      [id, title, task, deadline, weekId, p.owner_id, req.user.id, displayName(req.user)]);
    await flagProject(pool, { id: req.params.id, owner_id: p.owner_id }, req.user, "New task");
    res.json({ ok: true, task: { id, title, task, status: "Not started", notes: "", deadline, contact: "", done: false, supervisor: true, createdBy: req.user.id, createdByName: displayName(req.user) } });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "That task already exists" });
    console.error(e); res.status(500).json({ error: "Server error" });
  }
});

async function loadOwnSupervisorTask(req, res) {
  const t = (await pool.query("SELECT * FROM tasks WHERE id=$1 AND supervisor=TRUE", [req.params.id])).rows[0];
  if (!t) { res.status(404).json({ error: "Task not found" }); return null; }
  if (req.user.role !== "owner" && t.created_by !== req.user.id) { res.status(403).json({ error: "Only the author can change this task" }); return null; }
  return t;
}
app.put("/api/supervisor-tasks/:id", requireAuth, supervisorsOnly, async (req, res) => {
  const task = cleanText(req.body.task, 2000);
  const deadline = String(req.body.deadline || "");
  if (!task) return res.status(400).json({ error: "Describe the task" });
  if (deadline && !DATE_RE.test(deadline)) return res.status(400).json({ error: "Invalid date" });
  try {
    if (!(await loadOwnSupervisorTask(req, res))) return;
    await pool.query("UPDATE tasks SET task=$1, deadline=$2 WHERE id=$3", [task, deadline, req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});
app.delete("/api/supervisor-tasks/:id", requireAuth, supervisorsOnly, async (req, res) => {
  try {
    if (!(await loadOwnSupervisorTask(req, res))) return;
    await pool.query("DELETE FROM tasks WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// ── Lease Admin tasks ──────────────────────────────────────────
// The Owner, Supervisors and the project's own Agent can hand a Lease Admin a task from a project. The task
// lands on her board (and the project appears there until she has finished everything on it).
const assignedTaskOut = (r, assignee) => ({ ...taskShape(r), assigneeId: r.owner_id, assigneeName: assignee ? (assignee.name || assignee.username) : "" });
async function loadAssignee(id) {
  const r = await pool.query("SELECT id, name, username FROM users WHERE id=$1 AND role='admin' AND active=TRUE AND password <> $2", [id, NO_PASSWORD]);
  return r.rows[0] || null;
}
const assigners = requireRole("owner", "supervisor", "agent");

app.post("/api/projects/:id/admin-tasks", requireAuth, assigners, projectAccess("read"), async (req, res) => {
  const id = String(req.body.id || "");
  const task = cleanText(req.body.task, 2000);
  const deadline = String(req.body.deadline || "");
  if (!ID_RE.test(id)) return res.status(400).json({ error: "Invalid task id" });
  if (!task) return res.status(400).json({ error: "Describe the task" });
  if (deadline && !DATE_RE.test(deadline)) return res.status(400).json({ error: "Invalid date" });
  try {
    const assignee = await loadAssignee(String(req.body.assigneeId || ""));
    if (!assignee) return res.status(400).json({ error: "Choose a Lease Admin to assign this to" });
    const p = (await pool.query("SELECT name, address FROM projects WHERE id=$1", [req.params.id])).rows[0];
    const title = `${p.name || ""} — ${p.address || ""}`.trim();
    const weekId = await getWeekId(assignee.id);
    await pool.query(
      "INSERT INTO tasks (id,title,task,status,notes,deadline,contact,done,week_id,owner_id,assigned,project_id,created_by,created_by_name) VALUES ($1,$2,$3,'Not started','',$4,'',FALSE,$5,$6,TRUE,$7,$8,$9)",
      [id, title, task, deadline, weekId, assignee.id, req.params.id, req.user.id, displayName(req.user)]);
    const row = (await pool.query("SELECT * FROM tasks WHERE id=$1", [id])).rows[0];
    res.json({ ok: true, task: assignedTaskOut(row, assignee) });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "That task already exists" });
    console.error(e); res.status(500).json({ error: "Server error" });
  }
});

async function loadAssignedTask(req, res) {
  const t = (await pool.query("SELECT * FROM tasks WHERE id=$1 AND assigned=TRUE", [req.params.id])).rows[0];
  if (!t) { res.status(404).json({ error: "Task not found" }); return null; }
  if (req.user.role !== "owner" && t.created_by !== req.user.id) { res.status(403).json({ error: "Only the person who assigned this task can change it" }); return null; }
  return t;
}
app.put("/api/admin-tasks/:id", requireAuth, assigners, async (req, res) => {
  const task = cleanText(req.body.task, 2000);
  const deadline = String(req.body.deadline || "");
  if (!task) return res.status(400).json({ error: "Describe the task" });
  if (deadline && !DATE_RE.test(deadline)) return res.status(400).json({ error: "Invalid date" });
  try {
    const cur = await loadAssignedTask(req, res); if (!cur) return;
    let ownerId = cur.owner_id;
    if (req.body.assigneeId && String(req.body.assigneeId) !== cur.owner_id) {
      const a = await loadAssignee(String(req.body.assigneeId));
      if (!a) return res.status(400).json({ error: "Choose a Lease Admin" });
      ownerId = a.id;
    }
    await pool.query("UPDATE tasks SET task=$1, deadline=$2, owner_id=$3 WHERE id=$4", [task, deadline, ownerId, req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});
app.delete("/api/admin-tasks/:id", requireAuth, assigners, async (req, res) => {
  try {
    const cur = await loadAssignedTask(req, res); if (!cur) return;
    await pool.query("DELETE FROM tasks WHERE id=$1", [req.params.id]);
    // A finished task's "completed by" line is history; withdrawing the task withdraws that line too.
    if (cur.project_id) await mutateJournal(cur.project_id, list => { const keep = list.filter(e => !(e && e.system && e.taskId === cur.id)); list.length = 0; list.push(...keep); }).catch(() => {});
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// Add one entry to a project's journal without touching anything else on the project. This is how a Lease Admin
// writes notes (she can't save the project itself). Her entries are tagged with her role.
app.post("/api/projects/:id/journal", requireAuth, projectAccess("read"), async (req, res) => {
  const text = cleanText(req.body.text, 5000);
  const atts = Array.isArray(req.body.attachments) ? req.body.attachments.slice(0, 10) : [];
  const clean = [];
  for (const a of atts) {
    const m = a && KEY_RE.exec(String(a.key || ""));
    if (!m || m[1] !== req.params.id) return res.status(400).json({ error: "Invalid file" });
    clean.push({ key: String(a.key), name: cleanText(a.name, 200), size: Number(a.size) || 0 });
  }
  if (!text && !clean.length) return res.status(400).json({ error: "Write a note or attach a file" });
  try {
    const entry = { date: new Date().toISOString(), text };
    if (clean.length) entry.attachments = clean;
    if (req.user.role === "admin") entry.by = ROLE_LABEL.admin;
    const list = await mutateJournal(req.params.id, l => { l.unshift(entry); });
    res.json({ ok: true, notes: JSON.stringify(list) });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// Team dashboard: one summary per person (everyone but the viewer). `today` is the viewer's local date.
app.get("/api/team/overview", requireAuth, supervisorsOnly, async (req, res) => {
  const today = DATE_RE.test(String(req.query.today || "")) ? String(req.query.today) : new Date().toISOString().slice(0, 10);
  try {
    const people = await pool.query(
      "SELECT id, username, name, role FROM users WHERE active=TRUE AND password <> $1 AND id <> $2 ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'supervisor' THEN 1 WHEN 'agent' THEN 2 ELSE 3 END, lower(name), lower(username)",
      [NO_PASSWORD, req.user.id]);
    const projs = await pool.query(`
      SELECT owner_id,
        COUNT(*)::int AS total,
        COUNT(*) FILTER (WHERE COALESCE(status,'') NOT IN ('Closed','Completed','Dead'))::int AS active,
        COUNT(*) FILTER (WHERE COALESCE(status,'') NOT IN ('Closed','Completed','Dead') AND last_opened_at < NOW() - INTERVAL '14 days')::int AS idle_red,
        COUNT(*) FILTER (WHERE COALESCE(status,'') NOT IN ('Closed','Completed','Dead') AND last_opened_at < NOW() - INTERVAL '7 days' AND last_opened_at >= NOW() - INTERVAL '14 days')::int AS idle_yellow,
        COUNT(*) FILTER (WHERE sup_flag_at IS NOT NULL)::int AS flagged,
        COUNT(*) FILTER (WHERE type IN ('Lease','Renewal'))::int AS leases,
        COUNT(*) FILTER (WHERE type IN ('Sale','Purchase'))::int AS sales_purchases
      FROM projects GROUP BY owner_id`);
    const tks = await pool.query(`
      SELECT owner_id,
        COUNT(*) FILTER (WHERE NOT done)::int AS open_tasks,
        COUNT(*) FILTER (WHERE NOT done AND deadline <> '' AND deadline < $1)::int AS overdue,
        COUNT(*) FILTER (WHERE NOT done AND supervisor)::int AS supervisor_open,
        COUNT(*) FILTER (WHERE done)::int AS done_now,
        COUNT(*) FILTER (WHERE done AND COALESCE(completed_at, created_at) >= NOW() - INTERVAL '7 days')::int AS done_7,
        COUNT(DISTINCT project_id) FILTER (WHERE NOT done AND assigned)::int AS assigned_projects
      FROM tasks GROUP BY owner_id`, [today]);
    const arc = await pool.query(`
      SELECT owner_id, COUNT(*)::int AS archived,
        COUNT(*) FILTER (WHERE COALESCE(completed_at, archived_at) >= NOW() - INTERVAL '7 days')::int AS archived_7
      FROM archive GROUP BY owner_id`);
    const A = Object.fromEntries(arc.rows.map(r => [r.owner_id, r]));
    const P = Object.fromEntries(projs.rows.map(r => [r.owner_id, r]));
    const T = Object.fromEntries(tks.rows.map(r => [r.owner_id, r]));
    res.json({ people: people.rows.map(u => ({
      id: u.id, name: u.name || u.username, role: u.role,
      totalProjects: P[u.id]?.total || 0, activeProjects: P[u.id]?.active || 0,
      idleRed: P[u.id]?.idle_red || 0, idleYellow: P[u.id]?.idle_yellow || 0,
      flagged: P[u.id]?.flagged || 0, leases: P[u.id]?.leases || 0, salesPurchases: P[u.id]?.sales_purchases || 0,
      openTasks: T[u.id]?.open_tasks || 0, overdue: T[u.id]?.overdue || 0, supervisorOpen: T[u.id]?.supervisor_open || 0,
      completedTotal: (T[u.id]?.done_now || 0) + (A[u.id]?.archived || 0),
      completed7: (T[u.id]?.done_7 || 0) + (A[u.id]?.archived_7 || 0),
      assignedProjects: T[u.id]?.assigned_projects || 0
    })) });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

// ── File attachments: PDF and Word (stored in R2, referenced from journal entries) ──
// Upload: multipart form, field name "file". Returns the storage key to save in the note.
// A brand-new project uploads its files before the project itself is saved, so a missing project is
// allowed; an existing one must be writable by the caller.
//   mode "journal": attaching a file to a journal note. A Lease Admin may do this on a project she has a task on.
async function checkFileAccess(user, projectId, mode) {
  const p = await getProjectOwner(projectId);
  if (!p) return user.role === "admin" ? { ok: false, status: 404, error: "File not found" } : { ok: true };
  if (!(await canReadProjectDb(user, p))) return { ok: false, status: 404, error: "File not found" };
  if (mode === "journal" && user.role === "admin") return { ok: true };
  if ((mode === "write" || mode === "journal") && !canWriteProject(user, p)) return { ok: false, status: 403, error: "You don't have permission to change this project" };
  return { ok: true };
}

app.post("/api/projects/:id/attachments", requireAuth, requireR2, async (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ error: "Invalid project id" });
  try {
    const acc = await checkFileAccess(req.user, req.params.id, "journal");
    if (!acc.ok) return res.status(acc.status).json({ error: acc.error });
  } catch(e) { console.error(e); return res.status(500).json({ error: "Server error" }); }
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
  const km = KEY_RE.exec(key);
  if (!km) return res.status(400).json({ error: "Invalid file key" });
  try {
    const acc = await checkFileAccess(req.user, km[1], "read");
    if (!acc.ok) return res.status(acc.status).json({ error: acc.error });
  } catch(e) { console.error(e); return res.status(500).json({ error: "Server error" }); }
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
    const acc = await checkFileAccess(req.user, req.params.id, "write");
    if (!acc.ok) return res.status(acc.status).json({ error: acc.error });
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
