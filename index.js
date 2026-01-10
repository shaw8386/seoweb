// index.js (ESM)
import express from "express";
import cors from "cors";
import pkg from "pg";
import multer from "multer";
import crypto from "crypto";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

process.env.TZ = "Asia/Ho_Chi_Minh";
const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;

// ========================
// ENV
// ========================
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error("❌ Missing DATABASE_URL");
  process.exit(1);
}

// Railway Postgres thường cần ssl
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Token upload “ẩn”
const HIDDEN_UPLOAD_TOKEN = (process.env.HIDDEN_UPLOAD_TOKEN || "").trim();
if (!HIDDEN_UPLOAD_TOKEN) {
  console.warn("⚠️ Missing HIDDEN_UPLOAD_TOKEN (hidden-upload will be locked but token is empty)");
}

// Prefix key trên R2
const R2_KEY_PREFIX = (process.env.R2_KEY_PREFIX || "seo-web").trim();

// Cooldown (giờ) sau khi account bị đánh dấu limit → không dùng lại trong khoảng đó
const R2_COOLDOWN_HOURS = Number(process.env.R2_COOLDOWN_HOURS || 6);

// Soft limit dung lượng theo tháng cho mỗi account (GB) – do bạn tự đặt để “free tier”
const R2_MONTHLY_SOFT_LIMIT_GB = Number(process.env.R2_MONTHLY_SOFT_LIMIT_GB || 8);
const SOFT_LIMIT_BYTES = Math.floor(R2_MONTHLY_SOFT_LIMIT_GB * 1024 * 1024 * 1024);

// Optional seed JSON: array accounts
// [
//  {"name":"acc_cf_r2_01","account_id":"...","access_key_id":"...","secret_access_key":"...","bucket":"seoweb123","endpoint":"https://<accountid>.r2.cloudflarestorage.com"}
// ]
const R2_ACCOUNTS_SEED_JSON = (process.env.R2_ACCOUNTS_SEED_JSON || "").trim();

// ========================
// Multer upload memory
// ========================
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
});

// ========================
// Helpers
// ========================
function nowISO() {
  return new Date().toISOString();
}

function monthKeyUTC(d = new Date()) {
  // YYYY-MM
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}

function requireHiddenToken(req, res, next) {
  const token = (req.headers["x-hidden-token"] || "").toString().trim();
  if (!HIDDEN_UPLOAD_TOKEN || token !== HIDDEN_UPLOAD_TOKEN) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  next();
}

function sha1Short(buf) {
  return crypto.createHash("sha1").update(buf).digest("hex").slice(0, 10);
}

// ========================
// DB init
// ========================
async function initDB() {
  // USERS
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      allowed_ip VARCHAR(50)
    );
  `);

  // R2 accounts
  await pool.query(`
    CREATE TABLE IF NOT EXISTS r2_accounts (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      account_id TEXT NOT NULL,
      access_key_id TEXT NOT NULL,
      secret_access_key TEXT NOT NULL,
      bucket TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      is_disabled BOOLEAN NOT NULL DEFAULT FALSE,
      limited_until TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Monthly usage (tự track)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS r2_usage_monthly (
      id SERIAL PRIMARY KEY,
      account_id_ref INTEGER NOT NULL REFERENCES r2_accounts(id) ON DELETE CASCADE,
      month_key TEXT NOT NULL,
      used_bytes BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (account_id_ref, month_key)
    );
  `);

  // Upload logs
  await pool.query(`
    CREATE TABLE IF NOT EXISTS r2_upload_logs (
      id SERIAL PRIMARY KEY,
      session_id TEXT NOT NULL,
      kind TEXT NOT NULL, -- input|output
      original_name TEXT NOT NULL,
      size_bytes BIGINT NOT NULL,
      object_key TEXT NOT NULL,
      account_id_ref INTEGER NOT NULL REFERENCES r2_accounts(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("✔️ DB tables ensured.");

  // OPTIONAL: create admin default
  const checkAdmin = await pool.query("SELECT 1 FROM users WHERE username='admin' LIMIT 1");
  if (checkAdmin.rowCount === 0) {
    await pool.query(
      "INSERT INTO users (username, password, allowed_ip) VALUES ($1,$2,$3)",
      ["admin", "123456", null]
    );
    console.log("✔️ Created default admin / 123456");
  }

  // OPTIONAL: seed accounts from env
  if (R2_ACCOUNTS_SEED_JSON) {
    try {
      const arr = JSON.parse(R2_ACCOUNTS_SEED_JSON);
      if (Array.isArray(arr)) {
        for (const a of arr) {
          if (!a?.name) continue;
          await pool.query(
            `
            INSERT INTO r2_accounts (name, account_id, access_key_id, secret_access_key, bucket, endpoint)
            VALUES ($1,$2,$3,$4,$5,$6)
            ON CONFLICT (name) DO UPDATE SET
              account_id=EXCLUDED.account_id,
              access_key_id=EXCLUDED.access_key_id,
              secret_access_key=EXCLUDED.secret_access_key,
              bucket=EXCLUDED.bucket,
              endpoint=EXCLUDED.endpoint,
              updated_at=NOW()
            `,
            [
              String(a.name),
              String(a.account_id || ""),
              String(a.access_key_id || ""),
              String(a.secret_access_key || ""),
              String(a.bucket || ""),
              String(a.endpoint || ""),
            ]
          );
        }
        console.log("✔️ Seeded/updated r2_accounts from R2_ACCOUNTS_SEED_JSON");
      }
    } catch (e) {
      console.error("❌ R2_ACCOUNTS_SEED_JSON invalid:", e);
    }
  }
}

// Ensure reset each month
async function ensureMonthlyReset() {
  const mk = monthKeyUTC();
  // Không cần “reset” bảng, chỉ cần đảm bảo usage record tạo theo month hiện tại.
  // Nhưng bạn muốn “tự động reset đầu tháng” -> ta sẽ “unlock” limited_until nếu qua tháng.
  await pool.query(`
    UPDATE r2_accounts
    SET limited_until = NULL, updated_at = NOW()
    WHERE limited_until IS NOT NULL
  `);
  // usage_monthly là per month, không cần clear
  return mk;
}

// Get eligible account (not disabled, not in cooldown, and under soft-limit)
async function pickEligibleAccount(fileSizeBytes) {
  const mk = await ensureMonthlyReset();

  // lấy list accounts (ưu tiên account id nhỏ)
  const rs = await pool.query(`
    SELECT *
    FROM r2_accounts
    WHERE is_disabled = FALSE
    ORDER BY id ASC
  `);

  if (rs.rowCount === 0) return { ok: false, reason: "no_accounts" };

  for (const acc of rs.rows) {
    // cooldown check
    if (acc.limited_until && new Date(acc.limited_until).getTime() > Date.now()) {
      continue;
    }

    // get usage
    const usage = await pool.query(
      `SELECT used_bytes FROM r2_usage_monthly WHERE account_id_ref=$1 AND month_key=$2`,
      [acc.id, mk]
    );
    const used = usage.rowCount ? Number(usage.rows[0].used_bytes || 0) : 0;

    if (used + fileSizeBytes <= SOFT_LIMIT_BYTES) {
      return { ok: true, account: acc, month_key: mk, used_bytes: used };
    }

    // vượt soft-limit -> đánh dấu limited + cooldown
    const limitedUntil = new Date(Date.now() + R2_COOLDOWN_HOURS * 3600 * 1000);
    await pool.query(
      `UPDATE r2_accounts SET limited_until=$1, updated_at=NOW() WHERE id=$2`,
      [limitedUntil.toISOString(), acc.id]
    );
  }

  return { ok: false, reason: "all_limited" };
}

function makeS3Client(acc) {
  // Cloudflare R2 dùng S3 compatible
  return new S3Client({
    region: "auto",
    endpoint: acc.endpoint,
    credentials: {
      accessKeyId: acc.access_key_id,
      secretAccessKey: acc.secret_access_key,
    },
  });
}

async function addUsage(accId, monthKey, deltaBytes) {
  await pool.query(
    `
    INSERT INTO r2_usage_monthly (account_id_ref, month_key, used_bytes, updated_at)
    VALUES ($1,$2,$3,NOW())
    ON CONFLICT (account_id_ref, month_key)
    DO UPDATE SET used_bytes = r2_usage_monthly.used_bytes + EXCLUDED.used_bytes, updated_at = NOW()
    `,
    [accId, monthKey, Number(deltaBytes)]
  );
}

// ========================
// ROUTES
// ========================
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "Railway backend is running", time: nowISO() });
});

// Login API (giữ nguyên)
app.post("/api/login", async (req, res) => {
  const { username, password, ip } = req.body || {};
  if (!username || !password || !ip) {
    return res.status(400).json({ success: false, message: "Thiếu username / password / ip" });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (result.rowCount === 0) {
      return res.status(401).json({ success: false, message: "Sai username hoặc password" });
    }

    const user = result.rows[0];
    if (user.password !== password) {
      return res.status(401).json({ success: false, message: "Sai username hoặc password" });
    }

    return res.json({
      success: true,
      message: "Đăng nhập thành công",
      user: { id: user.id, username: user.username },
    });
  } catch (error) {
    console.error("❌ /api/login:", error);
    return res.status(500).json({ success: false, message: "Lỗi server" });
  }
});

// ===== Hidden upload endpoint =====
app.post(
  "/hidden-upload",
  requireHiddenToken,
  upload.single("file"),
  async (req, res) => {
    try {
      const session_id = (req.body?.session_id || "").toString().trim();
      const kind = (req.body?.kind || "").toString().trim(); // input|output
      const file = req.file;

      if (!session_id || !kind) {
        return res.status(400).json({ success: false, message: "Missing session_id/kind" });
      }
      if (!file || !file.buffer) {
        return res.status(400).json({ success: false, message: "Missing file" });
      }

      const fileSize = file.size || file.buffer.length || 0;

      // pick eligible account
      const pick = await pickEligibleAccount(fileSize);
      if (!pick.ok) {
        return res.status(429).json({ success: false, message: `No eligible R2 account: ${pick.reason}` });
      }

      const acc = pick.account;
      const s3 = makeS3Client(acc);

      // object key
      const safeName = (file.originalname || "file.xlsx").replace(/[^\w.\-]+/g, "_");
      const hash = sha1Short(file.buffer);
      const key = `${R2_KEY_PREFIX}/${session_id}/${kind}/${Date.now()}_${hash}_${safeName}`;

      // upload to R2
      await s3.send(
        new PutObjectCommand({
          Bucket: acc.bucket,
          Key: key,
          Body: file.buffer,
          ContentType: file.mimetype || "application/octet-stream",
        })
      );

      // update usage + log
      await addUsage(acc.id, pick.month_key, fileSize);

      await pool.query(
        `
        INSERT INTO r2_upload_logs (session_id, kind, original_name, size_bytes, object_key, account_id_ref)
        VALUES ($1,$2,$3,$4,$5,$6)
        `,
        [session_id, kind, file.originalname || "", fileSize, key, acc.id]
      );

      return res.json({
        success: true,
        object_key: key,
        bucket: acc.bucket,
        account_name: acc.name,
        size_bytes: fileSize,
        month_key: pick.month_key,
      });
    } catch (e) {
      console.error("❌ /hidden-upload:", e);
      return res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// ===== Endpoint xem account status/limit =====
app.get("/hidden/accounts", requireHiddenToken, async (req, res) => {
  try {
    const mk = monthKeyUTC();
    const rs = await pool.query(`
      SELECT a.*,
        COALESCE(u.used_bytes, 0) as used_bytes,
        $1::text as month_key
      FROM r2_accounts a
      LEFT JOIN r2_usage_monthly u
        ON u.account_id_ref = a.id AND u.month_key = $1
      ORDER BY a.id ASC
    `, [mk]);

    const out = rs.rows.map(r => ({
      id: r.id,
      name: r.name,
      bucket: r.bucket,
      endpoint: r.endpoint,
      is_disabled: r.is_disabled,
      limited_until: r.limited_until,
      used_bytes: Number(r.used_bytes || 0),
      soft_limit_bytes: SOFT_LIMIT_BYTES,
      soft_limit_gb: R2_MONTHLY_SOFT_LIMIT_GB,
      month_key: mk,
    }));

    res.json({ success: true, accounts: out });
  } catch (e) {
    console.error("❌ /hidden/accounts:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ===== Manual reset (optional) =====
app.post("/hidden/reset-month", requireHiddenToken, async (req, res) => {
  try {
    // reset “cooldown”
    await pool.query(`UPDATE r2_accounts SET limited_until=NULL, updated_at=NOW()`);
    res.json({ success: true, message: "Reset limited_until done" });
  } catch (e) {
    console.error("❌ /hidden/reset-month:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ========================
// START
// ========================
initDB()
  .then(() => {
    app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  })
  .catch((e) => {
    console.error("❌ initDB fatal:", e);
    process.exit(1);
  });
