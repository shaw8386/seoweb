// index.js
import express from "express";
import cors from "cors";
import pkg from "pg";

process.env.TZ = "Asia/Ho_Chi_Minh";

const { Pool } = pkg;

// ========================
//  CONFIG ENV NO .ENV FILE
// ========================
const PORT = process.env.PORT || 3000;

// Database URL đưa thẳng vào đây
const DATABASE_URL =
  process.env.DATABASE_URL ||
  "postgresql://postgres:TtpAYoZAzwRiDXxRjWwbiXlUkQjEKneY@postgres.railway.internal:5432/railway"; // TODO: thay bằng real Railway URL

// Railway thường yêu cầu SSL
const DB_SSL =
  process.env.DB_SSL === "true" || true
    ? { rejectUnauthorized: false }
    : false;

// ========================
//  INIT DATABASE
// ========================
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DB_SSL,
});

// ========================
//  AUTO CREATE TABLE USERS
// ========================
async function initDB() {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      allowed_ip VARCHAR(50)
    );
  `;

  try {
    await pool.query(createTableQuery);
    console.log("✔️ Table 'users' đã được tạo hoặc đã tồn tại.");

    // OPTIONAL: tạo user admin mặc định
    const checkAdmin = await pool.query(
      "SELECT * FROM users WHERE username = 'admin'"
    );

    if (checkAdmin.rowCount === 0) {
      await pool.query(
        "INSERT INTO users (username, password, allowed_ip) VALUES ($1, $2, $3)",
        ["admin", "123456", null]
      );
      console.log("✔️ Tạo user mặc định: admin / 123456");
    }
  } catch (err) {
    console.error("❌ Lỗi tạo table:", err);
  }
}

// Gọi initDB khi server start
initDB();

// ========================
//  EXPRESS APP
// ========================
const app = express();
app.use(cors());
app.use(express.json());

// ========================
//   ROUTES
// ========================

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "Railway login backend is running" });
});

// Login API
app.post("/api/login", async (req, res) => {
  const { username, password, ip } = req.body;

  if (!username || !password || !ip) {
    return res.status(400).json({
      success: false,
      message: "Thiếu username / password / ip",
    });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        success: false,
        message: "Sai username hoặc password",
      });
    }

    const user = result.rows[0];

    // So sánh password (plain text demo)
    if (user.password !== password) {
      return res.status(401).json({
        success: false,
        message: "Sai username hoặc password",
      });
    }

    // Check IP nếu có
    // if (user.allowed_ip && user.allowed_ip !== ip) {
    //   return res.status(403).json({
    //     success: false,
    //     message: `IP không được phép (chỉ cho phép: ${user.allowed_ip})`,
    //   });
    // }

    return res.json({
      success: true,
      message: "Đăng nhập thành công",
      user: {
        id: user.id,
        username: user.username,
      },
    });
  } catch (error) {
    console.error("❌ Lỗi /api/login:", error);
    return res.status(500).json({
      success: false,
      message: "Lỗi server",
    });
  }
});

// ========================
//  START SERVER
// ========================
app.listen(PORT, () => {
  console.log(`🚀 Server chạy tại port ${PORT}`);
});

// ========================
//  DIRECT CONFIG BELOW
// ========================

// Thay trực tiếp đường dẫn DATABASE_URL tại đây
// Railway sẽ tự động override nếu bạn set trong dashboard
process.env.DATABASE_URL = "postgresql://postgres:TtpAYoZAzwRiDXxRjWwbiXlUkQjEKneY@postgres.railway.internal:5432/railway";

// SSL luôn bật
process.env.DB_SSL = "true";
