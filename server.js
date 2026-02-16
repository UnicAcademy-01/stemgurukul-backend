const path = require("path");
const express = require("express");
const helmet = require("helmet");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

pool.connect((err) => {
  if (err) console.error("❌ DB Error:", err);
  else console.log("✅ PostgreSQL Connected");
});

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }),
);

// ✅ FIXED: Serve subject folders + PDFs
app.use(
  "/maths12-guide",
  express.static(path.join(__dirname, "public/maths12-guide")),
);
app.use(
  "/science12-guide",
  express.static(path.join(__dirname, "public/science12-guide")),
);
// Add more subjects...

// ✅ Generic PDF handler (catch-all)
app.use((req, res, next) => {
  if (req.path.match(/\.(pdf|json)$/)) {
    res.set(
      "Content-Type",
      req.path.endsWith(".pdf") ? "application/pdf" : "application/json",
    );
    res.set("Cross-Origin-Embedder-Policy", "unsafe-none");
    res.set("Cross-Origin-Resource-Policy", "cross-origin");
  }
  next();
});

app.use(express.static(path.join(__dirname, "build")));
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/signup", async (req, res) => {
  try {
    const { name, mobileNo, emailID, password } = req.body;

    const emailCheck = await pool.query(
      "SELECT 1 FROM user_table WHERE emailid = $1",
      [emailID],
    );

    if (emailCheck.rows.length > 0) {
      return res.status(409).json({ error: "Email exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO user_table (name, mobileno, emailid, password)
       VALUES ($1, $2, $3, $4)
       RETURNING user_id`,
      [name, mobileNo, emailID, hashedPassword],
    );

    res.json({ message: "✅ Registered", user: result.rows[0] });
  } catch (error) {
    console.error("Signup error:", error.message);
    res.status(500).json({ error: error.message });
  }
});

// ✅ Subscribe API (Insert or Update email in subscribe_table)
app.post("/api/subscribe", async (req, res) => {
  try {
    const { emailid, subscribers } = req.body;

    // Basic validation
    if (!emailid || !emailid.trim()) {
      return res.status(400).json({ error: "EmailID is required" });
    }

    const email = emailid.trim().toLowerCase();
    const subsValue = subscribers === false ? false : true; // default true

    // ✅ UPSERT Query
    const result = await pool.query(
      `INSERT INTO subscribe_table (emailid, subscribers, created_at, updated_at)
       VALUES ($1, $2, now(), now())
       ON CONFLICT (emailid)
       DO UPDATE SET
         subscribers = EXCLUDED.subscribers,
         updated_at = now()
       RETURNING subscribe_id, emailid, subscribers, created_at, updated_at`,
      [email, subsValue],
    );

    return res.json({
      message: "✅ Subscription saved successfully",
      data: result.rows[0],
    });
  } catch (error) {
    console.error("Subscribe error:", error.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { emailid, password } = req.body;

    // 1. Check email exists
    const userQuery = await pool.query(
      "SELECT * FROM user_table WHERE emailid = $1",
      [emailid],
    );

    if (userQuery.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userQuery.rows[0];

    // 2. Compare password using bcrypt
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Incorrect password" });
    }

    // ✅ Login success
    res.json({
      message: "✅ Login success",
      user: {
        user_id: user.user_id,
        name: user.name,
        emailid: user.emailid,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "build", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
