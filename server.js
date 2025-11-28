// server.js
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const mysql = require("mysql2");

const app = express();

// Allow requests from your frontend (running at port 4028)
app.use(cors({ origin: "http://localhost:4028" }));
app.use(express.json());

// MySQL connection (update password if needed)
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",   // keep your password here
  database: "smart_pickup"
});

db.connect((err) => {
  if (err) {
    console.error("MySQL connection error:", err);
    process.exit(1);
  }
  console.log("Connected to MySQL (smart_pickup)");
});

// ----------------- REGISTER -----------------
app.post("/api/register", async (req, res) => {
  try {
    const {
      role,
      full_name,
      email,
      phone_number,
      vehicle_number,
      staff_id,
      password,
      child1,
      child2,
      child3,
      child4
    } = req.body;

    if (!role || !full_name || !email || !phone_number || !password) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    if (role === "parent" && !child1) {
      return res.status(400).json({ message: "Child1 is required for parents" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const check = "SELECT * FROM users WHERE email = ? OR phone_number = ?";
    db.query(check, [email, phone_number], (err, result) => {
      if (err) return res.status(500).json({ error: err });

      if (result.length > 0) {
        return res.status(400).json({ message: "Email or phone already exists" });
      }

      let sql, values;

      if (role === "parent") {
        sql = `
          INSERT INTO users 
          (full_name, email, phone_number, password_hash, role, vehicle_number, child1_name, child2_name, child3_name, child4_name)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        values = [
          full_name,
          email,
          phone_number,
          hashed,
          role,
          vehicle_number || null,
          child1,
          child2 || null,
          child3 || null,
          child4 || null
        ];
      }

      if (role === "admin") {
        sql = `
          INSERT INTO users 
          (full_name, email, phone_number, password_hash, role, staff_id)
          VALUES (?, ?, ?, ?, ?, ?)
        `;

        values = [
          full_name,
          email,
          phone_number,
          hashed,
          role,
          staff_id || null
        ];
      }

      db.query(sql, values, (err2, result2) => {
        if (err2) {
          console.log("Insert Error:", err2);
          return res.status(500).json({ message: "Insert failed" });
        }

        return res.json({ message: "Registration successful" });
      });
    });

  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Server error" });
  }
});


// ----------------- LOGIN -----------------
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ message: "Email and password required" });

  const q = "SELECT * FROM users WHERE email = ? LIMIT 1";
  db.query(q, [email], async (err, results) => {
    if (err) {
      console.error("Login DB error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    if (!results || results.length === 0) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const user = results[0];
    try {
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        return res.status(400).json({ message: "Invalid email or password" });
      }

      // Return minimal user info for frontend
      return res.json({
        message: "Login successful",
        user: {
          user_id: user.user_id,
          full_name: user.full_name,
          role: user.role,
          vehicle_number: user.vehicle_number || null,
          staff_id: user.staff_id || null,
          child1: user.child1 || null,
          child2: user.child2 || null,
          child3: user.child3 || null,
          child4: user.child4 || null
        }
      });
    } catch (compareErr) {
      console.error("Password compare error:", compareErr);
      return res.status(500).json({ message: "Server error" });
    }
  });
});


// ---------------- FETCH QUEUE (JOIN users + plate_logs) ----------------
app.get("/api/queue", (req, res) => {
  const query = `
    SELECT 
      u.user_id AS id,
      u.child1_name AS studentName,
      u.vehicle_number,
      u.full_name AS guardianName,
      'Parent' AS relationship,
      p.detected_at AS arrivalTime,
      'Arrived' AS status
    FROM plate_logs p
    INNER JOIN users u
      ON p.detected_plate = u.vehicle_number
    ORDER BY p.detected_at DESC;
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error("Queue Fetch Error:", err);
      return res.status(500).json({ error: "Database error", details: err });
    }
    res.json(results);
  });
});


// Start server on port 5000
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

