const express = require("express");
const mysql = require("mysql");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const mongoose = require("mongoose");

const app = express();
const jwt = require("jsonwebtoken");
app.use(cors());
app.use(express.json()); // Middleware to parse JSON bodies

// MySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "12345678",
  database: "mywebapp",
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to database:", err);
    return;
  }
  console.log("Connected to database");
});

// Register endpoint
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, 8, (err, hashedPassword) => {
    if (err) {
      res.status(500).send("Error hashing password");
      return;
    }
    const query = "INSERT INTO users (username, password) VALUES (?, ?)";
    db.query(query, [username, hashedPassword], (err, result) => {
      if (err) {
        res.status(500).send("Error registering new user");
        return;
      }
      res.status(200).send("User registered");
    });
  });
});

// Login endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const query = "SELECT id, password FROM users WHERE username = ?";
  db.query(query, [username], async (err, results) => {
    if (err) {
      res.status(500).send("Server error");
      return;
    }
    if (results.length === 0) {
      res.status(401).json({ message: "Authentication failed" });
      return;
    }
    const userPassword = results[0].password;
    const authenticated = await bcrypt.compare(password, userPassword);
    if (authenticated) {
      const user = { id: results[0].id, username: username };
      const accessToken = jwt.sign(user, "your_secret_key", {
        expiresIn: "1h",
      });
      res.json({
        message: "Logged in successfully",
        token: accessToken,
      });
    } else {
      res.status(401).json({ message: "Authentication failed" });
    }
  });
});

// Update User endpoint
app.put("/update-user/:id", (req, res) => {
  const { username, password } = req.body;
  const userId = req.params.id;

  bcrypt.hash(password, 8, (err, hashedPassword) => {
    if (err) {
      res.status(500).send("Error hashing password");
      return;
    }
    const query = "UPDATE users SET username = ?, password = ? WHERE id = ?";
    db.query(query, [username, hashedPassword, userId], (err, result) => {
      if (err) {
        res.status(500).send("Error updating user");
        return;
      }
      res.status(200).send("User updated successfully");
    });
  });
});
// GET users endpoint
app.get("/users", (req, res) => {
  const query = "SELECT id, username FROM users"; // Select basic user info
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send("Server error retrieving users");
      return;
    }
    res.status(200).json(results);
  });
});

function checkPermission(permission) {
  return async (req, res, next) => {
    const userId = req.user.id; // Assume user id is set in req.user by a previous auth middleware
    const query = `
            SELECT p.name FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            JOIN roles r ON rp.role_id = r.id
            JOIN users u ON u.role_id = r.id
            WHERE u.id = ? AND p.name = ?;
        `;
    const results = await db.promise().query(query, [userId, permission]);
    if (results[0].length > 0) {
      return next();
    } else {
      res.status(403).json({
        message: "Access Denied: You do not have the required permission",
      });
    }
  };
}

app.post("/api/posts", checkPermission("post"), (req, res) => {
  // Logic to handle post creation
});

app.post("/assign-permission", checkRole("admin"), (req, res) => {
  const { userId, permissionId } = req.body;
  const query =
    "INSERT INTO user_permissions (user_id, permission_id) VALUES (?, ?)";
  db.query(query, [userId, permissionId], (err) => {
    if (err) {
      res.status(500).send("Error assigning permission");
      return;
    }
    res.status(200).send("Permission assigned successfully");
  });
});

app.get("/permissions", (req, res) => {
  const query = "SELECT * FROM permissions"; // Make sure this table exists and has data
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send("Error retrieving permissions: " + err.message);
      return;
    }
    res.json(results);
  });
});

// បន្ថែម middleware ដើម្បីពិនិត្យ JWT និងផ្ទៀងផ្ទាត់សិទ្ធិ
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, "your_secret_key", (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Middleware ពិនិត្យមើលសិទ្ធិ
function checkRole(roleRequired) {
  return (req, res, next) => {
    const userId = req.user.id;
    const query = `
      SELECT r.name FROM roles r
      JOIN user_roles ur ON ur.role_id = r.id
      WHERE ur.user_id = ? AND r.name = ?;
    `;
    db.query(query, [userId, roleRequired], (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).send("Server Error");
      }
      if (results.length > 0) {
        next();
      } else {
        res.status(403).send("Access Denied");
      }
    });
  };
}

// បន្ថែមកូដក្នុង app.use ដើម្បីប្រើ middleware ពិនិត្យមើលសិទ្ធិ
app.use(authenticateToken);

app.post("/api/posts", checkRole("admin"), (req, res) => {
  res.send("Post created successfully");
});

app.post("/assign-permission", checkRole("admin"), (req, res) => {
  const { userId, permissionId } = req.body;
  const query =
    "INSERT INTO user_permissions (user_id, permission_id) VALUES (?, ?)";
  db.query(query, [userId, permissionId], (err, result) => {
    if (err) {
      res.status(500).send("Error assigning permission");
      return;
    }
    res.status(200).send("Permission assigned successfully");
  });
});

app.get("/permissions", checkRole("admin"), (req, res) => {
  const query = "SELECT * FROM permissions";
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send("Error retrieving permissions");
      return;
    }
    res.json(results);
  });
});

app.post("/assign-role", checkRole("admin"), (req, res) => {
  const { userId, roleId } = req.body;
  const query = "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)";
  db.query(query, [userId, roleId], (err, result) => {
    if (err) {
      res.status(500).send("Error assigning role");
      return;
    }
    res.status(200).send("Role assigned successfully");
  });
});

// Super Admin Registration endpoint
// Correctly setup the endpoint without authentication middleware
app.post("/register-super-admin", (req, res) => {
  console.log("Registering super admin with:", req.body);
  const { username, password } = req.body;
  bcrypt.hash(password, 8, (err, hashedPassword) => {
    if (err) {
      res.status(500).send("Error hashing password");
      return;
    }
    const insertUserQuery =
      "INSERT INTO users (username, password) VALUES (?, ?)";
    db.query(insertUserQuery, [username, hashedPassword], (err, userResult) => {
      if (err) {
        res.status(500).send("Error registering new user");
        return;
      }
      const userId = userResult.insertId;
      const roleId = 1; // Ensure this role ID corresponds to 'super admin' in your roles table
      const insertUserRoleQuery =
        "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)";
      db.query(insertUserRoleQuery, [userId, roleId], (err, roleResult) => {
        if (err) {
          res.status(500).send("Error assigning role");
          return;
        }
        res
          .status(200)
          .send("Super admin registered and role assigned successfully");
      });
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
