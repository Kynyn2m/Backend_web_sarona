const db = require("../config/db");
const bcrypt = require("bcryptjs");

exports.updateUser = (req, res) => {
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
};

exports.getUsers = (req, res) => {
  const query = "SELECT id, username FROM users"; // Select basic user info
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send("Server error retrieving users");
      return;
    }
    res.status(200).json(results);
  });
};

exports.registerSuperAdmin = (req, res) => {
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
      db.query(insertUserRoleQuery, [userId, roleId], (err) => {
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
};
