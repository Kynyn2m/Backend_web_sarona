const express = require("express");
const router = express.Router();

router.post("/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 8);
  const sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
  connection.query(sql, [username, email, hashedPassword], (err, results) => {
    if (err) {
      console.error("Error inserting data into the database:", err);
      res.status(500).send("Failed to register user");
    } else {
      res.status(201).send("User registered successfully");
    }
  });
});

module.exports = router;
