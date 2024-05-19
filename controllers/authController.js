const db = require("../config/db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

exports.register = (req, res) => {
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
};

exports.login = async (req, res) => {
  const { username, password } = req.body;
  const query = "SELECT id, username, password FROM users WHERE username = ?";
  db.query(query, [username], async (err, results) => {
    if (err) {
      res.status(500).send("Server error");
      return;
    }
    if (results.length === 0) {
      res.status(401).json({ message: "Authentication failed" });
      return;
    }
    const user = results[0];
    const authenticated = await bcrypt.compare(password, user.password);
    if (authenticated) {
      const userPayload = { id: user.id, username: user.username };
      const accessToken = jwt.sign(userPayload, process.env.SECRET_KEY, {
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
};
