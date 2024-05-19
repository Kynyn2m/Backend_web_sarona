const db = require("../config/db");

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

module.exports = checkRole;
