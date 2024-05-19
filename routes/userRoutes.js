const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");
const authenticateToken = require("../middlewares/authMiddleware");
const checkRole = require("../middlewares/roleMiddleware");

router.put("/update-user/:id", userController.updateUser);
router.get("/users", userController.getUsers);
router.post("/register-super-admin", userController.registerSuperAdmin);

// Example protected routes
router.use(authenticateToken);

router.post("/api/posts", checkRole("admin"), (req, res) => {
  res.send("Post created successfully");
});

router.post("/assign-permission", checkRole("admin"), (req, res) => {
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

router.get("/permissions", checkRole("admin"), (req, res) => {
  const query = "SELECT * FROM permissions";
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).send("Error retrieving permissions");
      return;
    }
    res.json(results);
  });
});

router.post("/assign-role", checkRole("admin"), (req, res) => {
  const { userId, roleId } = req.body;
  const query = "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)";
  db.query(query, [userId, roleId], (err) => {
    if (err) {
      res.status(500).send("Error assigning role");
      return;
    }
    res.status(200).send("Role assigned successfully");
  });
});

module.exports = router;
