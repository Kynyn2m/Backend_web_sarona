const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const dotenv = require("dotenv");
const db = require("./config/db");

dotenv.config(); // Load environment variables from .env file

const app = express();
app.use(cors());
app.use(express.json()); // Middleware to parse JSON bodies

// Routes
const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes");

app.use("/auth", authRoutes);
app.use("/users", userRoutes);

module.exports = app;
