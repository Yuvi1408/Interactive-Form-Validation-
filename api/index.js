const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
require("dotenv").config();

const app = express();

// Middlewares
app.use(helmet());
app.use(cors());
app.use(express.json());

// Note: The rate limiter applies to all routes handled by this function
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(apiLimiter);

// In-memory data store
const users = new Map();
users.set("existinguser", { username: "existinguser" });

// API Endpoints
// FIXED: Removed "/api" prefix from the route
app.post("/validate-username", (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ available: false, message: "Username is required." });
  }
  const isTaken = users.has(username.toLowerCase());
  res.json({ available: !isTaken });
});

// FIXED: Removed "/api" prefix from the route
app.post(
  "/submit-form",
  body("username")
    .trim()
    .isLength({ min: 3 })
    .withMessage("Username must be at least 3 characters long.")
    .custom(async (value) => {
      if (users.has(value.toLowerCase())) {
        return Promise.reject("Username is already taken.");
      }
    }),
  body("email").trim().isEmail().withMessage("Please provide a valid email address.").normalizeEmail(),
  body("password").isLength({ min: 8 }).withMessage("Password must be at least 8 characters long."),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      const { username, email, password } = req.body;
      const hashedPassword = await bcrypt.hash(password, 12);

      const newUser = {
        id: Date.now().toString(),
        username: username,
        email: email,
        ...req.body,
        password: hashedPassword,
        registeredAt: new Date().toISOString()
      };
      
      users.set(username.toLowerCase(), newUser);

      console.log(`[INFO] New user registered: Username=${username}, Email=${email}`);
      
      const userResponse = { ...newUser };
      delete userResponse.password;

      res.status(201).json({ 
          success: true, 
          message: "Registration successful!",
          user: userResponse 
      });

    } catch (error) {
      console.error(`[ERROR] Registration failed for ${req.body.username}:`, error);
      res.status(500).json({ success: false, message: "An internal server error occurred." });
    }
  }
);

// Export the app for Vercel
module.exports = app;