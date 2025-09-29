const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(express.json());

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api", apiLimiter);

const users = new Map();
users.set("existinguser", { username: "existinguser" });

app.post("/api/validate-username", (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ available: false, message: "Username is required." });
  }
  const isTaken = users.has(username.toLowerCase());
  res.json({ available: !isTaken });
});

app.post(
  "/api/submit-form",
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
          id: Date.now().toString(), // Simple unique ID
          username: username,
          email: email,
          ...req.body, // Include other form fields
          password: hashedPassword,
          registeredAt: new Date().toISOString()
      };
      
      users.set(username.toLowerCase(), newUser);

      console.log(`[INFO] New user registered: Username=${username}, Email=${email}`);
      
      // Create a user object to send back (WITHOUT the password)
      const userResponse = { ...newUser };
      delete userResponse.password;

      // UPDATED: Return the user object in the response
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

app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));