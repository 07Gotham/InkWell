require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("./models/User");
const Blog = require("./models/Blog");

const app = express();
const PORT = process.env.PORT || 5000;

if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET is missing from .env");
}

if (!process.env.MONGODB_URI) {
  throw new Error("MONGODB_URI is missing from .env");
}

const allowedOrigins = [
  "http://localhost:5173",
  process.env.CLIENT_URL
].filter(Boolean);

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true
  })
);

app.use(express.json({ limit: "100kb" }));

function createToken(user) {
  return jwt.sign(
    { sub: user._id.toString(), email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "2h" }
  );
}

function authenticateToken(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ message: "Login required" });
  }

  try {
    req.auth = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res
      .status(401)
      .json({ message: "Invalid or expired token" });
  }
}

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    message: "Inkwell API is running",
  });
});

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    if (
      typeof name !== "string" ||
      !name.trim() ||
      typeof email !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) ||
      typeof password !== "string" ||
      password.length < 8
    ) {
      return res.status(400).json({
        message: "Provide a name, valid email, and password of at least 8 characters",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await User.findOne({
      email: normalizedEmail,
    });

    if (existingUser) {
      return res.status(409).json({
        message: "Email is already registered",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      passwordHash,
    });

    return res.status(201).json({
      message: "Registration successful",
      token: createToken(user),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "Email is already registered",
      });
    }

    console.error("Registration error:", error.message);
    return res.status(500).json({
      message: "Registration failed",
    });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase(),
    }).select("+passwordHash");

    if (
      !user ||
      !(await bcrypt.compare(password, user.passwordHash))
    ) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    return res.json({
      message: "Login successful",
      token: createToken(user),
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);
    return res.status(500).json({
      message: "Login failed",
    });
  }
});


app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.auth.sub).select("name email");

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    res.json({ user });
  } catch (error) {
    res.status(500).json({
      message: "Could not retrieve profile"
    });
  }
});

// Create a blog — login required
app.post("/api/blogs", authenticateToken, async (req, res) => {
  try {
    const { title, category, excerpt, content = "" } = req.body || {};

    if (
      typeof title !== "string" || !title.trim() ||
      typeof category !== "string" || !category.trim() ||
      typeof excerpt !== "string" || !excerpt.trim() ||
      typeof content !== "string"
    ) {
      return res.status(400).json({
        message: "Valid title, category, introduction, and content are required",
      });
    }

    if (
      title.length > 200 ||
      category.length > 80 ||
      excerpt.length > 1000 ||
      content.length > 50000
    ) {
      return res.status(400).json({
        message: "One or more blog fields exceed the allowed length",
      });
    }

    const user = await User.findById(req.auth.sub);

    if (!user) {
      return res.status(401).json({
        message: "User no longer exists",
      });
    }

    const blog = await Blog.create({
      title: title.trim(),
      category: category.trim(),
      excerpt: excerpt.trim(),
      content: content.trim(),
      author: user.name,
      userId: user._id,
    });

    return res.status(201).json({
      message: "Blog created",
      blog,
    });
  } catch (error) {
    console.error("Create blog error:", error.message);
    return res.status(500).json({
      message: "Could not create blog",
    });
  }
});

// Retrieve all blogs
app.get("/api/blogs", async (req, res) => {
  try {
    const { search, category } = req.query;
    const filter = {};

    if (category && category !== "All") {
      filter.category = category;
    }

    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: "i" } },
        { excerpt: { $regex: search, $options: "i" } },
        { content: { $regex: search, $options: "i" } }
      ];
    }

    const blogs = await Blog.find(filter)
      .sort({ createdAt: -1 })
      .lean();

    res.json({ blogs });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Could not retrieve blogs"
    });
  }
});


app.get("/api/my-blogs", authenticateToken, async (req, res) => {
  try {
    const blogs = await Blog.find({
      userId: req.auth.sub
    })
      .sort({ createdAt: -1 })
      .lean();

    res.json({ blogs });
  } catch (error) {
    res.status(500).json({
      message: "Could not retrieve your blogs"
    });
  }
});
// Retrieve one blog by its database ID

app.get("/api/blogs/:id", async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({
        message: "Invalid blog ID"
      });
    }

    const blog = await Blog.findById(req.params.id);

    if (!blog) {
      return res.status(404).json({
        message: "Blog not found"
      });
    }

    res.json({ blog });

  } catch (error) {
    res.status(500).json({
      message: "Could not retrieve blog"
    });
  }
});

app.put("/api/blogs/:id", authenticateToken, async (req, res) => {
  try {
    const { title, category, excerpt, content = "" } = req.body;

    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid blog ID" });
    }

    if (
      typeof title !== "string" || !title.trim() ||
      typeof category !== "string" || !category.trim() ||
      typeof excerpt !== "string" || !excerpt.trim() ||
      typeof content !== "string"
    ) {
      return res.status(400).json({ message: "All required fields must be valid" });
    }

    if (
      title.length > 200 ||
      category.length > 80 ||
      excerpt.length > 1000 ||
      content.length > 50000
    ) {
      return res.status(400).json({ message: "Blog fields are too long" });
    }

    const blog = await Blog.findOneAndUpdate(
      {
        _id: req.params.id,
        userId: req.auth.sub,
      },
      {
        title: title.trim(),
        category: category.trim(),
        excerpt: excerpt.trim(),
        content: content.trim(),
      },
      { new: true, runValidators: true }
    );

    if (!blog) {
      return res.status(404).json({
        message: "Blog not found or you are not its owner",
      });
    }

    res.json({ message: "Blog updated successfully", blog });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Could not update blog" });
  }
});


app.delete("/api/blogs/:id", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: "Invalid blog ID" });
    }

    const blog = await Blog.findOneAndDelete({
      _id: req.params.id,
      userId: req.auth.sub,
    });

    if (!blog) {
      return res.status(404).json({
        message: "Blog not found or you are not its owner",
      });
    }

    res.json({ message: "Blog deleted successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Could not delete blog" });
  }
});

app.use((req, res) => {
  res.status(404).json({ message: "API route not found" });
});

async function startServer() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);

    console.log("Connected to MongoDB");

    app.listen(PORT, () => {
      console.log(`Inkwell API running at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1);
  }
}

startServer();
