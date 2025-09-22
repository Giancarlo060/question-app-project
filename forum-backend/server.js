const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// -------------------- Database --------------------
// Change database name here for your new project
mongoose.connect("mongodb://127.0.0.1:27017/forum_new", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// -------------------- Schemas --------------------
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
});

const ReplySchema = new mongoose.Schema(
  {
    user: String,
    text: String,
  },
  { timestamps: true }
);

const QuestionSchema = new mongoose.Schema(
  {
    user: String,
    text: String,
    category: { type: String, default: "General" },
    replies: [ReplySchema],
  },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);
const Question = mongoose.model("Question", QuestionSchema);

// -------------------- Auth --------------------
const SECRET = "supersecretkey";

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// -------------------- Routes --------------------

// Register
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: "Missing fields" });

    // Case-insensitive username check
    const existingUser = await User.findOne({
      username: { $regex: new RegExp(`^${username}$`, "i") },
    });
    if (existingUser)
      return res.status(400).json({ error: "Username already exists" });

    const hashed = await bcrypt.hash(password, 10);
    await User.create({ username, password: hashed });
    res.json({ message: "User registered" });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({
      username: { $regex: new RegExp(`^${username}$`, "i") },
    });
    if (!user) return res.status(400).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Wrong password" });

    const token = jwt.sign({ username: user.username }, SECRET, {
      expiresIn: "1h",
    });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Get questions (optional category filter)
app.get("/questions", async (req, res) => {
  try {
    const { category } = req.query;
    const filter = category && category !== "All" ? { category } : {};
    const questions = await Question.find(filter).sort({ createdAt: -1 });
    res.json(questions);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Post a question
app.post("/questions", auth, async (req, res) => {
  try {
    const { text, category } = req.body;
    if (!text || !text.trim())
      return res.status(400).json({ error: "Question cannot be empty" });

    const q = await Question.create({
      user: req.user.username,
      text,
      category: category || "General",
      replies: [],
    });
    res.json(q);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Reply to a question
app.post("/questions/:id/reply", auth, async (req, res) => {
  try {
    const q = await Question.findById(req.params.id);
    if (!q) return res.sendStatus(404);

    if (!req.body.text || !req.body.text.trim())
      return res.status(400).json({ error: "Reply cannot be empty" });

    q.replies.push({ user: req.user.username, text: req.body.text });
    await q.save();
    res.json(q);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Delete a question (only owner)
app.delete("/questions/:id", auth, async (req, res) => {
  try {
    const q = await Question.findById(req.params.id);
    if (!q) return res.sendStatus(404);
    if (q.user !== req.user.username) return res.sendStatus(403);

    await Question.findByIdAndDelete(req.params.id);
    res.json({ message: "Question deleted" });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Delete a reply (only owner)
app.delete("/questions/:qid/replies/:rid", auth, async (req, res) => {
  try {
    const q = await Question.findById(req.params.qid);
    if (!q) return res.sendStatus(404);

    const reply = q.replies.id(req.params.rid);
    if (!reply) return res.sendStatus(404);

    if (reply.user !== req.user.username) return res.sendStatus(403);

    reply.remove();
    await q.save();
    res.json({ message: "Reply deleted" });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// -------------------- Start Server --------------------
app.listen(4000, () =>
  console.log("Server running on http://localhost:4000")
);
