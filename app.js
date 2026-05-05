require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const Joi = require("joi");
const { MongoClient } = require("mongodb");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const MONGODB_HOST = process.env.MONGODB_HOST;
const MONGODB_USER = process.env.MONGODB_USER;
const MONGODB_PASSWORD = process.env.MONGODB_PASSWORD;
const MONGODB_DATABASE = process.env.MONGODB_DATABASE;
const MONGODB_SESSION_SECRET = process.env.MONGODB_SESSION_SECRET;
const NODE_SESSION_SECRET = process.env.NODE_SESSION_SECRET;

const MONGO_URI =
  process.env.MONGO_URI ||
  `mongodb+srv://${MONGODB_USER}:${MONGODB_PASSWORD}@${MONGODB_HOST}/?appName=${MONGODB_DATABASE}`;

let userCollection;

async function connectDB() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  console.log("Connected to MongoDB");
  const db = client.db(MONGODB_DATABASE);
  userCollection = db.collection("users");
}

connectDB().catch((err) => {
  console.error("Failed to connect to MongoDB:", err);
  process.exit(1);
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: NODE_SESSION_SECRET,
    store: MongoStore.create({
      mongoUrl: MONGO_URI,
      crypto: { secret: MONGODB_SESSION_SECRET },
      collectionName: "sessions",
    }),
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 60 * 60 * 1000,
      secure: false,
    },
  }),
);

// Routes

app.get("/", (req, res) => {
  if (req.session.userId) {
    res.send(`
      <h1>Hello, ${req.session.name}!</h1>
      <button onclick="window.location.href='/members'">Go to Members Area</button><br><br>
      <button onclick="window.location.href='/logout'">Logout</button>
    `);
  } else {
    res.send(`
      <button onclick="window.location.href='/signup'">Sign up</button><br><br>
      <button onclick="window.location.href='/login'">Log in</button>
    `);
  }
});

app.get("/signup", (req, res) => {
  res.send(`
    <h2>create user</h2>
    <form action="/signupSubmit" method="POST">
      <input type="text"     name="name"     placeholder="name"     required /><br>
      <input type="email"    name="email"    placeholder="email"    required /><br>
      <input type="password" name="password" placeholder="password" required /><br>
      <button type="submit">Submit</button>
    </form>
  `);
});

app.post("/signupSubmit", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name) {
    return res.send(`Name is required.<br><a href="/signup">Try again</a>`);
  }
  if (!email) {
    return res.send(`Email is required.<br><a href="/signup">Try again</a>`);
  }
  if (!password) {
    return res.send(`Password is required.<br><a href="/signup">Try again</a>`);
  }

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    return res.send(`Invalid input.<br><a href="/signup">Try again</a>`);
  }

  const passwordHash = await bcrypt.hash(password, 10);

  await userCollection.insertOne({ name, email, passwordHash });

  req.session.userId = email;
  req.session.name = name;
  res.redirect("/members");
});

app.get("/login", (req, res) => {
  res.send(`
    <h2>log in</h2>
    <form action="/loginSubmit" method="POST">
      <input type="email"    name="email"    placeholder="email"    required /><br>
      <input type="password" name="password" placeholder="password" required /><br>
      <button type="submit">Submit</button>
    </form>
  `);
});

app.post("/loginSubmit", async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    return res.send(`Invalid input.<br><a href="/login">Try again</a>`);
  }

  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.send(
      `Invalid email/password combination.<br><a href="/login">Try again</a>`,
    );
  }

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) {
    return res.send(
      `Invalid email/password combination.<br><a href="/login">Try again</a>`,
    );
  }

  req.session.userId = user.email;
  req.session.name = user.name;
  res.redirect("/members");
});

app.get("/members", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/");
  }

  const images = ["image1.jpg", "image2.jpg", "image3.jpg"];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <h1>Welcome to the members area, ${req.session.name}!</h1>
    <img src="/images/${randomImage}" alt="Random image" style="max-width:400px;" /><br><br>
    <button onclick="window.location.href='/logout'">Sign out</button>
  `);
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Logout failed");
    }
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

app.use((req, res) => {
  res.status(404).send("<h1>Page not found - 404</h1>");
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
