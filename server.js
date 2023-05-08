const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const Joi = require("joi");
const bcrypt = require("bcrypt");
const { MongoClient, ObjectId } = require("mongodb");
const url = require("url");
require("dotenv").config();

const app = express();
let usersCollection;

const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_cluster = process.env.MONGODB_CLUSTER;
const mongodb_database = process.env.MONGODB_DATABASE;
const node_session_secret = process.env.NODE_SESSION_SECRET;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const hashedPassword = process.env.HASHED_PASSWORD;

const uri = `mongodb+srv://${mongodb_user}:${encodeURIComponent(mongodb_password)}@${mongodb_cluster}/${mongodb_database}`;

app.set('view engine', 'ejs');

const navLinks = [
  {name: "Home", link: "/"},
  {name: "Members", link: "/members"},
  {name: "Admin", link: "/admin"}
]

MongoClient.connect(uri, { useUnifiedTopology: true })
  .then((client) => {
    console.log("Connected to MongoDB");
    const db = client.db("test");
    usersCollection = db.collection("users");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB", error);
  });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Set up connect-mongo for session storage
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${encodeURIComponent(mongodb_password)}@${mongodb_cluster}/${mongodb_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    resave: true,
    saveUninitialized: false,
    cookie: {
      maxAge: 60 * 60 * 1000,
    },
  })
);


app.get("/", (req, res) => {
  res.render("home", {navLinks: navLinks, currentURL: url.parse(req.url).pathname, loggedIn: req.session.loggedIn, username: req.session.username });
});

app.get('/signup', (req, res) => {
  res.render("signup", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

app.post("/signup", async (req, res) => {
  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(50).required()
  });
  const validationResult = schema.validate(req.body);

  if (validationResult.error) {
    res.status(400).send(validationResult.error.details[0].message + "<br><a href='/signup'>Go back to sign up</a>");
  } else {
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const newUser = {
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
        admin: true // Set the admin field to false for new users
      };
      const result = await usersCollection.insertOne(newUser);
      req.session.loggedIn = true;
      req.session.username = newUser.name;
      req.session.email = newUser.email; // Save the email to the session
      res.redirect("/members");
    } catch (error) {
      res.status(500).send("Error signing up.");
    }
  }
});


app.get("/admin", async (req, res) => {
  if (req.session.loggedIn) {
    const currentUser = await usersCollection.findOne({ email: req.session.email });
    if (currentUser && currentUser.admin) {
      const users = await usersCollection.find({}).toArray();
      res.render("admin", {navLinks: navLinks, currentURL: url.parse(req.url).pathname, users: users });
    } else {
      res.status(403).send("You must be an admin to access this page.<br><a href='/'>Go back to home page</a>");
    }
  } else {
    res.status(403).send("You must be logged in to access this page.<br><a href='/'>Go back to home page</a>");
  }
});

app.get("/promote/:userId", async (req, res) => {
  const userId = req.params.userId;
  try {
    await usersCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { admin: true } });
    res.redirect("/admin");
  } catch (error) {
    res.status(500).send("Error promoting user.");
  }
});

app.get("/demote/:userId", async (req, res) => {
  const userId = req.params.userId;
  try {
    await usersCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { admin: false } });
    res.redirect("/admin");
  } catch (error) {
    res.status(500).send("Error demoting user.");
  }
});


app.get("/login", (req, res) => {
  res.render("login", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

app.post("/login", async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(50).required()
  });
  const validationResult = schema.validate(req.body);

  if (validationResult.error) {
    res.status(400).send(validationResult.error.details[0].message + "<br><a href='/login'>Go back to log in</a>");
  } else {
    try {
      const user = await usersCollection.findOne({ email: req.body.email });
      if (user && (await bcrypt.compare(req.body.password, user.password))) {
        req.session.loggedIn = true;
        req.session.username = user.name;
        req.session.email = user.email; // Save the user's email to the session
        res.redirect("/");
      } else {
        res.status(401).send("Incorrect email or password.<br><a href='/login'>Go back to log in</a>");
      }
    } catch (error) {
      res.status(500).send("Error logging in.");
    }
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session", err);
      res.status(500).send("Error logging out.");
    } else {
      res.redirect("/");
    }
  });
});

app.get("/members", (req, res) => {
  if (req.session.loggedIn) {
    res.render("members", {navLinks: navLinks, currentURL: url.parse(req.url).pathname, username: req.session.username });
  } else {
    res.status(403).send("You must be logged in to access the members area.<br><a href='/'>Go back to home page</a>");
  }
});


app.get('*', (req, res) => {
  res.status(404);
  res.render("404", {navLinks: navLinks, currentURL: url.parse(req.url).pathname});
});

app.listen(3000, () => {
  console.log('server is running on port 3000');
});