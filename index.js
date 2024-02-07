import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import Users from "./models/user.js";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import dotenv from "dotenv"; // Import dotenv for environment variables
import GoogleStrategy from "passport-google-oauth2"
dotenv.config(); // Load environment variables from .env file

const app = express();
const port = 3000;
const saltRounds = 10;
console.log("SESSION_SECRET:", process.env.SESSION_SECRET);

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret: process.env.SESSION_SECRECT, // Use SESSION_SECRET from environment variables
  resave: false,
  saveUninitialized: true,
  cookie:{
    maxAge:1000*60*60*24
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport Configuration
passport.use(new Strategy(async function(username, password, cb) {
  try {
    const user = await Users.findOne({ username });
    if (!user) {
      return cb(null, false, { message: "Incorrect username." });
    }
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return cb(null, false, { message: "Incorrect password." });
      }
      return cb(null, user);
    });
  } catch (err) {
    return cb(err);
  }
}));

passport.use("google",new GoogleStrategy({
    clientID:process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL:"http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo",
},async(accessToken,refreshToken,profile,cb)=>{
    console.log(profile);
}));

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const user = await Users.findById(id);
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/AngelaYU', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to the AngelaYU database successfully');
}).catch((error) => {
  console.error('Error connecting to the database:', error);
});

// Routes
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get("/auth/google",passport.authenticate("google",{
  scope:["profile","email"]
}));

app.get("/auth/google/secrets",passport.authenticate("google",{
  successRedirect:"/secretrs",
  failureRedirect:"login"
}))

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await Users.findOne({ username });
    if (user) {
      console.log("User already exists");
      return res.redirect("/register");
    }
    const hash = await bcrypt.hash(password, saltRounds);
    const newUser = new Users({ username, password: hash });
    await newUser.save();
    req.login(newUser, (err) => {
      if (err) {
        console.error("Error logging in after registration:", err);
        return res.status(500).send("Error logging in after registration");
      }
      res.render("secrets.ejs");
    });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).send("Error registering user");
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
