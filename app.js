//jshint esversion:6
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, {secret: process.env.SECRETS, encryptedFields: ["password"]});

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function (err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
    res.render("home");
})

app.get("/register", function(req, res) {
    res.render("register");
})

app.get("/login", function(req, res) {
    res.render("login");
})

app.get("/Secrets", function(req, res) {
    if(req.isAuthenticated()) {
        User.find(
            {secret: {$ne: null}},
            function(err, users) {
                if (!err) {
                    res.render("secrets", {usersWithSecret: users});
                }
            }
        )
    } else {
        res.redirect("/login");
    }
})

app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/Secrets');
});

app.post("/register", function(req, res) {
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/Secrets");
            })
        }
    })
})

app.post("/login", function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.passport
    })

    req.login(user, function(err) {
        if (err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/Secrets");
            })
        }
    })
})

app.get("/submit", function(req, res){
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})

app.post("/submit", function(req, res) {
    console.log(req.user);
    User.find({_id: req.user._id},
        function(err, foundUser) {
            if(err) {
                console.log(err);
            } else {
                if (foundUser) {
                    foundUser[0].secret = req.body.secret;
                    foundUser[0].save();
                    res.redirect("/Secrets");
                }
            }
        })
})

app.listen(3000, function() {
    console.log("Listening to port 3000.");
})