//jshint esversion:6
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const bcrypt = require("bcrypt");

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

// userSchema.plugin(encrypt, {secret: process.env.SECRETS, encryptedFields: ["password"]});

const User = mongoose.model("User", userSchema);


app.get("/", function(req, res) {
    res.render("home");
})

app.get("/register", function(req, res) {
    res.render("register");
})

app.get("/login", function(req, res) {
    res.render("login");
})

app.post("/register", function(req, res) {
    const saltRounds = 10;
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const user = new User({
            email: req.body.username,
            password: hash
        });
        
        user.save(function(err) {
        if (!err) {
            res.render("secrets");
        } else {
            res.send(err);
        }
    });
    })

    
})

app.post("/login", function(req, res) {
    User.findOne(
        {email: req.body.username},
        function(err, foundUser) {
            if (!err) {
                if (foundUser) {
                    bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
                        if (result == true) {
                            res.render("Secrets");
                        }
                    })
                }
            } else {
                res.send(err);
            }
        }
    )
})

app.listen(3000, function() {
    console.log("Listening to port 3000.");
})