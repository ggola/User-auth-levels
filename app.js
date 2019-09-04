//jshint esversion:6
require('dotenv').config();
// .env -> NAME=value (strict!)
// process.env.NAME (to use it)

const express = require('express');
const bodyParser = require('body-Parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
//const encrypt = require('mongoose-encryption');
//const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

//**************************************************************

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

// 1. Set up session
app.use(session({
  secret: "Sulemaniperleborrepassaunbirrino.",
  resave: false,
  saveUninitialized: false
}));
// 2. Initialize passport on the app
app.use(passport.initialize());
// 3. Tell app to use passport to manage our session
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});
// Secrect encryption key: longstring unguessable
// Add encryption as PLUGIN to the schema (plugins extend schema's functionalities)
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});

// 4. Add passport local mongoose as a plugin to the schema
//    We use this to hash + salt passwords and to add users to DB
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

// 5. Configure the passport local configuration
// --- CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());
// --- use static serialize and deserialize of model for passport session support
// --- SERIALIZE: create the cookie for the session of current user
// --- DESERIALIZE: open the cookie and get info about user
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//**************************************************************

app.get("/", function(req, res){
  res.render('home');
});

app.get("/login", function(req, res){
  res.render('login');
});

app.get("/register", function(req, res){
  res.render('register');
});

app.get("/secrets", function(req, res){
  // Verify that user is authenticated (isAuthenticated is from passportLocalMongoose)
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    // here the cookie is deserialized
    // force user to login page
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
  // .logout is method from passport
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res){

  // Use passportLocalMongoose
  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      // NOTE: the following callback is called only if the registration was successful
      passport.authenticate("local")(req, res, function(){
        // here the cookie is serialized.
        // the app.get("/secrets") handles the authentication
        res.redirect("/secrets");
      });
    }
  });

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     //password: md5(req.body.password)
  //     password: hash
  //   });
  //   newUser.save(function(err){
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       res.render('secrets');
  //     }
  //   });
  // });

});

app.post("/login", function(req, res){

  const newUser = new User({
    username: req.body.username,
    password: req.body.password
  });
  // Use passport method login() to login and authenticate the newUser
  req.login(newUser, function(err){
    if (err) {
      console.log(err);
    } else {
      // same as for register
      passport.authenticate("local")(req, res, function(){
        // here we send a cookie to the browser to store with the info that the current user is authorized (in the cookie content) to access the "secrets" page
        res.redirect("/secrets");
      });
    }
  })

  // const username = req.body.username;
  // //const password = md5(req.body.password);
  // const password = req.body.password;
  // User.findOne({email: username}, function(err, foundUser){
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       // Compare user-entered password with foundUser hash (= .password) - saltRounds are stored during registration
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //           if (result === true) {
  //             res.render('secrets');
  //           } else {
  //             console.log("Password is not correct");
  //           }
  //       });
  //       // if (foundUser.password === password) {
  //       //   res.render('secrets');
  //       // } else {
  //       //   console.log("Password is not correct");
  //       // }
  //     } else {
  //       console.log("User does not exist");
  //     }
  //   }
  // });

});

// NOTE: Cookies get all deleted when the server is restarted
app.listen(3000, function() {
  console.log("Server running on port 3000");
});
