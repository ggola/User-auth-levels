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
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});
// Secrect encryption key: longstring unguessable
// Add encryption as PLUGIN to the schema (plugins extend schema's functionalities)
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});

const User = new mongoose.model("User", userSchema);


app.get("/", function(req, res){
  res.render('home');
});

app.get("/login", function(req, res){
  res.render('login');
});

app.get("/register", function(req, res){
  res.render('register');
});

app.post("/register", function(req, res){

  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    const newUser = new User({
      email: req.body.username,
      //password: md5(req.body.password)
      password: hash
    });
    newUser.save(function(err){
      if (err) {
        console.log(err);
      } else {
        res.render('secrets');
      }
    });
  });
});

app.post("/login", function(req, res){
  const username = req.body.username;
  //const password = md5(req.body.password);
  const password = req.body.password;
  User.findOne({email: username}, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        // Compare user-entered password with foundUser hash (= .password) - saltRounds are stored during registration
        bcrypt.compare(password, foundUser.password, function(err, result) {
            if (result === true) {
              res.render('secrets');
            } else {
              console.log("Password is not correct");
            }
        });
        // if (foundUser.password === password) {
        //   res.render('secrets');
        // } else {
        //   console.log("Password is not correct");
        // }
      } else {
        console.log("User does not exist");
      }
    }
  });
});

app.listen(3000, function() {
  console.log("Server running on port 3000");
});
