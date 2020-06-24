
//jshint esversion:6
// for .env file and access the enviroment variables(must at the top of the code)
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
//session & cookies
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
// //encryption AES
// const encrypt = require("mongoose-encryption");

//login through google
const GoogleStrategy = require('passport-google-oauth20').Strategy;

//login through facebook
const FacebookStrategy = require('passport-facebook').Strategy;

//login through github
const GitHubStrategy = require('passport-github2').Strategy;


const findOrCreate = require("mongoose-findorcreate");

// //hashing
// const md5 = require("md5");
// // md5() method to apply


// //hashing and salting
// const bcrypt = require('bcrypt');
// const saltRounds = 10;


const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

//session setup
app.use(session({
  secret: "I am Gaurab.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

//TODO
mongoose.connect('mongodb://localhost:27017/SecretsDB', {useNewUrlParser: true, useUnifiedTopology: true});
//for session error resolve
mongoose.set("useCreateIndex", true);



const userAccountSchema = new mongoose.Schema({
  username: {
    type : String,

  },
  password: {
    type: String
  },
  googleId: {
    type: String
  },
  facebookId: {
    type: String
  },
  githubId: {
    type: String
  },
  secretStatement: {
    type: String
  }
});




// //encryption applied
// userAccountSchema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields: ["password"]});


//session & cookies
userAccountSchema.plugin(passportLocalMongoose);

//login through google
userAccountSchema.plugin(findOrCreate);

const User = mongoose.model("User", userAccountSchema);


//passport-local setting
passport.use(User.createStrategy());

// //for local registation
// passport.serializeUser(User.serializeUser());    //create a session
// passport.deserializeUser(User.deserializeUser());   //destroy the session

//for any type of registation
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//for google login setup
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//for facebook login setup
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//for github login setup
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

app.get("/register", function(req, res){
  res.render("register");
});


app.get("/secrets", function(req, res){
    if(req.isAuthenticated()){
      //find all the secrets from database
      User.find({"secretStatement": {$ne: null}}, function(err, doc5){
        if(!err){
          if(doc5){
            res.render("secrets", {userWithAllSecrets: doc5});
          }
        }
      });

    }else{
      res.redirect("/login");
    }
});


app.post("/register", function(req, res){
  User.findOne({username: req.body.username}, function(err, doc1){
    if(!err){
      if(doc1){
        res.send("Account Already Created");
      }else{
        //   //hasing & salting
        // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        //     // Store hash in your password DB.
        //     const newUser = new User({
        //       username: req.body.username,
        //       password: hash
        //     });
        //     newUser.save(function(err){
        //       if(err){
        //         console.log(err);
        //       }else{
        //         res.render("secrets");
        //       }
        //     });
        // });


        //cookies & Sessions
        //username must
        User.register({ username: req.body.username}, req.body.password, function(err, createdUser){
          if(err){
            console.log(err);
            res.redirect("/register");
          }else{
            passport.authenticate("local")(req, res,function(){
              res.redirect("/secrets");
            });
          }
        });
       }
    }
  });





});


//login through google redirect
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
    });


//login through facebook redirect
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


//login through github redirect
app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/secrets',
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });



app.get("/login", function(req, res){
  res.render("login");
});

app.post("/login", function(req, res){
  // User.findOne({username: req.body.username}, function(err, doc2){
  //   if(!err){
  //     if(doc2){
  //           //  compare of hashing & salting
  //       bcrypt.compare(req.body.password, doc2.password, function(err, result) {
  //         if(result === true){
  //           res.render("secrets");
  //         }else{
  //           res.send("Either Email Or Password is Wrong");
  //         }
  //       });
  //     }else{
  //       res.send("Account Is Not Created");
  //     }
  //   }
  // });


//session & cookies
  var user = new User({
    username: req.body.username,
    password:  req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req, res,function(){
        res.redirect("/secrets");
      });
    }
  });


});

//session ending
app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  var submitedStatement = req.body.secret;
  User.findById( req.user.id , function(err, founddoc){
    if(!err){
      if(founddoc){
          founddoc.secretStatement = submitedStatement;
          founddoc.save(function(err){
            if(!err){
              res.redirect("/secrets")
            }
          });
      }
    }
  });

});


app.listen(3000, function() {
  console.log("Server started on port 3000");
});
