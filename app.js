var express = require('express');
var app = express();

//Access Mongo DB PW & Cookie Secret//
var config = require('./config.secret');

const expressMongoDb = require('express-mongo-db');
app.use(expressMongoDb(config.mongo_uri));

//connect to Mongo Db//
var mongo = require('mongodb');
var MongoClient = require('mongodb').MongoClient;

//set view //
app.set('view engine', 'ejs');
/*access static pages*/
app.use(express.static('assets'));

//Cookie Parser//
var cookieParser = require('cookie-parser');
app.use(cookieParser(config.cookie_secret));

//parse post body//
var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: false }))

//Bcrypt for password hashing//
var bcrypt = require('bcryptjs');
const saltRounds = 10;


app.get('/', function(req,res){
  res.render('landing');
  console.log('Cookies: ', req.cookies)
});

app.post('/', function(req,res){
  console.log("I'm in log-in post", req.body.username, req.body.password);
  var username = req.body.username;
  var password = req.body.password;
  //search username in database
  req.db.collection('Authenticate').findOne({username: username}, function (err, user){
    if (!user){
      console.log('username not found');
      res.redirect('/');
    }
    else
    {
      console.log(user.password);
      //compare username and password. Must compare bcrype password//
      bcrypt.compare( password, user.password, function(err, result) {
        if(result) {
          // Passwords match
          console.log('username and password match');
          res.cookie('username', username, {signed: true});
          res.redirect('/home');
        } else {
          // Passwords don't match
          console.log('username and password do not match');
        }
      });
    };
  });
});

app.get('/home', function (req, res){
  console.log('Cookies: ', req.cookies)
  console.log('signed cookie:', req.signedCookies);
  //if user logged in (verified by cookies), then proceed to home,
  //else proceed to log in page//
  if (req.signedCookies.username !== undefined){
    res.render('home');
  }
  else{
    res.redirect('/');
  }
});

app.get('/signup', function(req, res){
  res.render('signup');
});

app.post('/signup', function(req, res){
  console.log("I'm in sign up Post");
  var name = req.body.name;
  var username = req.body.username;
  var password = req.body.password;
  var email = req.body.email;
  //hash password then insert into database//
  bcrypt.hash(password, saltRounds, function(err, hash) {
    req.db.collection('Authenticate').insertOne({'name': name, 'username': username,
    'email': email, 'password': hash}, function(err, result){
      if (err) throw err;
      console.log("document inserted");
      res.redirect('/');
    });
  });
});

//log user out, cookies cleared //
app.get('/signout', function(req,res){
  res.clearCookie('username');
  res.redirect('/');
});

if (require.main === module) {
    app.listen(config.port, function() {
        console.log("Local server started");
    });
}

module.exports = app;
