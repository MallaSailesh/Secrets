require('dotenv').config();
const express = require('express')
const ejs = require('ejs')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const encrypt = require('mongoose-encryption')

const app = express()
app.use(express.static('public'))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({
    extended : true
}));

mongoose.set('strictQuery', false);
mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email : String  ,
    password : String
});

userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields:['password'] });
const User = new mongoose.model('User', userSchema);

app.get("/",function(req,res){
    res.render('home');
});

app.get("/register",function(req,res){
    res.render('register');
});

app.get("/login",function(req,res){
    res.render('login');
});

app.post("/register",function(req,res){
    const newUser = new User({
        email : req.body.username,
        password : req.body.password
    });

    newUser.save(function(err){ // automatically encrypts when saved 
        if(!err){
            res.render('secrets');
        } else {
            console.log(err);
        }
    });
});

app.post("/login", function(req,res){
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email : username},function(err,foundUser){ // automatically decrypts when found
        if(err){
            res.send(err);
        } else {
            if(foundUser){
                if(foundUser.password === password){
                    res.render('secrets');
                }
            }
        }
    });
});



app.listen(3000,function(){
    console.log("Server started at port 3000");
});