import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import env from "dotenv";
//import { Strategy } from "passport-local";
import session from "express-session";
//import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
    session({
      secret: "kofta",
      resave: false,
      saveUninitialized: true,
      cookie:{
        maxAge:1000*60*60*24,
      }
    })
  );

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user:process.env.USER,
    host: process.env.HOST,
    database: process.env.DATABASE,
    password: process.env.PASSWORD,
    port: process.env.PORT,
})

db.connect()

app.get("/",(req,res)=>{
    res.render("home.ejs");
});


app.get("/login",(req,res)=>{
    res.render("login.ejs");
});

app.get("/logout",(req,res)=>{
    res.render("home.ejs");
})

app.get("/contact",(req,res)=>{
    res.render("contact.ejs");
})

app.get("/register",(req,res)=>{
    res.render("register.ejs");
});

app.post("/register",async (req,res)=>{
    const email = req.body.username;
    const password = req.body.password;
    try{
        const checkResult = await db.query('SELECT * FROM users WHERE email =$1',[email]);
        if(checkResult.rows.length>0){
            res.send('Email already exists.Try logging in.');
        }
        else{
            bcrypt.hash(password,saltRounds,async(err,hash)=>{
                if(err){
                    console.log("error hashing: ",err);
                }
                else{
                    const result = await db.query('INSERT INTO users (email,password) VALUES ($1,$2)',[email,hash]);
                    console.log(result);
                    res.render("shop.ejs");
                }
            })
        }
    }
    catch(err){
        console.log(err);
    }
})

app.post("/login",async(req,res)=>{
    const email = req.body.username;
    const loginPassword = req.body.password;
    try{
        const result = await db.query('SELECT * FROM users WHERE email = $1',[email]);
        if(result.rows.length>0){
            const user = result.rows[0];
            const storedHashedPassword = user.password;
            bcrypt.compare(loginPassword,storedHashedPassword,(err,result)=>{
                if(err){
                    console.log("error comparing passwords",err);
                }
                else{
                    if(result){
                        res.render("shop.ejs");
                    }
                    else{
                        res.send("Incorrect password,Try again")
                    }
                }
            })
        }
        else{
            res.send("user not found");
        }
    }
    catch(err){
        console.log(err);
    }
})


app.listen(port,()=>{
    console.log(`Running on port ${port}`);
})