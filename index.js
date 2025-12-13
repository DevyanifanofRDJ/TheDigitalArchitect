import 'dotenv/config';
import express from 'express';
import path from 'path';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import userModel from './model/userModel.js';
import cookieParser from 'cookie-parser';
import client from './redisClient.js';
import nodemailer from 'nodemailer';
import mailContent from './utils/mailContent.js';
import rateLimit from 'express-rate-limit';
import sanitize from 'mongo-sanitize';
import messageModel from './model/messageModel.js';
import forgotPasswordMailContent from './utils/forgotPasswordMailContent.js';

const app=express();
app.set('trust proxy',1);
app.set('view engine','ejs');
const absPathHtml=path.resolve('views');
const url=process.env.MONGO_URL;
const SECRET_KEY=process.env.SECRET_KEY;
const absPathPublic=path.resolve('public');

// --- FIXED TRANSPORTER ---
const transporter = nodemailer.createTransport({
    host: 'smtp.googlemail.com', // <--- CHANGED THIS
    port: 587,
    secure: false, 
    requireTLS: true,
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        ciphers: "SSLv3" 
    },
    family: 4 // Forces IPv4
});

// --- ADDED STARTUP VERIFICATION ---
transporter.verify((error, success) => {
    if (error) {
        console.error("❌ Transporter Error on Startup:", error);
    } else {
        console.log("✅ Transporter Ready: Connection established!");
    }
});

const startServer = async () => {
    try {
        await mongoose.connect(url);
        console.log("Database Connected Successfully!");
        
        // --- FIXED LISTENER ---
        const PORT = process.env.PORT || 3000;
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`); // <--- YOU NEED THIS LOG
        });
    } catch (error) {
        console.log("Error connecting to DB:", error);
    }
}
startServer();

app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.use(express.json());
app.use(express.static(absPathPublic));

// ... (Keep your verifyToken middleware) ...
const verifyToken=(req,resp,next)=>{
    const authHeader=req.headers["authorization"];
    let token;
    if(authHeader){
        token=authHeader.split(" ")[1];
    }
    else if(req.cookies&&req.cookies.token){
        token=req.cookies.token;
    }
    if(!token)
        return resp.sendFile(absPathHtml+'/login.html');
    try{
        const decode=jwt.verify(token,SECRET_KEY);
        req.user=decode;
        next();
    }
    catch(error){
        return resp.sendFile(absPathHtml+'/login.html');
    }
};

const rateCheck=rateLimit({
    windowMs:10*60*1000,
    max:3,
    message:{
        message:"Too Many requests! Try again after 10mins."
    }
});

const preventCache=(req,resp,next)=>{
    resp.set('Cache-Control','no-store,no-cache,must-revalidate,private');
    resp.set('Pragma','no-cache');
    resp.set('Expires','0');
    next();
};

const verifyAdmin=(req,resp,next)=>{
    if(req.user&&req.user.role=='admin')
        return next();
    resp.redirect('/');
};

app.get('/',verifyToken,preventCache,(req,resp)=>{
    resp.sendFile(absPathHtml+'/home.html');
});

app.get('/log',preventCache,(req,resp)=>{
    resp.sendFile(absPathHtml+'/login.html');
});

app.post('/login',preventCache,async (req,resp)=>{
    const email=sanitize(req.body.email);
    const password=sanitize(req.body.password);
    if(typeof email!='string'||typeof password!='string'){
        return resp.send("Invalid Input!");
    }
    const user=await userModel.findOne({email}).select('+password');
    if(!user)
        return resp.redirect('/sign');
    const isMatch=await bcrypt.compare(password,user.password);
    if(!isMatch)
        return resp.send("Invalid Credentials!");
    const token=jwt.sign({id:user._id,email:user.email,role:user.role},SECRET_KEY,{expiresIn:"2h"});
    resp.cookie("token",token,{
        httpOnly:true,
        sameSite:"lax",
        maxAge:2*60*60*1000
    });
    resp.redirect('/');
});

app.get('/sign',preventCache,async (req,resp)=>{
    resp.sendFile(absPathHtml+'/signup.html');
});

// --- UPDATED SIGNUP ROUTE ---
app.post('/signup',rateCheck,preventCache,async (req,resp)=>{
    const name=sanitize(req.body.name);
    const email=sanitize(req.body.email);
    const password=sanitize(req.body.password);
    
    // Validate inputs
    if(typeof name!='string'||typeof email!='string'||typeof password!='string'){
        return resp.send("Invalid Input");
    }
    
    const existingUser=await userModel.findOne({email});
    if(existingUser){
        return resp.sendFile(absPathHtml+'/login.html');
    }
    
    const salt=await bcrypt.genSalt(8);
    const hasedPass=await bcrypt.hash(password,salt);
    const otp=Math.floor(100000+Math.random()*900000).toString();
    const user=JSON.stringify({name,email,password:hasedPass,otp});
    
    await client.setEx(`tempUser:${email}`,1800,user);
    resp.cookie('temp_email',email,{
        httpOnly:true,
        sameSite:"strict",
        maxAge:10*60*1000
    });
    
    const mailOption={
        from:'Decent Engineer',
        to:email,
        subject:'Confirm Your Access Node',
        text:`Your OTP is ${otp}`,
        html:mailContent(name,otp)
    };

    // LOGGING ADDED HERE
    transporter.sendMail(mailOption,(error,info)=>{
        if(error){
            console.error("❌ EMAIL FAILED:", error); // Logs error to Render
            return resp.send("Try after 10 mins Please!");
        }
        else {    
            console.log("✅ EMAIL SENT:", info.response);
            return resp.status(200).redirect('/otp-verify');
        }
    });
});

app.get('/otp-verify',preventCache,(req,resp)=>{
    resp.sendFile(absPathHtml+'/otp.html');
});

app.post('/verifyOtp',rateCheck,preventCache,async (req,resp)=>{
    if(!req.cookies.temp_email){
        return resp.send("OTP Expired, Try Again!");
    }
    const {otp}=req.body;
    const email=req.cookies.temp_email;
    const data=await client.get(`tempUser:${email}`);
    if(!data){
        return resp.send("Try Again!");
    }
    const user=JSON.parse(data);
    if(otp!=user.otp){
        return resp.send("OTP does not Match!");
    }
    const newUser=await userModel.create({
        name:user.name,
        email:user.email,
        password:user.password
    });
    resp.clearCookie('temp_email');
    await client.del(`tempUser:${email}`);
    const token=jwt.sign({id:newUser._id,email:newUser.email,role:newUser.role},SECRET_KEY,{expiresIn:"2h"});
    resp.cookie("token",token,{
        httpOnly:true,
        sameSite:"lax",
        maxAge:2*60*60*1000
    });
    return resp.status(200).json({msg:"Success",redirect:"/"});
});

app.get('/resendOtp',rateCheck,preventCache,async (req,resp)=>{
    const email=req.cookies.email;
    if(!email){
        return resp.redirect('/sign');
    }
    const existingUser=await userModel.findOne({email});
    if(existingUser){
        return resp.redirect('/log');
    }
    const data=await client.get(`temp_email:${email}`);
    if(!data){
        return resp.redirect('/sign');
    }
    const otp=Math.floor(100000+Math.random()*900000).toString();
    data.otp=otp;
    await client.setEx(`temp_user:${email}`,1800,JSON.stringify(data));
    const mailOption={
        from:'tyagidevyani3@gmail.com',
        to:email,
        subject:'Confirm Your Access Code',
        text:`OTP: ${otp}`,
        html:mailContent(name,otp)
    };
    transporter.sendMail(mailOption,(error,info)=>{
        if(error){
            console.error("Resend OTP Error:", error);
            return resp.send("Email not Sent!");
        }
        else{
            return resp.redirect('/otp-verify');
        }
    });
});

app.get('/resume',verifyToken,preventCache,(req,resp)=>{
    resp.sendFile(absPathHtml+'/resume.html');
});

app.get('/logout',verifyToken,preventCache,(req,resp)=>{
    resp.clearCookie("token",{
        httpOnly:true,
        sameSite:"lax",
        maxAge:2*60*60*1000
    });
    resp.set('Clear-Site-Data','"cache","cookies","storage"');
    resp.redirect('/log');
});

app.get('/about',verifyToken,preventCache,(req,resp)=>{
    resp.sendFile(absPathHtml+'/about.html');
});

app.get('/contact',verifyToken,preventCache,(req,resp)=>{
    resp.sendFile(absPathHtml+'/contact.html');
});

app.post('/message',verifyToken,preventCache,async (req,resp)=>{
    const name=sanitize(req.body.name);
    const email=sanitize(req.body.email);
    const message=sanitize(req.body.message);
    if(typeof name!='string'||typeof email!='string'||typeof message!='string'){
        return resp.send("Invalid Input");
    }
    const actualMail=req.user.email;
    const recievedMessage=await messageModel.create({
        name:name,
        typedEmail:email,
        actualEmail:actualMail,
        message:message
    });
    resp.send("Success");
});

app.get('/viewMessage',verifyToken,verifyAdmin,preventCache,async (req,resp)=>{
    try{
        const messages=await messageModel.find();
        resp.render('admin',{messages:messages});
    }
    catch(error){
        return resp.send('Database error!');
    }
});

app.get('/forgotPassword',preventCache,(req,resp)=>{
    resp.sendFile(absPathHtml+'/forgotPassword.html');
});

app.post('/forgotPassword',preventCache,rateCheck,async (req,resp)=>{
    const email=sanitize(req.body.email);
    if(typeof email!='string'){
        return resp.send("Invalid Input");
    }
    const user=await userModel.findOne({email});
    if(!user){
        return resp.send("User Does not exists!");
    }
    const resetToken=jwt.sign({id:user._id},process.env.SECRET_KEY,{expiresIn:"15m"});
    const baseUrl=process.env.BASE_URL;
    const newLink=`${baseUrl}/resetPassword?token=${resetToken}`;
    const mailOption={
        from:"Decent Engineer",
        to:email,
        subject: '⚠️ Security Protocol: Credential Reset Requested',
        text:`Reset link: ${newLink}`,
        html:forgotPasswordMailContent(newLink)
    };
    transporter.sendMail(mailOption,(error,info)=>{
        if(error)
            return resp.send("Mail not sent");
        else
            return resp.redirect('/checkMail');
    });
});

app.get('/checkMail',preventCache,(req,resp)=>{
    resp.sendFile(absPathHtml+'/checkMail.html');
});

app.get('/resetPassword',preventCache,async (req,resp)=>{
    const {token}=req.query;
    if(!token){
        return resp.send("Token Expired");
    }
    const isUSed=await client.get(`Blacklist:${token}`);
    if(isUSed){
        return resp.send("Link has already been used!");
    }
    try{
        jwt.verify(token,process.env.SECRET_KEY);
        resp.render('reset',{token:token});
    }
    catch(error){
        return resp.send("Link Expired");
    }
});

app.post('/resetPassword',preventCache,rateCheck,async (req,resp)=>{
    const token=req.body.token;
    const newPassword=sanitize(req.body.newPassword);
    if(typeof newPassword!='string'){
        return resp.send("Invalid Password");
    }
    try{
        const isUsed=await client.get(`Blacklist:${token}`);
        if(isUsed){
            return resp.send("The link has already been used!");
        }
        const decode=jwt.verify(token,process.env.SECRET_KEY);
        const userId=decode.id;
        const salt=await bcrypt.genSalt(10);
        const hashedPassword=await bcrypt.hash(newPassword,salt);
        await userModel.findByIdAndUpdate(userId,{password:hashedPassword});
        await client.setEx(`Blacklist:${token}`,900,'true');
        resp.redirect('/passwordUpdated');
    }
    catch(error){
        resp.send("Session Expired");
    }
});

app.get('/passwordUpdated',(req,resp)=>{
    resp.sendFile(absPathHtml+'/passwordUpdated.html');
});