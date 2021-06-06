require ("dotenv").config();
const router = require('express').Router();
const { MongoClient, ObjectID } = require('mongodb')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
var jwt = require('jsonwebtoken')
const crypto = require('crypto')

const dbURL = process.env.DB_URL || 'mongodb://127.0.0.1:27017'

var transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "nodemailera91@gmail.com",
        pass: process.env.NODEMAILER_PASS
    }
});

router.post("/passwordreset", async (req, res) => {
    try {
        


        let client = await MongoClient.connect(dbURL);
        let db = await client.db('user');
        let data = await db.collection("logininfo").findOne({ email: req.body.email })
        if (data) {
            console.log(data)
            crypto.randomBytes(32,(err,buffer)=>{
                if(err){
                    console.log(err)
                }else{
                    const resetToken = buffer.toString("hex")
                    console.log(resetToken)
                    // req.body.resetToken = token;
        //    data.expireToken = Date.now()+ 3600000
            var mailOptions = {
                from: "nodemailera91@gmail.com",
                to:  req.body.email,
                subject: "Password Reset Link ",
                html: `<h4>Please click on this <a href="http://localhost:3000/Resetpassword/${resetToken}">link</a> to reset password</h4>`
            }
            transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    console.log(error)
                } else {
                    console.log("email sent " + info.response)
                }
            })
            res.status(200).json({message : "Email sent to user successfully"})
                }
            })
           
        } else {
            res.status(404).json({ message: "User not registered" })
        }
        client.close();
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ message: "Internal server error" })
    }
})

router.get("/login", async (req, res) => {
    try {
        let client = await MongoClient.connect(dbURL);
        let db = await client.db('user');
        let data = await db.collection("logininfo").findOne({ email: req.body.email })
        if (data) {
            let isValid = await bcrypt.compare(req.body.password, data.password)
            console.log(isValid)
            if (isValid) {
                let token = await jwt.sign({user_id:data._id},process.env.JWT_KEY)
                res.status(200).json({ message: "Login Sucessfull" ,token})
            }
            else {
                res.status(401).json({ message: "Invalid Credentials" })
            }
        } else {
            res.status(404).json({ message: "User not registered" })
        }
        client.close();
    }
    catch (error) {
        console.log(error)
        res.status(500).json({ message: "Internal server error" })
    }
})

router.post("/register", async (req, res) => {
    try {
        let client = await MongoClient.connect(dbURL);
        let db = await client.db('user');
        let data = await db.collection("logininfo").findOne({ email: req.body.email, password: req.body.password })
        if (!data) {
            let salt = await bcrypt.genSalt(10)
            let hash = await bcrypt.hash(req.body.password, salt)
            req.body.password = hash
            // console.log(req.body)
            await db.collection('logininfo').insertOne(req.body)
            res.status(200).json({ message: "user successfully registered" })
        }
        client.close();
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Internal server error" })

    }

})

module.exports = router;