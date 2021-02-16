const express = require('express')
const router = express.Router()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const config = require('../config')
const User = require('../model/userModel')

router.use(express.json());
router.use(express.urlencoded({extended : true}));

//get all user

router.get('/users', (req, res) => {
    User.find({}, (err, data) => {
        if (err) throw err
        res.send(data)
    })
})


//register user

router.post('/register', (req, res) => {
    let hash = bcrypt.hashSync(req.body.password)
    User.create({
        name: req.body.name,
        password: hash,
        email: req.body.email,
        role: req.body.role ? req.body.role : "User",
        isActive: true
    }, (err, user) => {
        if(err) return res.status(500).send('error while registering')
        return res.status(200).send("Register Successfull")
    })
})

//login user

router.post('/login', (req, res) => {
    User.findOne({email : req.body.email},(err, data) => {
        if(err) return res.status(500).send({auth : false, error : "Error while login"})
        if(!data) return res.status(500).send({auth : false, error : "no user found, register first"})
        else{
            const passIsValid = bcrypt.compareSync(req.body.password, data.password)
            if(!passIsValid){
                return res.status(500).send({auth : false,error : "Invalid Password"})
            }
            let token = jwt.sign({id: data.id}, config.secret, {expiresIn: 86400})
            return res.status(200).send({auth : true, token: token})
        }
    })
})

//user info

router.get('/userInfo', (req, res) => {
    let token = req.headers['x-access-token']
    if(!token) return res.status(500).send({auth : false,error : "No token provided"})
    jwt.verify(token,config.secret, (err, data) => {
        if(err) return res.status(500).send({auth : false,error : "Invalid Token"})
        User.findById(data.id,{password:0}, (err, result) => {
            res.send(result)
        })
    })

})

//update password

router.put('/updatePassword', (req, res) => {
    let token = req.headers['x-access-token']
    if(!token) return res.status(500).send({auth : false,error : "No token provided"})
    jwt.verify(token,config.secret, (err, data) => {
        if(err) return res.status(500).send({auth : false,error : "Invalid Token"})
        let hash = bcrypt.hashSync(req.body.password)
        User.updateOne({_id : data.id}, {password : hash}, (err, result) => {
            if (err) throw err
            return res.send('password updated')
        })
    })
})

module.exports = router