const router = require("express").Router()

const User = require("../models/User.model.js")

const bcrypt = require("bcryptjs")
const saltRounds = 10

const isLoggedIn = require("../middleware/isLoggedIn.js");
const isLoggedOut = require("../middleware/isLoggedOut.js");

// Vista de users/login
router.get("/login", isLoggedOut, (req, res, next)=>{
    res.render("users/login");
})

// Vista cuando rellenas el formulario de users/login: si está bien te lleva a users/profile, sino a users/login
router.post("/login", isLoggedOut, (req, res, next)=>{
    const { username, password } = req.body;

    User.findOne({username})
    .then(user => { 
        if(bcrypt.compareSync(password, user.password)) {
            req.session.currentUser=user;   
            res.redirect("/users/profile");
        } else {
            const data = {missatgeError: "Incorrect credentials"};
            if(req.session.currentUser) data.username = req.session.currentUser.username;
            res.render("users/login", data)
        }
    })
    .catch(err => {
        res.render("error", {missatgeError: err})   
    })
})

// Vista de users/singup
router.get("/signup", isLoggedOut, (req, res, next)=>{
    res.render("users/signup");
})

// Vista cuando te registras: si todo va bien te lleva a users/profile, si hay algo mal, users/signup
router.post("/signup", isLoggedOut, (req, res, next)=>{
    const {username, password, passwordRepeat} = req.body;

    if(!username || !password  || !passwordRepeat) {
        const data = {missatgeError: "Missing fields"};
        if(req.session.currentUser) data.username = req.session.currentUser.username;
        
        res.render("users/signup", data);
        return; 
    }
    if(password != passwordRepeat) {
        const data = {missatgeError: "Diferent passwords"};
        if(req.session.currentUser) data.username = req.session.currentUser.username;

        res.render("users/signup", data);
        return;
    }
    if (username === username) {
        const data = { missatgeError: "This username is already created" }
        if (req.session.currentUser) data.username = req.session.currentUser.username;
        
        res.render("users/signup", data);
        return;
    }

    // Para encriptar el password
    const salt = bcrypt.genSaltSync(saltRounds);
    const passwordHash = bcrypt.hashSync(password, salt);

    User.create({
        username,
        password: passwordHash
    })
    .then(result => {
        req.session.currentUser=result;   
        res.redirect("/users/profile");     
    })
    .catch(err => {
        const data = {missatgeError: err};
        if(req.session.currentUser) data.username = req.session.currentUser.username;

        res.render("error", data)   
    })
})

// Para ver la vista de users/profile
router.get("/profile", isLoggedIn, (req, res, next)=>{
    const data = {missatgeError: "Diferent passwords"};
    if(req.session.currentUser) data.username = req.session.currentUser.username;

    res.render("users/profile", data);    
});

router.get("/main", isLoggedIn ,(req, res, next)=>{
    const data = {missatgeError: "No estás loggeado"};
    if(req.session.currentUser) data.username = req.session.currentUser.username;
    res.render("users/main", data);    
});


router.get("/private", isLoggedIn ,(req, res, next)=>{
    const data = {missatgeError: "No estás loggeado"};
    if(req.session.currentUser) data.username = req.session.currentUser.username;
    res.render("users/private", data);    
});
module.exports = router
