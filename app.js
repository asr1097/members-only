require("dotenv").config();
const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const logger = require("morgan");
const compression = require("compression");
const helmet = require("helmet");
const mongoose = require("mongoose");
const createError = require('http-errors');
const {body, validationResult, check} = require("express-validator");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const passportSetup = require("./passport-setup");

const User = require("./models/user");
const Message = require("./models/message");
const SecretPassword = require("./models/password");

const MONGODB = process.env.MONGODB_URI;
mongoose.connect(MONGODB, { useNewUrlParser: true , useUnifiedTopology: true});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

const isAuth = (req, res, next) => {
    if(req.user) {return next();}
    else{return res.redirect("/login")};
};

const isAdmin = (req, res, next) => {
    if(req.session.isAdmin) {return next();}
    else{return res.redirect("/")}
};

const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const store = new MongoStore({
    mongoUrl: process.env.MONGODB_URI,
    collection: "sessions"
})

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: store
}));

app.use(passportSetup.initialize());
app.use(passportSetup.session());

app.use(helmet());
app.use(compression());

app.get("/", (req, res, next) => {
    Message.find().populate("author").then((messages) => {
        res.render("index", {
            user: req.user, 
            messages: messages, 
            isAdmin: req.session.isAdmin, 
            isMember: req.session.isMember
        });
    }).catch((err) => {throw err});
});

app.get("/sign-up", (req, res, next) => {
    res.render("sign-up", {first_name: null, last_name: null, email: null, errors: null});
});

app.post("/sign-up", 
    body("first_name").trim().isLength({min: 1}).escape(),
    body("last_name").trim().isLength({min: 1}).escape(),
    body("email").isEmail(),
    body("password").isLength({min: 8}),
    check("confirm_password").custom((value, {req}) => {
        if(value !== req.body.password) {
            return false;
        } else {return true;}
    }).withMessage("Passwords do not match."),

    (req, res, next) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            res.render("sign-up", {
                first_name: req.body.first_name,
                last_name: req.body.last_name,
                email: req.body.email,
                errors: errors.array()
            });
        } else {
            const hash = bcrypt.hashSync(req.body.password, 10);
            const user = new User({
                first_name: req.body.first_name,
                last_name: req.body.last_name,
                email: req.body.email,
                password: hash,
                isAdmin: req.body.isAdmin === "on" ? true : false
            });
            user.save().then(res.redirect("/"))
        }
    }
);

app.get("/login", (req, res, next) => {
    return res.render("log-in", {errors: null});
});

app.post("/login", [
    (req, res, next) => {
        passport.authenticate("local", (err, user, info) => {
            if(err) {return res.render("log-in", {errors: err})}
            if(!user) {return res.render("log-in", {errors: ["No user found."]})};
            req.logIn(user, (err) => {
                if(err) {return res.render("log-in", {errors: ["Log in failed."]})}
                
                next();
            })
        })(req, res, next)
    },

    (req, res, next) => {
        User.findOne({"_id": req.user}).then(user => {
            req.session.isMember = user.isMember;
            req.session.isAdmin = user.isAdmin;
            return res.redirect("/");
        });
    }
]);

app.get("/send-message", isAuth, (req, res, next) => {
    res.render("send-message", {errors: null});
});

app.post("/send-message", isAuth, 

    body("title").trim().isLength({min: 1}).escape(),
    body("message").trim().isLength({min: 1}).escape(),

    (req, res, next) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            res.render("/send-message", {errors: errors.array()});
        } else {
            User.findOne({"_id": req.user}).then((author) => {
                console.log(author);
                const message = new Message({
                    title: req.body.title,
                    text: req.body.message,
                    author: author,
                    timestamp: Date.now(),
                })
                message.save()
                    .then(res.redirect("/"))
                    .catch((err) => {throw err})
            }).catch((err) => {throw err});
        }
});

app.get("/join", isAuth, (req, res, next) => {
    res.render("join", {errors: null});
});

app.post("/join", isAuth, (req, res, next) => {
    SecretPassword.findOne().then(result => {
        bcrypt.compare(req.body.password, result.password, (err, isMatch) => {
            if(err) {throw err};
            if(isMatch) {
                User.findByIdAndUpdate(req.user, {"isMember": true}, {new: true})
                    .then(data => {
                        req.session.isMember = data.isMember;
                        res.redirect("/");
                    })
                    .catch(err => {throw err})
            } else{
                res.render("/join", {errors: ["Wrong password."]})
            }
        })
    }).catch(err => {throw err})
});

app.post("/delete", isAdmin, 

    body("id").escape(),

    (req, res, next) => {
        Message.findByIdAndRemove(req.body.id, {}).then(msg => 
            {res.redirect("/");}
        ).catch(err => {throw err})
    }
);

app.post("/logout", (req, res, next) => {
    req.logout();
    res.redirect("/")
});
 
// catch 404 and forward to error handler
app.use(function(req, res, next) {
    next(createError(404));
});
  
// error handler
app.use(function(err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
  
    // render the error page
    res.status(err.status || 500);
    res.render('error');
});

module.exports = app;