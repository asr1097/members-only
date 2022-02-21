const bcrypt = require("bcryptjs");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const User = require("./models/user");

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id)
        .then((user) => {return done(null, user)})
        .catch((err) => {return done(null, false, {message: err})});
});

passport.use(
    new LocalStrategy({usernameField: "email"}, (email, password, done) => {
            User.findOne({email: email})
                .then((user) => {
                    bcrypt.compare(password, user.password, (err, isMatch) => {
                        if(err) throw err;
                        if(isMatch) {
                            return done(null, user);
                        } else {
                            return done(null, false, {message: "Wrong password"})
                        }
                    })
                })
                .catch((err) => {
                    return done(null, false, {message: err});
                });
        }
    )
);

module.exports = passport;