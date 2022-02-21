const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const UserSchema = new Schema(
    {
        first_name: {type: String, maxlength: 100, required: true},
        last_name: {type: String, maxlength: 100, required: true},
        email: {type: String, maxlength: 100, required: true},
        password: {type: String, required: true},
        isMember: {type: Boolean, required: true, default: false},
        isAdmin: {type: Boolean, default: false}
    }
);

UserSchema.virtual("name").get(function() {
    return this.first_name + " " + this.last_name;
});

module.exports = mongoose.model("User", UserSchema);