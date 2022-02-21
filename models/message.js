const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const MessageSchema = new Schema(
    {
        title: {type: String, maxlength: 100, required: true},
        text: {type: String, maxlength: 999, required: true},
        timestamp: {type: Date, required: true},
        author: {type: Schema.Types.ObjectId, ref: "User", required: true}
    }
);

module.exports = mongoose.model("Message", MessageSchema);