import mongoose from "mongoose";

const passwordResetSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    }
}, { timestamps: true })

export default mongoose.model("PasswordReset", passwordResetSchema);