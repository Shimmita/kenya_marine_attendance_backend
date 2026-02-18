import mongoose from "mongoose";

const messageUser = new mongoose.Schema(
    {
        user_email: {
            type: String,
            required: true,
            lowercase: true,
            trim: true,
        },

        message: { type: String, required: true },
        title: { type: String, required: true },
        label: {
            type: String,
            enum: ["urgent", "none"],
            // Todo: make this required
            default: "none",
        },
        status: {
            type: String,
            enum: ["pending", "rejected", "success","granted"],
            default: "pending",
        },

    },
    { timestamps: true }
);


export default mongoose.model("user_message", messageUser);
