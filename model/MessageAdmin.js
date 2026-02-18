import mongoose from "mongoose";

const messageAdmin = new mongoose.Schema(
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
            enum: ["pending", "rejected", "success", "granted"],
            default: "pending",
        },

        responded: {
            type: String,
            enum: ["admin", "hr", "supervisor",""],
            default: "",
        },

        respondedName: {
            type: String,
            default: "",
        },

        device_fingerprint: { type: String, required: true, unique: true },

    },
    { timestamps: true }
);


export default mongoose.model("admin_message", messageAdmin);
