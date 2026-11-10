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

        // Not unique: a device can be reported more than once (e.g. after a
        // rejected report) and look-alike devices can share a fingerprint.
        device_fingerprint: { type: String, required: true },

    },
    { timestamps: true }
);


export default mongoose.model("admin_message", messageAdmin);
