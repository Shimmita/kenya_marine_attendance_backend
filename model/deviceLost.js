import mongoose from "mongoose";

const deviceLost = new mongoose.Schema(
    {
        description: { type: String, required: true, trim: true },
        user_email: {
            type: String,
            required: true,
            lowercase: true,
            trim: true,
        },

        startDate: { type: String, required: true },
        endDate: { type: String, required: true },
        status: {
            type: String,
            enum: ["pending", "rejected", "granted"],
            default: "pending",
        },
        responded: {
            type: String,
            enum: ["admin", "hr", "supervisor",""],
            default: "",
        },
        device_fingerprint: { type: String, required: true, unique: true },

    },
    { timestamps: true }
);


export default mongoose.model("lostDevice", deviceLost);
